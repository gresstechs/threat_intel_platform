"""
alert_prioritiser.py — D3.1: Automated Alert Prioritisation System

Implements the multi-factor alert scoring and prioritisation algorithm
that reduces security analyst workload by ranking and suppressing
low-value alerts before they reach the analyst queue.

Prioritisation Algorithm:
    priority_score = (
        w1 * combined_confidence +
        w2 * severity_normalised +
        w3 * source_agreement_bonus +
        w4 * recency_bonus +
        w5 * category_weight
    )

Priority Tiers:
    CRITICAL : priority_score >= 0.80
    HIGH     : priority_score >= 0.60
    MEDIUM   : priority_score >= 0.40
    LOW      : priority_score  < 0.40

Objective 3 Target: Reduce analyst workload by >= 40% by:
  1. Suppressing LOW-priority alerts from the active queue
  2. Auto-resolving known false positive patterns
  3. Deduplicating multi-feed alerts for the same indicator
  4. Batching related alerts by threat category and country

Deliverable: D3.1 | Deadline: Week 16 (May 23, 2026)
"""

import logging
import time
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from config import Config
from normaliser import ThreatIndicator, ThreatCategory, SourceFeed
from db import db

logger = logging.getLogger(__name__)


# ── Priority Tiers ────────────────────────────────────────────────────────────

class AlertPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ── Scoring Weights ───────────────────────────────────────────────────────────

# Weights must sum to 1.0
WEIGHT_CONFIDENCE    = 0.35   # Combined feed confidence score
WEIGHT_SEVERITY      = 0.25   # Severity score (normalised 0-1)
WEIGHT_SOURCE_AGREE  = 0.15   # Bonus when multiple feeds agree
WEIGHT_RECENCY       = 0.10   # Bonus for recently seen indicators
WEIGHT_CATEGORY      = 0.15   # Threat category risk multiplier

# Category risk multipliers — higher = more dangerous to the organisation
CATEGORY_WEIGHTS = {
    ThreatCategory.RANSOMWARE:  1.00,
    ThreatCategory.MALWARE:     0.95,
    ThreatCategory.PHISHING:    0.85,
    ThreatCategory.DDOS:        0.75,
    ThreatCategory.BOTNET:      0.70,
    ThreatCategory.SCANNING:    0.40,
    ThreatCategory.SPAM:        0.25,
    ThreatCategory.UNKNOWN:     0.30,
}

# False positive suppression patterns
# Indicators matching these patterns are auto-flagged as likely false positives
FALSE_POSITIVE_PATTERNS = {
    "known_safe_ips": {
        "8.8.8.8",         # Google DNS
        "8.8.4.4",         # Google DNS
        "1.1.1.1",         # Cloudflare DNS
        "1.0.0.1",         # Cloudflare DNS
        "208.67.222.222",  # OpenDNS
        "208.67.220.220",  # OpenDNS
    },
    "max_confidence_threshold": 0.05,  # Below this = almost certainly benign
    "min_malicious_count": 1,          # At least 1 engine must flag as malicious
}

# Recency bonus windows
RECENCY_24H_BONUS  = 1.0   # Seen in last 24 hours — maximum recency bonus
RECENCY_7D_BONUS   = 0.6   # Seen in last 7 days
RECENCY_30D_BONUS  = 0.3   # Seen in last 30 days
RECENCY_OLD_BONUS  = 0.1   # Older than 30 days


# ── Scored Alert Dataclass ────────────────────────────────────────────────────

@dataclass
class ScoredAlert:
    """
    A threat indicator enriched with a priority score and tier.
    Created by the prioritisation algorithm from raw ThreatIndicators.
    """
    indicator_value:    str
    indicator_type:     str
    threat_category:    str
    alert_priority:     AlertPriority
    priority_score:     float               # 0.0 - 1.0 composite score

    # Component scores (for audit and dashboard transparency)
    combined_confidence:    float
    severity_score:         float
    source_agreement_bonus: float
    recency_bonus:          float
    category_weight:        float

    # Multi-feed data
    sources_count:      int = 0             # How many feeds reported this
    sources_agreed:     bool = False        # All feeds agree on category
    otx_score:          Optional[float] = None
    vt_score:           Optional[float] = None
    abuseipdb_score:    Optional[float] = None

    # Context
    country_code:       Optional[str] = None
    is_false_positive:  bool = False
    fp_reason:          Optional[str] = None
    scored_at:          datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ── Alert Prioritiser ─────────────────────────────────────────────────────────

class AlertPrioritiser:
    """
    Implements the multi-factor alert prioritisation algorithm.

    Takes raw ThreatIndicators (or batches of them for the same indicator
    across multiple feeds) and produces a single ScoredAlert with a
    priority tier and composite score.

    Usage:
        prioritiser = AlertPrioritiser()

        # Score a single indicator
        alert = prioritiser.score_indicator(indicator)

        # Score and store a batch
        stats = prioritiser.process_and_store(indicators)
    """

    def __init__(self) -> None:
        self.total_processed   = 0
        self.total_suppressed  = 0   # LOW priority — not shown to analysts
        self.total_fp_flagged  = 0   # Auto-flagged false positives
        self.total_queued      = 0   # Added to active alert queue

    # ── Core Scoring ─────────────────────────────────────────────────────────

    def _compute_recency_bonus(self, last_seen: Optional[datetime]) -> float:
        """Compute recency bonus based on when the indicator was last seen."""
        if last_seen is None:
            return RECENCY_OLD_BONUS
        now = datetime.now(timezone.utc)
        # Ensure last_seen is timezone-aware
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        age = now - last_seen
        if age <= timedelta(hours=24):
            return RECENCY_24H_BONUS
        elif age <= timedelta(days=7):
            return RECENCY_7D_BONUS
        elif age <= timedelta(days=30):
            return RECENCY_30D_BONUS
        return RECENCY_OLD_BONUS

    def _compute_source_agreement(
        self, indicators: list[ThreatIndicator]
    ) -> tuple[float, bool]:
        """
        Compute the source agreement bonus.
        Returns (bonus_score, sources_agreed).
        Agreement = all feeds classify the same threat category.
        """
        if len(indicators) <= 1:
            return 0.0, False

        categories = {i.threat_category for i in indicators}
        sources_agreed = len(categories) == 1

        # Bonus scales with number of agreeing sources
        if sources_agreed:
            if len(indicators) == 3:
                return 1.0, True    # All three feeds agree — maximum bonus
            elif len(indicators) == 2:
                return 0.6, True    # Two feeds agree
        return 0.2, False           # Feeds disagree — small partial bonus

    def _get_category_weight(self, category: ThreatCategory) -> float:
        """Return the risk multiplier for a threat category."""
        return CATEGORY_WEIGHTS.get(category, 0.30)

    def _is_false_positive(
        self, indicator_value: str, combined_confidence: float,
        malicious_count: int
    ) -> tuple[bool, Optional[str]]:
        """
        Check if an indicator matches known false positive patterns.
        Returns (is_fp, reason_string).
        """
        if indicator_value in FALSE_POSITIVE_PATTERNS["known_safe_ips"]:
            return True, f"Known safe IP address: {indicator_value}"

        if combined_confidence < FALSE_POSITIVE_PATTERNS["max_confidence_threshold"]:
            return True, f"Confidence too low: {combined_confidence:.4f} < 0.05 threshold"

        if malicious_count < FALSE_POSITIVE_PATTERNS["min_malicious_count"]:
            return True, f"No malicious detections across all engines"

        return False, None

    def _compute_combined_confidence(
        self, indicators: list[ThreatIndicator]
    ) -> float:
        """
        Compute a weighted combined confidence across all feeds.
        VirusTotal gets a higher weight due to its multi-engine coverage.
        """
        if not indicators:
            return 0.0

        feed_weights = {
            SourceFeed.OTX:        0.30,
            SourceFeed.VIRUSTOTAL: 0.45,
            SourceFeed.ABUSEIPDB:  0.25,
        }

        total_weight = 0.0
        weighted_sum = 0.0

        for ind in indicators:
            w = feed_weights.get(ind.source_feed, 0.33)
            weighted_sum += ind.confidence_score * w
            total_weight += w

        return round(weighted_sum / total_weight, 4) if total_weight > 0 else 0.0

    def _assign_priority_tier(self, score: float) -> AlertPriority:
        """Assign priority tier based on composite score."""
        if score >= 0.80:
            return AlertPriority.CRITICAL
        elif score >= 0.60:
            return AlertPriority.HIGH
        elif score >= 0.40:
            return AlertPriority.MEDIUM
        return AlertPriority.LOW

    # ── Public API ────────────────────────────────────────────────────────────

    def score_indicators(
        self, indicators: list[ThreatIndicator]
    ) -> ScoredAlert:
        """
        Score a group of ThreatIndicators for the same indicator_value
        (one per source feed) and produce a single ScoredAlert.

        This is the core of the multi-source correlation benefit:
        the same IP flagged by all three feeds gets a higher priority
        score than if only one feed reported it.

        Args:
            indicators: List of ThreatIndicators (1-3) for the same IOC

        Returns:
            ScoredAlert with priority tier and composite score
        """
        if not indicators:
            raise ValueError("indicators list cannot be empty")

        # Use the highest-severity indicator as the representative
        primary = max(indicators, key=lambda x: x.confidence_score)

        # ── Component 1: Combined confidence (weighted across feeds) ──────────
        combined_confidence = self._compute_combined_confidence(indicators)

        # ── Component 2: Severity (normalised from 0-10 to 0-1) ──────────────
        severity_normalised = round(primary.severity_score / 10.0, 4)

        # ── Component 3: Source agreement bonus ──────────────────────────────
        source_agreement_bonus, sources_agreed = self._compute_source_agreement(
            indicators
        )

        # ── Component 4: Recency bonus ────────────────────────────────────────
        latest_seen = max(
            (i.last_seen for i in indicators if i.last_seen is not None),
            default=None
        )
        recency_bonus = self._compute_recency_bonus(latest_seen)

        # ── Component 5: Category weight ─────────────────────────────────────
        # Use the most dangerous category if feeds disagree
        most_dangerous_category = max(
            indicators,
            key=lambda x: CATEGORY_WEIGHTS.get(x.threat_category, 0.30)
        ).threat_category
        category_weight = self._get_category_weight(most_dangerous_category)

        # ── Composite priority score ──────────────────────────────────────────
        priority_score = round(
            (WEIGHT_CONFIDENCE   * combined_confidence)    +
            (WEIGHT_SEVERITY     * severity_normalised)    +
            (WEIGHT_SOURCE_AGREE * source_agreement_bonus) +
            (WEIGHT_RECENCY      * recency_bonus)          +
            (WEIGHT_CATEGORY     * category_weight),
            4
        )
        # Clamp to [0.0, 1.0]
        priority_score = max(0.0, min(1.0, priority_score))

        # ── False positive check ──────────────────────────────────────────────
        total_malicious = sum(i.malicious_count for i in indicators)
        is_fp, fp_reason = self._is_false_positive(
            primary.indicator_value, combined_confidence, total_malicious
        )

        # Override priority to LOW if false positive
        if is_fp:
            priority_score = min(priority_score, 0.39)

        priority_tier = self._assign_priority_tier(priority_score)

        # ── Per-feed scores (for dashboard transparency) ──────────────────────
        feed_scores = {i.source_feed: i.confidence_score for i in indicators}

        return ScoredAlert(
            indicator_value        = primary.indicator_value,
            indicator_type         = primary.indicator_type.value,
            threat_category        = most_dangerous_category.value,
            alert_priority         = priority_tier,
            priority_score         = priority_score,
            combined_confidence    = combined_confidence,
            severity_score         = round(primary.severity_score, 2),
            source_agreement_bonus = round(source_agreement_bonus, 4),
            recency_bonus          = round(recency_bonus, 4),
            category_weight        = round(category_weight, 4),
            sources_count          = len(indicators),
            sources_agreed         = sources_agreed,
            otx_score              = feed_scores.get(SourceFeed.OTX),
            vt_score               = feed_scores.get(SourceFeed.VIRUSTOTAL),
            abuseipdb_score        = feed_scores.get(SourceFeed.ABUSEIPDB),
            country_code           = primary.country_code,
            is_false_positive      = is_fp,
            fp_reason              = fp_reason,
        )

    def process_and_store(
        self,
        indicators: list[ThreatIndicator],
        suppress_low: bool = True,
        suppress_false_positives: bool = True,
    ) -> dict:
        """
        Process a batch of ThreatIndicators:
        1. Group by indicator_value
        2. Score each group using multi-feed correlation
        3. Apply suppression rules (LOW priority, false positives)
        4. Store qualifying alerts in the alert_queue table
        5. Store all results in correlation_results table
        6. Return workload reduction statistics

        Args:
            indicators:               List of ThreatIndicators from API ingestion
            suppress_low:             If True, LOW priority alerts are not queued
            suppress_false_positives: If True, FP alerts are not queued

        Returns:
            dict with processing statistics including workload_reduction_pct
        """
        start = time.time()
        stats = {
            "total_indicators":      len(indicators),
            "unique_iocs":           0,
            "critical":              0,
            "high":                  0,
            "medium":                0,
            "low":                   0,
            "false_positives":       0,
            "suppressed":            0,
            "queued_for_analyst":    0,
            "workload_reduction_pct": 0.0,
            "processing_time_s":     0.0,
        }

        if not indicators:
            return stats

        # ── Step 1: Group indicators by indicator_value ───────────────────────
        groups: dict[str, list[ThreatIndicator]] = {}
        for ind in indicators:
            key = ind.indicator_value
            if key not in groups:
                groups[key] = []
            groups[key].append(ind)

        stats["unique_iocs"] = len(groups)
        logger.info(
            f"AlertPrioritiser | Processing {len(indicators)} indicators "
            f"across {len(groups)} unique IOCs"
        )

        # ── Step 2: Score each group ──────────────────────────────────────────
        scored_alerts: list[ScoredAlert] = []
        for ioc_value, ioc_indicators in groups.items():
            try:
                alert = self.score_indicators(ioc_indicators)
                scored_alerts.append(alert)

                # Count by priority tier
                stats[alert.alert_priority.value.lower()] += 1
                if alert.is_false_positive:
                    stats["false_positives"] += 1

            except Exception as e:
                logger.error(f"AlertPrioritiser | Scoring failed for {ioc_value}: {e}")

        # ── Step 3: Apply suppression rules ──────────────────────────────────
        analyst_queue = []
        suppressed = []

        for alert in scored_alerts:
            should_suppress = False

            if suppress_false_positives and alert.is_false_positive:
                should_suppress = True
                logger.debug(
                    f"Suppressed FP: {alert.indicator_value} — {alert.fp_reason}"
                )

            elif suppress_low and alert.alert_priority == AlertPriority.LOW:
                should_suppress = True
                logger.debug(
                    f"Suppressed LOW: {alert.indicator_value} "
                    f"(score={alert.priority_score:.4f})"
                )

            if should_suppress:
                suppressed.append(alert)
                stats["suppressed"] += 1
            else:
                analyst_queue.append(alert)

        stats["queued_for_analyst"] = len(analyst_queue)

        # ── Step 4: Compute workload reduction ────────────────────────────────
        # Workload reduction = percentage of alerts suppressed before analyst review
        # Baseline: without prioritisation, analyst sees ALL unique IOC alerts
        total_unique = stats["unique_iocs"]
        if total_unique > 0:
            reduction = (stats["suppressed"] / total_unique) * 100
            stats["workload_reduction_pct"] = round(reduction, 2)

        logger.info(
            f"AlertPrioritiser | Results: "
            f"CRITICAL={stats['critical']} | HIGH={stats['high']} | "
            f"MEDIUM={stats['medium']} | LOW={stats['low']} | "
            f"FP={stats['false_positives']} | "
            f"Suppressed={stats['suppressed']} | "
            f"Queued={stats['queued_for_analyst']} | "
            f"Workload reduction={stats['workload_reduction_pct']:.1f}%"
        )

        # ── Step 5: Store to database ─────────────────────────────────────────
        self._store_correlation_results(scored_alerts)
        self._store_alert_queue(analyst_queue)

        # ── Step 6: Update internal counters ─────────────────────────────────
        self.total_processed  += len(indicators)
        self.total_suppressed += stats["suppressed"]
        self.total_fp_flagged += stats["false_positives"]
        self.total_queued     += stats["queued_for_analyst"]

        stats["processing_time_s"] = round(time.time() - start, 3)

        return stats

    def _store_correlation_results(self, alerts: list[ScoredAlert]) -> None:
        """Store all scored alerts in the correlation_results table."""
        for alert in alerts:
            try:
                with db.cursor() as cur:
                    cur.execute("""
                        INSERT INTO correlation_results (
                            indicator_value, indicator_type,
                            otx_score, vt_score, abuseipdb_score,
                            combined_score, sources_count, sources_agreed,
                            predicted_category, ml_confidence, is_malicious,
                            alert_priority, priority_score, correlated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, NOW()
                        )
                        ON CONFLICT (indicator_value, correlated_at)
                        DO UPDATE SET
                            combined_score    = EXCLUDED.combined_score,
                            alert_priority    = EXCLUDED.alert_priority,
                            priority_score    = EXCLUDED.priority_score
                    """, (
                        alert.indicator_value,
                        alert.indicator_type,
                        alert.otx_score,
                        alert.vt_score,
                        alert.abuseipdb_score,
                        alert.combined_confidence,
                        alert.sources_count,
                        alert.sources_agreed,
                        alert.threat_category,
                        alert.combined_confidence,
                        not alert.is_false_positive,
                        alert.alert_priority.value,
                        alert.priority_score,
                    ))
            except Exception as e:
                logger.error(f"DB | Failed to store correlation result: {e}")

    def _store_alert_queue(self, alerts: list[ScoredAlert]) -> None:
        """Store analyst-facing alerts in the alert_queue table."""
        for alert in alerts:
            try:
                with db.cursor() as cur:
                    cur.execute("""
                        INSERT INTO alert_queue (
                            indicator_value, indicator_type, threat_category,
                            alert_priority, priority_score, combined_score,
                            country_code, is_false_positive, status, created_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, 'OPEN', NOW()
                        )
                    """, (
                        alert.indicator_value,
                        alert.indicator_type,
                        alert.threat_category,
                        alert.alert_priority.value,
                        alert.priority_score,
                        alert.combined_confidence,
                        alert.country_code,
                        alert.is_false_positive,
                    ))
            except Exception as e:
                logger.error(f"DB | Failed to store alert queue entry: {e}")

    def get_workload_reduction_stats(self) -> dict:
        """Return cumulative workload reduction statistics."""
        overall_reduction = (
            (self.total_suppressed / self.total_processed * 100)
            if self.total_processed > 0 else 0.0
        )
        return {
            "total_processed":        self.total_processed,
            "total_suppressed":       self.total_suppressed,
            "total_fp_flagged":       self.total_fp_flagged,
            "total_queued":           self.total_queued,
            "overall_reduction_pct":  round(overall_reduction, 2),
            "objective_3_target_pct": 40.0,
            "objective_3_met":        overall_reduction >= 40.0,
        }

    def print_stats(self) -> None:
        """Print workload reduction statistics to console."""
        stats = self.get_workload_reduction_stats()
        print("\n" + "=" * 60)
        print("  ALERT PRIORITISER — WORKLOAD REDUCTION STATISTICS")
        print("=" * 60)
        for key, value in stats.items():
            print(f"  {key:<35} {value}")
        print("=" * 60 + "\n")
