"""
normaliser.py — Unified threat indicator schema and normalisation pipeline

Converts raw API responses from OTX, VirusTotal, and AbuseIPDB into a
consistent ThreatIndicator dataclass that can be stored in PostgreSQL
and compared / deduplicated across sources.

Normalisation is the critical technical step that makes multi-source
correlation possible — without it, the same malicious IP might appear
in three different formats from three different feeds.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ── Enumerations ──────────────────────────────────────────────────────────────

class IndicatorType(str, Enum):
    """Standardised indicator types across all three feeds."""
    IP_ADDRESS  = "ip_address"
    DOMAIN      = "domain"
    URL         = "url"
    FILE_HASH   = "file_hash"
    EMAIL       = "email"
    UNKNOWN     = "unknown"


class ThreatCategory(str, Enum):
    """
    Unified threat categories used by the ML classifier.
    Maps from each feed's proprietary category naming.
    """
    MALWARE     = "malware"
    PHISHING    = "phishing"
    DDOS        = "ddos"
    SCANNING    = "scanning"
    BOTNET      = "botnet"
    RANSOMWARE  = "ransomware"
    SPAM        = "spam"
    UNKNOWN     = "unknown"


class SourceFeed(str, Enum):
    """The three integrated threat intelligence feeds."""
    OTX         = "alienvault_otx"
    VIRUSTOTAL  = "virustotal"
    ABUSEIPDB   = "abuseipdb"


# ── Category Mapping Tables ───────────────────────────────────────────────────

# Map OTX tags/categories to unified ThreatCategory
OTX_CATEGORY_MAP: dict[str, ThreatCategory] = {
    "malware":          ThreatCategory.MALWARE,
    "ransomware":       ThreatCategory.RANSOMWARE,
    "phishing":         ThreatCategory.PHISHING,
    "ddos":             ThreatCategory.DDOS,
    "scanning":         ThreatCategory.SCANNING,
    "botnet":           ThreatCategory.BOTNET,
    "spam":             ThreatCategory.SPAM,
    "c2":               ThreatCategory.MALWARE,
    "rat":              ThreatCategory.MALWARE,
    "trojan":           ThreatCategory.MALWARE,
}

# Map AbuseIPDB category IDs to unified ThreatCategory
# Full list: https://www.abuseipdb.com/categories
ABUSEIPDB_CATEGORY_MAP: dict[int, ThreatCategory] = {
    1:  ThreatCategory.DDOS,        # DNS Compromise
    2:  ThreatCategory.DDOS,        # DNS Poisoning
    3:  ThreatCategory.SCANNING,    # Fraud Orders
    4:  ThreatCategory.DDOS,        # DDoS Attack
    5:  ThreatCategory.SCANNING,    # FTP Brute-Force
    6:  ThreatCategory.SPAM,        # Ping of Death
    7:  ThreatCategory.PHISHING,    # Phishing
    8:  ThreatCategory.SPAM,        # Fraud VoIP
    9:  ThreatCategory.SCANNING,    # Open Proxy
    10: ThreatCategory.SPAM,        # Web Spam
    11: ThreatCategory.SPAM,        # Email Spam
    12: ThreatCategory.SCANNING,    # Blog Spam
    13: ThreatCategory.SCANNING,    # VPN IP
    14: ThreatCategory.SCANNING,    # Port Scan
    15: ThreatCategory.MALWARE,     # Hacking
    16: ThreatCategory.MALWARE,     # SQL Injection
    17: ThreatCategory.SCANNING,    # Spoofing
    18: ThreatCategory.SCANNING,    # Brute-Force
    19: ThreatCategory.DDOS,        # Bad Web Bot
    20: ThreatCategory.SCANNING,    # Exploited Host
    21: ThreatCategory.DDOS,        # Web Attack
    22: ThreatCategory.MALWARE,     # SSH Brute-Force
    23: ThreatCategory.DDOS,        # IoT Targeted
}


# ── Unified Threat Indicator ──────────────────────────────────────────────────

@dataclass
class ThreatIndicator:
    """
    Normalised threat indicator — the unified schema for all three feeds.

    Every raw API response from OTX, VirusTotal, and AbuseIPDB is
    converted to this structure before storage in PostgreSQL.
    This enables deduplication, correlation, and ML feature extraction
    to operate on a consistent data model regardless of source.
    """

    # Core identity fields
    indicator_value:  str                        # The actual IOC (IP, hash, domain, etc.)
    indicator_type:   IndicatorType              # Standardised type
    source_feed:      SourceFeed                 # Which feed this came from
    threat_category:  ThreatCategory             # Unified threat category

    # Confidence and scoring
    confidence_score: float = 0.0               # 0.0–1.0 normalised confidence
    severity_score:   float = 0.0               # 0.0–10.0 severity (CVSS-inspired scale)
    malicious_count:  int   = 0                 # Number of engines/reports flagging as malicious
    total_count:      int   = 0                 # Total engines/reports checked

    # Contextual metadata
    country_code:     Optional[str]  = None     # ISO-3166 country code
    asn:              Optional[str]  = None     # Autonomous System Number
    isp:              Optional[str]  = None     # ISP/organisation name
    tags:             list[str]      = field(default_factory=list)
    description:      Optional[str]  = None

    # Temporal fields
    first_seen:       Optional[datetime] = None
    last_seen:        Optional[datetime] = None
    fetched_at:       datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Deduplication key (SHA-256 of value + source)
    dedup_key:        str = field(init=False)

    def __post_init__(self) -> None:
        """Compute deduplication key after initialisation."""
        raw = f"{self.indicator_value}::{self.source_feed.value}"
        self.dedup_key = hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        """Convert to dictionary for database insertion."""
        d = asdict(self)
        # Convert enums to their string values
        d["indicator_type"]  = self.indicator_type.value
        d["source_feed"]     = self.source_feed.value
        d["threat_category"] = self.threat_category.value
        # Convert datetimes to ISO strings
        for key in ("first_seen", "last_seen", "fetched_at"):
            if d[key] is not None:
                d[key] = d[key].isoformat() if hasattr(d[key], "isoformat") else d[key]
        return d


# ── Normalisation Helpers ─────────────────────────────────────────────────────

def _parse_iso(date_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 date string to datetime, returning None on failure."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _map_otx_category(tags: list[str]) -> ThreatCategory:
    """Map OTX pulse tags to unified ThreatCategory."""
    for tag in [t.lower() for t in tags]:
        for key, category in OTX_CATEGORY_MAP.items():
            if key in tag:
                return category
    return ThreatCategory.UNKNOWN


def _map_abuseipdb_category(category_ids: list[int]) -> ThreatCategory:
    """Map AbuseIPDB category IDs to unified ThreatCategory (highest priority wins)."""
    # Priority order: malware > ransomware > ddos > phishing > scanning > spam
    priority = [
        ThreatCategory.MALWARE,
        ThreatCategory.RANSOMWARE,
        ThreatCategory.DDOS,
        ThreatCategory.PHISHING,
        ThreatCategory.SCANNING,
        ThreatCategory.SPAM,
    ]
    mapped = {ABUSEIPDB_CATEGORY_MAP.get(cid, ThreatCategory.UNKNOWN) for cid in category_ids}
    for category in priority:
        if category in mapped:
            return category
    return ThreatCategory.UNKNOWN


def _detect_indicator_type(value: str) -> IndicatorType:
    """Infer indicator type from its format."""
    import re
    # IPv4 address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return IndicatorType.IP_ADDRESS
    # MD5, SHA1, SHA256 hashes
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return IndicatorType.FILE_HASH
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return IndicatorType.FILE_HASH
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return IndicatorType.FILE_HASH
    # URL
    if value.startswith(("http://", "https://")):
        return IndicatorType.URL
    # Email
    if "@" in value and "." in value.split("@")[-1]:
        return IndicatorType.EMAIL
    # Domain (fallback)
    if "." in value:
        return IndicatorType.DOMAIN
    return IndicatorType.UNKNOWN


# ── Public Normalisation Functions ────────────────────────────────────────────

def normalise_otx(raw: dict, indicator_value: str) -> ThreatIndicator:
    """
    Convert a raw AlienVault OTX API response to a ThreatIndicator.

    OTX returns pulse-based intelligence. We extract the most
    relevant pulse data and map it to the unified schema.
    """
    tags = raw.get("tags", [])
    pulse_info = raw.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)

    # Confidence: based on pulse count (more pulses = higher confidence)
    # Normalised to 0-1 using a soft cap at 50 pulses
    confidence = min(pulse_count / 50.0, 1.0)

    # Severity: OTX doesn't provide explicit severity, infer from pulse count
    severity = min(pulse_count / 5.0, 10.0)

    # Extract geo data from general section
    general = raw.get("general", {})
    country_code = general.get("country_code")
    asn_raw = general.get("asn", "")
    asn = asn_raw.split(" ")[0] if asn_raw else None

    return ThreatIndicator(
        indicator_value  = indicator_value,
        indicator_type   = _detect_indicator_type(indicator_value),
        source_feed      = SourceFeed.OTX,
        threat_category  = _map_otx_category(tags),
        confidence_score = round(confidence, 4),
        severity_score   = round(severity, 2),
        malicious_count  = pulse_count,
        total_count      = pulse_count,
        country_code     = country_code,
        asn              = asn,
        tags             = tags[:20],  # cap at 20 tags
        description      = f"OTX: {pulse_count} pulse(s) referencing this indicator.",
        first_seen       = _parse_iso(general.get("first_seen")),
        last_seen        = _parse_iso(general.get("last_seen")),
    )


def normalise_virustotal(raw: dict, indicator_value: str) -> ThreatIndicator:
    """
    Convert a raw VirusTotal API v3 response to a ThreatIndicator.

    VirusTotal returns multi-engine scan results. Confidence is
    derived from the ratio of malicious detections to total engines.
    """
    attributes = raw.get("data", {}).get("attributes", {})

    last_analysis = attributes.get("last_analysis_stats", {})
    malicious  = last_analysis.get("malicious", 0)
    suspicious = last_analysis.get("suspicious", 0)
    total      = sum(last_analysis.values()) if last_analysis else 0

    # Confidence: ratio of (malicious + suspicious) to total engines
    confidence = round((malicious + suspicious) / total, 4) if total > 0 else 0.0

    # Severity: based on malicious ratio, scaled to 0-10
    severity = round((malicious / total) * 10, 2) if total > 0 else 0.0

    # Tags from VirusTotal popular threat labels
    tags = list(attributes.get("popular_threat_classification", {})
                .get("popular_threat_name", {}).keys())[:10]

    # Infer category from tags/type tags
    type_tags = [t.lower() for t in attributes.get("tags", [])]
    category = _map_otx_category(type_tags)  # reuse OTX mapper, same keyword logic

    # Geo / network info
    country_code = attributes.get("country")
    asn = str(attributes.get("asn", "")) or None
    isp = attributes.get("as_owner")

    return ThreatIndicator(
        indicator_value  = indicator_value,
        indicator_type   = _detect_indicator_type(indicator_value),
        source_feed      = SourceFeed.VIRUSTOTAL,
        threat_category  = category,
        confidence_score = confidence,
        severity_score   = severity,
        malicious_count  = malicious,
        total_count      = total,
        country_code     = country_code,
        asn              = asn,
        isp              = isp,
        tags             = tags,
        description      = (
            f"VirusTotal: {malicious}/{total} engines flagged as malicious."
        ),
        last_seen        = _parse_iso(
            str(attributes.get("last_analysis_date", "")) or None
        ),
    )


def normalise_abuseipdb(raw: dict, indicator_value: str) -> ThreatIndicator:
    """
    Convert a raw AbuseIPDB API v2 response to a ThreatIndicator.

    AbuseIPDB provides an abuse confidence score (0-100) and
    category IDs per report. We normalise to the unified schema.
    """
    data = raw.get("data", {})

    # AbuseIPDB confidence score is already 0-100, normalise to 0-1
    abuse_score = data.get("abuseConfidenceScore", 0)
    confidence  = round(abuse_score / 100.0, 4)

    # Severity: derived from abuse confidence and total reports
    total_reports = data.get("totalReports", 0)
    severity = round(min((abuse_score / 10.0) + (total_reports / 100.0), 10.0), 2)

    # Category mapping
    reports = data.get("reports", [])
    all_category_ids: list[int] = []
    for report in reports:
        all_category_ids.extend(report.get("categories", []))
    category = _map_abuseipdb_category(list(set(all_category_ids)))

    return ThreatIndicator(
        indicator_value  = indicator_value,
        indicator_type   = IndicatorType.IP_ADDRESS,  # AbuseIPDB is IP-only
        source_feed      = SourceFeed.ABUSEIPDB,
        threat_category  = category,
        confidence_score = confidence,
        severity_score   = severity,
        malicious_count  = total_reports,
        total_count      = total_reports,
        country_code     = data.get("countryCode"),
        isp              = data.get("isp"),
        tags             = [str(cid) for cid in list(set(all_category_ids))[:20]],
        description      = (
            f"AbuseIPDB: {abuse_score}% confidence, "
            f"{total_reports} report(s)."
        ),
        last_seen        = _parse_iso(data.get("lastReportedAt")),
    )
