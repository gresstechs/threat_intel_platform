"""
main.py — Platform entry point and orchestration

Ties together all three API clients (OTX, VirusTotal, AbuseIPDB),
the normaliser, and the database layer into a single cohesive
threat intelligence ingestion pipeline.

Usage:
    # Query a single indicator across all three feeds:
    python main.py --indicator 8.8.8.8 --type ip

    # Run a full bulk ingestion cycle:
    python main.py --ingest

    # Show database statistics:
    python main.py --stats
"""

import argparse
import logging
import time
from typing import Optional

from config import Config
from db import db
from normaliser import ThreatIndicator, IndicatorType
from otx_client import OTXClient
from virustotal_client import VirusTotalClient
from abuseipdb_client import AbuseIPDBClient

# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class ThreatIntelPlatform:
    """
    Main platform orchestrator.

    Coordinates querying all three threat intelligence feeds,
    normalising the responses, deduplicating, and storing in PostgreSQL.
    """

    def __init__(self) -> None:
        Config.validate()
        self.otx   = OTXClient()
        self.vt    = VirusTotalClient()
        self.abuse = AbuseIPDBClient()
        db.connect()
        logger.info("ThreatIntelPlatform initialised. All three feeds connected.")

    def query_all_feeds(
        self, indicator_value: str, indicator_type: str = "ip"
    ) -> list[ThreatIndicator]:
        """
        Query all three feeds for a given indicator and store results.

        This is the core function demonstrating multi-source correlation:
        the same indicator is queried across OTX, VirusTotal, and AbuseIPDB,
        results normalised to a common schema, deduplicated, and stored.

        Args:
            indicator_value: The IOC to query (IP, domain, hash, URL).
            indicator_type:  One of: ip, domain, hash, url.

        Returns:
            List of ThreatIndicators (one per feed that returned data).
        """
        start_time = time.time()
        results: list[ThreatIndicator] = []

        logger.info(f"Querying all feeds for [{indicator_type}] {indicator_value}")

        # ── OTX ──────────────────────────────────────────────────────────────
        otx_result: Optional[ThreatIndicator] = None
        if indicator_type == "ip":
            otx_result = self.otx.query_ip(indicator_value)
        elif indicator_type == "domain":
            otx_result = self.otx.query_domain(indicator_value)
        elif indicator_type == "hash":
            otx_result = self.otx.query_hash(indicator_value)
        elif indicator_type == "url":
            otx_result = self.otx.query_url(indicator_value)

        if otx_result:
            results.append(otx_result)

        # ── VirusTotal ────────────────────────────────────────────────────────
        vt_result: Optional[ThreatIndicator] = None
        if indicator_type == "ip":
            vt_result = self.vt.query_ip(indicator_value)
        elif indicator_type == "domain":
            vt_result = self.vt.query_domain(indicator_value)
        elif indicator_type == "hash":
            vt_result = self.vt.query_hash(indicator_value)
        elif indicator_type == "url":
            vt_result = self.vt.query_url(indicator_value)

        if vt_result:
            results.append(vt_result)

        # ── AbuseIPDB (IP only) ───────────────────────────────────────────────
        if indicator_type == "ip":
            abuse_result = self.abuse.query_ip(indicator_value)
            if abuse_result:
                results.append(abuse_result)

        # ── Store all results ─────────────────────────────────────────────────
        inserted = updated = 0
        for indicator in results:
            _, is_new = db.store_indicator(indicator)
            if is_new:
                inserted += 1
            else:
                updated += 1

        elapsed = time.time() - start_time

        logger.info(
            f"Query complete | {indicator_value} | "
            f"feeds_returned={len(results)} | "
            f"inserted={inserted} | updated={updated} | "
            f"elapsed={elapsed:.3f}s"
        )

        if elapsed > Config.PROCESSING_TIMEOUT:
            logger.warning(
                f"Processing time {elapsed:.3f}s exceeded target "
                f"of {Config.PROCESSING_TIMEOUT}s for {indicator_value}"
            )

        return results

    def summarise_results(self, results: list[ThreatIndicator]) -> dict:
        """
        Produce a human-readable summary of multi-feed results.
        Shows agreement/disagreement between feeds — the key
        indicator of correlation quality.
        """
        if not results:
            return {"verdict": "CLEAN", "sources": 0, "avg_confidence": 0.0}

        avg_confidence = sum(r.confidence_score for r in results) / len(results)
        max_severity   = max(r.severity_score for r in results)
        categories     = list({r.threat_category.value for r in results})
        feeds          = [r.source_feed.value for r in results]
        sources_agreed = len(set(categories)) == 1  # all feeds agree on category

        verdict = "MALICIOUS" if avg_confidence > 0.5 else (
                  "SUSPICIOUS" if avg_confidence > 0.2 else "CLEAN")

        return {
            "indicator":      results[0].indicator_value,
            "verdict":        verdict,
            "avg_confidence": round(avg_confidence, 4),
            "max_severity":   round(max_severity, 2),
            "categories":     categories,
            "feeds_queried":  feeds,
            "sources_agreed": sources_agreed,
            "sources_count":  len(results),
        }

    def run_bulk_ingestion(self) -> None:
        """
        Bulk ingestion cycle:
        1. Fetches recent OTX pulses and queries contained indicators
        2. Fetches AbuseIPDB blacklist
        Stores everything in PostgreSQL.
        """
        logger.info("Starting bulk ingestion cycle...")
        start = time.time()
        total_stored = 0

        # ── OTX: recent pulses ────────────────────────────────────────────────
        logger.info("Fetching recent OTX pulses...")
        pulses = self.otx.get_recent_pulses(limit=10)
        for pulse in pulses:
            for indicator in pulse.get("indicators", [])[:50]:  # cap per pulse
                ioc_type  = indicator.get("type", "")
                ioc_value = indicator.get("indicator", "")
                if not ioc_value:
                    continue
                # Map OTX types to our internal types
                type_map = {
                    "IPv4": "ip", "IPv6": "ip",
                    "domain": "domain", "hostname": "domain",
                    "URL": "url",
                    "FileHash-MD5": "hash", "FileHash-SHA1": "hash",
                    "FileHash-SHA256": "hash",
                }
                internal_type = type_map.get(ioc_type)
                if internal_type:
                    self.query_all_feeds(ioc_value, internal_type)
                    total_stored += 1

        # ── AbuseIPDB: blacklist ──────────────────────────────────────────────
        logger.info("Fetching AbuseIPDB blacklist...")
        blacklist = self.abuse.get_blacklist(confidence_minimum=90, limit=500)
        inserted, updated = db.store_indicators_batch(blacklist)
        total_stored += inserted + updated

        elapsed = time.time() - start
        logger.info(
            f"Bulk ingestion complete | "
            f"total_processed={total_stored} | elapsed={elapsed:.1f}s"
        )

    def print_stats(self) -> None:
        """Print current database statistics to the console."""
        stats = db.get_stats()
        print("\n" + "=" * 60)
        print("  THREAT INTELLIGENCE PLATFORM — DATABASE STATISTICS")
        print("=" * 60)
        for key, value in stats.items():
            print(f"  {key:<30} {value}")
        print("=" * 60 + "\n")

    def shutdown(self) -> None:
        """Gracefully close the database connection pool."""
        db.close()
        logger.info("Platform shutdown complete.")


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated Threat Intelligence Correlation Platform"
    )
    parser.add_argument("--indicator", "-i", type=str,
                        help="Indicator value to query (IP, domain, hash, URL)")
    parser.add_argument("--type", "-t", type=str, default="ip",
                        choices=["ip", "domain", "hash", "url"],
                        help="Indicator type (default: ip)")
    parser.add_argument("--ingest", action="store_true",
                        help="Run a bulk ingestion cycle")
    parser.add_argument("--stats", action="store_true",
                        help="Print database statistics")

    args = parser.parse_args()
    platform = ThreatIntelPlatform()

    try:
        if args.indicator:
            results = platform.query_all_feeds(args.indicator, args.type)
            summary = platform.summarise_results(results)
            print("\n" + "=" * 60)
            print(f"  VERDICT: {summary['verdict']}")
            print(f"  Avg confidence:  {summary['avg_confidence']:.2%}")
            print(f"  Max severity:    {summary['max_severity']}/10")
            print(f"  Feeds returned:  {summary['sources_count']}")
            print(f"  Categories:      {', '.join(summary['categories'])}")
            print(f"  Sources agreed:  {summary['sources_agreed']}")
            print("=" * 60)

        elif args.ingest:
            platform.run_bulk_ingestion()

        elif args.stats:
            platform.print_stats()

        else:
            parser.print_help()

    finally:
        platform.shutdown()


if __name__ == "__main__":
    main()
