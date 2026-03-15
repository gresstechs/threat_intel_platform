"""
abuseipdb_client.py — AbuseIPDB API v2 integration module

Supports querying AbuseIPDB for:
  - IP address abuse reports and confidence score
  - Bulk IP checking (up to 10,000 IPs per request on free tier)
  - Blacklist retrieval (top abusive IPs)

Rate limit: Free tier = 1,000 requests/day.
We enforce rate limiting and exponential backoff on failures.

Note: AbuseIPDB is IP-address only — it does not support
domain, URL, or file hash lookups. For those, use OTX or VT.
"""

import time
import logging
from typing import Optional

import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from config import Config
from normaliser import ThreatIndicator, normalise_abuseipdb

logger = logging.getLogger(__name__)


class AbuseIPDBClient:
    """
    Client for the AbuseIPDB REST API v2.

    Usage:
        client = AbuseIPDBClient()
        indicator = client.query_ip("198.51.100.0")
    """

    BASE_URL = Config.ABUSEIPDB_BASE_URL

    def __init__(self, api_key: str = Config.ABUSEIPDB_API_KEY) -> None:
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatIntelPlatform/1.0 (MSc Dissertation Research)"
        })

    @retry(
        stop=stop_after_attempt(Config.MAX_RETRIES),
        wait=wait_exponential(multiplier=Config.RETRY_BACKOFF, min=1, max=30),
        retry=retry_if_exception_type(requests.exceptions.RequestException),
    )
    def _get(self, endpoint: str, params: dict) -> dict:
        """
        Internal GET with retry logic and rate limit sleep.
        """
        url = f"{self.BASE_URL}/{endpoint}"
        logger.debug(f"AbuseIPDB GET: {url} | params={params}")
        response = self.session.get(url, params=params, timeout=Config.PROCESSING_TIMEOUT)

        # Handle 429 Too Many Requests
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            logger.warning(f"AbuseIPDB rate limited. Backing off {retry_after}s.")
            time.sleep(retry_after)
            response = self.session.get(url, params=params, timeout=Config.PROCESSING_TIMEOUT)

        response.raise_for_status()
        time.sleep(Config.RATE_LIMIT_SLEEP)
        return response.json()

    # ── Public Query Methods ──────────────────────────────────────────────────

    def query_ip(
        self,
        ip: str,
        max_age_days: int = 90,
        include_reports: bool = True,
    ) -> Optional[ThreatIndicator]:
        """
        Query AbuseIPDB for a single IPv4 or IPv6 address.

        Args:
            ip:              The IP address to query.
            max_age_days:    Only include reports from the last N days (default: 90).
            include_reports: Whether to include individual report details.

        Returns:
            A normalised ThreatIndicator, or None on failure / not found.
        """
        try:
            params = {
                "ipAddress":     ip,
                "maxAgeInDays":  max_age_days,
                "verbose":       "" if include_reports else None,
            }
            # Remove None params
            params = {k: v for k, v in params.items() if v is not None}

            raw = self._get("check", params)
            data = raw.get("data", {})

            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)

            indicator = normalise_abuseipdb(raw, ip)

            logger.info(
                f"AbuseIPDB | IP {ip} | score={abuse_score}% "
                f"| reports={total_reports} | category={indicator.threat_category.value}"
            )
            return indicator

        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 422:
                # 422 = invalid IP format
                logger.warning(f"AbuseIPDB | IP {ip} | Invalid IP format")
                return None
            logger.error(f"AbuseIPDB | IP {ip} | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"AbuseIPDB | IP {ip} | Unexpected error: {e}")
            return None

    def get_blacklist(
        self,
        confidence_minimum: int = 90,
        limit: int = 1000,
    ) -> list[ThreatIndicator]:
        """
        Retrieve the AbuseIPDB blacklist — the most reported IPs
        above a minimum confidence threshold.

        Useful for bulk ingestion during scheduled collection runs.

        Args:
            confidence_minimum: Minimum abuse confidence score (0-100).
            limit:              Maximum number of IPs to retrieve.

        Returns:
            List of normalised ThreatIndicators.
        """
        try:
            params = {
                "confidenceMinimum": confidence_minimum,
                "limit":             limit,
            }
            raw = self._get("blacklist", params)
            entries = raw.get("data", [])

            indicators = []
            for entry in entries:
                ip = entry.get("ipAddress", "")
                if not ip:
                    continue
                # Construct minimal raw dict compatible with normaliser
                synthetic_raw = {
                    "data": {
                        "ipAddress":           ip,
                        "abuseConfidenceScore": entry.get("abuseConfidenceScore", 0),
                        "totalReports":        entry.get("totalReports", 0),
                        "countryCode":         entry.get("countryCode"),
                        "lastReportedAt":      entry.get("lastReportedAt"),
                        "reports":             [],
                    }
                }
                indicator = normalise_abuseipdb(synthetic_raw, ip)
                indicators.append(indicator)

            logger.info(
                f"AbuseIPDB | Blacklist retrieved: {len(indicators)} IPs "
                f"(confidence >= {confidence_minimum}%)"
            )
            return indicators

        except Exception as e:
            logger.error(f"AbuseIPDB | Blacklist fetch failed: {e}")
            return []

    def check_bulk(self, ips: list[str], max_age_days: int = 90) -> list[ThreatIndicator]:
        """
        Query multiple IPs sequentially (free tier has no bulk endpoint).
        Respects rate limiting between each request.

        Args:
            ips:           List of IP address strings.
            max_age_days:  Report age filter.

        Returns:
            List of ThreatIndicators for IPs that returned results.
        """
        results = []
        for ip in ips:
            indicator = self.query_ip(ip, max_age_days=max_age_days)
            if indicator is not None:
                results.append(indicator)
        logger.info(f"AbuseIPDB | Bulk check: {len(results)}/{len(ips)} IPs returned data")
        return results
