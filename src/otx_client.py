"""
otx_client.py — AlienVault OTX API integration module

Supports querying OTX for:
  - IP address reputation and pulse data
  - Domain reputation
  - File hash (MD5/SHA1/SHA256) analysis
  - URL analysis

Rate limit: OTX free tier allows ~1,000 requests/day.
We enforce a 1-second sleep between calls and use exponential
backoff retry logic on transient failures.
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
from normaliser import ThreatIndicator, normalise_otx

logger = logging.getLogger(__name__)


class OTXClient:
    """
    Client for the AlienVault OTX REST API v1.

    Usage:
        client = OTXClient()
        indicator = client.query_ip("8.8.8.8")
    """

    BASE_URL = Config.OTX_BASE_URL

    def __init__(self, api_key: str = Config.OTX_API_KEY) -> None:
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatIntelPlatform/1.0 (MSc Dissertation Research)"
        })

    @retry(
        stop=stop_after_attempt(Config.MAX_RETRIES),
        wait=wait_exponential(multiplier=Config.RETRY_BACKOFF, min=1, max=30),
        retry=retry_if_exception_type(requests.exceptions.RequestException),
    )
    def _get(self, endpoint: str) -> dict:
        """
        Internal GET request with retry logic.
        Raises requests.HTTPError on 4xx/5xx responses.
        """
        url = f"{self.BASE_URL}/{endpoint}"
        logger.debug(f"OTX GET: {url}")
        response = self.session.get(url, timeout=Config.PROCESSING_TIMEOUT)
        response.raise_for_status()
        time.sleep(Config.RATE_LIMIT_SLEEP)
        return response.json()

    # ── Public Query Methods ──────────────────────────────────────────────────

    def query_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """
        Query OTX for an IPv4 address.
        Returns a normalised ThreatIndicator or None on failure.
        """
        try:
            general   = self._get(f"indicators/IPv4/{ip}/general")
            # Merge all sections into one raw dict for normaliser
            raw = {
                "general":    general,
                "tags":       general.get("tags", []),
                "pulse_info": general.get("pulse_info", {}),
            }
            indicator = normalise_otx(raw, ip)
            logger.info(f"OTX | IP {ip} | pulses={raw['pulse_info'].get('count',0)} "
                        f"| category={indicator.threat_category.value}")
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"OTX | IP {ip} | Not found (no OTX data)")
                return None
            logger.error(f"OTX | IP {ip} | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"OTX | IP {ip} | Unexpected error: {e}")
            return None

    def query_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """
        Query OTX for a domain name.
        Returns a normalised ThreatIndicator or None on failure.
        """
        try:
            general = self._get(f"indicators/domain/{domain}/general")
            raw = {
                "general":    general,
                "tags":       general.get("tags", []),
                "pulse_info": general.get("pulse_info", {}),
            }
            indicator = normalise_otx(raw, domain)
            logger.info(f"OTX | Domain {domain} | pulses={raw['pulse_info'].get('count',0)}")
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"OTX | Domain {domain} | Not found")
                return None
            logger.error(f"OTX | Domain {domain} | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"OTX | Domain {domain} | Error: {e}")
            return None

    def query_hash(self, file_hash: str) -> Optional[ThreatIndicator]:
        """
        Query OTX for a file hash (MD5, SHA1, or SHA256).
        Returns a normalised ThreatIndicator or None on failure.
        """
        try:
            general = self._get(f"indicators/file/{file_hash}/general")
            raw = {
                "general":    general,
                "tags":       general.get("tags", []),
                "pulse_info": general.get("pulse_info", {}),
            }
            indicator = normalise_otx(raw, file_hash)
            logger.info(f"OTX | Hash {file_hash[:16]}... | pulses={raw['pulse_info'].get('count',0)}")
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"OTX | Hash {file_hash[:16]}... | Not found")
                return None
            logger.error(f"OTX | Hash {file_hash[:16]}... | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"OTX | Hash {file_hash[:16]}... | Error: {e}")
            return None

    def query_url(self, url: str) -> Optional[ThreatIndicator]:
        """
        Query OTX for a URL.
        Returns a normalised ThreatIndicator or None on failure.
        """
        try:
            general = self._get(f"indicators/url/{url}/general")
            raw = {
                "general":    general,
                "tags":       general.get("tags", []),
                "pulse_info": general.get("pulse_info", {}),
            }
            indicator = normalise_otx(raw, url)
            logger.info(f"OTX | URL {url[:40]}... | pulses={raw['pulse_info'].get('count',0)}")
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"OTX | URL {url[:40]}... | Not found")
                return None
            logger.error(f"OTX | URL {url[:40]}... | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"OTX | URL {url[:40]}... | Error: {e}")
            return None

    def get_recent_pulses(self, limit: int = 20) -> list[dict]:
        """
        Retrieve the most recent OTX threat pulses (community feed).
        Used for bulk indicator ingestion during scheduled collection runs.
        """
        try:
            result = self._get(f"pulses/subscribed?limit={limit}&modified_since=2024-01-01")
            pulses = result.get("results", [])
            logger.info(f"OTX | Retrieved {len(pulses)} recent pulses")
            return pulses
        except Exception as e:
            logger.error(f"OTX | Failed to fetch recent pulses: {e}")
            return []
