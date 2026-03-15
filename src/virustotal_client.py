"""
virustotal_client.py — VirusTotal API v3 integration module

Supports querying VirusTotal for:
  - IP address reputation (multi-engine analysis)
  - Domain reputation
  - File hash analysis (MD5/SHA1/SHA256)
  - URL analysis

Rate limit: Free tier = 4 requests/minute, 500 requests/day.
We enforce rate limiting via sleep and use exponential backoff
on transient failures (429 Too Many Requests).
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
from normaliser import ThreatIndicator, normalise_virustotal

logger = logging.getLogger(__name__)

# VirusTotal free tier: 4 req/minute → 15 seconds between calls
# We use Config.RATE_LIMIT_SLEEP but enforce a minimum of 15s for VT
VT_MIN_SLEEP = 15.0


class VirusTotalClient:
    """
    Client for the VirusTotal Public API v3.

    Usage:
        client = VirusTotalClient()
        indicator = client.query_ip("8.8.8.8")
    """

    BASE_URL = Config.VT_BASE_URL

    def __init__(self, api_key: str = Config.VT_API_KEY) -> None:
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ThreatIntelPlatform/1.0 (MSc Dissertation Research)"
        })
        self._last_request_time: float = 0.0

    def _enforce_rate_limit(self) -> None:
        """
        Enforce VirusTotal's 4 requests/minute limit.
        Sleeps if insufficient time has elapsed since the last request.
        """
        elapsed = time.time() - self._last_request_time
        sleep_needed = VT_MIN_SLEEP - elapsed
        if sleep_needed > 0:
            logger.debug(f"VT rate limit: sleeping {sleep_needed:.1f}s")
            time.sleep(sleep_needed)
        self._last_request_time = time.time()

    @retry(
        stop=stop_after_attempt(Config.MAX_RETRIES),
        wait=wait_exponential(multiplier=Config.RETRY_BACKOFF, min=2, max=60),
        retry=retry_if_exception_type(requests.exceptions.RequestException),
    )
    def _get(self, endpoint: str) -> dict:
        """
        Internal GET with rate limiting and retry logic.
        """
        self._enforce_rate_limit()
        url = f"{self.BASE_URL}/{endpoint}"
        logger.debug(f"VT GET: {url}")
        response = self.session.get(url, timeout=Config.PROCESSING_TIMEOUT)

        # Handle 429 explicitly — back off longer
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            logger.warning(f"VT rate limited. Backing off {retry_after}s.")
            time.sleep(retry_after)
            response = self.session.get(url, timeout=Config.PROCESSING_TIMEOUT)

        response.raise_for_status()
        return response.json()

    # ── Public Query Methods ──────────────────────────────────────────────────

    def query_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """
        Query VirusTotal for an IPv4 address.
        Returns a normalised ThreatIndicator or None on failure.
        """
        try:
            raw = self._get(f"ip_addresses/{ip}")
            indicator = normalise_virustotal(raw, ip)
            stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            logger.info(
                f"VT | IP {ip} | malicious={stats.get('malicious',0)}"
                f"/{sum(stats.values())} | confidence={indicator.confidence_score:.2%}"
            )
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"VT | IP {ip} | Not found in VT database")
                return None
            logger.error(f"VT | IP {ip} | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"VT | IP {ip} | Unexpected error: {e}")
            return None

    def query_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """
        Query VirusTotal for a domain name.
        Returns a normalised ThreatIndicator or None on failure.
        """
        try:
            raw = self._get(f"domains/{domain}")
            indicator = normalise_virustotal(raw, domain)
            stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            logger.info(
                f"VT | Domain {domain} | malicious={stats.get('malicious',0)}"
                f"/{sum(stats.values())}"
            )
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"VT | Domain {domain} | Not found")
                return None
            logger.error(f"VT | Domain {domain} | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"VT | Domain {domain} | Error: {e}")
            return None

    def query_hash(self, file_hash: str) -> Optional[ThreatIndicator]:
        """
        Query VirusTotal for a file hash (MD5, SHA1, or SHA256).
        Returns a normalised ThreatIndicator or None on failure.
        """
        try:
            raw = self._get(f"files/{file_hash}")
            indicator = normalise_virustotal(raw, file_hash)
            stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            logger.info(
                f"VT | Hash {file_hash[:16]}... | malicious={stats.get('malicious',0)}"
                f"/{sum(stats.values())}"
            )
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"VT | Hash {file_hash[:16]}... | Not found")
                return None
            logger.error(f"VT | Hash {file_hash[:16]}... | HTTP error: {e}")
            return None
        except Exception as e:
            logger.error(f"VT | Hash {file_hash[:16]}... | Error: {e}")
            return None

    def query_url(self, url: str) -> Optional[ThreatIndicator]:
        """
        Query VirusTotal for a URL.
        VirusTotal requires the URL to be base64-encoded (no padding).
        Returns a normalised ThreatIndicator or None on failure.
        """
        import base64
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            raw = self._get(f"urls/{url_id}")
            indicator = normalise_virustotal(raw, url)
            stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            logger.info(
                f"VT | URL {url[:40]}... | malicious={stats.get('malicious',0)}"
                f"/{sum(stats.values())}"
            )
            return indicator
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.info(f"VT | URL not found in VT database")
                return None
            logger.error(f"VT | URL error: {e}")
            return None
        except Exception as e:
            logger.error(f"VT | URL error: {e}")
            return None
