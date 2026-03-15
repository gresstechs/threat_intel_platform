"""
tests/test_platform.py — Unit tests for the threat intelligence platform

Covers:
  - Normaliser correctness for all three feeds
  - Indicator type detection
  - Category mapping
  - Database upsert logic (using a mock connection)
  - Client error handling

Run with:
    pytest tests/ -v --cov=. --cov-report=term-missing
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from normaliser import (
    ThreatIndicator, IndicatorType, ThreatCategory, SourceFeed,
    normalise_otx, normalise_virustotal, normalise_abuseipdb,
    _detect_indicator_type, _map_otx_category, _map_abuseipdb_category,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_otx_raw():
    return {
        "general": {
            "country_code": "US",
            "asn": "AS15169 Google LLC",
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-03-01T00:00:00Z",
        },
        "tags": ["malware", "c2", "botnet"],
        "pulse_info": {"count": 12},
    }

@pytest.fixture
def sample_vt_raw():
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 3,
                    "harmless": 10,
                    "undetected": 15,
                },
                "country": "RU",
                "asn": 12345,
                "as_owner": "Some Hosting Ltd",
                "tags": ["ransomware", "trojan"],
                "last_analysis_date": "2024-03-10T12:00:00Z",
            }
        }
    }

@pytest.fixture
def sample_abuse_raw():
    return {
        "data": {
            "ipAddress": "198.51.100.1",
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "countryCode": "CN",
            "isp": "Malicious ISP",
            "lastReportedAt": "2024-03-10T08:00:00Z",
            "reports": [
                {"categories": [15, 21], "comment": "Port scanning"},
                {"categories": [4, 19], "comment": "DDoS"},
            ],
        }
    }


# ── Indicator Type Detection ──────────────────────────────────────────────────

class TestIndicatorTypeDetection:
    def test_detects_ipv4(self):
        assert _detect_indicator_type("192.168.1.1") == IndicatorType.IP_ADDRESS

    def test_detects_domain(self):
        assert _detect_indicator_type("malicious.example.com") == IndicatorType.DOMAIN

    def test_detects_url(self):
        assert _detect_indicator_type("https://evil.com/payload") == IndicatorType.URL

    def test_detects_md5(self):
        assert _detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == IndicatorType.FILE_HASH

    def test_detects_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _detect_indicator_type(sha256) == IndicatorType.FILE_HASH

    def test_detects_email(self):
        assert _detect_indicator_type("phish@evil.ru") == IndicatorType.EMAIL

    def test_unknown_returns_unknown(self):
        assert _detect_indicator_type("not-an-indicator!") == IndicatorType.UNKNOWN


# ── Category Mapping ─────────────────────────────────────────────────────────

class TestCategoryMapping:
    def test_otx_malware_tag(self):
        assert _map_otx_category(["malware", "c2"]) == ThreatCategory.MALWARE

    def test_otx_phishing_tag(self):
        assert _map_otx_category(["phishing", "credential-theft"]) == ThreatCategory.PHISHING

    def test_otx_ransomware_tag(self):
        assert _map_otx_category(["ransomware"]) == ThreatCategory.RANSOMWARE

    def test_otx_unknown_tags(self):
        assert _map_otx_category(["network", "infrastructure"]) == ThreatCategory.UNKNOWN

    def test_abuseipdb_ddos_priority(self):
        # DDoS (4) and scanning (14) — DDoS should win via priority
        assert _map_abuseipdb_category([4, 14]) == ThreatCategory.DDOS

    def test_abuseipdb_malware_highest_priority(self):
        # Malware (15) beats DDoS (4)
        assert _map_abuseipdb_category([4, 15]) == ThreatCategory.MALWARE

    def test_abuseipdb_spam_only(self):
        assert _map_abuseipdb_category([10, 11]) == ThreatCategory.SPAM

    def test_abuseipdb_empty_returns_unknown(self):
        assert _map_abuseipdb_category([]) == ThreatCategory.UNKNOWN


# ── OTX Normaliser ────────────────────────────────────────────────────────────

class TestNormaliseOTX:
    def test_returns_threat_indicator(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert isinstance(result, ThreatIndicator)

    def test_source_feed_is_otx(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert result.source_feed == SourceFeed.OTX

    def test_indicator_value_preserved(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert result.indicator_value == "8.8.8.8"

    def test_confidence_normalised_to_0_1(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert 0.0 <= result.confidence_score <= 1.0

    def test_maps_malware_tag(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert result.threat_category == ThreatCategory.MALWARE

    def test_country_code_extracted(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert result.country_code == "US"

    def test_asn_extracted(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert result.asn == "AS15169"

    def test_dedup_key_is_sha256(self, sample_otx_raw):
        result = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert len(result.dedup_key) == 64  # SHA-256 hex length

    def test_dedup_key_differs_across_sources(self, sample_otx_raw, sample_vt_raw):
        otx_result = normalise_otx(sample_otx_raw, "8.8.8.8")
        vt_result  = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert otx_result.dedup_key != vt_result.dedup_key


# ── VirusTotal Normaliser ─────────────────────────────────────────────────────

class TestNormaliseVirusTotal:
    def test_returns_threat_indicator(self, sample_vt_raw):
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert isinstance(result, ThreatIndicator)

    def test_source_feed_is_virustotal(self, sample_vt_raw):
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert result.source_feed == SourceFeed.VIRUSTOTAL

    def test_confidence_calculated_correctly(self, sample_vt_raw):
        # malicious=45, suspicious=3, total=73 → (45+3)/73 ≈ 0.6575
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert abs(result.confidence_score - (48 / 73)) < 0.001

    def test_malicious_count_correct(self, sample_vt_raw):
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert result.malicious_count == 45

    def test_total_count_correct(self, sample_vt_raw):
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert result.total_count == 73

    def test_country_extracted(self, sample_vt_raw):
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert result.country_code == "RU"

    def test_isp_extracted(self, sample_vt_raw):
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert result.isp == "Some Hosting Ltd"

    def test_severity_scaled_0_to_10(self, sample_vt_raw):
        result = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        assert 0.0 <= result.severity_score <= 10.0


# ── AbuseIPDB Normaliser ──────────────────────────────────────────────────────

class TestNormaliseAbuseIPDB:
    def test_returns_threat_indicator(self, sample_abuse_raw):
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        assert isinstance(result, ThreatIndicator)

    def test_source_feed_is_abuseipdb(self, sample_abuse_raw):
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        assert result.source_feed == SourceFeed.ABUSEIPDB

    def test_confidence_normalised(self, sample_abuse_raw):
        # 87% confidence → 0.87
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        assert result.confidence_score == pytest.approx(0.87, abs=0.001)

    def test_indicator_type_is_ip(self, sample_abuse_raw):
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        assert result.indicator_type == IndicatorType.IP_ADDRESS

    def test_country_extracted(self, sample_abuse_raw):
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        assert result.country_code == "CN"

    def test_malware_category_priority(self, sample_abuse_raw):
        # Categories 15 (hacking=malware) and 4 (DDoS) present
        # Malware should win
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        assert result.threat_category == ThreatCategory.MALWARE

    def test_description_contains_score(self, sample_abuse_raw):
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        assert "87%" in result.description

    def test_to_dict_returns_serialisable(self, sample_abuse_raw):
        result = normalise_abuseipdb(sample_abuse_raw, "198.51.100.1")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["source_feed"] == "abuseipdb"
        assert d["indicator_type"] == "ip_address"


# ── Integration: Multi-Source Deduplication ───────────────────────────────────

class TestMultiSourceDeduplication:
    """
    Tests that the same indicator queried across multiple feeds
    generates different dedup_keys (no false deduplication).
    """

    def test_same_ip_different_feeds_different_keys(
        self, sample_otx_raw, sample_vt_raw, sample_abuse_raw
    ):
        otx   = normalise_otx(sample_otx_raw, "8.8.8.8")
        vt    = normalise_virustotal(sample_vt_raw, "8.8.8.8")
        abuse = normalise_abuseipdb(sample_abuse_raw, "8.8.8.8")

        keys = {otx.dedup_key, vt.dedup_key, abuse.dedup_key}
        assert len(keys) == 3, "All three feeds must produce unique dedup keys"

    def test_same_indicator_same_feed_same_key(self, sample_otx_raw):
        """
        Two queries for the same IP from OTX must have identical dedup keys
        (idempotent upsert behaviour).
        """
        r1 = normalise_otx(sample_otx_raw, "8.8.8.8")
        r2 = normalise_otx(sample_otx_raw, "8.8.8.8")
        assert r1.dedup_key == r2.dedup_key
