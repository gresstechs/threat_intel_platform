"""
tests/test_playbooks.py — Unit tests for all 5 MITRE ATT&CK playbooks

Covers:
  - Playbook instantiation and metadata
  - Trigger logic (should_trigger) for all 5 playbooks
  - Full execution of each playbook with mock context
  - Step completion and status tracking
  - Success rate calculation
  - PlaybookResult properties

Run with:
    pytest tests/test_playbooks.py -v
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'automation'))

from playbook_base import (
    BasePlaybook, ResponseStep, PlaybookResult, ExecutionStatus
)
from PB001_Phishing import PB001_Phishing
from PB002_LateralMovement import PB002_LateralMovement
from PB003_PrivilegeEscalation import PB003_PrivilegeEscalation
from PB004_CommandAndControl import PB004_CommandAndControl
from PB005_DataExfiltration import PB005_DataExfiltration


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def pb001(): return PB001_Phishing()

@pytest.fixture
def pb002(): return PB002_LateralMovement()

@pytest.fixture
def pb003(): return PB003_PrivilegeEscalation()

@pytest.fixture
def pb004(): return PB004_CommandAndControl()

@pytest.fixture
def pb005(): return PB005_DataExfiltration()

@pytest.fixture
def critical_phishing_alert():
    return {
        "indicator_value":    "http://evil-phishing[.]com/login",
        "indicator_type":     "url",
        "threat_category":    "phishing",
        "alert_priority":     "CRITICAL",
        "combined_confidence": 0.88,
        "combined_score":     0.88,
        "severity_score":     8.5,
        "sources_count":      3,
        "sources_agreed":     True,
        "country_code":       "RU",
    }

@pytest.fixture
def critical_malware_alert():
    return {
        "indicator_value":    "198.51.100.42",
        "indicator_type":     "ip_address",
        "threat_category":    "malware",
        "alert_priority":     "CRITICAL",
        "combined_confidence": 0.92,
        "combined_score":     0.92,
        "severity_score":     9.2,
        "sources_count":      3,
        "sources_agreed":     True,
        "country_code":       "CN",
    }

@pytest.fixture
def high_malware_alert():
    return {
        "indicator_value":    "203.0.113.99",
        "indicator_type":     "ip_address",
        "threat_category":    "malware",
        "alert_priority":     "HIGH",
        "combined_confidence": 0.75,
        "combined_score":     0.75,
        "severity_score":     7.0,
        "sources_count":      2,
        "sources_agreed":     True,
        "country_code":       "KP",
    }

@pytest.fixture
def low_confidence_context():
    return {
        "indicator_value":    "10.0.0.1",
        "threat_category":    "phishing",
        "alert_priority":     "LOW",
        "combined_confidence": 0.10,
        "combined_score":     0.10,
        "severity_score":     1.0,
        "sources_count":      1,
        "sources_agreed":     False,
        "country_code":       "US",
    }


# ── Playbook Metadata ─────────────────────────────────────────────────────────

class TestPlaybookMetadata:
    def test_pb001_has_correct_technique(self, pb001):
        assert pb001.MITRE_TECHNIQUE == "T1566"

    def test_pb002_has_correct_technique(self, pb002):
        assert pb002.MITRE_TECHNIQUE == "T1021"

    def test_pb003_has_correct_technique(self, pb003):
        assert pb003.MITRE_TECHNIQUE == "T1068"

    def test_pb004_has_correct_technique(self, pb004):
        assert pb004.MITRE_TECHNIQUE == "T1071"

    def test_pb005_has_correct_technique(self, pb005):
        assert pb005.MITRE_TECHNIQUE == "T1041"

    def test_all_playbooks_have_names(self, pb001, pb002, pb003, pb004, pb005):
        for pb in [pb001, pb002, pb003, pb004, pb005]:
            assert pb.PLAYBOOK_NAME != ""

    def test_all_playbooks_have_tactics(self, pb001, pb002, pb003, pb004, pb005):
        for pb in [pb001, pb002, pb003, pb004, pb005]:
            assert pb.MITRE_TACTIC != ""

    def test_five_unique_techniques(self, pb001, pb002, pb003, pb004, pb005):
        techniques = {pb.MITRE_TECHNIQUE for pb in [pb001, pb002, pb003, pb004, pb005]}
        assert len(techniques) == 5


# ── Trigger Logic ─────────────────────────────────────────────────────────────

class TestTriggerLogic:
    def test_pb001_triggers_on_critical_phishing(self, pb001, critical_phishing_alert):
        assert pb001.should_trigger(critical_phishing_alert) is True

    def test_pb001_does_not_trigger_on_malware(self, pb001, critical_malware_alert):
        assert pb001.should_trigger(critical_malware_alert) is False

    def test_pb001_does_not_trigger_on_low_priority(self, pb001, low_confidence_context):
        assert pb001.should_trigger(low_confidence_context) is False

    def test_pb002_triggers_on_malware_with_agreement(self, pb002, critical_malware_alert):
        assert pb002.should_trigger(critical_malware_alert) is True

    def test_pb002_does_not_trigger_without_source_agreement(self, pb002):
        alert = {
            "threat_category": "malware",
            "alert_priority": "CRITICAL",
            "sources_agreed": False,
        }
        assert pb002.should_trigger(alert) is False

    def test_pb003_triggers_only_on_critical(self, pb003, critical_malware_alert):
        assert pb003.should_trigger(critical_malware_alert) is True

    def test_pb003_does_not_trigger_on_high(self, pb003, high_malware_alert):
        assert pb003.should_trigger(high_malware_alert) is False

    def test_pb004_triggers_on_botnet(self, pb004):
        alert = {
            "threat_category": "botnet",
            "alert_priority": "CRITICAL",
        }
        assert pb004.should_trigger(alert) is True

    def test_pb004_triggers_on_high_malware(self, pb004, high_malware_alert):
        assert pb004.should_trigger(high_malware_alert) is True

    def test_pb005_triggers_on_critical_high_confidence(self, pb005, critical_malware_alert):
        assert pb005.should_trigger(critical_malware_alert) is True

    def test_pb005_does_not_trigger_on_low_confidence(self, pb005):
        alert = {
            "threat_category": "malware",
            "alert_priority": "CRITICAL",
            "combined_score": 0.50,  # Below 0.75 threshold
        }
        assert pb005.should_trigger(alert) is False


# ── PB001 Phishing Execution ──────────────────────────────────────────────────

class TestPB001Execution:
    def test_executes_successfully_with_high_confidence(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil-phishing.com/login", critical_phishing_alert)
        assert result.execution_status == ExecutionStatus.SUCCESS

    def test_all_5_steps_complete(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil-phishing.com/login", critical_phishing_alert)
        assert result.steps_total == 5
        assert result.steps_completed == 5
        assert result.steps_failed == 0

    def test_url_is_defanged_in_step_3(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil.com/login", critical_phishing_alert)
        step3 = next(s for s in result.steps if s.step_id == 3)
        assert "[.]" in (step3.output or "") or "[://]" in (step3.output or "")

    def test_fails_gracefully_on_low_confidence(self, pb001, low_confidence_context):
        result = pb001.execute("http://low.com", low_confidence_context)
        assert result.steps_completed == 0
        assert result.execution_status in (ExecutionStatus.FAILED, ExecutionStatus.PARTIAL)


# ── PB002 Lateral Movement Execution ─────────────────────────────────────────

class TestPB002Execution:
    def test_executes_successfully(self, pb002, critical_malware_alert):
        result = pb002.execute("198.51.100.42", critical_malware_alert)
        assert result.execution_status == ExecutionStatus.SUCCESS

    def test_all_4_steps_complete(self, pb002, critical_malware_alert):
        result = pb002.execute("198.51.100.42", critical_malware_alert)
        assert result.steps_total == 4
        assert result.steps_completed == 4

    def test_correct_technique(self, pb002, critical_malware_alert):
        result = pb002.execute("198.51.100.42", critical_malware_alert)
        assert result.mitre_technique == "T1021"

    def test_step_2_mentions_ssh_rdp(self, pb002, critical_malware_alert):
        result = pb002.execute("198.51.100.42", critical_malware_alert)
        step2 = next(s for s in result.steps if s.step_id == 2)
        assert "SSH" in (step2.output or "") or "RDP" in (step2.output or "")


# ── PB003 Privilege Escalation Execution ─────────────────────────────────────

class TestPB003Execution:
    def test_executes_on_critical(self, pb003, critical_malware_alert):
        result = pb003.execute("198.51.100.42", critical_malware_alert)
        assert result.execution_status == ExecutionStatus.SUCCESS

    def test_all_5_steps_complete(self, pb003, critical_malware_alert):
        result = pb003.execute("198.51.100.42", critical_malware_alert)
        assert result.steps_total == 5
        assert result.steps_completed == 5

    def test_fails_on_non_critical(self, pb003, high_malware_alert):
        result = pb003.execute("203.0.113.99", high_malware_alert)
        # Step 1 should fail — non-critical priority
        assert result.steps_completed == 0

    def test_step_5_mentions_ciso(self, pb003, critical_malware_alert):
        result = pb003.execute("198.51.100.42", critical_malware_alert)
        step5 = next(s for s in result.steps if s.step_id == 5)
        assert "CISO" in (step5.output or "")


# ── PB004 Command and Control Execution ──────────────────────────────────────

class TestPB004Execution:
    def test_executes_successfully(self, pb004, critical_malware_alert):
        result = pb004.execute("198.51.100.42", critical_malware_alert)
        assert result.execution_status == ExecutionStatus.SUCCESS

    def test_all_5_steps_complete(self, pb004, critical_malware_alert):
        result = pb004.execute("198.51.100.42", critical_malware_alert)
        assert result.steps_total == 5
        assert result.steps_completed == 5

    def test_step_4_mentions_sinkhole(self, pb004, critical_malware_alert):
        result = pb004.execute("198.51.100.42", critical_malware_alert)
        step4 = next(s for s in result.steps if s.step_id == 4)
        assert "sinkhole" in (step4.output or "").lower()

    def test_step_5_mentions_threat_hunt(self, pb004, critical_malware_alert):
        result = pb004.execute("198.51.100.42", critical_malware_alert)
        step5 = next(s for s in result.steps if s.step_id == 5)
        assert "hunt" in (step5.output or "").lower()


# ── PB005 Data Exfiltration Execution ────────────────────────────────────────

class TestPB005Execution:
    def test_executes_successfully_on_high_confidence(self, pb005, critical_malware_alert):
        result = pb005.execute("198.51.100.42", critical_malware_alert)
        assert result.execution_status == ExecutionStatus.SUCCESS

    def test_all_5_steps_complete(self, pb005, critical_malware_alert):
        result = pb005.execute("198.51.100.42", critical_malware_alert)
        assert result.steps_total == 5
        assert result.steps_completed == 5

    def test_fails_on_low_confidence(self, pb005):
        context = {
            "combined_confidence": 0.40,
            "alert_priority": "CRITICAL",
            "severity_score": 5.0,
            "country_code": "CN",
            "sources_count": 1,
        }
        result = pb005.execute("1.2.3.4", context)
        assert result.steps_completed == 0

    def test_step_5_mentions_gdpr(self, pb005, critical_malware_alert):
        result = pb005.execute("198.51.100.42", critical_malware_alert)
        step5 = next(s for s in result.steps if s.step_id == 5)
        assert "GDPR" in (step5.output or "")


# ── PlaybookResult Properties ─────────────────────────────────────────────────

class TestPlaybookResult:
    def test_success_rate_100_when_all_steps_pass(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil.com", critical_phishing_alert)
        assert result.success_rate == 100.0

    def test_is_successful_true_on_success(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil.com", critical_phishing_alert)
        assert result.is_successful is True

    def test_execution_time_recorded(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil.com", critical_phishing_alert)
        assert result.execution_time_ms >= 0

    def test_completed_at_is_set(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil.com", critical_phishing_alert)
        assert result.completed_at is not None

    def test_indicator_value_preserved(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://test-indicator.com", critical_phishing_alert)
        assert result.indicator_value == "http://test-indicator.com"

    def test_all_steps_have_executed_at_timestamp(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil.com", critical_phishing_alert)
        for step in result.steps:
            assert step.executed_at is not None

    def test_all_steps_have_duration(self, pb001, critical_phishing_alert):
        result = pb001.execute("http://evil.com", critical_phishing_alert)
        for step in result.steps:
            assert step.duration_ms is not None
            assert step.duration_ms >= 0
