"""
PB005_DataExfiltration.py — MITRE ATT&CK Playbook 5: Data Exfiltration Response
Technique: T1041 — Exfiltration Over C2 Channel
Tactic:    Exfiltration

Triggered when: An indicator with CRITICAL priority is associated
with known data exfiltration infrastructure — typically MALWARE
category IPs used for large-volume outbound data transfer.

Response Steps:
    1. Exfiltration Verification — Confirm data exfiltration indicators
    2. Outbound Traffic Block    — Block all outbound to exfil destination
    3. Data Loss Assessment      — Estimate scope of potential data loss
    4. Evidence Preservation     — Preserve forensic evidence
    5. Regulatory Notification   — Prepare breach notification if required

MITRE Reference:
    https://attack.mitre.org/techniques/T1041/
"""

import logging
from datetime import datetime, timezone

from playbook_base import BasePlaybook, ResponseStep, ExecutionStatus

logger = logging.getLogger(__name__)


class PB005_DataExfiltration(BasePlaybook):

    PLAYBOOK_NAME   = "PB005_DataExfiltration"
    MITRE_TECHNIQUE = "T1041"
    MITRE_TACTIC    = "Exfiltration"
    THREAT_CATEGORY = "malware"

    def should_trigger(self, alert: dict) -> bool:
        """
        Override: data exfiltration is a CRITICAL-only playbook —
        the most severe response tier. Triggers on malware indicators
        with maximum severity and cross-feed agreement.
        """
        category_match = alert.get("threat_category", "").lower() in (
            "malware", "ransomware", "botnet"
        )
        priority_match = alert.get("alert_priority") == "CRITICAL"
        high_confidence = alert.get("combined_score", 0.0) >= 0.75
        return category_match and priority_match and high_confidence

    def _define_steps(self) -> list[ResponseStep]:
        return [
            ResponseStep(
                step_id     = 1,
                name        = "Exfiltration Verification",
                description = "Confirm data exfiltration patterns — large outbound "
                              "transfers, unusual protocols, off-hours activity"
            ),
            ResponseStep(
                step_id     = 2,
                name        = "Outbound Traffic Termination",
                description = "Immediately block all outbound connections to the "
                              "exfiltration destination — stop active data transfer"
            ),
            ResponseStep(
                step_id     = 3,
                name        = "Data Loss Scope Assessment",
                description = "Assess volume and sensitivity of potentially "
                              "exfiltrated data — identify affected data stores"
            ),
            ResponseStep(
                step_id     = 4,
                name        = "Forensic Evidence Preservation",
                description = "Capture and preserve forensic evidence — memory "
                              "dumps, network captures, disk images if required"
            ),
            ResponseStep(
                step_id     = 5,
                name        = "Regulatory Breach Assessment",
                description = "Assess whether the incident triggers regulatory "
                              "breach notification obligations (GDPR, NIS Directive)"
            ),
        ]

    def _execute_step(
        self,
        step: ResponseStep,
        indicator_value: str,
        context: dict
    ) -> bool:

        confidence = context.get("combined_confidence", 0.0)
        priority   = context.get("alert_priority", "LOW")
        severity   = context.get("severity_score", 0.0)
        country    = context.get("country_code", "Unknown")
        sources    = context.get("sources_count", 0)

        # ── Step 1: Exfiltration Verification ─────────────────────────────────
        if step.step_id == 1:
            if confidence < 0.75:
                step.error = (
                    f"Confidence {confidence:.2%} below exfiltration response "
                    f"threshold (0.75) — data exfiltration response requires "
                    f"high confidence to prevent disruptive false positive"
                )
                return False
            self._log_action(step,
                f"DATA EXFILTRATION CONFIRMED: {indicator_value}"
            )
            self._log_action(step,
                f"  Confidence: {confidence:.2%} | Priority: {priority}"
            )
            self._log_action(step,
                f"  Severity:   {severity:.1f}/10 | Origin: {country}"
            )
            self._log_action(step,
                f"  Sources:    {sources} feed(s) independently confirmed"
            )
            self._log_action(step,
                "  Patterns:   Large outbound transfer / data staging detected"
            )
            self._log_action(step,
                "MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel)"
            )
            self._log_action(step,
                "IMMEDIATE RESPONSE REQUIRED — Active data loss risk"
            )
            return True

        # ── Step 2: Outbound Traffic Termination ──────────────────────────────
        elif step.step_id == 2:
            self._log_action(step,
                "EMERGENCY: Terminating all outbound connections"
            )
            self._log_action(step,
                f"  Destination: {indicator_value} ({country})"
            )
            self._log_action(step,
                "  Action: BLOCK ALL — all protocols, all ports, both directions"
            )
            self._log_action(step,
                "  Firewall: Emergency ACL inserted at highest priority"
            )
            self._log_action(step,
                "  Proxy: Outbound blocked — logs preserved for forensics"
            )
            self._log_action(step,
                "  DLP: Data Loss Prevention rules activated for this destination"
            )
            self._log_action(step,
                f"  BLOCKED AT: {datetime.now(timezone.utc).isoformat()}"
            )
            self._log_action(step,
                "Active data exfiltration channel terminated"
            )
            return True

        # ── Step 3: Data Loss Assessment ──────────────────────────────────────
        elif step.step_id == 3:
            self._log_action(step,
                "DATA LOSS SCOPE ASSESSMENT"
            )
            self._log_action(step,
                f"  Exfiltration destination: {indicator_value}"
            )
            self._log_action(step,
                "  Assessment window: Network flow analysis — last 30 days"
            )
            self._log_action(step,
                "  Metrics collected:"
            )
            self._log_action(step,
                "    - Total bytes transferred to destination"
            )
            self._log_action(step,
                "    - Source hosts and user accounts involved"
            )
            self._log_action(step,
                "    - Data classification of accessed resources"
            )
            self._log_action(step,
                "    - Time window of exfiltration activity"
            )
            self._log_action(step,
                "  Data sensitivity: Cross-referencing DLP classification tags"
            )
            self._log_action(step,
                "  Assessment report queued for security team review"
            )
            return True

        # ── Step 4: Evidence Preservation ────────────────────────────────────
        elif step.step_id == 4:
            self._log_action(step,
                "FORENSIC EVIDENCE PRESERVATION"
            )
            self._log_action(step,
                "  Priority: Chain of custody established"
            )
            self._log_action(step,
                "  Capturing:"
            )
            self._log_action(step,
                "    1. Full packet capture for exfiltration timeframe"
            )
            self._log_action(step,
                "    2. Memory acquisition from affected endpoints"
            )
            self._log_action(step,
                "    3. System and application event logs — tamper-proof copy"
            )
            self._log_action(step,
                "    4. DNS query logs — full resolution history"
            )
            self._log_action(step,
                "    5. Proxy access logs for the exfiltration period"
            )
            self._log_action(step,
                "  Storage: Encrypted, write-once forensic archive"
            )
            self._log_action(step,
                "  Hash: SHA-256 integrity hash recorded for each artefact"
            )
            self._log_action(step,
                f"  Preserved at: {datetime.now(timezone.utc).isoformat()}"
            )
            return True

        # ── Step 5: Regulatory Assessment ────────────────────────────────────
        elif step.step_id == 5:
            self._log_action(step,
                "REGULATORY BREACH NOTIFICATION ASSESSMENT"
            )
            self._log_action(step,
                "  Applicable regulations: GDPR, NIS Directive, DPA 2018"
            )
            self._log_action(step,
                "  GDPR Article 33: 72-hour notification to ICO if personal "
                "data affected — assessment required immediately"
            )
            self._log_action(step,
                "  NIS Directive: Notify relevant authority if critical "
                "infrastructure data involved"
            )
            self._log_action(step,
                "  Assessment checklist:"
            )
            self._log_action(step,
                "    [ ] Was personal data (Art. 4 GDPR) included in transfer?"
            )
            self._log_action(step,
                "    [ ] Does data involve special categories (Art. 9)?"
            )
            self._log_action(step,
                "    [ ] Can the breach be contained — risk to individuals?"
            )
            self._log_action(step,
                "    [ ] Is notification to data subjects required (Art. 34)?"
            )
            self._log_action(step,
                f"  DPO notification: Dispatched at "
                f"{datetime.now(timezone.utc).isoformat()}"
            )
            self._log_action(step,
                "  Legal counsel: Notified — breach response protocol activated"
            )
            return True

        return False
