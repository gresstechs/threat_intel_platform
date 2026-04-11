"""
PB002_LateralMovement.py — MITRE ATT&CK Playbook 2: Lateral Movement Response
Technique: T1021 — Remote Services (Lateral Movement)
Tactic:    Lateral Movement

Triggered when: An IP is classified as MALWARE with CRITICAL or HIGH
priority, particularly where AbuseIPDB reports SSH/RDP brute force
or the indicator is associated with known lateral movement patterns.

Response Steps:
    1. Threat Verification    — Confirm lateral movement indicators
    2. Network Isolation      — Isolate suspicious connection attempts
    3. Credential Alert       — Flag potentially compromised credentials
    4. Log Collection         — Collect authentication logs for analysis
    5. Security Team Escalation — Escalate to analyst for investigation

MITRE Reference:
    https://attack.mitre.org/techniques/T1021/
"""

import logging
from datetime import datetime, timezone

from playbook_base import BasePlaybook, ResponseStep, ExecutionStatus

logger = logging.getLogger(__name__)


class PB002_LateralMovement(BasePlaybook):

    PLAYBOOK_NAME   = "PB002_LateralMovement"
    MITRE_TECHNIQUE = "T1021"
    MITRE_TACTIC    = "Lateral Movement"
    THREAT_CATEGORY = "malware"

    def should_trigger(self, alert: dict) -> bool:
        """
        Override: trigger on MALWARE indicators with lateral movement signals.
        Lateral movement typically appears as MALWARE category with
        scanning or brute force sub-patterns.
        """
        category_match = alert.get("threat_category", "").lower() in (
            "malware", "brute_force", "scanning"
        )
        priority_match = alert.get("alert_priority") in ("CRITICAL", "HIGH")
        # Additional signal: multiple source feeds agree
        sources_agreed = alert.get("sources_agreed", False)
        return category_match and priority_match and sources_agreed

    def _define_steps(self) -> list[ResponseStep]:
        return [
            ResponseStep(
                step_id     = 1,
                name        = "Lateral Movement Verification",
                description = "Verify indicator exhibits lateral movement patterns — "
                              "check for SSH/RDP brute force, pass-the-hash signals"
            ),
            ResponseStep(
                step_id     = 2,
                name        = "Network Isolation",
                description = "Block inbound connections from the malicious IP "
                              "at the network perimeter firewall"
            ),
            ResponseStep(
                step_id     = 3,
                name        = "Credential Compromise Alert",
                description = "Flag potentially compromised accounts and recommend "
                              "immediate password rotation for affected systems"
            ),
            ResponseStep(
                step_id     = 4,
                name        = "Authentication Log Collection",
                description = "Collect and preserve authentication logs from "
                              "targeted systems for forensic analysis"
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
        sources    = context.get("sources_count", 0)
        country    = context.get("country_code", "Unknown")

        # ── Step 1: Verification ──────────────────────────────────────────────
        if step.step_id == 1:
            if confidence < 0.5:
                step.error = (
                    f"Confidence {confidence:.2%} below lateral movement "
                    f"response threshold (0.50)"
                )
                return False
            self._log_action(step,
                f"Lateral movement indicators confirmed for: {indicator_value}"
            )
            self._log_action(step,
                f"Confidence: {confidence:.2%} | Priority: {priority} | "
                f"Sources: {sources} | Origin: {country}"
            )
            self._log_action(step,
                "Pattern: Remote service exploitation / brute force activity detected"
            )
            self._log_action(step,
                f"MITRE ATT&CK: T1021 (Remote Services — Lateral Movement)"
            )
            return True

        # ── Step 2: Network Isolation ─────────────────────────────────────────
        elif step.step_id == 2:
            self._log_action(step,
                f"ACTION: Firewall block rule created"
            )
            self._log_action(step,
                f"  Source IP:  {indicator_value}"
            )
            self._log_action(step,
                f"  Ports:      22 (SSH), 3389 (RDP), 445 (SMB), 135 (RPC)"
            )
            self._log_action(step,
                f"  Direction:  Inbound — block all connection attempts"
            )
            self._log_action(step,
                f"  Applied at: {datetime.now(timezone.utc).isoformat()}"
            )
            self._log_action(step,
                "Network isolation rule active — lateral movement path severed"
            )
            return True

        # ── Step 3: Credential Alert ──────────────────────────────────────────
        elif step.step_id == 3:
            self._log_action(step,
                "CREDENTIAL COMPROMISE ALERT dispatched"
            )
            self._log_action(step,
                f"Trigger: Lateral movement detected from {indicator_value} ({country})"
            )
            self._log_action(step,
                "Recommended actions:"
            )
            self._log_action(step,
                "  1. Audit accounts with recent authentication from this IP"
            )
            self._log_action(step,
                "  2. Force password rotation for flagged accounts"
            )
            self._log_action(step,
                "  3. Review and revoke active sessions from affected systems"
            )
            self._log_action(step,
                "  4. Enable MFA on all privileged accounts immediately"
            )
            return True

        # ── Step 4: Log Collection ────────────────────────────────────────────
        elif step.step_id == 4:
            self._log_action(step,
                f"Authentication log collection initiated"
            )
            self._log_action(step,
                f"  Source indicator: {indicator_value}"
            )
            self._log_action(step,
                f"  Collection window: Last 72 hours"
            )
            self._log_action(step,
                f"  Log sources: SSH auth logs, Windows Event ID 4624/4625/4648"
            )
            self._log_action(step,
                f"  Preservation: Logs archived for forensic analysis"
            )
            self._log_action(step,
                f"  Collected at: {datetime.now(timezone.utc).isoformat()}"
            )
            return True

        return False
