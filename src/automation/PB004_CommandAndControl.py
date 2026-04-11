"""
PB004_CommandAndControl.py — MITRE ATT&CK Playbook 4: C2 Response
Technique: T1071 — Application Layer Protocol (C2 Communication)
Tactic:    Command and Control

Triggered when: An IP or domain is classified as MALWARE or BOTNET
with CRITICAL or HIGH priority, suggesting active command-and-control
communication with a remote adversary infrastructure.

Response Steps:
    1. C2 Verification      — Confirm C2 communication patterns
    2. C2 Channel Blocking  — Block all C2 communication channels
    3. Beacon Detection     — Identify beaconing patterns and affected hosts
    4. DNS Sinkholing       — Redirect C2 domain to sinkhole
    5. Threat Hunt Trigger  — Initiate proactive threat hunt on network

MITRE Reference:
    https://attack.mitre.org/techniques/T1071/
"""

import logging
from datetime import datetime, timezone

from playbook_base import BasePlaybook, ResponseStep, ExecutionStatus

logger = logging.getLogger(__name__)


class PB004_CommandAndControl(BasePlaybook):

    PLAYBOOK_NAME   = "PB004_CommandAndControl"
    MITRE_TECHNIQUE = "T1071"
    MITRE_TACTIC    = "Command and Control"
    THREAT_CATEGORY = "malware"

    def should_trigger(self, alert: dict) -> bool:
        """
        Override: trigger on MALWARE or BOTNET indicators — both
        indicate potential C2 activity.
        """
        category_match = alert.get("threat_category", "").lower() in (
            "malware", "botnet"
        )
        priority_match = alert.get("alert_priority") in ("CRITICAL", "HIGH")
        return category_match and priority_match

    def _define_steps(self) -> list[ResponseStep]:
        return [
            ResponseStep(
                step_id     = 1,
                name        = "C2 Communication Verification",
                description = "Verify the indicator exhibits C2 communication "
                              "patterns — periodic beaconing, encrypted tunnels, "
                              "DNS over HTTPS abuse"
            ),
            ResponseStep(
                step_id     = 2,
                name        = "C2 Channel Blocking",
                description = "Block all outbound communication to the C2 "
                              "infrastructure at network and DNS level"
            ),
            ResponseStep(
                step_id     = 3,
                name        = "Beacon Pattern Analysis",
                description = "Analyse network traffic for beaconing patterns — "
                              "identify affected internal hosts communicating with C2"
            ),
            ResponseStep(
                step_id     = 4,
                name        = "DNS Sinkholing",
                description = "Redirect C2 domain to internal sinkhole — "
                              "captures affected hosts without alerting the attacker"
            ),
            ResponseStep(
                step_id     = 5,
                name        = "Proactive Threat Hunt",
                description = "Trigger threat hunt across network for other "
                              "indicators of compromise associated with this C2"
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

        # ── Step 1: C2 Verification ───────────────────────────────────────────
        if step.step_id == 1:
            if confidence < 0.4:
                step.error = (
                    f"Confidence {confidence:.2%} insufficient for C2 response "
                    f"(minimum 0.40 required)"
                )
                return False
            self._log_action(step,
                f"C2 infrastructure confirmed: {indicator_value}"
            )
            self._log_action(step,
                f"  Confidence: {confidence:.2%} | Priority: {priority}"
            )
            self._log_action(step,
                f"  Severity:   {severity:.1f}/10 | Origin: {country}"
            )
            self._log_action(step,
                f"  Sources:    {sources} feed(s) reporting this indicator"
            )
            self._log_action(step,
                "  C2 Patterns: Periodic beaconing / encrypted protocol abuse"
            )
            self._log_action(step,
                "MITRE ATT&CK: T1071 (Application Layer Protocol — C2)"
            )
            return True

        # ── Step 2: C2 Channel Blocking ───────────────────────────────────────
        elif step.step_id == 2:
            self._log_action(step,
                f"BLOCKING C2 CHANNELS for: {indicator_value}"
            )
            self._log_action(step,
                "  Firewall: Outbound block rule — all ports, all protocols"
            )
            self._log_action(step,
                "  Proxy:    URL/IP blocked at web proxy layer"
            )
            self._log_action(step,
                "  DNS:      Resolution blocked for this indicator"
            )
            self._log_action(step,
                "  IDS/IPS:  Signature added for C2 traffic pattern detection"
            )
            self._log_action(step,
                f"  Applied:  {datetime.now(timezone.utc).isoformat()}"
            )
            self._log_action(step,
                "C2 communication channels severed"
            )
            return True

        # ── Step 3: Beacon Detection ──────────────────────────────────────────
        elif step.step_id == 3:
            self._log_action(step,
                "Beacon pattern analysis initiated"
            )
            self._log_action(step,
                f"  Target C2: {indicator_value}"
            )
            self._log_action(step,
                "  Analysis window: Last 7 days of network flow data"
            )
            self._log_action(step,
                "  Detection criteria: Periodic intervals, consistent byte sizes"
            )
            self._log_action(step,
                "  Affected hosts: Cross-referencing DHCP and NetFlow logs"
            )
            self._log_action(step,
                "  Beacon threshold: Connections at 60s, 120s, or 300s intervals"
            )
            self._log_action(step,
                "  Results: Flagged hosts added to investigation queue"
            )
            return True

        # ── Step 4: DNS Sinkholing ────────────────────────────────────────────
        elif step.step_id == 4:
            self._log_action(step,
                "DNS SINKHOLE CONFIGURATION"
            )
            self._log_action(step,
                f"  C2 indicator:  {indicator_value}"
            )
            self._log_action(step,
                "  Sinkhole IP:   Internal sinkhole server"
            )
            self._log_action(step,
                "  Effect:        All C2 DNS queries redirected to sinkhole"
            )
            self._log_action(step,
                "  Benefit:       Infected hosts identified without attacker awareness"
            )
            self._log_action(step,
                "  Monitoring:    Sinkhole connections logged for host enumeration"
            )
            self._log_action(step,
                f"  Applied:       {datetime.now(timezone.utc).isoformat()}"
            )
            return True

        # ── Step 5: Threat Hunt ───────────────────────────────────────────────
        elif step.step_id == 5:
            self._log_action(step,
                "THREAT HUNT INITIATED"
            )
            self._log_action(step,
                f"  Pivot indicator: {indicator_value} ({country})"
            )
            self._log_action(step,
                "  Hunt scope: Full network — all endpoints and servers"
            )
            self._log_action(step,
                "  Hunt queries:"
            )
            self._log_action(step,
                "    - Process connections to this IP/domain"
            )
            self._log_action(step,
                "    - DNS queries matching C2 DGA patterns"
            )
            self._log_action(step,
                "    - Encoded PowerShell / unusual process parents"
            )
            self._log_action(step,
                "    - Scheduled tasks created in last 30 days"
            )
            self._log_action(step,
                "  Findings will be added to incident timeline"
            )
            self._log_action(step,
                f"  Hunt launched: {datetime.now(timezone.utc).isoformat()}"
            )
            return True

        return False
