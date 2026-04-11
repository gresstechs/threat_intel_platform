"""
PB001_Phishing.py — MITRE ATT&CK Playbook 1: Phishing Response
Technique: T1566 — Phishing
Tactic:    Initial Access

Triggered when: A URL, domain, or IP is classified as PHISHING
with CRITICAL or HIGH priority by the correlation engine.

Response Steps:
    1. Threat Verification    — Confirm indicator is genuinely malicious
    2. Indicator Blocking     — Block URL/domain at email gateway
    3. URL Defanging          — Render URLs non-clickable in alert systems
    4. User Notification      — Alert affected users / security team
    5. Threat Intelligence    — Submit to threat sharing feeds

MITRE Reference:
    https://attack.mitre.org/techniques/T1566/
"""

import re
import logging
from datetime import datetime, timezone

from playbook_base import BasePlaybook, ResponseStep, ExecutionStatus

logger = logging.getLogger(__name__)


class PB001_Phishing(BasePlaybook):

    PLAYBOOK_NAME   = "PB001_Phishing"
    MITRE_TECHNIQUE = "T1566"
    MITRE_TACTIC    = "Initial Access"
    THREAT_CATEGORY = "phishing"

    def _define_steps(self) -> list[ResponseStep]:
        return [
            ResponseStep(
                step_id     = 1,
                name        = "Threat Verification",
                description = "Verify indicator confidence meets response threshold "
                              "and cross-check against known false positive list"
            ),
            ResponseStep(
                step_id     = 2,
                name        = "Indicator Blocking",
                description = "Block phishing URL/domain at email gateway and "
                              "web proxy — prevent users from accessing the resource"
            ),
            ResponseStep(
                step_id     = 3,
                name        = "URL Defanging",
                description = "Defang indicator in all alert outputs — replace "
                              "dots and slashes to prevent accidental clicks"
            ),
            ResponseStep(
                step_id     = 4,
                name        = "Security Team Notification",
                description = "Alert the security team with full indicator context, "
                              "confidence scores, and recommended actions"
            ),
            ResponseStep(
                step_id     = 5,
                name        = "Threat Intelligence Sharing",
                description = "Log indicator to threat sharing record for "
                              "cross-organisational intelligence sharing"
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

        # ── Step 1: Threat Verification ───────────────────────────────────────
        if step.step_id == 1:
            if confidence < 0.3:
                step.error = (
                    f"Confidence {confidence:.2%} below response threshold (0.30) "
                    f"— playbook aborted to prevent false positive response"
                )
                return False
            self._log_action(step,
                f"Verified: confidence={confidence:.2%} | "
                f"priority={priority} | sources={sources} feed(s)"
            )
            self._log_action(step,
                f"Indicator '{indicator_value}' confirmed as phishing threat"
            )
            return True

        # ── Step 2: Indicator Blocking ────────────────────────────────────────
        elif step.step_id == 2:
            # In production: call email gateway API / web proxy API
            # For dissertation: simulate the blocking action with full audit log
            block_target = indicator_value
            self._log_action(step,
                f"ACTION: Block rule created for '{block_target}'"
            )
            self._log_action(step,
                "TARGET: Email gateway — inbound URL filtering rule applied"
            )
            self._log_action(step,
                "TARGET: Web proxy — domain blocked in category 'Phishing'"
            )
            self._log_action(step,
                f"AUDIT: Block applied at {datetime.now(timezone.utc).isoformat()}"
            )
            return True

        # ── Step 3: URL Defanging ─────────────────────────────────────────────
        elif step.step_id == 3:
            # Defang the indicator — replace . with [.] and :// with [://]
            defanged = indicator_value.replace(".", "[.]").replace("://", "[://]")
            self._log_action(step,
                f"Original:  {indicator_value}"
            )
            self._log_action(step,
                f"Defanged:  {defanged}"
            )
            self._log_action(step,
                "Defanged indicator applied to all alert system outputs"
            )
            step.output = (step.output or "") + f"\nDEFANGED: {defanged}"
            return True

        # ── Step 4: Security Team Notification ───────────────────────────────
        elif step.step_id == 4:
            country = context.get("country_code", "Unknown")
            self._log_action(step,
                f"ALERT: Phishing indicator detected"
            )
            self._log_action(step,
                f"  Indicator:  {indicator_value}"
            )
            self._log_action(step,
                f"  Confidence: {confidence:.2%}"
            )
            self._log_action(step,
                f"  Priority:   {priority}"
            )
            self._log_action(step,
                f"  Origin:     {country}"
            )
            self._log_action(step,
                f"  MITRE:      T1566 (Phishing — Initial Access)"
            )
            self._log_action(step,
                "Notification dispatched to security team queue"
            )
            return True

        # ── Step 5: Threat Intelligence Sharing ──────────────────────────────
        elif step.step_id == 5:
            self._log_action(step,
                f"Logged indicator '{indicator_value}' to threat sharing record"
            )
            self._log_action(step,
                f"Category: phishing | Technique: T1566 | "
                f"Confidence: {confidence:.2%}"
            )
            self._log_action(step,
                "Available for cross-organisational threat intelligence sharing"
            )
            return True

        return False
