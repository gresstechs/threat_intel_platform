"""
playbook_base.py — Base class for all MITRE ATT&CK response playbooks

Defines the shared interface, execution engine, and logging framework
used by all five automated response playbooks. Each playbook inherits
from this base class and implements its own detection criteria and
response steps.

Architecture:
    BasePlaybook
        ├── PB001_Phishing           (T1566 — Initial Access)
        ├── PB002_LateralMovement    (T1021 — Lateral Movement)
        ├── PB003_PrivilegeEscalation(T1068 — Privilege Escalation)
        ├── PB004_CommandAndControl  (T1071 — Command and Control)
        └── PB005_DataExfiltration   (T1041 — Exfiltration)

Deliverable: D3.3 | Deadline: Week 20 (Jun 20, 2026)
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ── Execution Status ──────────────────────────────────────────────────────────

class ExecutionStatus(str, Enum):
    PENDING  = "PENDING"
    RUNNING  = "RUNNING"
    SUCCESS  = "SUCCESS"
    FAILED   = "FAILED"
    PARTIAL  = "PARTIAL"   # Some steps completed, some failed


# ── Response Step ─────────────────────────────────────────────────────────────

@dataclass
class ResponseStep:
    """
    A single step within a playbook execution.
    Each step represents one concrete defensive action.
    """
    step_id:     int
    name:        str
    description: str
    status:      ExecutionStatus = ExecutionStatus.PENDING
    output:      Optional[str]   = None
    error:       Optional[str]   = None
    duration_ms: Optional[int]   = None
    executed_at: Optional[datetime] = None


# ── Playbook Result ───────────────────────────────────────────────────────────

@dataclass
class PlaybookResult:
    """
    Complete result of a playbook execution run.
    Stored in the playbook_executions table.
    """
    playbook_name:      str
    mitre_technique:    str
    mitre_tactic:       str
    indicator_value:    str
    threat_category:    str
    execution_status:   ExecutionStatus
    steps_total:        int
    steps_completed:    int
    steps_failed:       int
    execution_time_ms:  int
    steps:              list[ResponseStep] = field(default_factory=list)
    error_message:      Optional[str] = None
    triggered_by:       str = "AUTO"
    executed_at:        datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    completed_at:       Optional[datetime] = None

    @property
    def success_rate(self) -> float:
        """Percentage of steps completed successfully."""
        if self.steps_total == 0:
            return 0.0
        return round(self.steps_completed / self.steps_total * 100, 2)

    @property
    def is_successful(self) -> bool:
        return self.execution_status == ExecutionStatus.SUCCESS


# ── Base Playbook ─────────────────────────────────────────────────────────────

class BasePlaybook(ABC):
    """
    Abstract base class for all MITRE ATT&CK response playbooks.

    Subclasses must implement:
        - PLAYBOOK_NAME: str
        - MITRE_TECHNIQUE: str  (e.g. "T1566")
        - MITRE_TACTIC: str     (e.g. "Initial Access")
        - THREAT_CATEGORY: str
        - _define_steps() -> list[ResponseStep]
        - _execute_step(step, indicator, context) -> bool
    """

    # ── Subclass must define these ────────────────────────────────────────────
    PLAYBOOK_NAME:   str = ""
    MITRE_TECHNIQUE: str = ""
    MITRE_TACTIC:    str = ""
    THREAT_CATEGORY: str = ""

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def _define_steps(self) -> list[ResponseStep]:
        """Define the ordered response steps for this playbook."""
        pass

    @abstractmethod
    def _execute_step(
        self,
        step: ResponseStep,
        indicator_value: str,
        context: dict
    ) -> bool:
        """
        Execute a single response step.

        Args:
            step:            The ResponseStep to execute
            indicator_value: The IOC being responded to
            context:         Additional context (confidence, category, country, etc.)

        Returns:
            True if step succeeded, False if it failed
        """
        pass

    def should_trigger(self, alert: dict) -> bool:
        """
        Determine whether this playbook should trigger for a given alert.
        Default: triggers when alert threat_category matches THREAT_CATEGORY
        and alert_priority is CRITICAL or HIGH.
        """
        category_match = (
            alert.get("threat_category", "").lower() ==
            self.THREAT_CATEGORY.lower()
        )
        priority_match = alert.get("alert_priority") in ("CRITICAL", "HIGH")
        return category_match and priority_match

    def execute(
        self,
        indicator_value: str,
        context: dict,
        triggered_by: str = "AUTO"
    ) -> PlaybookResult:
        """
        Execute the full playbook for a given indicator.

        Args:
            indicator_value: The IOC triggering this playbook
            context:         Alert context (priority, confidence, country, etc.)
            triggered_by:    "AUTO" or "MANUAL"

        Returns:
            PlaybookResult with full execution details
        """
        start_time = time.time()
        steps = self._define_steps()
        completed = 0
        failed    = 0

        self.logger.info(
            f"[{self.PLAYBOOK_NAME}] Executing for indicator: {indicator_value} "
            f"| technique={self.MITRE_TECHNIQUE} | triggered_by={triggered_by}"
        )

        # Execute each step in order
        for step in steps:
            step.status     = ExecutionStatus.RUNNING
            step.executed_at = datetime.now(timezone.utc)
            step_start      = time.time()

            try:
                success = self._execute_step(step, indicator_value, context)
                step.duration_ms = max(1, int((time.time() - step_start) * 1000))

                if success:
                    step.status = ExecutionStatus.SUCCESS
                    completed  += 1
                    self.logger.info(
                        f"[{self.PLAYBOOK_NAME}] Step {step.step_id} "
                        f"'{step.name}' — SUCCESS ({step.duration_ms}ms)"
                    )
                else:
                    step.status = ExecutionStatus.FAILED
                    failed     += 1
                    self.logger.warning(
                        f"[{self.PLAYBOOK_NAME}] Step {step.step_id} "
                        f"'{step.name}' — FAILED: {step.error}"
                    )
                    # If step 1 (verification) fails — abort remaining steps
                    if step.step_id == 1:
                        self.logger.warning(
                            f"[{self.PLAYBOOK_NAME}] Verification failed — "
                            f"aborting playbook to prevent false positive response"
                        )
                        break

            except Exception as e:
                step.status      = ExecutionStatus.FAILED
                step.error       = str(e)
                step.duration_ms = max(1, int((time.time() - step_start) * 1000))
                failed          += 1
                self.logger.error(
                    f"[{self.PLAYBOOK_NAME}] Step {step.step_id} "
                    f"'{step.name}' — EXCEPTION: {e}"
                )

        # Determine overall status
        if failed == 0:
            overall_status = ExecutionStatus.SUCCESS
        elif completed == 0:
            overall_status = ExecutionStatus.FAILED
        else:
            overall_status = ExecutionStatus.PARTIAL

        execution_time_ms = int((time.time() - start_time) * 1000)

        result = PlaybookResult(
            playbook_name     = self.PLAYBOOK_NAME,
            mitre_technique   = self.MITRE_TECHNIQUE,
            mitre_tactic      = self.MITRE_TACTIC,
            indicator_value   = indicator_value,
            threat_category   = self.THREAT_CATEGORY,
            execution_status  = overall_status,
            steps_total       = len(steps),
            steps_completed   = completed,
            steps_failed      = failed,
            execution_time_ms = execution_time_ms,
            steps             = steps,
            triggered_by      = triggered_by,
            completed_at      = datetime.now(timezone.utc),
        )

        self.logger.info(
            f"[{self.PLAYBOOK_NAME}] Complete — "
            f"status={overall_status.value} | "
            f"steps={completed}/{len(steps)} | "
            f"time={execution_time_ms}ms"
        )

        return result

    def _log_action(self, step: ResponseStep, message: str) -> None:
        """Append a message to the step output log."""
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        step.output = f"{step.output}\n{entry}" if step.output else entry
