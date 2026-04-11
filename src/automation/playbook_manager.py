"""
playbook_manager.py — Playbook Orchestration Engine

Manages all five MITRE ATT&CK response playbooks, determines which
playbooks should trigger for a given alert, executes them, and
stores results in the playbook_executions database table.

Usage:
    manager = PlaybookManager()
    results = manager.process_alert(alert_dict)
"""

import logging
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timezone

from db import db
from playbook_base import PlaybookResult, ExecutionStatus
from PB001_Phishing import PB001_Phishing
from PB002_LateralMovement import PB002_LateralMovement
from PB003_PrivilegeEscalation import PB003_PrivilegeEscalation
from PB004_CommandAndControl import PB004_CommandAndControl
from PB005_DataExfiltration import PB005_DataExfiltration

logger = logging.getLogger(__name__)


class PlaybookManager:
    """
    Orchestrates all five MITRE ATT&CK response playbooks.
    Determines which playbooks trigger for each alert and
    records execution results in the database.
    """

    def __init__(self) -> None:
        self.playbooks = [
            PB001_Phishing(),
            PB002_LateralMovement(),
            PB003_PrivilegeEscalation(),
            PB004_CommandAndControl(),
            PB005_DataExfiltration(),
        ]
        logger.info(
            f"PlaybookManager initialised — "
            f"{len(self.playbooks)} playbooks registered"
        )

    def process_alert(
        self,
        alert: dict,
        triggered_by: str = "AUTO"
    ) -> list[PlaybookResult]:
        """
        Evaluate all playbooks against an alert and execute those that match.

        Args:
            alert:        Alert dict from alert_queue or correlation_results
            triggered_by: "AUTO" (pipeline) or "MANUAL" (analyst)

        Returns:
            List of PlaybookResults for each triggered playbook
        """
        results = []
        indicator_value = alert.get("indicator_value", "")
        priority        = alert.get("alert_priority", "LOW")

        logger.info(
            f"PlaybookManager | Processing alert: {indicator_value} "
            f"| priority={priority}"
        )

        for playbook in self.playbooks:
            if playbook.should_trigger(alert):
                logger.info(
                    f"Triggering {playbook.PLAYBOOK_NAME} for {indicator_value}"
                )
                result = playbook.execute(
                    indicator_value = indicator_value,
                    context         = alert,
                    triggered_by    = triggered_by
                )
                results.append(result)
                self._store_result(result, alert.get("id"))
            else:
                logger.debug(
                    f"{playbook.PLAYBOOK_NAME} — not triggered "
                    f"(category/priority mismatch)"
                )

        logger.info(
            f"PlaybookManager | {len(results)} playbook(s) executed "
            f"for {indicator_value}"
        )
        return results

    def process_batch(self, alerts: list[dict]) -> dict:
        """
        Process a batch of alerts through the playbook engine.
        Returns summary statistics.
        """
        stats = {
            "alerts_processed":    len(alerts),
            "playbooks_triggered": 0,
            "playbooks_succeeded": 0,
            "playbooks_failed":    0,
            "playbooks_partial":   0,
        }

        for alert in alerts:
            results = self.process_alert(alert)
            for result in results:
                stats["playbooks_triggered"] += 1
                if result.execution_status == ExecutionStatus.SUCCESS:
                    stats["playbooks_succeeded"] += 1
                elif result.execution_status == ExecutionStatus.FAILED:
                    stats["playbooks_failed"] += 1
                else:
                    stats["playbooks_partial"] += 1

        # Compute success rate
        triggered = stats["playbooks_triggered"]
        if triggered > 0:
            stats["success_rate_pct"] = round(
                stats["playbooks_succeeded"] / triggered * 100, 2
            )
        else:
            stats["success_rate_pct"] = 0.0

        logger.info(
            f"PlaybookManager batch complete | "
            f"triggered={triggered} | "
            f"success_rate={stats.get('success_rate_pct', 0)}%"
        )
        return stats

    def _store_result(
        self, result: PlaybookResult, alert_id: int = None
    ) -> None:
        """Store playbook execution result in the database."""
        try:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO playbook_executions (
                        alert_id, playbook_name, mitre_technique, mitre_tactic,
                        indicator_value, threat_category, execution_status,
                        steps_total, steps_completed, steps_failed,
                        execution_time_ms, triggered_by, executed_at, completed_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s
                    )
                """, (
                    alert_id,
                    result.playbook_name,
                    result.mitre_technique,
                    result.mitre_tactic,
                    result.indicator_value,
                    result.threat_category,
                    result.execution_status.value,
                    result.steps_total,
                    result.steps_completed,
                    result.steps_failed,
                    result.execution_time_ms,
                    result.triggered_by,
                    result.executed_at,
                    result.completed_at,
                ))
        except Exception as e:
            logger.error(f"Failed to store playbook result: {e}")

    def get_success_rates(self) -> dict:
        """
        Retrieve playbook execution success rates from the database.
        Evidence for Objective 5: >90% execution success rate.
        """
        try:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT
                        playbook_name,
                        mitre_technique,
                        COUNT(*) as total,
                        COUNT(*) FILTER (WHERE execution_status = 'SUCCESS') as succeeded,
                        ROUND(
                            COUNT(*) FILTER (WHERE execution_status = 'SUCCESS')
                            * 100.0 / NULLIF(COUNT(*), 0), 2
                        ) as success_rate_pct
                    FROM playbook_executions
                    WHERE playbook_name != 'INIT'
                    GROUP BY playbook_name, mitre_technique
                    ORDER BY playbook_name
                """)
                rows = cur.fetchall()
                return {
                    row["playbook_name"]: {
                        "technique":        row["mitre_technique"],
                        "total":            row["total"],
                        "succeeded":        row["succeeded"],
                        "success_rate_pct": float(row["success_rate_pct"] or 0)
                    }
                    for row in rows
                }
        except Exception as e:
            logger.error(f"Failed to retrieve success rates: {e}")
            return {}

    def print_success_rates(self) -> None:
        """Print playbook success rates — evidence for Objective 5."""
        rates = self.get_success_rates()
        print("\n" + "=" * 65)
        print("  PLAYBOOK EXECUTION SUCCESS RATES (Objective 5 Target: >90%)")
        print("=" * 65)
        print(f"  {'Playbook':<35} {'Technique':<8} {'Success Rate':>12}")
        print(f"  {'-'*55}")
        all_met = True
        for name, data in rates.items():
            rate = data["success_rate_pct"]
            met  = "✅" if rate >= 90.0 else "❌"
            if rate < 90.0:
                all_met = False
            print(f"  {name:<35} {data['technique']:<8} {rate:>10.1f}% {met}")
        print(f"  {'-'*55}")
        print(f"  Objective 5 overall: {'✅ MET' if all_met else '❌ NOT MET'}")
        print("=" * 65 + "\n")
