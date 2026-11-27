"""Route Security Scanner auditing route collections against compliance rules."""
from __future__ import annotations

import time
from collections import defaultdict
from typing import List
from secguard.auditor.rules import run_all_rules
from secguard.models import AuditReport, AuditViolation, RouteDefinition, Severity


class RouteAuditor:
    """Enterprise security scanner evaluating API routes for OWASP API Top 10 compliance."""

    def audit_routes(self, routes: List[RouteDefinition]) -> AuditReport:
        start_time = time.perf_counter()
        all_violations: List[AuditViolation] = []
        severity_counts = defaultdict(int)

        compliant_count = 0
        vulnerable_count = 0

        for route in routes:
            v_list = run_all_rules(route)
            if v_list:
                vulnerable_count += 1
                all_violations.extend(v_list)
                for v in v_list:
                    severity_counts[v.severity.value] += 1
            else:
                compliant_count += 1

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Calculate weighted compliance score
        # Penalty weights: CRITICAL = 10, HIGH = 5, MEDIUM = 2, LOW = 1
        total_routes = len(routes)
        if total_routes == 0:
            score = 100.0
        else:
            penalty = (
                severity_counts["CRITICAL"] * 10
                + severity_counts["HIGH"] * 5
                + severity_counts["MEDIUM"] * 2
                + severity_counts["LOW"] * 1
            )
            max_penalty = total_routes * 10
            raw_score = max(0.0, 100.0 - (penalty / max_penalty * 100.0))
            score = round(raw_score, 1)

        return AuditReport(
            total_routes_scanned=total_routes,
            compliant_routes=compliant_count,
            vulnerable_routes=vulnerable_count,
            compliance_score=score,
            violations_by_severity=dict(severity_counts),
            violations=all_violations,
            execution_time_ms=round(elapsed_ms, 2),
        )
