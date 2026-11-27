"""Executive compliance score card and reporting formatter."""
from __future__ import annotations

import json
from pathlib import Path
from secguard.models import AuditReport


def print_executive_audit_report(report: AuditReport) -> None:
    print("=" * 80)
    print("🛡️  SECGUARD: 256-ROUTE APPLICATION SECURITY AUDIT SCORE CARD")
    print("=" * 80)
    print(f"• Total Routes Scanned:    {report.total_routes_scanned:,}")
    print(f"• Compliant Routes:        {report.compliant_routes:,} ({report.compliant_routes/report.total_routes_scanned*100:.1f}%)")
    print(f"• Vulnerable Routes:       {report.vulnerable_routes:,} ({report.vulnerable_routes/report.total_routes_scanned*100:.1f}%)")
    print(f"• Executive Health Score:  {report.compliance_score:.1f} / 100.0")
    print(f"• Audit Scan Latency:      {report.execution_time_ms} ms")
    print("-" * 80)
    print("Violations Breakdown by Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = report.violations_by_severity.get(sev, 0)
        marker = "🚨" if sev == "CRITICAL" else ("⚠️ " if sev == "HIGH" else "ℹ️ ")
        print(f"  {marker} {sev:<10}: {cnt}")
    print("=" * 80)

    if report.violations:
        print("\nTop Sample Vulnerabilities Identified:")
        for v in report.violations[:5]:
            print(f"  [{v.severity.value}] {v.rule_id} -> {v.method.value} {v.path}")
            print(f"       Issue: {v.description}")
            print(f"       Fix:   {v.remediation}\n")


def export_report_json(report: AuditReport, output_path: str) -> None:
    path = Path(output_path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(mode="json"), f, indent=2)
