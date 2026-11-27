"""OWASP API Security Top 10 compliance rules for enterprise route auditing."""
from __future__ import annotations

import re
from typing import List, Optional
from secguard.models import AuditViolation, HttpMethod, RouteDefinition, Severity

SENSITIVE_RESPONSE_FIELDS = {
    "password",
    "password_hash",
    "secret",
    "api_key",
    "aadhaar",
    "ssn",
    "credit_card",
    "cvv",
}


def evaluate_bola_idor(route: RouteDefinition) -> Optional[AuditViolation]:
    """OWASP API1: Broken Object Level Authorization (BOLA/IDOR)."""
    # If path references an object ID like /api/v1/users/{user_id}/orders/{order_id}
    has_path_param = bool(re.search(r"\{[a-zA-Z0-9_]+\}", route.path))

    if has_path_param and not route.has_tenant_check:
        return AuditViolation(
            rule_id="OWASP-API1-BOLA",
            rule_name="Broken Object Level Authorization (IDOR)",
            path=route.path,
            method=route.method,
            severity=Severity.CRITICAL,
            description="Route accesses object identifier without verifying tenant/user ownership in authorization context.",
            remediation="Inject tenant-scoping dependency (e.g. Depends(verify_tenant_ownership)) before database access.",
        )
    return None


def evaluate_broken_authentication(route: RouteDefinition) -> Optional[AuditViolation]:
    """OWASP API2: Broken Authentication."""
    if not route.requires_auth and not route.is_public:
        return AuditViolation(
            rule_id="OWASP-API2-NOAUTH",
            rule_name="Unauthenticated Route Exposure",
            path=route.path,
            method=route.method,
            severity=Severity.HIGH,
            description="Route omits authentication dependency but is not explicitly declared as a public endpoint.",
            remediation="Add authentication middleware or explicitly mark route with @public_endpoint decorator.",
        )
    return None


def evaluate_leaky_pii_model(route: RouteDefinition) -> Optional[AuditViolation]:
    """OWASP API3: Broken Object Property Level Authorization (Leaky PII)."""
    leaked = []
    for f in route.response_fields:
        if f.lower() in SENSITIVE_RESPONSE_FIELDS:
            leaked.append(f)

    if leaked:
        return AuditViolation(
            rule_id="OWASP-API3-LEAKY-PII",
            rule_name="Sensitive Data & PII Exposure in Response Model",
            path=route.path,
            method=route.method,
            severity=Severity.CRITICAL,
            description=f"Response schema exposes sensitive attributes directly to caller: {', '.join(leaked)}.",
            remediation="Exclude sensitive fields from Pydantic response models using Field(exclude=True) or dedicated DTOs.",
        )
    return None


def evaluate_function_level_rbac(route: RouteDefinition) -> Optional[AuditViolation]:
    """OWASP API5: Broken Function Level Authorization (Missing RBAC)."""
    is_privileged_path = route.path.startswith("/admin") or route.path.startswith("/api/admin") or "/billing" in route.path

    if is_privileged_path:
        has_admin_role = any(r in ["admin", "superadmin", "billing_admin"] for r in route.required_roles)
        if not has_admin_role:
            return AuditViolation(
                rule_id="OWASP-API5-MISSING-RBAC",
                rule_name="Privileged Route Missing Function-Level RBAC",
                path=route.path,
                method=route.method,
                severity=Severity.HIGH,
                description="Administrative endpoint does not enforce administrative role permission check.",
                remediation="Attach role validation guard (e.g. Depends(require_roles(['admin']))) to endpoint definition.",
            )
    return None


def run_all_rules(route: RouteDefinition) -> List[AuditViolation]:
    violations: List[AuditViolation] = []
    for rule in [
        evaluate_bola_idor,
        evaluate_broken_authentication,
        evaluate_leaky_pii_model,
        evaluate_function_level_rbac,
    ]:
        res = rule(route)
        if res:
            violations.append(res)
    return violations
