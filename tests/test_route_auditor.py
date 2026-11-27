"""Tests for Route Security Auditor rules and compliance reporting."""
from secguard.auditor.rules import (
    evaluate_bola_idor,
    evaluate_broken_authentication,
    evaluate_function_level_rbac,
    evaluate_leaky_pii_model,
)
from secguard.auditor.scanner import RouteAuditor
from secguard.models import HttpMethod, RouteDefinition, Severity


def test_bola_idor_detection():
    # Vulnerable route: has path parameter {user_id} but no tenant check
    vulnerable_route = RouteDefinition(
        path="/api/v1/users/{user_id}/orders",
        method=HttpMethod.GET,
        handler_name="get_orders",
        has_tenant_check=False,
    )
    violation = evaluate_bola_idor(vulnerable_route)
    assert violation is not None
    assert violation.severity == Severity.CRITICAL
    assert violation.rule_id == "OWASP-API1-BOLA"

    # Compliant route: has tenant check
    compliant_route = RouteDefinition(
        path="/api/v1/users/{user_id}/orders",
        method=HttpMethod.GET,
        handler_name="get_orders",
        has_tenant_check=True,
    )
    assert evaluate_bola_idor(compliant_route) is None


def test_broken_authentication_detection():
    # Route without auth and not marked public
    unprotected = RouteDefinition(
        path="/api/v1/internal/metrics",
        method=HttpMethod.GET,
        handler_name="get_metrics",
        requires_auth=False,
        is_public=False,
    )
    v = evaluate_broken_authentication(unprotected)
    assert v is not None
    assert v.severity == Severity.HIGH

    # Explicit public route (e.g. health check)
    public_endpoint = RouteDefinition(
        path="/health",
        method=HttpMethod.GET,
        handler_name="health_check",
        requires_auth=False,
        is_public=True,
    )
    assert evaluate_broken_authentication(public_endpoint) is None


def test_leaky_pii_response_detection():
    route = RouteDefinition(
        path="/api/v1/users/me",
        method=HttpMethod.GET,
        handler_name="get_me",
        response_fields=["user_id", "email", "password_hash", "aadhaar"],
    )
    v = evaluate_leaky_pii_model(route)
    assert v is not None
    assert v.severity == Severity.CRITICAL
    assert "password_hash" in v.description
    assert "aadhaar" in v.description


def test_function_level_rbac_detection():
    route = RouteDefinition(
        path="/admin/users/delete",
        method=HttpMethod.DELETE,
        handler_name="delete_user",
        required_roles=["user"],  # Missing admin role!
    )
    v = evaluate_function_level_rbac(route)
    assert v is not None
    assert v.severity == Severity.HIGH
    assert v.rule_id == "OWASP-API5-MISSING-RBAC"


def test_auditor_scans_multiple_routes():
    auditor = RouteAuditor()
    routes = [
        RouteDefinition(path="/public/ping", method=HttpMethod.GET, handler_name="ping", requires_auth=False, is_public=True),
        RouteDefinition(path="/users/{user_id}", method=HttpMethod.GET, handler_name="get_user", has_tenant_check=False),
    ]

    report = auditor.audit_routes(routes)
    assert report.total_routes_scanned == 2
    assert report.compliant_routes == 1
    assert report.vulnerable_routes == 1
    assert len(report.violations) == 1
