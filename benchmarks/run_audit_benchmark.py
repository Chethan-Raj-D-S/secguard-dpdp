"""256-Route Application Security Audit Benchmark Suite."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secguard.auditor.reporter import print_executive_audit_report
from secguard.auditor.scanner import RouteAuditor
from secguard.models import HttpMethod, RouteDefinition


def generate_enterprise_256_routes() -> list[RouteDefinition]:
    """Generates the enterprise 256-route microservice catalog."""
    routes: list[RouteDefinition] = []

    # 1. User & Identity Service (32 routes)
    for i in range(1, 33):
        routes.append(
            RouteDefinition(
                path=f"/api/v1/users/{{user_id}}/profile_part_{i}",
                method=HttpMethod.GET if i % 2 == 0 else HttpMethod.PUT,
                handler_name=f"get_user_profile_segment_{i}",
                requires_auth=True,
                has_tenant_check=True,
                required_roles=["user"],
                response_fields=["user_id", "display_name", "created_at"],
            )
        )

    # 2. Authentication & Session Service (16 routes)
    for i in range(1, 17):
        is_pub = i in [1, 2]  # login, signup are public
        routes.append(
            RouteDefinition(
                path=f"/api/v1/auth/endpoint_{i}",
                method=HttpMethod.POST,
                handler_name=f"auth_handler_{i}",
                requires_auth=not is_pub,
                is_public=is_pub,
                has_tenant_check=True,
                response_fields=["token", "expires_in"],
            )
        )

    # 3. Organization & Billing Service (48 routes)
    for i in range(1, 49):
        routes.append(
            RouteDefinition(
                path=f"/api/v1/orgs/{{org_id}}/billing/invoice_{i}",
                method=HttpMethod.GET if i % 2 == 0 else HttpMethod.POST,
                handler_name=f"billing_invoice_{i}",
                requires_auth=True,
                has_tenant_check=True,
                required_roles=["admin", "billing_admin"],
                response_fields=["invoice_id", "amount", "status"],
            )
        )

    # 4. Content & Curriculum Engine (64 routes)
    for i in range(1, 65):
        routes.append(
            RouteDefinition(
                path=f"/api/v1/courses/{{course_id}}/modules/module_{i}",
                method=HttpMethod.GET,
                handler_name=f"get_course_module_{i}",
                requires_auth=True,
                has_tenant_check=True,
                required_roles=["student", "teacher"],
                response_fields=["module_id", "title", "content_url"],
            )
        )

    # 5. AI & Recommendation Services (48 routes)
    for i in range(1, 49):
        routes.append(
            RouteDefinition(
                path=f"/api/v1/ai/recommendations/model_{i}",
                method=HttpMethod.POST,
                handler_name=f"ai_recommendation_handler_{i}",
                requires_auth=True,
                has_tenant_check=True,
                required_roles=["user"],
                response_fields=["recommendation_id", "confidence_score"],
            )
        )

    # 6. Admin & Platform Diagnostics (48 routes)
    for i in range(1, 49):
        routes.append(
            RouteDefinition(
                path=f"/admin/system/diagnostics/metric_{i}",
                method=HttpMethod.GET,
                handler_name=f"admin_diagnostics_{i}",
                requires_auth=True,
                has_tenant_check=True,
                required_roles=["admin"],
                response_fields=["metric_name", "value", "timestamp"],
            )
        )

    # Intentionally inject 4 legacy vulnerabilities to demonstrate auditor detection
    # A. Injected BOLA/IDOR vulnerability in User Service
    routes[5].has_tenant_check = False
    routes[5].path = "/api/v1/users/{user_id}/financial_records"

    # B. Injected Missing Auth in Billing Service
    routes[40].requires_auth = False
    routes[40].is_public = False

    # C. Injected Leaky PII Response in Auth Service
    routes[12].response_fields = ["user_id", "password_hash", "aadhaar"]

    # D. Injected Missing Admin RBAC in Admin Diagnostics
    routes[210].required_roles = ["guest"]

    return routes


def main():
    routes = generate_enterprise_256_routes()
    assert len(routes) == 256, f"Expected 256 routes, got {len(routes)}"

    auditor = RouteAuditor()
    report = auditor.audit_routes(routes)

    print_executive_audit_report(report)


if __name__ == "__main__":
    main()
