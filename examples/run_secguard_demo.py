"""Live interactive demonstration of SecGuard-DPDP security auditor and PII redactor."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secguard.auditor.reporter import print_executive_audit_report
from secguard.auditor.scanner import RouteAuditor
from secguard.governance.consent_log import ConsentManager
from secguard.governance.sanitizer import NonProdDataSanitizer
from secguard.models import HttpMethod, RouteDefinition
from secguard.pii.redactor import PIIRedactor
from secguard.pii.vault import PseudonymizationVault


def main():
    print("=" * 80)
    print("🛡️  SecGuard-DPDP: Enterprise Security & Governance Demonstration")
    print("   Domain Pedigree: 256-Route Audit · DPDP Act 2023 · Zero Dev/QA PII Leakage")
    print("=" * 80)

    # 1. Route Security Audit
    print("\n[PART 1]: Running Automated Security Scanner against API Routes...")
    auditor = RouteAuditor()
    sample_routes = [
        RouteDefinition(path="/health", method=HttpMethod.GET, handler_name="health", requires_auth=False, is_public=True),
        RouteDefinition(path="/api/v1/users/{user_id}/profile", method=HttpMethod.GET, handler_name="profile", has_tenant_check=True),
        RouteDefinition(path="/api/v1/orders/{order_id}/receipt", method=HttpMethod.GET, handler_name="receipt", has_tenant_check=False), # BOLA!
        RouteDefinition(path="/admin/settings/purge", method=HttpMethod.DELETE, handler_name="purge", required_roles=["user"]), # Missing Admin RBAC!
        RouteDefinition(path="/api/v1/auth/login", method=HttpMethod.POST, handler_name="login", response_fields=["token", "password_hash"]), # Leaky PII!
    ]
    report = auditor.audit_routes(sample_routes)
    print_executive_audit_report(report)

    # 2. Real-Time DPDP PII Redaction
    print("\n[PART 2]: Real-Time Indian DPDP & GDPR PII Redaction...")
    redactor = PIIRedactor(mask_style="formatted")
    sample_log = (
        "User KYC submitted: Aadhaar 4532-9876-1234, PAN BKZPA8921K, "
        "Mobile +91 9876543210, Card 4532-0150-1234-5678, Email priya.sharma@startup.in"
    )
    print(f"\nOriginal Payload:\n  \"{sample_log}\"")

    res = redactor.redact(sample_log)
    print(f"\nRedacted Output (Elapsed: {res.execution_time_ms} ms):\n  \"{res.redacted_text}\"")
    print(f"Entities Masked: {res.detected_entities}")

    # 3. Reversible Pseudonymization Vault
    print("\n" + "-" * 80)
    print("[PART 3]: Reversible Cryptographic Tokenization for AI Agents...")
    vault = PseudonymizationVault()
    tokenized, count = vault.tokenize_text("Agent Query: What is the account balance for customer with PAN ABCDE1234F?")
    print(f"  ├─ Outbound to LLM: \"{tokenized}\"")
    detokenized = vault.detokenize_text(tokenized)
    print(f"  └─ Rehydrated by Authorized App: \"{detokenized}\"")

    # 4. Non-Prod Data Masking
    print("\n" + "-" * 80)
    print("[PART 4]: Sanitizing Production Records for Dev/QA/UAT Environments...")
    sanitizer = NonProdDataSanitizer()
    prod_sample = [{"id": 1, "name": "Rahul Verma", "aadhaar": "9876-5432-1234", "pan": "ABCDE1234F"}]
    clean_sample = sanitizer.sanitize_user_records(prod_sample)
    print(f"  ├─ Production Record: {prod_sample[0]}")
    print(f"  └─ Sanitized Dev Record: {clean_sample[0]}")

    print("\n" + "=" * 80)
    print("✅ SecGuard-DPDP demonstration completed successfully.")
    print("=" * 80)


if __name__ == "__main__":
    main()
