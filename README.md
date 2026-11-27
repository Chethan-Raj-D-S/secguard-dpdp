# SecGuard-DPDP: Enterprise 256-Route Security Auditor & DPDP/GDPR Compliance Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security: OWASP API Top 10](https://img.shields.io/badge/Security-OWASP_API_Top_10-red.svg)]()
[![Compliance: DPDP Act 2023 & GDPR](https://img.shields.io/badge/Compliance-Indian_DPDP_%7C_GDPR-green.svg)]()
[![Audit Scope: 256 Routes](https://img.shields.io/badge/Audit_Scope-256_Enterprise_Routes-purple.svg)]()
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-orange.svg)](https://opensource.org/licenses/Apache-2.0)

> **Architect & Author:** Chethan Raj D S (`chethanraj.d.s@gmail.com`)  
> **Domain Pedigree:** Enterprise SaaS Technical Lead · 256-Route Application Security Audit · GDPR & Indian DPDP Act 2023 Grievance Point of Contact · Zero PII Leakage across Dev/QA/UAT

---

## 1. Executive Summary & Problem Statement

As enterprise B2B SaaS platforms scale to hundreds of microservice endpoints and integrate Generative AI agents, two critical security liabilities emerge:

1. **Authorization Drift (OWASP API Top 10):** Developers accidentally expose endpoints without role-based access control (RBAC), omit tenant isolation checks leading to Broken Object Level Authorization (BOLA / IDOR), or allow mass-assignment of sensitive fields.
2. **Regulatory Non-Compliance (Indian DPDP Act 2023 & GDPR):** Feeding unmasked Personally Identifiable Information (PII) such as Indian **Aadhaar numbers**, **PAN cards**, mobile numbers, or credit card numbers into external LLM prompts, server logs, or non-production staging environments (Dev/QA/UAT) incurs statutory penalties and data breach liability.

`SecGuard-DPDP` solves both challenges through an automated, dual-layer security architecture:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SECGUARD-DPDP ARCHITECTURE                             │
├────────────────────────────────────────────────────┬───────────────────────────────────┤
│ LAYER 1: STATIC ROUTE AUDITOR (PRE-DEPLOY)         │ LAYER 2: REAL-TIME PII GOVERNANCE │
├────────────────────────────────────────────────────┼───────────────────────────────────┤
│ • AST Parser scanning all 256 API endpoints        │ • Sub-millisecond stream redactor │
│ • Evaluates OWASP API Top 10 (BOLA, RBAC, Auth)    │ • Indian DPDP: Aadhaar, PAN, Phone│
│ • Detects leaky PII models & missing permissions   │ • GDPR: Emails, Cards, SSN        │
│ • Emits executive compliance score card            │ • Reversible Vault Tokenization   │
│ • Enforces Dev/QA/UAT synthetic data sanitization  │ • Immutable Right-to-Erasure Log  │
└────────────────────────────────────────────────────┴───────────────────────────────────┘
```

---

## 2. Technical Capabilities

### A. Automated 256-Route Security Scanner
* **API1 (BOLA / IDOR):** Detects path parameters (e.g., `/{user_id}`, `/{org_id}`) accessed without tenant-scoped authorization dependencies.
* **API2 (Broken Authentication):** Flags public routes lacking authentication tokens unless explicitly marked with `@public_endpoint`.
* **API3 (Leaky Response Models):** Inspects Pydantic response models for unredacted attributes (`password_hash`, `ssn`, `aadhaar`, `internal_token`).
* **API5 (Missing Function-Level RBAC):** Verifies that administrative endpoints (`/admin/*`, `/billing/*`) enforce strict role permissions (`admin`, `billing_manager`).

### B. Indian DPDP & GDPR Real-Time Redactor
* **Indian Identifiers:**
  * **Aadhaar Numbers:** 12-digit format `XXXX-XXXX-XXXX` with Verhoeff-compatible pattern validation.
  * **PAN Cards:** 10-character alphanumeric `[A-Z]{5}[0-9]{4}[A-Z]`.
  * **Indian Mobile Numbers:** 10-digit mobile numbers with optional `+91` prefix.
* **International Identifiers:**
  * **Credit Cards:** 16-digit major cards (Visa, MasterCard, Amex) with Luhn checksum validation.
  * **Email Addresses & IP Addresses.**
* **Reversible Pseudonymization:** Replaces sensitive tokens with cryptographic HMAC tokens (`[TOKEN:aadhaar:ab8912]`), allowing authorized backend services to detokenize while protecting logs and third-party LLM context.

### C. Dev/QA/UAT Data Sanitizer
* Generates non-reversible, synthetic, referentially-consistent test datasets from production schemas, closing unrestricted PII access across development environments.

---

## 3. Directory Structure

```
secguard-dpdp/
├── pyproject.toml                     # Modern package spec & dependencies
├── secguard/
│   ├── models.py                      # Route schemas, violations, and severity enums
│   ├── auditor/
│   │   ├── rules.py                   # OWASP API Top 10 compliance rules
│   │   ├── scanner.py                 # Route AST parser & inspector
│   │   └── reporter.py                # Executive compliance score card generator
│   ├── pii/
│   │   ├── patterns.py                # Regex & checksum validators (Aadhaar, PAN, Cards)
│   │   ├── redactor.py                # Streaming redactor & token masking
│   │   └── vault.py                   # Reversible cryptographic pseudonymization vault
│   └── governance/
│       ├── sanitizer.py               # Non-prod synthetic data generator
│       └── consent_log.py             # DPDP/GDPR consent & right-to-erasure audit ledger
├── benchmarks/
│   ├── run_audit_benchmark.py         # Full 256-route audit simulation
│   └── run_pii_benchmark.py           # Throughput benchmark: 100,000+ records/sec
├── tests/
│   ├── conftest.py
│   ├── test_route_auditor.py          # BOLA, Auth, RBAC detection tests
│   ├── test_pii_redactor.py           # Aadhaar, PAN, card, email masking tests
│   ├── test_pseudonymization.py       # Vault reversible detokenization tests
│   └── test_governance.py             # Dev/QA sanitizer & consent ledger tests
└── examples/
    └── run_secguard_demo.py           # Live interactive CLI demonstration
```

---

## 4. Quickstart

```bash
# 1. Clone repository
git clone https://github.com/Chethan-Raj-D-S/secguard-dpdp.git
cd secguard-dpdp

# 2. Run unit test suite (100% offline, zero external dependencies)
pytest tests/ -v

# 3. Run the 256-Route Security Audit Benchmark
python benchmarks/run_audit_benchmark.py

# 4. Run interactive demonstration
python examples/run_secguard_demo.py
```
