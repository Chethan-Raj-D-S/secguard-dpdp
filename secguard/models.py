"""Data models for route definitions, security violations, and compliance audit reports."""
from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PIIType(str, Enum):
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    CREDIT_CARD = "CREDIT_CARD"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    SSN = "SSN"


class AuditViolation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    rule_name: str
    path: str
    method: HttpMethod
    severity: Severity
    description: str
    remediation: str


class RouteDefinition(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path: str
    method: HttpMethod
    handler_name: str
    requires_auth: bool = True
    is_public: bool = False
    required_roles: List[str] = Field(default_factory=list)
    has_tenant_check: bool = True
    response_fields: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuditReport(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_routes_scanned: int
    compliant_routes: int
    vulnerable_routes: int
    compliance_score: float  # Percentage 0.0 - 100.0
    violations_by_severity: Dict[str, int]
    violations: List[AuditViolation]
    execution_time_ms: float


class RedactionResult(BaseModel):
    original_text: str
    redacted_text: str
    detected_entities: List[str]
    entities_count: int
    execution_time_ms: float
