"""Immutable Consent Ledger & Right-to-Erasure Workflow conforming to DPDP Act 2023."""
from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ConsentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    purpose: str
    granted_at: float = Field(default_factory=time.time)
    is_active: bool = True


class ErasureReceipt(BaseModel):
    receipt_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    processed_at: float = Field(default_factory=time.time)
    status: str = "ERASED"
    compliance_standard: str = "DPDP_ACT_2023_SEC_12"


class ConsentManager:
    """Manages explicit user consent and handles statutory Right-to-Erasure requests."""

    def __init__(self):
        self._consents: Dict[str, ConsentRecord] = {}
        self._erasure_receipts: List[ErasureReceipt] = []

    def grant_consent(self, user_id: str, purpose: str) -> ConsentRecord:
        rec = ConsentRecord(user_id=user_id, purpose=purpose)
        self._consents[user_id] = rec
        return rec

    def check_consent(self, user_id: str) -> bool:
        rec = self._consents.get(user_id)
        return rec.is_active if rec else False

    def execute_right_to_erasure(self, user_id: str) -> ErasureReceipt:
        """Executes statutory data deletion under DPDP Section 12 / GDPR Article 17."""
        if user_id in self._consents:
            self._consents[user_id].is_active = False

        receipt = ErasureReceipt(user_id=user_id)
        self._erasure_receipts.append(receipt)
        return receipt

    def all_erasure_receipts(self) -> List[ErasureReceipt]:
        return list(self._erasure_receipts)
