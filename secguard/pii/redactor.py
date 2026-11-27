"""High-speed PII redactor masking sensitive data for logs and LLM model prompts."""
from __future__ import annotations

import time
from typing import List
from secguard.models import PIIType, RedactionResult
from secguard.pii.patterns import PII_REGEX_PATTERNS, validate_luhn_checksum


class PIIRedactor:
    """Detects and redacts sensitive Indian DPDP and GDPR identifiers."""

    def __init__(self, mask_style: str = "formatted"):
        # "formatted" preserves last few digits (e.g. XXXX-XXXX-1234); "token" replaces with [REDACTED_TYPE]
        self.mask_style = mask_style

    def _mask_aadhaar(self, match_str: str) -> str:
        clean = "".join(c for c in match_str if c.isdigit())
        if self.mask_style == "formatted" and len(clean) == 12:
            return f"XXXX-XXXX-{clean[-4:]}"
        return "[REDACTED_AADHAAR]"

    def _mask_pan(self, match_str: str) -> str:
        if self.mask_style == "formatted" and len(match_str) == 10:
            return f"{match_str[:2]}XXXXXX{match_str[-2:]}"
        return "[REDACTED_PAN]"

    def _mask_card(self, match_str: str) -> str:
        clean = "".join(c for c in match_str if c.isdigit())
        if self.mask_style == "formatted" and len(clean) >= 4:
            return f"XXXX-XXXX-XXXX-{clean[-4:]}"
        return "[REDACTED_CREDIT_CARD]"

    def _mask_email(self, match_str: str) -> str:
        if self.mask_style == "formatted" and "@" in match_str:
            parts = match_str.split("@")
            user = parts[0]
            masked_user = f"{user[0]}***{user[-1]}" if len(user) > 2 else "***"
            return f"{masked_user}@{parts[1]}"
        return "[REDACTED_EMAIL]"

    def _mask_phone(self, match_str: str) -> str:
        clean = "".join(c for c in match_str if c.isdigit())
        if self.mask_style == "formatted" and len(clean) >= 4:
            return f"XXXXX-XX{clean[-4:]}"
        return "[REDACTED_PHONE]"

    def redact(self, text: str) -> RedactionResult:
        start_time = time.perf_counter()
        redacted = text
        detected: List[str] = []

        # 1. Redact Credit Card (16 digits - check first to avoid prefix overlap)
        for m in PII_REGEX_PATTERNS[PIIType.CREDIT_CARD].finditer(text):
            val = m.group(0)
            if validate_luhn_checksum(val):
                redacted = redacted.replace(val, self._mask_card(val))
                detected.append(f"CARD:{val[-4:]}")

        # 2. Redact Aadhaar (12 digits)
        for m in PII_REGEX_PATTERNS[PIIType.AADHAAR].finditer(text):
            val = m.group(0)
            redacted = redacted.replace(val, self._mask_aadhaar(val))
            detected.append(f"AADHAAR:{val[-4:]}")

        # 3. Redact PAN
        for m in PII_REGEX_PATTERNS[PIIType.PAN].finditer(text):
            val = m.group(0)
            redacted = redacted.replace(val, self._mask_pan(val))
            detected.append(f"PAN:{val[:2]}..{val[-2:]}")

        # 4. Redact Email
        for m in PII_REGEX_PATTERNS[PIIType.EMAIL].finditer(text):
            val = m.group(0)
            redacted = redacted.replace(val, self._mask_email(val))
            detected.append(f"EMAIL:{val}")

        # 5. Redact Phone
        for m in PII_REGEX_PATTERNS[PIIType.PHONE].finditer(text):
            val = m.group(0)
            redacted = redacted.replace(val, self._mask_phone(val))
            detected.append(f"PHONE:{val[-4:]}")

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return RedactionResult(
            original_text=text,
            redacted_text=redacted,
            detected_entities=detected,
            entities_count=len(detected),
            execution_time_ms=round(elapsed_ms, 3),
        )
