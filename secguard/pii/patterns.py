"""Regex patterns and checksum validators for Indian DPDP Act and GDPR PII identifiers."""
from __future__ import annotations

import re
from typing import Dict, Pattern
from secguard.models import PIIType


def validate_luhn_checksum(card_number: str) -> bool:
    """Validates credit card number using Luhn mod-10 algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d

    return checksum % 10 == 0


# Compiled high-performance regex patterns
PII_REGEX_PATTERNS: Dict[PIIType, Pattern] = {
    # Credit / Debit Card Numbers (13-19 digits with optional spaces/hyphens)
    PIIType.CREDIT_CARD: re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b|\b\d{15,16}\b"),

    # Indian Aadhaar: 12 digits, cannot start with 0 or 1, optional spaces or dashes, negative lookahead for extra digits
    PIIType.AADHAAR: re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![\s-]?\d)\b"),

    # Indian Income Tax PAN Card: 5 uppercase letters, 4 digits, 1 uppercase letter
    PIIType.PAN: re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),

    # Indian Mobile Numbers: 10 digits starting with 6, 7, 8, or 9, optional +91 prefix
    PIIType.PHONE: re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{9}\b"),

    # Email Addresses
    PIIType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),

    # US Social Security Numbers (SSN)
    PIIType.SSN: re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
}
