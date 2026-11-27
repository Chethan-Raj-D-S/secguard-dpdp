"""Tests for Indian DPDP Act and GDPR PII Redaction."""
from secguard.pii.redactor import PIIRedactor


def test_redacts_indian_aadhaar():
    redactor = PIIRedactor(mask_style="formatted")
    text = "Citizen Aadhaar number is 5432-8765-4321 for verification."
    res = redactor.redact(text)

    assert "5432-8765-4321" not in res.redacted_text
    assert "XXXX-XXXX-4321" in res.redacted_text
    assert any("AADHAAR:4321" in e for e in res.detected_entities)


def test_redacts_indian_pan():
    redactor = PIIRedactor(mask_style="formatted")
    text = "Taxpayer registered under PAN ABCDE1234F."
    res = redactor.redact(text)

    assert "ABCDE1234F" not in res.redacted_text
    assert "ABXXXXXX4F" in res.redacted_text
    assert any("PAN:AB..4F" in e for e in res.detected_entities)


def test_redacts_indian_mobile():
    redactor = PIIRedactor(mask_style="formatted")
    text = "Contact support at +91 9876543210 immediately."
    res = redactor.redact(text)

    assert "9876543210" not in res.redacted_text
    assert "3210" in res.redacted_text


def test_redacts_credit_card_with_luhn_check():
    redactor = PIIRedactor(mask_style="formatted")
    # Valid Visa card test number with valid Luhn checksum
    valid_card = "4532-0150-1234-5671"
    text = f"Charged card {valid_card} for order."
    res = redactor.redact(text)

    assert valid_card not in res.redacted_text
    assert "XXXX-XXXX-XXXX-5671" in res.redacted_text


def test_redacts_email():
    redactor = PIIRedactor(mask_style="formatted")
    text = "User email is rahul.sharma@enterprise.in."
    res = redactor.redact(text)

    assert "rahul.sharma@enterprise.in" not in res.redacted_text
    assert "@enterprise.in" in res.redacted_text
