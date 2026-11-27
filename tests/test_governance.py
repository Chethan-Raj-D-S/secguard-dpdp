"""Tests for Non-Prod Data Sanitizer and DPDP Consent Manager."""
from secguard.governance.consent_log import ConsentManager
from secguard.governance.sanitizer import NonProdDataSanitizer


def test_non_prod_data_sanitizer():
    sanitizer = NonProdDataSanitizer()
    prod_data = [
        {
            "id": 101,
            "name": "Arun Kumar",
            "email": "arun.kumar@gmail.com",
            "aadhaar": "9876-5432-1098",
            "pan": "ABCDE5678G",
            "phone": "+91-9876543210",
        }
    ]

    sanitized = sanitizer.sanitize_user_records(prod_data)
    assert len(sanitized) == 1
    clean = sanitized[0]

    assert clean["name"] != "Arun Kumar"
    assert "Test_User_" in clean["name"]
    assert clean["email"] != "arun.kumar@gmail.com"
    assert clean["aadhaar"] != "9876-5432-1098"
    assert clean["pan"] != "ABCDE5678G"


def test_consent_manager_and_right_to_erasure():
    mgr = ConsentManager()
    user_id = "user_cust_889"

    # Grant consent
    consent = mgr.grant_consent(user_id=user_id, purpose="MARKETING_ANALYTICS")
    assert consent.is_active is True
    assert mgr.check_consent(user_id) is True

    # Execute Right to Erasure
    receipt = mgr.execute_right_to_erasure(user_id=user_id)
    assert receipt.status == "ERASED"
    assert receipt.user_id == user_id
    assert mgr.check_consent(user_id) is False
