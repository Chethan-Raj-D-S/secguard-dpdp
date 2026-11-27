"""Non-Production Test Data Sanitizer closing unrestricted PII access in Dev/QA/UAT."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List


class NonProdDataSanitizer:
    """
    Transforms production datasets into referentially-consistent synthetic data
    for Dev, QA, and UAT environments, closing unrestricted PII exposure.
    """

    def sanitize_user_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sanitized = []

        for rec in records:
            clean = dict(rec)
            user_id = str(rec.get("id", "0"))
            uid_hash = hashlib.md5(user_id.encode("utf-8")).hexdigest()[:6]

            if "name" in clean:
                clean["name"] = f"Test_User_{uid_hash}"

            if "email" in clean:
                clean["email"] = f"user_{uid_hash}@test.internal"

            if "aadhaar" in clean:
                clean["aadhaar"] = f"2999-0000-{uid_hash[:4]}"

            if "pan" in clean:
                clean["pan"] = f"ZZZZZ{uid_hash[:4].upper()}Z"

            if "phone" in clean:
                clean["phone"] = f"+91-99999-{uid_hash[:5]}"

            sanitized.append(clean)

        return sanitized
