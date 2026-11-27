"""Reversible Cryptographic Pseudonymization Vault for safe LLM agent execution."""
from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Tuple
from secguard.models import PIIType
from secguard.pii.patterns import PII_REGEX_PATTERNS


class PseudonymizationVault:
    """
    Enables zero-leakage LLM processing by replacing PII with encrypted tokens
    and rehydrating responses back in authorized internal contexts.
    """

    def __init__(self, vault_secret: str = "secguard-default-vault-key-2026"):
        self.vault_secret = vault_secret.encode("utf-8")
        # token -> original_value
        self._vault_store: Dict[str, str] = {}
        # original_value -> token
        self._reverse_store: Dict[str, str] = {}

    def _generate_token(self, pii_type: PIIType, raw_value: str) -> str:
        sig = hmac.new(self.vault_secret, raw_value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        return f"[TOKEN:{pii_type.value}:{sig}]"

    def tokenize_text(self, text: str) -> Tuple[str, int]:
        tokenized = text
        count = 0

        for pii_type, pattern in PII_REGEX_PATTERNS.items():
            for m in pattern.finditer(text):
                val = m.group(0)
                if val not in self._reverse_store:
                    token = self._generate_token(pii_type, val)
                    self._vault_store[token] = val
                    self._reverse_store[val] = token
                else:
                    token = self._reverse_store[val]

                tokenized = tokenized.replace(val, token)
                count += 1

        return tokenized, count

    def detokenize_text(self, tokenized_text: str) -> str:
        detokenized = tokenized_text
        for token, original in self._vault_store.items():
            detokenized = detokenized.replace(token, original)
        return detokenized

    def purge_vault(self) -> None:
        """Purges stored tokens supporting statutory Right-to-Erasure."""
        self._vault_store.clear(
        )
        self._reverse_store.clear()
