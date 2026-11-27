"""Tests for Reversible Pseudonymization Vault."""
from secguard.pii.vault import PseudonymizationVault


def test_reversible_tokenization_and_detokenization():
    vault = PseudonymizationVault(vault_secret="test-secret-key-12345")
    raw_prompt = "User KYC verified with PAN ABCDE1234F and email client@domain.com."

    # 1. Tokenize for external LLM dispatch
    tokenized_text, count = vault.tokenize_text(raw_prompt)

    assert count >= 2
    assert "ABCDE1234F" not in tokenized_text
    assert "client@domain.com" not in tokenized_text
    assert "[TOKEN:PAN:" in tokenized_text
    assert "[TOKEN:EMAIL:" in tokenized_text

    # 2. Simulate LLM response referencing token
    llm_simulated_response = f"Approved loan application for customer with email [TOKEN:EMAIL:{tokenized_text.split('[TOKEN:EMAIL:')[1].split(']')[0]}]."

    # 3. Detokenize inside authorized internal service
    detokenized = vault.detokenize_text(llm_simulated_response)
    assert "client@domain.com" in detokenized
    assert "[TOKEN:" not in detokenized


def test_vault_purge_for_right_to_erasure():
    vault = PseudonymizationVault()
    text = "User Aadhaar is 5432-8765-4321."
    tokenized, _ = vault.tokenize_text(text)

    # Purge vault
    vault.purge_vault()

    # Detokenization can no longer restore purged tokens
    detokenized = vault.detokenize_text(tokenized)
    assert "5432-8765-4321" not in detokenized
