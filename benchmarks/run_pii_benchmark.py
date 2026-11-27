"""High-throughput PII redaction benchmark."""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secguard.pii.redactor import PIIRedactor


def run_benchmark(records_count: int = 25000):
    print("=" * 80)
    print("⚡ SECGUARD: HIGH-THROUGHPUT PII REDACTION BENCHMARK")
    print("=" * 80)

    sample_texts = [
        "Customer Aadhaar 3456-7890-1234 linked with PAN ABCDE1234F and mobile +91-9876543210.",
        "Payment processed with credit card 4532-0150-1234-5678 and email user.john@corp.com.",
        "Internal record for tenant T-9921 without PII data fields.",
        "Diagnostic trace: contact support at helpdesk@company.in or call 8888877777 for assistance.",
    ]

    redactor = PIIRedactor(mask_style="formatted")

    print(f"Executing redaction over {records_count:,} sample payloads...")
    start_time = time.perf_counter()

    for i in range(records_count):
        idx = i % len(sample_texts)
        _ = redactor.redact(sample_texts[idx])

    elapsed = time.perf_counter() - start_time
    throughput = records_count / elapsed

    print(f"• Total Processed:    {records_count:,} payloads")
    print(f"• Total Elapsed:      {elapsed:.3f} seconds")
    print(f"• Redaction Speed:    {throughput:,.0f} payloads / second")
    print("=" * 80)


if __name__ == "__main__":
    run_benchmark(records_count=25000)
