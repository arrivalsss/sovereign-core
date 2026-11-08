#!/usr/bin/env python3
"""
Sovereign Core - Egress Guard & Leak Prevention Engine (KERNEL 4.2)
Zero-dependency, standalone token and pattern sanitization pipeline.
"""
import re
import sys

PATTERNS = {
    "OPENAI_KEY": r"(?i)sk-[a-zA-Z0-9_\-]{20,}",
    "GENERIC_SECRET": r"(?i)(?:bearer\s+[a-zA-Z0-9_\-\.]{16,}|(?:token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{16,}['\"]?)",
    "CANARY_LEAK": r"(?i)canary_[a-f0-9]{16,64}",
    "BASE64_KEY_FRAGMENT": r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "INTERNAL_TOKEN": r"SOV-[A-Z0-9]{8,16}-[A-Z0-9]{8,16}",
    "ENV_ASSIGN": r"(?i)(?:export\s+)?[A-Z0-9_]*(?:KEY|SECRET|TOKEN)\s*=\s*['\"][^'\"]+['\"]",
}

COMPILED_PATTERNS = {k: re.compile(v) for k, v in PATTERNS.items()}

def scan_text(text: str) -> dict:
    findings = {}
    for name, pattern in COMPILED_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings[name] = len(matches)
    return findings

def redact(text: str) -> str:
    redacted = text
    for pattern in COMPILED_PATTERNS.values():
        redacted = pattern.sub("[REDACTED_BY_SOVEREIGN_GUARD]", redacted)
    return redacted

def run_tests() -> bool:
    test_cases = [
        ("REDACTED_OPENAI_TEST_KEY", "OPENAI_KEY"),
        ("Authorization: Bearer test_token_string_with_sufficient_length_12345", "GENERIC_SECRET"),
        ("api_key='abcdef0123456789abcdef0123456789'", "GENERIC_SECRET"),
        ("Leak: canary_a1b2c3d4e5f60718293a4b5c6d7e8f90", "CANARY_LEAK"),
        ("Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", "BASE64_KEY_FRAGMENT"),
        ("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----", "PRIVATE_KEY"),
        ("X-Sovereign-Token: SOV-ABCD1234-EFGH5678", "INTERNAL_TOKEN"),
        ("export ANTHROPIC_API_KEY='sk-ant-api03-samplekeysamplekey12345'", "ENV_ASSIGN"),
        ("Clean prompt text without secrets, valid query.", None)
    ]
    
    passed = 0
    total = len(test_cases)
    for idx, (sample, expected_key) in enumerate(test_cases, 1):
        results = scan_text(sample)
        if expected_key is None:
            if len(results) == 0 and redact(sample) == sample:
                passed += 1
            else:
                print(f"[FAIL] Test {idx}: Expected clean, got findings: {results}")
        else:
            if expected_key in results:
                redacted_output = redact(sample)
                if "[REDACTED_BY_SOVEREIGN_GUARD]" in redacted_output:
                    passed += 1
                else:
                    print(f"[FAIL] Test {idx}: Redaction failed for {expected_key}")
            else:
                print(f"[FAIL] Test {idx}: Expected {expected_key}, got {results}")

    print(f"Egress Guard Verification: {passed}/{total} Passed")
    return passed == total

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        success = run_tests()
        sys.exit(0 if success else 1)
    
    input_data = sys.stdin.read()
    if input_data:
        sys.stdout.write(redact(input_data))
