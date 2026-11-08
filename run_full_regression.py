import sys
import threading
import unicodedata
from enum import Enum
from detector import SecurityDetector
from normalizer import TextNormalizer

class Verdict(Enum):
    CLEAN = "CLEAN"
    BLOCKED = "BLOCKED"

def evaluate_egress(detector: SecurityDetector, text: str) -> Verdict:
    safe = detector.inspect_output(text)
    return Verdict.CLEAN if safe else Verdict.BLOCKED

def main():
    canary = "deadbeef12345678deadbeef12345678"
    det = SecurityDetector(canary_nonce=canary)

    print("=== 1. Combining Mark Saturation Test (U+0301 x 17) ===")
    sat_char = "\u0301" * 17
    sat_text = sat_char.join(list(canary))
    verdict = evaluate_egress(det, sat_text)
    print(f"  Saturation test result: {verdict.value}")
    assert verdict == Verdict.BLOCKED, "Failed on U+0301 x 17 saturation!"
    print("  [PASS] U+0301 x 17 saturation blocked successfully.\n")

    print("=== 2. Matrix 8 Variants x {1, 3, 6, 7} ZW Injections ===")
    zw_samples = [
        ("\u200B", "ZWSP"),
        ("\u200C", "ZWNJ"),
        ("\u200D", "ZWJ"),
        ("\uFEFF", "ZWNBSP"),
    ]
    import codecs, base64
    variants = [
        canary,
        canary.upper(),
        canary[::-1],
        codecs.encode(canary, 'rot13'),
        canary.encode('utf-8').hex(),
        base64.b64encode(canary.encode('utf-8')).decode('ascii'),
        " ".join(canary),
        ".".join(canary)
    ]

    total_matrix_tests = len(variants) * len(zw_samples)
    matrix_passed = 0
    for v in variants:
        for zw_ch, zw_name in zw_samples:
            injected = zw_ch.join(list(v))
            v_res = evaluate_egress(det, injected)
            if v_res == Verdict.BLOCKED:
                matrix_passed += 1
            else:
                print(f"  [FAIL] Variant leak on {zw_name}: {v[:10]}...")

    print(f"  Matrix Results: {matrix_passed}/{total_matrix_tests} Blocked")
    assert matrix_passed == total_matrix_tests, "Matrix test failed!"
    print("  [PASS] 8x4 Matrix completely blocked (32/32).\n")

    print("=== 3. Concurrency Thread Stress Test ===")
    errors = []
    def worker(worker_id):
        local_det = SecurityDetector(canary_nonce=f"canary_thread_{worker_id}_{canary[:16]}")
        c_verdict = evaluate_egress(local_det, f"Harmless thread text from worker {worker_id}")
        if c_verdict != Verdict.CLEAN:
            errors.append(f"Worker {worker_id} false positive")
        leak_verdict = evaluate_egress(local_det, f"thread_{worker_id}_{canary[:16]}")
        if leak_verdict != Verdict.BLOCKED:
            errors.append(f"Worker {worker_id} leak bypassed")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()

    print(f"  Thread errors: {len(errors)}")
    assert len(errors) == 0, f"Thread stress failed: {errors}"
    print("  [PASS] 20/20 Threads concurrent isolation validated.\n")

    print("=== 4. Polarity & False Positive Verification ===")
    fp_corpus = [
        "Normal technical documentation about cryptographic hash chains.",
        "System update completed with 0 errors reported.",
        "Python 3.12 unicode consortium specifications and derived properties.",
        "Flag test: \U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F is England."
    ]
    for sample in fp_corpus:
        v_fp = evaluate_egress(det, sample)
        assert v_fp == Verdict.CLEAN, f"False positive detected on: {sample}"
    print("  [PASS] Polarity unified (Verdict enum) with 0 False Positives.\n")

    print("ALL REGRESSION & HARDENING INVARIANTS SATISFIED (0 FAILURES)")

if __name__ == "__main__":
    main()
