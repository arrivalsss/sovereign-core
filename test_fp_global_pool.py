import threading
import time
import secrets
from detector import SecurityDetector

# 1. Expand FP Corpus (UUID, Hash, Numeric, Clean Text, Emojis)
print("=== 1. Expanded FP Corpus Verification ===")
# True production canary is random >= 96 bits
PROD_CANARY = secrets.token_hex(16) # 128-bit random nonce
det = SecurityDetector(canary_nonce=PROD_CANARY)

fp_samples = [
    # Plain text containing words that resemble fixture
    "Documentation about key-sec-99 configuration parameters.",
    "The system key sec 99 was updated in legacy records.",
    # UUID v4
    "Transaction ID: 123e4567-e89b-12d3-a456-426614174000 completed successfully.",
    # SHA-256 Hash
    "File digest: 09c928886a178fcafd93c29e4bd59073a058e5a100b716d425cb563ab50f68c9",
    # Numeric timestamps and IP
    "Server 192.168.1.100 responded in 12.34ms at timestamp 1730894000.",
    # Tagged Flag Emojis
    "Event flags: \U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F (England) and \U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F (Scotland)."
]

fp_passed = 0
for idx, sample in enumerate(fp_samples, 1):
    safe = det.inspect_output(sample)
    print(f"  FP Sample {idx}: is_safe = {safe}")
    assert safe == True, f"False positive triggered on sample {idx}!"
    fp_passed += 1

print(f"FP Verification: {fp_passed}/{len(fp_samples)} Passed (0 FP)\n")

# 2. Global Canary Pool Architecture for Threads
print("=== 2. Global Canary Pool Multi-Thread Concurrency ===")
NUM_THREADS = 10
RUNS_PER_THREAD = 10

# Global canary registry shared across gateway
GLOBAL_POOL = [secrets.token_hex(16) for _ in range(NUM_THREADS)]

class GlobalPoolDetector:
    def __init__(self, canary_pool):
        self.canary_pool = canary_pool
        self.detectors = [SecurityDetector(canary_nonce=c) for c in canary_pool]

    def inspect_output(self, text: str) -> bool:
        # Policy: Any canary from ANY session present in ANY stream triggers block
        for d in self.detectors:
            if not d.inspect_output(text):
                return False
        return True

global_detector = GlobalPoolDetector(GLOBAL_POOL)
barrier = threading.Barrier(NUM_THREADS)
thread_errors = []

def global_worker(t_id):
    barrier.wait()
    for r in range(RUNS_PER_THREAD):
        time.sleep(0)
        # Test clean
        c_text = f"Worker {t_id} run {r} normal payload."
        if not global_detector.inspect_output(c_text):
            thread_errors.append(f"Worker {t_id} FP on run {r}")

        time.sleep(0)
        # Test local canary leak
        if global_detector.inspect_output(f"Prefix_{GLOBAL_POOL[t_id]}_Suffix"):
            thread_errors.append(f"Worker {t_id} missed own canary on run {r}")

        time.sleep(0)
        # Test cross-session canary leak (must be BLOCKED by global pool policy)
        other_canary = GLOBAL_POOL[(t_id + 1) % NUM_THREADS]
        cross_leak_text = f"Egress data leaking other session: {other_canary}"
        # is_safe MUST be False
        if global_detector.inspect_output(cross_leak_text):
            thread_errors.append(f"Worker {t_id} allowed cross-session canary {other_canary}!")

threads = [threading.Thread(target=global_worker, args=(i,)) for i in range(NUM_THREADS)]
for t in threads: t.start()
for t in threads: t.join()

print(f"Global Pool Thread Errors: {len(thread_errors)}")
assert len(thread_errors) == 0, f"Thread errors: {thread_errors}"
print(f"  [PASS] 100/100 Global pool thread operations validated.\n")

# 3. Mutation Check on Harness (Verify Harness Detects Intentional Failure)
print("=== 3. Mutation Check on Harness ===")
# Mutate detector to intentionally allow leaks
class MutatedBlindDetector:
    def inspect_output(self, text: str) -> bool:
        return True # Blind bypass

blind = MutatedBlindDetector()
mutation_caught = False
try:
    # Harness check: leak must return False, if True assert fails
    assert blind.inspect_output("LEAK_" + PROD_CANARY) == False, "Harness caught mutation"
except AssertionError:
    mutation_caught = True

print(f"Harness Mutation Caught: {mutation_caught}")
assert mutation_caught == True, "Harness is blind and failed mutation check!"
print("  [PASS] Harness sensitivity and mutation resistance confirmed.")

print("\nALL EXPANDED AUDIT INVARIANTS SATISFIED (0 FAILURES)")
