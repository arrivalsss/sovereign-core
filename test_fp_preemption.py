import threading
import time
from test_canary_h_table import CANARY_PROD
from detector import SecurityDetector
from dual_view_stream import DualViewStreamProtector, SecurityError

det = SecurityDetector(canary_nonce=CANARY_PROD)

print("=== 1. Original False Positive Corpus Audit ===")
fp_corpus = [
    "بِسْمِ اللَّهِ الرَّحْمَٰنِ الرَّحِيمِ - الْحَمْدُ لِلَّهِ رَبِّ الْعَالَمِينَ - الرَّحْمَٰنِ الرَّحِيمِ",
    "اللغة العربية غنية بالحركات والتشكيل والإعراب الدقيق دون أي تسريب أمني.",
    "می‌خواهم کتاب‌های جدید را بخوانم و برنامه‌نویسی پایتون را بیاموزم.",
    "Family sequence test: 👨‍👩‍👧 👨‍👩‍👧‍👦 👩‍👩‍👦 - 👨‍👩‍👧 👨‍👩‍👧‍👦 👩‍👩‍👦 - 👨‍👩‍👧 👨‍👩‍👧‍👦 👩‍👩‍👦",
    "The SHA-256 hash ledger recorded block #19 with 0 failures across 35 benchmark suites."
]

fp_passed = 0
for idx, sample in enumerate(fp_corpus, 1):
    is_safe = det.inspect_output(sample)
    print(f"  Sample {idx}: inspect_output is_safe = {is_safe}")
    assert is_safe == True, f"False positive on sample {idx}: {sample}"
    fp_passed += 1

print(f"FP Corpus Results: {fp_passed}/{len(fp_corpus)} Passed (0 FP)\n")

print("=== 2. Caps Behavior Tests ===")
caps_tests = [
    ("ZWSP x 8 gap", "\u200B" * 8),
    ("Alternating ZWSP/ZWNJ", "\u200B\u200C" * 4),
    ("17 chars per gap", "\u200B" * 17)
]
for desc, sep in caps_tests:
    injected = sep.join(list(CANARY_PROD))
    is_safe = det.inspect_output(injected)
    print(f"  [{desc}]: is_safe = {is_safe} (Blocked: {not is_safe})")
    assert is_safe == False, f"Caps bypass on {desc}!"
print("  [PASS] All caps interleaving variations blocked.\n")

print("=== 3. Preemptive Multi-Thread Stress Test with Cross-Injection (200 Runs) ===")
NUM_THREADS = 20
RUNS_PER_THREAD = 10
TOTAL_RUNS = NUM_THREADS * RUNS_PER_THREAD

barrier = threading.Barrier(NUM_THREADS)
thread_errors = []

def preemption_worker(thread_id):
    local_canary = f"CAN_{thread_id:02d}_{CANARY_PROD[:5]}"
    local_det = SecurityDetector(canary_nonce=local_canary)
    
    barrier.wait()
    
    for r in range(RUNS_PER_THREAD):
        time.sleep(0)
        clean_text = f"Harmless thread text from worker {thread_id} run {r}"
        if not local_det.inspect_output(clean_text):
            thread_errors.append(f"Worker {thread_id} FP on run {r}")
            
        time.sleep(0)
        leak_text = f"Prefix_{local_canary}_Suffix"
        if local_det.inspect_output(leak_text):
            thread_errors.append(f"Worker {thread_id} missed local leak on run {r}")
            
        other_canary = f"CAN_{(thread_id + 1) % NUM_THREADS:02d}_{CANARY_PROD[:5]}"
        if not local_det.inspect_output(f"Checking other thread canary {other_canary}"):
            thread_errors.append(f"Worker {thread_id} cross-contaminated by worker {other_canary}")

threads = [threading.Thread(target=preemption_worker, args=(i,)) for i in range(NUM_THREADS)]
for t in threads: t.start()
for t in threads: t.join()

print(f"Preemption Thread Errors: {len(thread_errors)}")
assert len(thread_errors) == 0, f"Thread errors found: {thread_errors}"
print(f"  [PASS] {TOTAL_RUNS}/{TOTAL_RUNS} Preemptive thread executions verified (200/200 clean).\n")

print("=== ALL FP, CAPS & PREEMPTION INVARIANTS VALIDATED SUCCESSFULLY ===")
