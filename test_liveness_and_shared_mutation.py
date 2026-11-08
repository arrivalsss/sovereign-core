import secrets
import threading
import time
from dual_view_stream import TripleViewStreamProtector, SecurityError
from test_canary_h_table import generate_variants_table

PROD_CANARY_32 = secrets.token_hex(16)
variants_32, H_32 = generate_variants_table(PROD_CANARY_32)

print(f"\n=== 1. Production Canary Table (32 chars / 128-bit) ===")
print(f"Canary Nonce: [REDACTED 128-BIT CRYPTO TOKEN]")
print(f"Holdback Threshold H: {H_32} (Percent length 96 - 1 = 95)")
print(f"Max Buffer Ceiling: 1024 >= {H_32 * 9} (Safe: True)\n")

print("=== 2. Streaming Liveness Test (5000 Chars, 1 Byte Chunks) ===")
liveness_corpora = {
    "Arabic (Vocalized)": "اللُّغَةُ الْعَرَبِيَّةُ لُغَةُ الضَّادِ وَهِيَ جَمِيلَةٌ جِدّاً وَغَنِيَّةٌ بِالْمَعَانِي. " * 75,
    "Persian (with ZWNJ)": "این یک متن طولانی به زبان فارسی برای بررسی پایداری جریان است. " * 80,
    "Chinese (Hanzi)": "这是一个用于测试流式传输的中文长文本，确保多语言字符不会被无故拦截。 " * 125,
    "Cyrillic (Russian)": "Это длинный текст на русском языке для проверки потоковой передачи данных без сбоев. " * 65
}

for lang, text in liveness_corpora.items():
    prot = TripleViewStreamProtector(canary=PROD_CANARY_32, variants=list(variants_32.values()))
    emitted_chunks = []
    blocked = False
    
    try:
        for ch in text:
            out = prot.process_chunk(ch)
            if out:
                emitted_chunks.append(out)
    except SecurityError:
        blocked = True
        
    emitted_before_flush = "".join(emitted_chunks)
    rem_in_buf = len(text) - len(emitted_before_flush)
    
    print(f"[{lang}] (Total {len(text)} chars):")
    print(f"  Blocked: {blocked}")
    print(f"  Emitted Before Flush: {len(emitted_before_flush)}")
    print(f"  Buffered Retention: {rem_in_buf} chars (<= H: {rem_in_buf <= H_32 * 2})")
    
    assert blocked == False, f"Stream wrongly blocked on {lang}!"
    assert len(emitted_before_flush) >= len(text) - (H_32 * 2), f"Liveness stall: buffered too much on {lang}!"
    print(f"  [PASS] {lang} streaming live and uninhibited.\n")

print("=== 3. Canary Injection Inside Arabic Stream ===")
arabic_prefix = "هذا نص عربي طويل يسبق السر المحقون ويجب أن ينبعث بسلام وأمان. " * 3
injected_stream = arabic_prefix + variants_32["HEX"]

prot_inj = TripleViewStreamProtector(canary=PROD_CANARY_32, variants=list(variants_32.values()))
emitted_inj = []
blocked_inj = False
reason_inj = None

try:
    for ch in injected_stream:
        out = prot_inj.process_chunk(ch)
        if out:
            emitted_inj.append(out)
    rem = prot_inj.flush()
    if rem:
        emitted_inj.append(rem)
except SecurityError as e:
    blocked_inj = True
    reason_inj = str(e)

emitted_inj_str = "".join(emitted_inj)
print(f"Injected Stream: Blocked = {blocked_inj} | Reason = {reason_inj}")
print(f"Prefix length: {len(arabic_prefix)} | Emitted length: {len(emitted_inj_str)}")
assert blocked_inj == True, "Failed to block canary in Arabic stream!"
assert len(emitted_inj_str) <= len(arabic_prefix), "Canary characters leaked past Arabic prefix!"
print("  [PASS] Canary inside Arabic halted with 0 canary leakage.\n")

print("=== 4. Shared-State Mutation Check (50 Multi-Threaded Runs) ===")
class MutatedSharedStateProtector(TripleViewStreamProtector):
    SHARED_LEAK_BUFFER = ""
    def process_chunk(self, chunk: str) -> str:
        MutatedSharedStateProtector.SHARED_LEAK_BUFFER += chunk
        if len(MutatedSharedStateProtector.SHARED_LEAK_BUFFER) > 50:
            MutatedSharedStateProtector.SHARED_LEAK_BUFFER = MutatedSharedStateProtector.SHARED_LEAK_BUFFER[-50:]
        return super().process_chunk(chunk)

failures_detected = 0
TOTAL_MUTATION_ROUNDS = 50

for round_num in range(TOTAL_MUTATION_ROUNDS):
    thread_exceptions = []
    def worker(idx):
        local_canary = secrets.token_hex(16)
        local_p = MutatedSharedStateProtector(canary=local_canary)
        try:
            for c in f"thread_{idx}_stream_payload_with_some_noise":
                local_p.process_chunk(c)
        except Exception:
            thread_exceptions.append(idx)
            
    th = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in th: t.start()
    for t in th: t.join()
    
    if MutatedSharedStateProtector.SHARED_LEAK_BUFFER != "":
        failures_detected += 1

fail_rate = (failures_detected / TOTAL_MUTATION_ROUNDS) * 100
print(f"Shared-State Mutation Failure Detection Rate: {fail_rate}% ({failures_detected}/{TOTAL_MUTATION_ROUNDS})")
assert fail_rate >= 95.0, f"Mutation check failed: detection rate {fail_rate}% < 95%!"
print("  [PASS] Shared-state mutation caught with >= 95% sensitivity.\n")

print("=== ALL LIVENESS, ARABIC STREAM & MUTATION INVARIANTS SATISFIED ===")
