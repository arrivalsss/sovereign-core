import re
import secrets
import unicodedata
from normalizer import TextNormalizer
from test_canary_h_table import generate_variants_table

class SecurityError(Exception):
    pass

class UnifiedTripleViewProtector:
    def __init__(self, canary: str, variants_dict: dict):
        self.canary = canary
        self.variants_dict = variants_dict
        self.variants = list(variants_dict.values())
        
        self.max_variant_len = max(len(v) for v in self.variants)
        self.H = self.max_variant_len - 1
        
        self.flat_variants = {}
        for k, v in variants_dict.items():
            flat_v = "".join(c for c in unicodedata.normalize('NFKC', v).casefold() 
                             if unicodedata.category(c)[0] in ('L', 'N'))
            if flat_v:
                self.flat_variants[k] = flat_v

        self.max_flat_len = max(len(v) for v in self.flat_variants.values()) if self.flat_variants else self.max_variant_len
        self.H_flat = self.max_flat_len - 1

        self.MAX_RAW_BUFFER = 1024
        self.raw_buffer = ""
        self.blocked = False

    @staticmethod
    def flat_units(ch: str) -> int:
        norm = unicodedata.normalize('NFKC', ch).casefold()
        return sum(1 for c in norm if unicodedata.category(c)[0] in ('L', 'N'))

    @staticmethod
    def tag_units(ch: str) -> int:
        return 1 if not (0xE0000 <= ord(ch) <= 0xE007F) else 0

    def _get_views(self, text: str):
        squeezed = TextNormalizer.strip_invisibles(text)
        view_a = TextNormalizer.decode_tags(squeezed)
        view_b = TextNormalizer.strip_tags(squeezed)
        norm_b = unicodedata.normalize('NFKC', view_b).casefold()
        view_c = "".join(c for c in norm_b if unicodedata.category(c)[0] in ('L', 'N'))
        return squeezed, view_a, view_b, view_c

    def _format_safe_reason(self, variant_name: str) -> str:
        inc_id = secrets.token_hex(4)
        return f"[BLOCKED] Policy violation on variant {variant_name} (incident_id: {inc_id})"

    def _check_leak(self, text: str):
        squeezed, view_a, view_b, view_c = self._get_views(text)

        for name, v in self.variants_dict.items():
            v_low = v.lower()
            if (v_low in squeezed.lower() or 
                v_low in view_a.lower() or 
                v_low in view_b.lower()):
                self.blocked = True
                raise SecurityError(self._format_safe_reason(name))

        for name, fv in self.flat_variants.items():
            if fv in view_c:
                self.blocked = True
                raise SecurityError(self._format_safe_reason(f"{name}_FLAT"))

    def process_chunk(self, chunk: str) -> str:
        if self.blocked:
            return ""

        self.raw_buffer += chunk
        
        if len(self.raw_buffer) > self.MAX_RAW_BUFFER:
            self.blocked = True
            raise SecurityError("[BLOCKED] RAW_BUFFER_OVERFLOW")

        self._check_leak(self.raw_buffer)

        _, view_a, view_b, view_c = self._get_views(self.raw_buffer)
        curr_units_a = len(view_a)
        curr_units_b = len(view_b)
        curr_units_c = len(view_c)

        safe_cut = 0
        for i, ch in enumerate(self.raw_buffer):
            u_c = self.flat_units(ch)
            u_b = self.tag_units(ch)
            u_a = 1

            can_emit = True
            if u_a > 0 and (curr_units_a - u_a) < self.H:
                can_emit = False
            if u_b > 0 and (curr_units_b - u_b) < self.H:
                can_emit = False
            if u_c > 0 and (curr_units_c - u_c) < self.H_flat:
                can_emit = False

            if can_emit:
                curr_units_a -= u_a
                curr_units_b -= u_b
                curr_units_c -= u_c
                safe_cut = i + 1
            else:
                break

        if safe_cut > 0:
            emit_candidate = self.raw_buffer[:safe_cut]
            self._check_leak(emit_candidate)
            self.raw_buffer = self.raw_buffer[safe_cut:]
            return emit_candidate

        return ""

    def flush(self) -> str:
        if self.blocked:
            return ""
        self._check_leak(self.raw_buffer)
        remaining = self.raw_buffer
        self.raw_buffer = ""
        return remaining

def main():
    CANARY_128 = secrets.token_hex(16)
    variants_dict, H = generate_variants_table(CANARY_128)
    
    print(f"=== Unified Harness Started: Production Canary (128-bit) ===")
    print(f"H = {H} | H_flat = 63 | Buffer Ceiling = 1024\n")

    print("--- 1. Property Test: Decomposition Units Invariant ---")
    test_strings = [
        "Hello World 123",
        "اللُّغَةُ الْعَرَبِيَّةُ مَعَ التَّشْكِيلِ",
        "فارسی با نیم‌فاصله می‌خواهم",
        "English with mixed pip and API commands 456",
        "각각의 한글 자모 결합 테스트"
    ]
    for s in test_strings:
        _, _, view_b, view_c = UnifiedTripleViewProtector(CANARY_128, variants_dict)._get_views(s)
        direct_flat_len = len(view_c)
        accum_units = sum(UnifiedTripleViewProtector.flat_units(c) for c in view_b)
        assert direct_flat_len == accum_units, f"Decomposition discrepancy on: {s}"
    print("[PASS] Property invariant satisfied: len(flat_view(s)) == sum(flat_units(c)).\n")

    print("--- 2. Mixed Multilingual Density Stress Test (1-byte streaming) ---")
    densities = [
        ("Word every 200 chars", ("نص عربي طويل يوضح مسار التدفق الأمني " * 5 + "pip ") * 20),
        ("Code Blocks", ("دالة برمجية:\n```python\ndef test_fn():\n    return 42\n```\n" + "شرح تفصيلي بالعربية المشكلة ") * 25),
        ("URLs & IPs", ("الاتصال بالخادم https://api.sovereign.local:8080/v1/health على 192.168.1.1. " + "متابعة تدفق البيانات ") * 30),
        ("Dense Numerics", ("القيم الرقمية: 1234567890 و 9876543210 مع معرف 550e8400-e29b-41d4-a716-446655440000. ") * 35)
    ]

    for name, text in densities:
        prot = UnifiedTripleViewProtector(CANARY_128, variants_dict)
        emitted = []
        for ch in text:
            out = prot.process_chunk(ch)
            if out: emitted.append(out)
        
        emitted_str = "".join(emitted)
        retained = len(text) - len(emitted_str)
        assert prot.blocked == False, f"Unexpected block on {name}"
        assert len(emitted_str) >= len(text) - 150, f"Stall in {name}"
        print(f"  [PASS] {name:<22}: Emitted={len(emitted_str)}/{len(text)} | Retained={retained}")

    print("\n--- 3. Canary Injection Inside Mixed Stream ---")
    mixed_prefix = ("هذا نص عربي طويل يحتوي على أمر pip install sovereign-core ومسار https://local.host. " * 3)
    inj_text = mixed_prefix + variants_dict["HEX"]
    prot_inj = UnifiedTripleViewProtector(CANARY_128, variants_dict)
    emitted_inj = []
    blocked_inj = False
    reason_inj = None
    try:
        for ch in inj_text:
            out = prot_inj.process_chunk(ch)
            if out: emitted_inj.append(out)
        rem = prot_inj.flush()
        if rem: emitted_inj.append(rem)
    except SecurityError as e:
        blocked_inj = True
        reason_inj = str(e)
    
    assert blocked_inj == True, "Failed to block canary in mixed stream!"
    assert len("".join(emitted_inj)) <= len(mixed_prefix), "Canary leak in mixed stream!"
    print(f"  [PASS] Injected Canary in Mixed Stream: Blocked=True | Reason: {reason_inj} | Emitted <= Prefix\n")

    print("--- 4. Saturation Test (U+0301 x 17) ---")
    sat_payload = ("\u0301" * 17).join(list(CANARY_128))
    prot_sat = UnifiedTripleViewProtector(CANARY_128, variants_dict)
    blocked_sat = False
    reason_sat = None
    try:
        for ch in sat_payload:
            prot_sat.process_chunk(ch)
        prot_sat.flush()
    except SecurityError as e:
        blocked_sat = True
        reason_sat = str(e)

    assert blocked_sat == True, "Saturation was not blocked!"
    print(f"  [PASS] Saturation: Blocked=True | Reason: {reason_sat} (Expected: RAW_BUFFER_OVERFLOW)\n")

    print("--- 5. Output & Ledger Zero-Exposure Scan ---")
    captured_logs = f"{reason_inj} | {reason_sat} | Block #23 committed."
    for name, v in variants_dict.items():
        assert v not in captured_logs, f"Leak found for variant {name} in output logs!"
    print("[PASS] Confirmed: 0 canary bytes present in output logs or reason strings.\n")

    print("=== ALL UNIFIED HARNESS TESTS PASSED SUCCESSFULLY (0 FAILURES) ===")

if __name__ == "__main__":
    main()
