import secrets
import unicodedata
from test_canary_h_table import generate_variants_table
from dual_view_stream import TripleViewStreamProtector, SecurityError

CANARY = secrets.token_hex(16)
variants_dict, H = generate_variants_table(CANARY)

print("=== 1. Combo Exploit Test: Dot + U+3164 (Hex Variant, Prefix=52) ===")
hex_val = variants_dict["HEX"]
combo_sep = ".\u3164"
injected_payload = ("A" * 52) + combo_sep.join(list(hex_val))

prot = TripleViewStreamProtector(CANARY, variants_dict)
emitted = []
blocked = False
reason = None

try:
    for ch in injected_payload:
        out = prot.process_chunk(ch)
        if out:
            emitted.append(out)
    rem = prot.flush()
    if rem:
        emitted.append(rem)
except SecurityError as e:
    blocked = True
    reason = str(e)

emitted_str = "".join(emitted)
print(f"Blocked: {blocked} | Reason: {reason}")
print(f"Emitted text length: {len(emitted_str)}")
print(f"All benign 'A's: {all(c == 'A' for c in emitted_str)}")

assert blocked == True, "Failed to block Dot + U+3164 combo attack!"
assert all(c == "A" for c in emitted_str), f"Canary leaked in combo attack: {emitted_str}"
print("  [PASS] Dot + U+3164 combo attack completely blocked with 0 canary leak!\n")

print("=== 2. Raw Buffer Overflow on Percent + U+0301 x 17 ===")
pct_val = variants_dict["PERCENT"]
overflow_payload = ("\u0301" * 17).join(list(pct_val))
print(f"Overflow payload length: {len(overflow_payload)} (Ceiling: 1024)")

prot_of = TripleViewStreamProtector(CANARY, variants_dict)
blocked_of = False
reason_of = None

try:
    for ch in overflow_payload:
        prot_of.process_chunk(ch)
    prot_of.flush()
except SecurityError as e:
    blocked_of = True
    reason_of = str(e)

print(f"Blocked: {blocked_of} | Reason: {reason_of}")
assert blocked_of == True, "Overflow attack was not blocked!"
assert "RAW_BUFFER_OVERFLOW" in reason_of, f"Expected RAW_BUFFER_OVERFLOW, got: {reason_of}"
print("  [PASS] Buffer overflow verified: RAW_BUFFER_OVERFLOW triggered correctly.\n")

print("=== 3. Decomposition Property Test on Entire s (with Jamo L+V+T) ===")
decomposed_hangul = "\u1100\u1161\u11A8"
test_strings = [
    "Hello World 123",
    "اللُّغَةُ الْعَرَبِيَّةُ",
    "فارسی با نیم‌فاصله",
    f"Hangul Decomposed: {decomposed_hangul}",
    "Fillers test \u115F\u1160\u3164\uFFA0 with dots ."
]

for s in test_strings:
    _, _, view_b, view_c = TripleViewStreamProtector(CANARY, variants_dict)._get_views(s)
    direct_flat_len = len(view_c)
    accum_units = sum(TripleViewStreamProtector.flat_units(c) for c in s)
    print(f"  String '{s[:25]}...': direct_flat_len={direct_flat_len} | accum_units={accum_units}")
    assert direct_flat_len == accum_units, f"Decomposition mismatch on: {s}"

print("  [PASS] Decomposition property validated on full s.\n")

print("=== ALL CRITICAL VULNERABILITY AUDITS PASSED (0 FAILURES) ===")
