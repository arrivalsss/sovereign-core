import secrets
from test_canary_h_table import generate_variants_table
from dual_view_stream import QuadViewStreamProtector, SecurityError

CANARY = "deadbeef12345678deadbeef12345678"
variants_dict, H = generate_variants_table(CANARY)

print("=== 1. Compatibility Forms Test (NFKD) ===")
# Circled numbers mapping for '1' and '2'
circled_sample = "deadbeef\u2460\u2461345678deadbeef12345678"
prot1 = QuadViewStreamProtector(CANARY, variants_dict)
blocked1 = False
try:
    for ch in ("A" * 52) + circled_sample:
        prot1.process_chunk(ch)
    prot1.flush()
except SecurityError:
    blocked1 = True

print(f"  Circled Numbers Variant: Blocked = {blocked1}")
assert blocked1 == True, "Failed to catch circled numbers compatibility leak!"

# Math Monospace mapping for 'dead' -> 𝚍𝚎𝚊𝚍
math_mono_sample = "\U0001D68D\U0001D68E\U0001D68A\U0001D68Dbeef12345678deadbeef12345678"
prot1_mono = QuadViewStreamProtector(CANARY, variants_dict)
blocked1_mono = False
try:
    for ch in ("A" * 52) + math_mono_sample:
        prot1_mono.process_chunk(ch)
    prot1_mono.flush()
except SecurityError:
    blocked1_mono = True

print(f"  Math Monospace Variant: Blocked = {blocked1_mono}")
assert blocked1_mono == True, "Failed to catch math monospace compatibility leak!"
print("  [PASS] Compatibility forms (NFKD) blocked.\n")

print("=== 2. Tags with Hyphen Separator Test (View D) ===")
# Canary encoded as tags with '-' separator between characters
tag_hyphen_sample = "-".join(chr(0xE0000 + ord(c)) for c in CANARY)
prot2 = QuadViewStreamProtector(CANARY, variants_dict)
blocked2 = False
reason2 = None
try:
    for ch in ("A" * 52) + tag_hyphen_sample:
        prot2.process_chunk(ch)
    prot2.flush()
except SecurityError as e:
    blocked2 = True
    reason2 = str(e)

print(f"  Tags with '-' Separator: Blocked = {blocked2} | Reason = {reason2}")
assert blocked2 == True, "Failed to catch tags with '-' separator!"
print("  [PASS] Decoded Flat View (View D) caught tags with punctuation.\n")

print("=== 3. Cyrillic Confusables Replacement Test ===")
# Replace Latin 'a', 'e', 'c', 'o' with Cyrillic equivalents: а (0x430), е (0x435), с (0x441), о (0x43E)
cyr_canary = CANARY.replace('a', '\u0430').replace('e', '\u0435').replace('c', '\u0441')
prot3 = QuadViewStreamProtector(CANARY, variants_dict)
blocked3 = False
try:
    for ch in ("A" * 52) + cyr_canary:
        prot3.process_chunk(ch)
    prot3.flush()
except SecurityError:
    blocked3 = True

print(f"  Cyrillic Confusables Injection: Blocked = {blocked3}")
assert blocked3 == True, "Failed to catch Cyrillic confusables replacement!"
print("  [PASS] Confusables mapping active and verified.\n")

print("=== 4. Immutability & Thread Concurrency Safe Dict ===")
prot4 = QuadViewStreamProtector(CANARY, variants_dict)
is_immutable = False
try:
    prot4.variants_dict["MUTATED"] = "leak"
except TypeError:
    is_immutable = True

print(f"  MappingProxyType Immutable: {is_immutable}")
assert is_immutable == True, "Variant dictionary is still mutable!"
print("  [PASS] Variants table immutable and thread-safe.\n")

print("=== ALL FOUR CRITICAL AUDIT FIXES VERIFIED SUCCESSFULLY (0 FAILURES) ===")
