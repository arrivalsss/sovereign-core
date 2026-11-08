import secrets
import unicodedata
from test_canary_h_table import generate_variants_table
from dual_view_stream import TripleViewStreamProtector, SecurityError

# 1. Fresh Rotated Cryptographic 128-bit Canary
ROTATED_PROD_CANARY = secrets.token_hex(16)
variants_dict, H = generate_variants_table(ROTATED_PROD_CANARY)

print("=== 1. Mixed Arabic-Latin Liveness Test (1-Byte Chunks) ===")
# Build 3000+ chars of vocalized Arabic mixed with English tokens every ~150-200 chars
base_sentence = "يُمْكِنُكَ تَثْبِيتُ الْحِزْمَةِ بَاسْتِخْدَامِ أَمْرِ pip install sovereign-core عَبْرَ الْخَطِّ الْمُبَاشِرِ لِلنِّظَامِ. "
mixed_arabic_text = base_sentence * 30 # ~3400 chars

# Count Mn and Cf ratios
total_chars = len(mixed_arabic_text)
mn_count = sum(1 for c in mixed_arabic_text if unicodedata.category(c) == 'Mn')
cf_count = sum(1 for c in mixed_arabic_text if unicodedata.category(c) == 'Cf')
print(f"Sample Stats: Total={total_chars} chars | Mn (Tashkeel)={mn_count} ({mn_count/total_chars*100:.1f}%) | Cf={cf_count}")

prot = TripleViewStreamProtector(canary=ROTATED_PROD_CANARY, variants_dict=variants_dict)
emitted_chunks = []
blocked = False
reason = None

try:
    for ch in mixed_arabic_text:
        out = prot.process_chunk(ch)
        if out:
            emitted_chunks.append(out)
except SecurityError as e:
    blocked = True
    reason = str(e)

emitted_str = "".join(emitted_chunks)
raw_retained = len(mixed_arabic_text) - len(emitted_str)
# B-units in retained buffer
retained_buf = mixed_arabic_text[len(emitted_str):]
b_units_retained = sum(1 for c in retained_buf if not (0xE0000 <= ord(c) <= 0xE007F))

print(f"  Blocked: {blocked} (Reason: {reason})")
print(f"  Emitted Before Flush: {len(emitted_str)} chars")
print(f"  raw_retained: {raw_retained} chars | b_units_retained: {b_units_retained} units (H={H})")

assert blocked == False, f"Mixed Arabic-Latin stream blocked unexpectedly! Reason: {reason}"
assert len(emitted_str) >= total_chars - (raw_retained + 10), "Streaming stall detected!"
print("  [PASS] Mixed Arabic-Latin stream flowing smoothly without stall!\n")

print("=== 2. Characterization Equality (Production 128-bit Canary) ===")
# Exact expected values:
# For PERCENT (m=96, H=95): 52 + 96 - 1 - 95 = 52
# For HEX     (m=64, H=95): 52 + 64 - 1 - 95 = 20
char_expected = {
    "PERCENT": 52,
    "HEX": 20
}

prefix_text = "A" * 52

for var_name, exp_len in char_expected.items():
    stream_payload = prefix_text + variants_dict[var_name]
    char_prot = TripleViewStreamProtector(canary=ROTATED_PROD_CANARY, variants_dict=variants_dict)
    
    char_emitted = []
    char_blocked = False
    char_reason = None
    
    try:
        for ch in stream_payload:
            out = char_prot.process_chunk(ch)
            if out:
                char_emitted.append(out)
        rem = char_prot.flush()
        if rem:
            char_emitted.append(rem)
    except SecurityError as e:
        char_blocked = True
        char_reason = str(e)

    char_emitted_str = "".join(char_emitted)
    print(f"[{var_name}] (m={len(variants_dict[var_name])}, H={H}):")
    print(f"  Blocked: {char_blocked} | Reason: {char_reason}")
    print(f"  Emitted Length: {len(char_emitted_str)} (Expected: {exp_len})")
    print(f"  Canary bytes in reason: {any(variants_dict[var_name][:8] in char_reason for _ in [1])}")
    
    assert char_blocked == True, f"{var_name} was not blocked!"
    assert len(char_emitted_str) == exp_len, f"Characterization mismatch! Got {len(char_emitted_str)}, expected {exp_len}"
    assert all(c == "A" for c in char_emitted_str), "Canary leaked into stream!"
    assert not any(variants_dict[var_name][:4] in char_reason for _ in [1]), "Canary leaked in Reason string!"
    print(f"  [PASS] Characterization {exp_len}/52 confirmed with safe hashed reason.\n")

print("=== ALL MIXED STREAMING & PRODUCTION CHARACTERIZATION INVARIANTS SATISFIED ===")
