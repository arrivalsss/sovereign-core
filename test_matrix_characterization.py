from test_canary_h_table import generate_variants_table, CANARY_PROD
from dual_view_stream import DualViewStreamProtector, SecurityError

variants, H = generate_variants_table(CANARY_PROD)
zw_counts = [1, 3, 6, 7]
zw_char = "\u200B"

print(f"\n=== 1. Matrix Execution: 12 Variants x 4 ZW Amounts (12x4 = 48 Tests) ===")
matrix_passed = 0
total_tests = len(variants) * len(zw_counts)

for name, val in variants.items():
    for count in zw_counts:
        injected = (zw_char * count).join(list(val))
        prot = DualViewStreamProtector(canary=CANARY_PROD, variants=[val])
        
        emitted_chunks = []
        blocked = False
        block_reason = None
        
        try:
            for i in range(0, len(injected), 2):
                c = injected[i:i+2]
                out = prot.process_chunk(c)
                if out:
                    emitted_chunks.append(out)
            rem = prot.flush()
            if rem:
                emitted_chunks.append(rem)
        except SecurityError as e:
            blocked = True
            block_reason = str(e)

        emitted_total = "".join(emitted_chunks)
        assert blocked == True, f"Failed to block {name} with ZW x {count}"
        assert len(emitted_total) == 0, f"Leaked {len(emitted_total)} chars in {name} ZW x {count}"
        matrix_passed += 1

print(f"Matrix Results: {matrix_passed}/{total_tests} Tests Passed (Blocked=True, Emitted=0)\n")

print("=== 2. Characterization Equality Test (Prefix=52, Chunk Size=1) ===")
prefix_len = 52
prefix_text = "A" * prefix_len

# Expected characterization emitted prefix:
# For PERCENT (m=30, H=29): 52 + 30 - 1 - 29 = 52
# For HEX (m=20, H=29): 52 + 20 - 1 - 29 = 42
expected_map = {
    "HEX": 42,
    "PERCENT": 52
}

for test_var_name in ["HEX", "PERCENT"]:
    target_var = variants[test_var_name]
    m = len(target_var)
    stream_input = prefix_text + target_var
    
    # Use the full variants list so H remains 29 across the protector
    prot = DualViewStreamProtector(canary=CANARY_PROD, variants=list(variants.values()))
    emitted = []
    blocked = False
    reason = None
    
    try:
        for ch in stream_input:
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
    expected_emitted = expected_map[test_var_name]
    
    print(f"[{test_var_name}] (m={m}, H={H}):")
    print(f"  Blocked: {blocked} | Reason: {reason}")
    print(f"  Emitted Length: {len(emitted_str)} | Expected: {expected_emitted}")
    print(f"  All benign 'A's: {all(c == 'A' for c in emitted_str)}")
    
    assert blocked == True, f"{test_var_name} was not blocked!"
    assert all(c == "A" for c in emitted_str), f"Canary leaked into emitted stream!"
    assert len(emitted_str) == expected_emitted, f"Mismatch: Got {len(emitted_str)}, expected {expected_emitted}"
    print(f"  [PASS] Characterization equality confirmed ({expected_emitted}/52) for {test_var_name}.\n")

print("=== ALL MATRIX & CHARACTERIZATION EQUALITY TESTS PASSED (42/52 CONFIRMED) ===")
