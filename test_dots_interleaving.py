from test_canary_h_table import generate_variants_table, CANARY_PROD
from dual_view_stream import TripleViewStreamProtector, SecurityError

variants, H = generate_variants_table(CANARY_PROD)
dot_counts = [1, 4, 20]
prefix = "A" * 52

print(f"\n=== Interleaved Dot Tests (. x {dot_counts}) with Prefix=52 ===")
print(f"{'Variant':<10} | {'Dots':<5} | {'Blocked':<8} | {'Emitted Len':<12} | {'Reason':<40}")
print("-" * 80)

passed = 0
total = len(variants) * len(dot_counts)

for v_name, v_val in variants.items():
    for dots in dot_counts:
        sep = "." * dots
        injected = prefix + sep.join(list(v_val))
        
        prot = TripleViewStreamProtector(canary=CANARY_PROD, variants=list(variants.values()))
        emitted_chunks = []
        blocked = False
        reason = None
        
        try:
            # Stream in 1-byte chunks
            for ch in injected:
                out = prot.process_chunk(ch)
                if out:
                    emitted_chunks.append(out)
            rem = prot.flush()
            if rem:
                emitted_chunks.append(rem)
        except SecurityError as e:
            blocked = True
            reason = str(e)
            
        emitted_str = "".join(emitted_chunks)
        # Invariant checks:
        # 1. Must be blocked
        # 2. Emitted must contain only benign prefix 'A's (zero canary leakage)
        is_safe_emit = all(c == "A" for c in emitted_str)
        assert blocked == True, f"Failed to block {v_name} with . x {dots}"
        assert is_safe_emit == True, f"Canary leaked into stream on {v_name} . x {dots}!"
        
        passed += 1
        short_reason = reason[:38] + ".." if len(reason) > 40 else reason
        print(f"{v_name:<10} | {dots:<5} | {str(blocked):<8} | {len(emitted_str):<12} | {short_reason:<40}")

print("-" * 80)
print(f"Results: {passed}/{total} Tests Passed (Blocked=True, 0 Canary Leaked)")
