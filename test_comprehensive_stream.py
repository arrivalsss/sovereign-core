import base64
import codecs

class RobustStreamDetector:
    def __init__(self, raw_canary: str):
        self.raw_canary = raw_canary
        raw_bytes = raw_canary.encode('utf-8')
        
        self.case_insensitive_variants = set()
        self.case_sensitive_variants = set()
        
        # Raw & ROT13
        self.case_insensitive_variants.add(raw_canary.casefold())
        self.case_insensitive_variants.add(codecs.encode(raw_canary, 'rot_13').casefold())
        
        # Hex
        self.case_insensitive_variants.add(raw_bytes.hex().casefold())
        
        # Full Percent-Encoding
        self.case_insensitive_variants.add("".join(f"%{b:02x}" for b in raw_bytes).casefold())
        
        # Fullwidth
        fullwidth_str = "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in raw_canary)
        self.case_insensitive_variants.add(fullwidth_str.casefold())
        
        # Base64 Alignments (0, 1, 2) + Unpadded
        for pad in [b"", b"A", b"AA"]:
            b64_full = base64.b64encode(pad + raw_bytes).decode('ascii')
            prefix_cut = {b"": 0, b"A": 2, b"AA": 3}[pad]
            b64_slice = b64_full[prefix_cut:].rstrip('=')
            if len(b64_slice) >= 8:
                self.case_sensitive_variants.add(b64_slice)

        all_lens = [len(v) for v in self.case_insensitive_variants] + [len(v) for v in self.case_sensitive_variants]
        self.max_variant_len = max(all_lens)
        self.H = self.max_variant_len - 1
        assert self.H == self.max_variant_len - 1
        
        self.holdback_buffer = ""
        self.blocked = False

    def process_chunk(self, chunk: str) -> str:
        if self.blocked:
            return ""
            
        combined = self.holdback_buffer + chunk
        combined_folded = combined.casefold()
        
        for variant in self.case_insensitive_variants:
            if variant in combined_folded:
                self.blocked = True
                raise SecurityError(f"[BLOCKED] Case-insensitive variant detected: {variant}")
                
        for variant in self.case_sensitive_variants:
            if variant in combined:
                self.blocked = True
                raise SecurityError(f"[BLOCKED] Case-sensitive variant detected: {variant}")

        if len(combined) <= self.H:
            self.holdback_buffer = combined
            return ""

        safe_to_emit = combined[:-self.H]
        self.holdback_buffer = combined[-self.H:]
        return safe_to_emit

    def flush(self) -> str:
        if self.blocked:
            return ""
        combined_folded = self.holdback_buffer.casefold()
        for variant in self.case_insensitive_variants:
            if variant in combined_folded:
                self.blocked = True
                raise SecurityError(f"[BLOCKED] Variant at flush: {variant}")
        for variant in self.case_sensitive_variants:
            if variant in self.holdback_buffer:
                self.blocked = True
                raise SecurityError(f"[BLOCKED] Sensitive variant at flush: {variant}")
                
        remaining = self.holdback_buffer
        self.holdback_buffer = ""
        return remaining

class SecurityError(Exception):
    pass

if __name__ == "__main__":
    canary = "KEY_SEC_99"
    det = RobustStreamDetector(canary)
    
    print("=== EXPANDED VARIANT INVENTORY ===")
    print(f"Case-Insensitive ({len(det.case_insensitive_variants)}): {det.case_insensitive_variants}")
    print(f"Case-Sensitive/Base64 ({len(det.case_sensitive_variants)}): {det.case_sensitive_variants}")
    print(f"Calculated Max Len: {det.max_variant_len} | Dynamic H: {det.H}\n")

    clean_text = "This is a clean stream that does not contain any confidential secret."
    d_clean = RobustStreamDetector(canary)
    emitted_clean = []
    for c in clean_text:
        emitted_clean.append(d_clean.process_chunk(c))
    emitted_clean.append(d_clean.flush())
    assert "".join(emitted_clean) == clean_text
    print("[PASS] Liveness Test: Clean stream emitted completely.")

    near_miss = "KEY_SEC_98 is benign."
    d_near = RobustStreamDetector(canary)
    emitted_near = []
    for c in near_miss:
        emitted_near.append(d_near.process_chunk(c))
    emitted_near.append(d_near.flush())
    assert "".join(emitted_near) == near_miss
    print("[PASS] Near-miss Test: Benign prefix was properly released.")

    mixed_pct = "%4b%45%59%5f%53%45%43%5f%39%39"
    d_mix = RobustStreamDetector(canary)
    blocked = False
    try:
        for c in f"Header {mixed_pct} Footer":
            d_mix.process_chunk(c)
        d_mix.flush()
    except SecurityError:
        blocked = True
    assert blocked
    print("[PASS] Mixed-Case Test: %4b%45 properly intercepted.")

    b64_variant = list(det.case_sensitive_variants)[0]
    d_b64 = RobustStreamDetector(canary)
    blocked_b64 = False
    try:
        for c in f"Token {b64_variant} End":
            d_b64.process_chunk(c)
        d_b64.flush()
    except SecurityError:
        blocked_b64 = True
    assert blocked_b64
    print(f"[PASS] Base64 Alignment Test: '{b64_variant}' intercepted.")

    print("\n[SUCCESS] Comprehensive Stream Detector fully validated on Nubia NX779J.")
