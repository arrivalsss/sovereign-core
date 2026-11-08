import urllib.parse

class MultiVariantStreamDetector:
    def __init__(self, raw_canary: str):
        self.raw_canary = raw_canary
        
        # 1. توليد كافة الصيغ المشفرة المتوقعة للكناري
        self.variants = set()
        self.variants.add(raw_canary)
        self.variants.add(raw_canary.lower())
        self.variants.add(raw_canary.upper())
        self.variants.add(raw_canary.encode().hex())
        self.variants.add(raw_canary.encode().hex().upper())
        self.variants.add(urllib.parse.quote(raw_canary))
        
        # احتساب أقصى طول لأي صيغة مشفرة
        self.max_variant_len = max(len(v) for v in self.variants)
        self.holdback_buffer = ""

    def process_chunk(self, chunk: str) -> str:
        combined = self.holdback_buffer + chunk
        
        # فحص وجود أي صيغة مشفرة داخل النص المتدفق
        for variant in self.variants:
            if variant in combined:
                raise SecurityError(f"[EGRESS_LEAK_BLOCKED] Detected canary variant: {variant}")

        # احتجاز الحجم الأقصى للصيغة المشفرة لضمان عدم تسريب أي بايت
        if len(combined) < self.max_variant_len:
            self.holdback_buffer = combined
            return ""

        safe_boundary = len(combined) - (self.max_variant_len - 1)
        safe_to_emit = combined[:safe_boundary]
        self.holdback_buffer = combined[safe_boundary:]
        return safe_to_emit

    def flush(self) -> str:
        for variant in self.variants:
            if variant in self.holdback_buffer:
                raise SecurityError(f"[EGRESS_LEAK_BLOCKED] Detected canary variant at stream end: {variant}")
        remaining = self.holdback_buffer
        self.holdback_buffer = ""
        return remaining

class SecurityError(Exception):
    pass

if __name__ == "__main__":
    canary = "KEY_SEC_99"
    detector = MultiVariantStreamDetector(canary)
    
    # تجربة صيغة Hex مقسمة على مستوى 1-byte
    hex_variant = canary.encode().hex()
    test_stream = f"Output data: {hex_variant} completed."
    
    emitted = []
    print(f"[TEST] Streaming Hex variant ({hex_variant}) in 1-byte chunks...")
    try:
        for char in test_stream:
            out = detector.process_chunk(char)
            if out:
                emitted.append(out)
        out = detector.flush()
        if out:
            emitted.append(out)
        print("[FAIL] Hex variant leaked!")
    except SecurityError as e:
        emitted_text = "".join(emitted)
        print(f"[SUCCESS] {e}")
        print(f"[AUDIT] Emitted text before block: '{emitted_text}'")
        assert hex_variant not in emitted_text
        print("[VERIFIED] Multi-variant 1-byte chunk split defense holds.")
