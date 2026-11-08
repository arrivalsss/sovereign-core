class MultiVariantStreamDetector:
    def __init__(self, raw_canary: str):
        self.raw_canary = raw_canary
        raw_bytes = raw_canary.encode('utf-8')
        
        # 1. توليد كافة الصيغ المشفرة بدقة رياضية
        self.variants = set()
        self.variants.add(raw_canary)
        self.variants.add(raw_canary.lower())
        self.variants.add(raw_canary.upper())
        self.variants.add(raw_bytes.hex())
        self.variants.add(raw_bytes.hex().upper())
        # Percent-encoding القسري لكافة البايتات
        self.variants.add("".join(f"%{b:02X}" for b in raw_bytes))
        self.variants.add("".join(f"%{b:02x}" for b in raw_bytes))
        
        # حساب أقصى طول لأي صيغة مشفرة وقيمة H
        self.max_variant_len = max(len(v) for v in self.variants)
        self.H = self.max_variant_len - 1
        self.holdback_buffer = ""
        self.blocked = False

    def process_chunk(self, chunk: str) -> str:
        if self.blocked:
            return ""
            
        combined = self.holdback_buffer + chunk
        
        for variant in self.variants:
            if variant in combined:
                self.blocked = True
                raise SecurityError(f"[EGRESS_LEAK_BLOCKED] Detected canary variant: {variant}")

        if len(combined) <= self.H:
            self.holdback_buffer = combined
            return ""

        safe_to_emit = combined[:-self.H]
        self.holdback_buffer = combined[-self.H:]
        return safe_to_emit

    def flush(self) -> str:
        if self.blocked:
            return ""
        for variant in self.variants:
            if variant in self.holdback_buffer:
                self.blocked = True
                raise SecurityError(f"[EGRESS_LEAK_BLOCKED] Detected canary at flush: {variant}")
        remaining = self.holdback_buffer
        self.holdback_buffer = ""
        return remaining

class SecurityError(Exception):
    pass

if __name__ == "__main__":
    canary = "KEY_SEC_99"
    detector = MultiVariantStreamDetector(canary)
    
    # 1. طباعة جدول الصيغ و H
    print("=== VARIANT TABLE ===")
    for v in sorted(detector.variants, key=lambda x: (len(x), x)):
        print(f"Variant: {v:<32} | Len: {len(v)}")
    print(f"Calculated Max Len: {detector.max_variant_len} | Holdback (H): {detector.H}\n")

    # 2. تشغيل فحص شامل (Property Test) عبر Chunks ومواضع مختلفة
    chunk_sizes = [1, 2, 3, 7]
    positions = ["start", "mid", "end"]
    prefix = "PREFIX_DATA_HEADER_"
    suffix = "_SUFFIX_DATA_FOOTER"
    
    total_tests = 0
    passed_tests = 0

    print("=== RUNNING PROPERTY TEST MATRIX ===")
    for variant in list(detector.variants):
        for pos in positions:
            for c_size in chunk_sizes:
                total_tests += 1
                det = MultiVariantStreamDetector(canary)
                
                if pos == "start":
                    full_stream = variant + suffix
                    expected_pre_token = ""
                elif pos == "mid":
                    full_stream = prefix + variant + suffix
                    expected_pre_token = prefix
                else:  # end
                    full_stream = prefix + variant
                    expected_pre_token = prefix

                emitted = []
                blocked = False
                
                # تقسيم التدفق إلى Chunks
                for i in range(0, len(full_stream), c_size):
                    chunk = full_stream[i:i+c_size]
                    try:
                        out = det.process_chunk(chunk)
                        if out:
                            emitted.append(out)
                    except SecurityError:
                        blocked = True
                        break
                        
                # اختبار post-block flush للتأكد من عدم تسريب شيء بعد الحظر
                try:
                    extra = det.flush()
                    if extra:
                        emitted.append(extra)
                except SecurityError:
                    pass

                emitted_str = "".join(emitted)
                
                # التحقق الصارم: يجب الحجب، ويجب ألا يتجاوز النص المصدر pre-token context
                assert blocked, f"Failed to block variant {variant} at pos {pos} with chunk {c_size}"
                assert variant not in emitted_str, f"Canary leaked in emitted text: '{emitted_str}'"
                assert expected_pre_token.startswith(emitted_str), f"Emitted text overflowed pre-token boundary!"
                passed_tests += 1

    print(f"[SUCCESS] All {passed_tests}/{total_tests} test cases in property matrix PASSED completely.")
