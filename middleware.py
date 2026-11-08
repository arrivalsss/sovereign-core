import html
import urllib.parse
from normalizer import TextNormalizer
from detector import SecurityDetector

class SovereignMiddleware:
    def __init__(self):
        self.detector = SecurityDetector()
        self.normalizer = TextNormalizer()

    def process_incoming(self, raw_user_prompt: str) -> dict:
        # 1. فحص النص الخام قبل التطهير لحسم حالات الإخفاء وقنابل العمق
        raw_inspection = self.detector.inspect_raw(raw_user_prompt)
        if not raw_inspection["is_safe"]:
            return {
                "status": "BLOCKED",
                "reason": "Security invariants violated in raw payload",
                "details": raw_inspection["threats"],
                "sanitized_payload": None
            }

        # 2. فحص استعلامات الروابط والمدخل المطهر
        check_targets = [raw_user_prompt]
        if '%' in raw_user_prompt:
            try:
                check_targets.append(urllib.parse.unquote(raw_user_prompt))
            except Exception:
                pass

        for target in check_targets:
            clean_text = self.normalizer.deep_normalize(target)
            inspection = self.detector.inspect_input(clean_text)
            if not inspection["is_safe"]:
                return {
                    "status": "BLOCKED",
                    "reason": "Security invariants violated",
                    "details": inspection["threats"],
                    "sanitized_payload": None
                }

        # تغليف المدخل الأصلي المُنظف مع تأمين محارف XML
        base_clean = self.normalizer.deep_normalize(raw_user_prompt)
        safe_body = html.escape(base_clean, quote=True)

        canary = self.detector.canary_nonce
        encapsulated_prompt = (
            f"<!-- SYSTEM GATE ACTIVE. CANARY REF: {canary[:4]}**** -->\n"
            f"<user_query_isolated>\n{safe_body}\n</user_query_isolated>"
        )

        return {
            "status": "APPROVED",
            "sanitized_payload": encapsulated_prompt,
            "canary": canary
        }

    def process_outgoing(self, raw_llm_response: str) -> dict:
        is_safe = self.detector.inspect_output(raw_llm_response)

        if not is_safe:
            return {
                "status": "LEAK_INTERCEPTED",
                "delivered_text": "[ERROR: Output suppressed due to security boundary breach]"
            }

        return {
            "status": "CLEAN",
            "delivered_text": raw_llm_response
        }
