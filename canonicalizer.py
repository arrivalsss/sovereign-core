import unicodedata
import re

class Canonicalizer:
    # إضافة \u1160 الناتج عن تحويل NFKC لـ \u3164 مع بقية الفراغات
    HIDDEN_CHARS_PATTERN = re.compile(
        r'[\u200B-\u200D\uFEFF\u2060\u202A-\u202E\u3164\u1160\u2800\uFFA0]'
    )
    
    ARABIC_TASHKEEL = re.compile(r'[\u064B-\u065F\u0670]')
    ARABIC_TATWEEL = re.compile(r'\u0640')
    ARABIC_ALEF = re.compile(r'[إأآا]')

    @classmethod
    def get_detection_view(cls, text: str) -> str:
        # 1. تطبيع التوافق الموحد NFKC
        normalized = unicodedata.normalize('NFKC', text)
        
        # 2. إزالة المحارف المخفية والفراغات الخادعة
        cleaned = cls.HIDDEN_CHARS_PATTERN.sub('', normalized)
        
        # 3. إزالة التشكيل والتطويل في النص العربي
        cleaned = cls.ARABIC_TASHKEEL.sub('', cleaned)
        cleaned = cls.ARABIC_TATWEEL.sub('', cleaned)
        
        # 4. توحيد الألف
        cleaned = cls.ARABIC_ALEF.sub('ا', cleaned)
        
        return cleaned.lower()

if __name__ == "__main__":
    test_cases = [
        ("تــــجــــاهـــــل", "تجاهل"),
        ("تَجَاهَلْ", "تجاهل"),
        ("إِجْرَاء", "اجراء"),
        ("te\u200Bst\u3164word", "testword"),
        ("ＳＥＣＲＥＴ", "secret")
    ]
    
    print("[TEST] Running Canonicalization & Edge-Case Tests...")
    all_passed = True
    for original, expected in test_cases:
        view = Canonicalizer.get_detection_view(original)
        if view == expected:
            print(f"[PASS] '{original}' -> '{view}'")
        else:
            print(f"[FAIL] '{original}' -> '{view}' (Expected: '{expected}')")
            all_passed = False
            
    if all_passed:
        print("[SUCCESS] All normalization and evasion vectors resolved correctly.")
