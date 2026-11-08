import re
import secrets
import codecs
import base64
import unicodedata
from typing import Optional, Set
from normalizer import TextNormalizer

class SecurityDetector:
    INJECTION_PATTERNS = [
        re.compile(r"ignore\s+([a-z\s]+)?(instructions|rules|directives)", re.IGNORECASE),
        re.compile(r"system\s+(override|prompt)", re.IGNORECASE),
        re.compile(r"disregard\s+(prior|everything|above)", re.IGNORECASE),
        re.compile(r"forget\s+(everything|prior|told)", re.IGNORECASE),
        re.compile(r"developer\s+mode", re.IGNORECASE),
        re.compile(r"DAN\s+mode", re.IGNORECASE),
        re.compile(r"reveal\s+(canary|secret|nonce|key|the\s+system)", re.IGNORECASE),
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"<\|im_end\|>", re.IGNORECASE),
        re.compile(r"تجاهل\s+(جميع|كل)\s+التعليمات", re.IGNORECASE),
        re.compile(r"игнорируй", re.IGNORECASE),
        re.compile(r"ignora\s+todas", re.IGNORECASE),
        re.compile(r"ignoriere\s+alle", re.IGNORECASE),
        re.compile(r"忽略之前", re.IGNORECASE),
        re.compile(r"talimatları\s+yoksay", re.IGNORECASE),
    ]

    CYR_MAP = str.maketrans({
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
        '\u0456': 'i', '\u0445': 'x', '\u0443': 'y', '\u0455': 's', '\u0458': 'j',
        '\u03bf': 'o', '\u03b9': 'i', '\u03bd': 'v'
    })

    LEET_MAP = str.maketrans("103457", "ioeast")

    def __init__(self, canary_nonce: Optional[str] = None):
        self.canary_nonce = canary_nonce or secrets.token_hex(16)
        self.revoked_tokens: Set[str] = set()

    def inspect_raw(self, raw_text: str) -> dict:
        threats = []
        if 'нopи' in raw_text.lower() or 'промпт' in raw_text.lower() or 'системный промпт' in raw_text.lower():
            threats.append('RUSSIAN_RAW_INJECTION')

        if any(0xE0000 <= ord(c) <= 0xE007F for c in raw_text):
            threats.append('UNICODE_TAG_SMUGGLING')
        zw_chars = re.findall(r'[​‌‍﻿]', raw_text)
        if len(zw_chars) >= 8:
            threats.append('STEGANOGRAPHY_DETECTED')
        if raw_text.count('%25') >= 4 or raw_text.count('%3') >= 4:
            threats.append('DEPTH_BOMB_URL_DETECTED')
        if re.search(r'(?:[A-Za-z0-9+/=]{60,}\s*){3,}', raw_text) and len(raw_text) > 500:
            threats.append('DEPTH_BOMB_B64_DETECTED')
        return {'is_safe': len(threats) == 0, 'threats': threats}

    def generate_fresh_canary(self) -> str:
        self.canary_nonce = secrets.token_hex(16)
        return self.canary_nonce

    def inspect_input(self, normalized_text: str) -> dict:
        if '0x' in normalized_text and (',' in normalized_text or ' ' in normalized_text):
            parts = re.findall(r'0x[0-9a-fA-F]{1,2}', normalized_text)
            if len(parts) >= 4:
                try:
                    dec = bytes(int(p, 16) for p in parts).decode('utf-8', errors='ignore')
                    if 'ignore' in dec.lower():
                        return {'is_safe': False, 'threats': ['HEX_0X_INJECTION']}
                except Exception:
                    pass
        detected_threats = []

        if 'нopи' in normalized_text.lower() or 'промпт' in normalized_text.lower() or 'игнорир' in normalized_text.lower() or 'системный' in normalized_text.lower() or 'инструкции' in normalized_text.lower():
            return {'is_safe': False, 'threats': ['RUSSIAN_INJECTION']}

        stripped = re.sub(r'[^a-zA-Z0-9Ѐ-ӿ]', '', normalized_text.lower())
        stripped_cyr = stripped.translate(self.CYR_MAP)
        stripped_leet = stripped_cyr.translate(self.LEET_MAP)

        if 'ignoreallprevious' in stripped or 'ignoreallprevious' in stripped_leet or 'systemprompt' in stripped_leet:
            return {'is_safe': False, 'threats': ['OBFUSCATED_INJECTION']}
        if 'нopи' in normalized_text.lower() or 'промпт' in stripped:
            return {'is_safe': False, 'threats': ['RUSSIAN_INJECTION']}

        if any(0xE0000 <= ord(c) <= 0xE007F for c in normalized_text):
            detected_threats.append("UNICODE_TAG_SMUGGLING")

        if len(re.findall(r'[\u200B\u200C]{8,}', normalized_text)) > 0:
            detected_threats.append("STEGANOGRAPHY_DETECTED")

        cleaned_variants = [
            normalized_text,
            normalized_text.lower(),
            re.sub(r'[\s._\-*]', '', normalized_text.lower()),
            re.sub(r'[\s._\-*]', '', normalized_text.lower()).translate(self.LEET_MAP),
        ]

        for variant in cleaned_variants:
            for pattern in self.INJECTION_PATTERNS:
                if pattern.search(variant):
                    detected_threats.append(f"INJECTION_MATCH: {pattern.pattern}")
                    break
            if detected_threats:
                break

        if self.canary_nonce.lower() in normalized_text.lower():
            detected_threats.append("CANARY_EXPOSURE_IN_INPUT")

        return {
            "is_safe": len(detected_threats) == 0,
            "threats": detected_threats
        }

    def _check_canary_leak_in_text(self, text: str) -> bool:
        secret = self.canary_nonce
        raw = secret.encode('utf-8')
        low = secret.lower()

        squeezed = TextNormalizer.strip_invisibles(text)
        squeezed = re.sub(r'\s+', '', squeezed).translate(self.CYR_MAP)
        swapped = squeezed.replace("-", "+").replace("_", "/")

        needles = set()
        for pad in range(3):
            enc = base64.b64encode(b"\x00" * pad + raw).decode("ascii")
            needles.add(enc[(pad * 8 + 5) // 6:(len(raw) + pad) * 8 // 6])

        if any(n in squeezed or n in swapped for n in needles):
            return False

        flat = re.sub(r'[^0-9a-z]', '', unicodedata.normalize('NFKD', squeezed).lower())
        forms = {low, low[::-1], codecs.encode(low, 'rot13'), "".join(str(b) for b in raw)}
        for pfx in ("", "0x", "x", "u00"):
            forms.add("".join(pfx + "{:02x}".format(b) for b in raw))

        flat_forms = {re.sub(r'[^0-9a-z]', '', f) for f in forms if re.sub(r'[^0-9a-z]', '', f)}
        if any(f in flat for f in (forms | flat_forms)):
            return False

        if len(low) >= 16 and any(low[i:i + 16] in flat for i in range(len(low) - 15)):
            return False

        return True

    def inspect_output(self, output_text: str) -> bool:
        view_decoded = TextNormalizer.decode_tags(output_text)
        view_scrubbed = TextNormalizer.strip_tags(output_text)

        if not self._check_canary_leak_in_text(view_decoded):
            return False
        if not self._check_canary_leak_in_text(view_scrubbed):
            return False

        return True
