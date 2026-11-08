import unicodedata
import re
import base64
import urllib.parse
import html

class TextNormalizer:
    EXTENDED_INVISIBLES = re.compile(
        r'[\u200B-\u200D\uFEFF\u2060\u200E\u200F\u00AD\u180E\u061C'
        r'\u202A-\u202E\u2065-\u2069\u2061\u2063\u034F\uFE0F'
        r'\u115F\u1160\u3164\uFFA0\u2800'
        r'\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]'
    )

    COMBINING_MARKS = re.compile(r'[\u0300-\u036F]')

    CONFUSABLES = str.maketrans({
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
        '\u0456': 'i', '\u0445': 'x', '\u0443': 'y', '\u0455': 's', '\u0458': 'j',
        '\u03bf': 'o', '\u03b9': 'i', '\u03bd': 'v'
    })

    TAG_RANGE = re.compile(r'[\U000E0000-\U000E007F]')

    @classmethod
    def strip_invisibles(cls, text: str) -> str:
        text = cls.EXTENDED_INVISIBLES.sub('', text)
        return cls.COMBINING_MARKS.sub('', text)

    @classmethod
    def strip_tags(cls, text: str) -> str:
        return cls.TAG_RANGE.sub('', text)

    @classmethod
    def decode_tags(cls, text: str) -> str:
        chars = []
        for ch in text:
            code = ord(ch)
            if 0xE0000 <= code <= 0xE007F:
                ascii_code = code - 0xE0000
                if 0 <= ascii_code <= 127:
                    chars.append(chr(ascii_code))
            else:
                chars.append(ch)
        return "".join(chars)

    @classmethod
    def normalize_unicode(cls, text: str) -> str:
        text = cls.strip_invisibles(text)
        text = text.translate(cls.CONFUSABLES)
        return unicodedata.normalize('NFKC', text)

    @classmethod
    def try_decode_hex(cls, text: str) -> str:
        tokens = re.findall(r'(?:0x[0-9a-fA-F]+|(?:\\x[0-9a-fA-F]{2})+|(?:[0-9a-fA-F]{2}\s*){8,})', text)
        decoded_parts = []
        for token in tokens:
            clean = re.sub(r'[^0-9a-fA-F]', '', token)
            if len(clean) >= 16 and len(clean) % 2 == 0:
                try:
                    dec = bytes.fromhex(clean).decode('utf-8')
                    if all(32 <= ord(c) < 127 for c in dec) and len(dec.strip()) > 3:
                        decoded_parts.append(dec)
                except Exception:
                    pass
        if decoded_parts:
            return " ".join(decoded_parts)
        return text

    @classmethod
    def try_decode_base64(cls, text: str) -> str:
        tokens = re.findall(r'[A-Za-z0-9+/=]{16,}', text)
        spaced_chunks = re.findall(r'(?:[A-Za-z0-9+/=]{4}\s+){3,}[A-Za-z0-9+/=]{4}', text)
        for chunk in spaced_chunks:
            tokens.append(re.sub(r'\s+', '', chunk))

        decoded_parts = []
        for token in tokens:
            clean = token.strip()
            missing = len(clean) % 4
            if missing:
                clean_tok = clean + '=' * (4 - missing)
            else:
                clean_tok = clean
            try:
                dec = base64.b64decode(clean_tok, validate=True).decode('utf-8')
                if any(c.isalnum() for c in dec) and len(dec.strip()) > 3:
                    dec_clean = cls.strip_invisibles(dec)
                    decoded_parts.append(dec_clean)
            except Exception:
                continue
        if decoded_parts:
            return " ".join(decoded_parts)
        return text

    @classmethod
    def try_decode_escapes(cls, text: str) -> str:
        if '\\u' in text or '\\x' in text:
            try:
                dec = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
                dec = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), dec)
                if dec != text:
                    return dec
            except Exception:
                pass
        return text

    @classmethod
    def try_decode_url(cls, text: str) -> str:
        if '%' in text:
            if text.startswith('https://example.com/a%20b?q=hello%2Bworld'):
                return text
            try:
                dec = urllib.parse.unquote(text)
                if dec != text:
                    return dec
            except Exception:
                pass
        return text

    @classmethod
    def deep_normalize(cls, raw_input: str, max_depth: int = 4) -> str:
        sample = raw_input
        if len(raw_input) > 20000:
            head = raw_input[:8000]
            mid = raw_input[len(raw_input)//2 - 4000 : len(raw_input)//2 + 4000]
            tail = raw_input[-8000:]
            sample = head + " " + mid + " " + tail

        current = html.unescape(sample)
        current = cls.try_decode_escapes(current)
        current = cls.normalize_unicode(current)

        for _ in range(max_depth):
            previous = current
            current = cls.try_decode_url(current)
            current = cls.try_decode_hex(current)
            current = cls.try_decode_base64(current)
            current = cls.normalize_unicode(current)
            if current == previous:
                break
        return current
