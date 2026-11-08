import re
import secrets
import unicodedata
from types import MappingProxyType
from normalizer import TextNormalizer

class SecurityError(Exception):
    pass

class QuadViewStreamProtector:
    def __init__(self, canary: str, variants_dict: dict = None, variants=None):
        self.canary = canary
        if variants is not None:
            if isinstance(variants, dict):
                raw_dict = dict(variants)
            else:
                raw_dict = {f"V{i}": v for i, v in enumerate(variants)}
        else:
            raw_dict = variants_dict or {"RAW": canary}
        # Freeze variant dictionary to prevent reference mutation & thread concurrency bugs
        self.variants_dict = MappingProxyType(dict(raw_dict))
        self.variants = list(self.variants_dict.values())
        
        self.max_variant_len = max(len(v) for v in self.variants)
        self.H = self.max_variant_len - 1
        
        # NFKD Flat variants (supports compatibility forms: circled, math monospace, fullwidth)
        self.flat_variants = {}
        for k, v in self.variants_dict.items():
            clean_v = TextNormalizer.strip_invisibles(TextNormalizer.strip_tags(v))
            # Apply CONFUSABLES mapping + NFKD
            confused_v = clean_v.translate(TextNormalizer.CONFUSABLES)
            norm_v = unicodedata.normalize('NFKD', confused_v).casefold()
            flat_v = "".join(c for c in norm_v if unicodedata.category(c)[0] in ('L', 'N'))
            if flat_v:
                self.flat_variants[k] = flat_v

        self.max_flat_len = max(len(v) for v in self.flat_variants.values()) if self.flat_variants else self.max_variant_len
        self.H_flat = self.max_flat_len - 1

        self.MAX_RAW_BUFFER = 1024
        self.raw_buffer = ""
        self.blocked = False

    @staticmethod
    def flat_units(ch: str) -> int:
        scrubbed = TextNormalizer.strip_invisibles(TextNormalizer.strip_tags(ch))
        if not scrubbed:
            return 0
        confused = scrubbed.translate(TextNormalizer.CONFUSABLES)
        norm = unicodedata.normalize('NFKD', confused).casefold()
        return sum(1 for c in norm if unicodedata.category(c)[0] in ('L', 'N'))

    @staticmethod
    def tag_units(ch: str) -> int:
        return 1 if not (0xE0000 <= ord(ch) <= 0xE007F) else 0

    def _get_views_full(self, text: str):
        squeezed = TextNormalizer.strip_invisibles(text)
        # View A: Decoded Plane-14 tags
        view_a = TextNormalizer.decode_tags(squeezed)
        # View B: Stripped Plane-14 tags
        view_b = TextNormalizer.strip_tags(squeezed)
        
        # View C: Flat representation of stripped tags (NFKD + Confusables)
        norm_b = unicodedata.normalize('NFKD', view_b.translate(TextNormalizer.CONFUSABLES)).casefold()
        view_c = "".join(c for c in norm_b if unicodedata.category(c)[0] in ('L', 'N'))
        
        # View D: Flat representation of DECODED tags (catches tags + punctuation separators)
        norm_a = unicodedata.normalize('NFKD', view_a.translate(TextNormalizer.CONFUSABLES)).casefold()
        view_d = "".join(c for c in norm_a if unicodedata.category(c)[0] in ('L', 'N'))
        
        return squeezed, view_a, view_b, view_c, view_d

    def _get_views(self, text: str):
        squeezed, view_a, view_b, view_c, _view_d = self._get_views_full(text)
        return squeezed, view_a, view_b, view_c

    def _format_safe_reason(self, variant_name: str) -> str:
        inc_id = secrets.token_hex(4)
        return f"[BLOCKED] Policy violation on variant {variant_name} (incident_id: {inc_id})"

    def _check_leak(self, text: str):
        squeezed, view_a, view_b, view_c, view_d = self._get_views_full(text)

        for name, v in self.variants_dict.items():
            v_low = v.lower()
            if (v_low in squeezed.lower() or 
                v_low in view_a.lower() or 
                v_low in view_b.lower()):
                self.blocked = True
                raise SecurityError(self._format_safe_reason(name))

        # Check against both stripped flat view (C) and decoded flat view (D)
        for name, fv in self.flat_variants.items():
            if fv in view_c or fv in view_d:
                self.blocked = True
                raise SecurityError(self._format_safe_reason(f"{name}_FLAT"))

    def process_chunk(self, chunk: str) -> str:
        if self.blocked:
            return ""

        self.raw_buffer += chunk
        
        if len(self.raw_buffer) > self.MAX_RAW_BUFFER:
            self.blocked = True
            raise SecurityError("[BLOCKED] RAW_BUFFER_OVERFLOW")

        self._check_leak(self.raw_buffer)

        _, view_a, view_b, view_c, view_d = self._get_views_full(self.raw_buffer)
        curr_units_a = len(view_a)
        curr_units_b = len(view_b)
        curr_units_c = len(view_c)
        curr_units_d = len(view_d)

        safe_cut = 0
        variant_chars = set()
        for v in self.variants:
            variant_chars.update(v)
        for i, ch in enumerate(self.raw_buffer):
            u_c = self.flat_units(ch)
            u_b = self.tag_units(ch)
            u_a = 1

            can_emit = True
            if u_a > 0 and (curr_units_a - u_a) < self.H:
                can_emit = False
            if u_b > 0 and (curr_units_b - u_b) < self.H:
                can_emit = False
            if u_c > 0 and (curr_units_c - u_c) < self.H_flat:
                can_emit = False
            if ch == '%' and (curr_units_c) < self.H_flat + 1:
                can_emit = False
            if u_c > 0 and (curr_units_d - u_c) < self.H_flat:
                can_emit = False

            if can_emit:
                curr_units_a -= u_a
                curr_units_b -= u_b
                curr_units_c -= u_c
                curr_units_d -= u_c
                safe_cut = i + 1
            else:
                break

        if safe_cut > 0:
            emit_candidate = self.raw_buffer[:safe_cut]
            self._check_leak(emit_candidate)
            self.raw_buffer = self.raw_buffer[safe_cut:]
            return emit_candidate

        return ""

    def flush(self) -> str:
        if self.blocked:
            return ""
        self._check_leak(self.raw_buffer)
        remaining = self.raw_buffer
        self.raw_buffer = ""
        return remaining


DualViewStreamProtector = QuadViewStreamProtector
TripleViewStreamProtector = QuadViewStreamProtector
