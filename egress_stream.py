import sys, codecs, unicodedata, base64

ALL_CLEAN_RE_CHARS = {'Cf', 'Mn', 'Me', 'Cc', 'Cn', 'Co', 'Cs'}
LO_FILLERS = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800}

def canonical_clean_char(c: str) -> str:
    cp = ord(c)
    if 0xE0000 <= cp <= 0xE007F:
        return chr(cp - 0xE0000)
    cat = unicodedata.category(c)
    if cat.startswith(('L', 'N', 'P', 'S')) or cat == 'Zs':
        return c
    return ''

CUT = (0, 2, 3)
def get_b64_stems(canary_bytes: bytes) -> list[str]:
    stems = []
    for k in range(3):
        s = base64.b64encode(b'\x00' * k + canary_bytes).decode().rstrip('=')[CUT[k]:]
        if (k + len(canary_bytes)) % 3 != 0:
            s = s[:-1]
        stems.append(s)
    return stems

class HardenedStreamDetector:
    def __init__(self, canary_str: str):
        self.canary_str = canary_str
        b_c = canary_str.encode('utf-8')
        self.ci_variants = {
            canary_str.casefold(),
            codecs.encode(canary_str, 'rot_13').casefold(),
            b_c.hex().casefold(),
            ''.join(f'%{b:02x}' for b in b_c).casefold(),
            ''.join(chr(ord(ch) + 0xFEE0) if 0x21 <= ord(ch) <= 0x7E else ch for ch in canary_str).casefold()
        }
        self.cs_b64_stems = set(get_b64_stems(b_c))
        all_lens = [len(v) for v in self.ci_variants] + [len(v) for v in self.cs_b64_stems]
        self.H = max(all_lens) - 1
        self.buffer = ''
        self.blocked = False
        self.block_reason = ''

    def feed_char(self, c: str) -> str:
        if self.blocked: return ''
        if len(self.buffer) + len(c) > 512:
            self.blocked = True
            self.block_reason = 'RAW_BUFFER_OVERFLOW'
            raise RuntimeError(self.block_reason)

        self.buffer += c
        clean_view = ''.join(canonical_clean_char(ch) for ch in self.buffer)
        clean_view_ci = clean_view.casefold()

        for v in self.ci_variants:
            if v in clean_view_ci:
                self.blocked = True
                self.block_reason = 'CANARY_DETECTED'
                raise RuntimeError(self.block_reason)

        for v in self.cs_b64_stems:
            if v in clean_view:
                self.blocked = True
                self.block_reason = 'CANARY_DETECTED'
                raise RuntimeError(self.block_reason)

        clean_len = len(clean_view)
        if clean_len <= self.H:
            return ''

        excess = clean_len - self.H
        counted = 0
        cut_idx = 0
        for idx, ch in enumerate(self.buffer):
            if canonical_clean_char(ch) != '':
                counted += 1
            if counted == excess:
                cut_idx = idx + 1
                break

        safe = self.buffer[:cut_idx]
        self.buffer = self.buffer[cut_idx:]
        return safe

    def flush(self) -> str:
        if self.blocked: return ''
        clean_view = ''.join(canonical_clean_char(ch) for ch in self.buffer)
        clean_view_ci = clean_view.casefold()
        for v in self.ci_variants:
            if v in clean_view_ci:
                self.blocked = True
                self.block_reason = 'CANARY_DETECTED'
                raise RuntimeError(self.block_reason)
        for v in self.cs_b64_stems:
            if v in clean_view:
                self.blocked = True
                self.block_reason = 'CANARY_DETECTED'
                raise RuntimeError(self.block_reason)
        rem = self.buffer
        self.buffer = ''
        return rem
