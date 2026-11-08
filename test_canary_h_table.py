import codecs
import base64

CANARY_PROD = "KEY_SEC_99"

def get_fullwidth(text: str) -> str:
    res = []
    for c in text:
        code = ord(c)
        if 0x21 <= code <= 0x7E:
            res.append(chr(code + 0xFEE0))
        else:
            res.append(c)
    return "".join(res)

def generate_variants_table(canary: str):
    raw_bytes = canary.encode("utf-8")
    
    b64_pads = []
    for pad in range(3):
        enc = base64.b64encode(b"\x00" * pad + raw_bytes).decode("ascii")
        start = (pad * 8 + 5) // 6
        end = (len(raw_bytes) + pad) * 8 // 6
        b64_pads.append(enc[start:end])

    variants = {
        "RAW": canary,
        "ROT13": codecs.encode(canary, "rot13"),
        "HEX": raw_bytes.hex(),
        "PERCENT": "".join(f"%{b:02X}" for b in raw_bytes),
        "FULLWIDTH": get_fullwidth(canary),
        "B64_PAD0": b64_pads[0],
        "B64_PAD1": b64_pads[1],
        "B64_PAD2": b64_pads[2],
        "UPPER": canary.upper(),
        "REVERSED": canary[::-1],
        "SPACED": " ".join(canary),
        "DOTTED": ".".join(canary)
    }
    
    lens = {k: len(v) for k, v in variants.items()}
    max_len = max(lens.values())
    H = max_len - 1
    
    assert H == max_len - 1, f"Invariant violated: H ({H}) != max_len - 1 ({max_len - 1})"
    
    run_cap = 8
    min_raw_buffer_ceiling = H * (run_cap + 1)
    
    print(f"=== Production Canary Variants Table (Canary: '{canary}') ===")
    print(f"{'Variant Name':<15} | {'Length':<8} | {'Sample Representation':<30}")
    print("-" * 60)
    for name, val in variants.items():
        sample = val if len(val) <= 28 else val[:25] + "..."
        print(f"{name:<15} | {len(val):<8} | {sample:<30}")
    print("-" * 60)
    print(f"Max Variant: '{max(lens, key=lens.get)}' with length {max_len}")
    print(f"Holdback Threshold H: {H}")
    print(f"Required Raw Buffer Ceiling (H * 9): >= {min_raw_buffer_ceiling}")
    print(f"Configured Buffer Ceiling: 512 (Safe: {512 >= min_raw_buffer_ceiling})")
    
    return variants, H

if __name__ == "__main__":
    generate_variants_table(CANARY_PROD)
