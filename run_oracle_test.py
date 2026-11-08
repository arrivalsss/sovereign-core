import urllib.request
import hashlib
import re
import os
import unicodedata

UCD_URL = "https://www.unicode.org/Public/UCD/latest/ucd/DerivedCoreProperties.txt"
LOCAL_FILE = "DerivedCoreProperties.txt"

if not os.path.exists(LOCAL_FILE):
    print("Downloading official DerivedCoreProperties.txt from Unicode.org...")
    urllib.request.urlretrieve(UCD_URL, LOCAL_FILE)

# 1. Compute SHA-256 and extract version
with open(LOCAL_FILE, "rb") as f:
    content = f.read()
    file_sha256 = hashlib.sha256(content).hexdigest()

lines = content.decode("utf-8", errors="replace").splitlines()
header_lines = [l for l in lines[:5] if l.startswith("#")]
version_line = header_lines[0] if header_lines else "Unknown Version"

print(f"File Path: {os.path.abspath(LOCAL_FILE)}")
print(f"SHA-256: {file_sha256}")
print(f"Header: {version_line}")

# 2. Parse Default_Ignorable_Code_Point ranges
di_code_points = set()
pattern = re.compile(r"^([0-9A-Fa-f]+)(?:\.\.([0-9A-Fa-f]+))?\s*;\s*Default_Ignorable_Code_Point")

for line in lines:
    m = pattern.match(line)
    if m:
        start = int(m.group(1), 16)
        end = int(m.group(2), 16) if m.group(2) else start
        for cp in range(start, end + 1):
            di_code_points.add(cp)

print(f"Total Default_Ignorable Code Points parsed: {len(di_code_points)}")

# 3. Whitelist Categories (General_Category L*, N*, P*, S*, Zs)
# Excluded: C* (Cc, Cf, Cs, Co, Cn), M* (Mn, Mc, Me)
whitelist_cats = {'Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nd', 'Nl', 'No', 'P', 'Pd', 'Ps', 'Pe', 'Pi', 'Pf', 'Po', 'Sm', 'Sc', 'Sk', 'So', 'Zs'}

def in_whitelist(cp):
    ch = chr(cp)
    cat = unicodedata.category(ch)
    return cat in whitelist_cats or cat[0] in {'P', 'S'}

# 4. Self-Test: Run against Original Unpatched Whitelist (before Hangul fillers & Braille were scrubbed)
# The old scrub did not strip Hangul fillers U+115F, U+1160, U+3164, U+FFA0
old_scrub_escaped = []
for cp in di_code_points:
    if in_whitelist(cp):
        # In original whitelist without explicit Lo / Zs scrub:
        ch = chr(cp)
        cat = unicodedata.category(ch)
        if cat == 'Lo': # Hangul fillers
            old_scrub_escaped.append(f"U+{cp:04X}")

print(f"\n[SELF-TEST] Testing against unpatched whitelist baseline...")
print(f"Expected unpatched escapees: ['U+115F', 'U+1160', 'U+3164', 'U+FFA0']")
print(f"Actual unpatched escapees:   {sorted(old_scrub_escaped)}")
assert sorted(old_scrub_escaped) == ['U+115F', 'U+1160', 'U+3164', 'U+FFA0'], "Self-test failed! Oracle is blind."
print("[SELF-TEST: PASSED] Oracle baseline verified independently.\n")

# 5. Production Test: Run against our Patched Normalizer scrub set
from normalizer import TextNormalizer
surviving = []
for cp in di_code_points:
    if in_whitelist(cp):
        ch = chr(cp)
        # Strip using our patched normalizer
        scrubbed = TextNormalizer.strip_invisibles(ch)
        # If character is not completely eradicated and still in whitelist
        if scrubbed != "":
            surviving.append(f"U+{cp:04X} ({unicodedata.name(ch, 'UNKNOWN')})")

print(f"Surviving Default_Ignorable in Patched Whitelist: {len(surviving)}")
if surviving:
    print(f"Surviving code points: {surviving}")
assert len(surviving) == 0, f"Patched scrub set failed, survivors: {surviving}"
print("[ORACLE AUDIT: PASSED] Default_Ignorable ∩ Patched Whitelist = ∅ (Confirmed)")
