with open("detector.py", "r") as f:
    code = f.read()

# Make sure forms has both original and stripped versions matching flat regex
old_flat_check = "if any(f in flat for f in forms):"
new_flat_check = """flat_forms = {re.sub(r'[^0-9a-z]', '', f) for f in forms if re.sub(r'[^0-9a-z]', '', f)}
        if any(f in flat for f in (forms | flat_forms)):"""

if old_flat_check in code:
    code = code.replace(old_flat_check, new_flat_check)
    with open("detector.py", "w") as f:
        f.write(code)
    print("detector.py patched with flat_forms.")
else:
    print("Warning: flat check snippet not found.")
