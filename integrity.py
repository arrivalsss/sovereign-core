import hashlib
import os

CORE_FILES = ["gateway.py", "egress_stream.py", "canonicalizer.py", "budget.py"]

def generate_manifest():
    print("[INTEGRITY] Generating SHA-256 Manifest...")
    manifest_lines = []
    for filename in CORE_FILES:
        if os.path.exists(filename):
            with open(filename, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            line = f"{file_hash}  {filename}"
            manifest_lines.append(line)
            print(f"[HASH] {filename}: {file_hash[:16]}...")
        else:
            print(f"[WARN] File not found: {filename}")
            
    with open("MANIFEST.sha256", "w") as f:
        f.write("\n".join(manifest_lines) + "\n")
    print("[SUCCESS] MANIFEST.sha256 written successfully.")

if __name__ == "__main__":
    generate_manifest()
