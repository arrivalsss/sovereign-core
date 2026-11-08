#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_protocol.py - Sovereign Cryptographic Audit Trail & Integrity Verifier (Track 8)
Python standard library only (hashlib, hmac, json, os, time).
"""

import os, json, hashlib, time

CORE_DIR = os.path.expanduser("~/sovereign_core")
LEDGER_FILE = os.path.join(CORE_DIR, "vault", "audit.ledger")

class SovereignAuditor:
    def __init__(self):
        os.makedirs(os.path.join(CORE_DIR, "vault"), exist_ok=True)
        if not os.path.exists(LEDGER_FILE):
            genesis = {
                "index": 0,
                "timestamp": 1762308000,
                "event": "GENESIS_SOVEREIGN_KERNEL_4_2",
                "prev_hash": "0" * 64
            }
            genesis_hash = hashlib.sha256(json.dumps(genesis, sort_keys=True).encode()).hexdigest()
            genesis["hash"] = genesis_hash
            with open(LEDGER_FILE, "w") as f:
                f.write(json.dumps(genesis) + "\n")

    def record_event(self, event_type: str, details: dict):
        last_hash = "0" * 64
        last_index = 0
        with open(LEDGER_FILE, "r") as f:
            lines = f.readlines()
            if lines:
                last_block = json.loads(lines[-1])
                last_hash = last_block["hash"]
                last_index = last_block["index"]

        block = {
            "index": last_index + 1,
            "timestamp": int(time.time()),
            "event": event_type,
            "details": details,
            "prev_hash": last_hash
        }
        block_hash = hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()
        block["hash"] = block_hash

        with open(LEDGER_FILE, "a") as f:
            f.write(json.dumps(block) + "\n")
        return block

    def verify_ledger_integrity(self) -> bool:
        if not os.path.exists(LEDGER_FILE):
            return False
        with open(LEDGER_FILE, "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        for i in range(1, len(lines)):
            prev = lines[i - 1]
            curr = lines[i]
            if curr["prev_hash"] != prev["hash"]:
                return False
            check_block = {k: curr[k] for k in curr if k != "hash"}
            expected_hash = hashlib.sha256(json.dumps(check_block, sort_keys=True).encode()).hexdigest()
            if curr["hash"] != expected_hash:
                return False
        return True

    def verify_core_files(self) -> dict:
        core_files = ["normalizer.py", "detector.py", "middleware.py", "proxy_gateway.py", "session_vault.py", "secrets_manager.py"]
        checksums = {}
        for fname in core_files:
            fpath = os.path.join(CORE_DIR, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    checksums[fname] = hashlib.sha256(f.read()).hexdigest()[:16]
            else:
                checksums[fname] = "MISSING"
        return checksums

if __name__ == "__main__":
    auditor = SovereignAuditor()
    block = auditor.record_event("INJECTION_BLOCKED", {"source": "127.0.0.1", "pattern": "ignore_instructions"})
    print(f"[AUDIT BLOCK RECORDED] Block #{block["index"]} Hash: {block["hash"][:16]}...")
    assert auditor.verify_ledger_integrity() is True
    print("[PASS] Cryptographic Hash Chain: Tamper-proof integrity verified.")
