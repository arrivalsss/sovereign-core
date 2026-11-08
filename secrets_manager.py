#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secrets_manager.py - Sovereign Encrypted Secrets Vault (Track 6)
Encrypts and manages API keys and provider endpoints natively.
Python standard library only.
"""

import os, json, hashlib
from session_vault import SovereignSessionVault, VAULT_DIR

SECRETS_FILE = os.path.join(VAULT_DIR, ".secrets.vault")

class SecretsManager:
    def __init__(self):
        self.vault = SovereignSessionVault()
        self.key = hashlib.sha256(self.vault.master_key + b"_secrets_key").digest()

    def _crypt(self, data: bytes) -> bytes:
        keystream = hashlib.sha256(self.key + b"stream").digest()
        return bytes([b ^ keystream[i % len(keystream)] for i, b in enumerate(data)])

    def set_secret(self, provider: str, api_key: str, endpoint: str = None):
        secrets = self.get_all_secrets()
        secrets[provider.lower()] = {
            "api_key": api_key,
            "endpoint": endpoint or "https://api.openai.com/v1/chat/completions"
        }
        raw = json.dumps(secrets).encode("utf-8")
        encrypted = self._crypt(raw)
        with open(SECRETS_FILE, "wb") as f:
            f.write(encrypted)
        os.chmod(SECRETS_FILE, 0o600)

    def get_all_secrets(self) -> dict:
        if not os.path.exists(SECRETS_FILE):
            return {}
        try:
            with open(SECRETS_FILE, "rb") as f:
                decrypted = self._crypt(f.read())
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            return {}

    def get_secret(self, provider: str) -> dict:
        return self.get_all_secrets().get(provider.lower(), {})

if __name__ == "__main__":
    sm = SecretsManager()
    sm.set_secret("openai_test", "sk-mock-key-12345", "https://api.openai.com/v1/chat/completions")
    sec = sm.get_secret("openai_test")
    assert sec.get("api_key") == "sk-mock-key-12345"
    print("[PASS] SecretsManager: Key encrypted, stored and retrieved cleanly.")
