#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secrets_manager.py - Sovereign Encrypted Secrets Vault (Track 6)

Encrypts and manages API keys and provider endpoints natively.
Uses Fernet (AES-128-CBC + HMAC-SHA256) for new writes.
Legacy XOR-encrypted vaults are read transparently and migrated on first write.
"""

import os, json, hashlib, base64
from cryptography.fernet import Fernet, InvalidToken
from session_vault import SovereignSessionVault, VAULT_DIR

SECRETS_FILE = os.path.join(VAULT_DIR, ".secrets.vault")


class SecretsManager:
    def __init__(self):
        self.vault = SovereignSessionVault()
        self.key = hashlib.sha256(self.vault.master_key + b"_secrets_key").digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(self.key))

    def _encrypt_fernet(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)

    def _decrypt_fernet(self, data: bytes) -> bytes:
        return self.fernet.decrypt(data)

    def _crypt_legacy(self, data: bytes) -> bytes:
        keystream = hashlib.sha256(self.key + b"stream").digest()
        return bytes([b ^ keystream[i % len(keystream)] for i, b in enumerate(data)])

    def _write(self, raw: bytes):
        encrypted = self._encrypt_fernet(raw)
        with open(SECRETS_FILE, "wb") as f:
            f.write(encrypted)
        os.chmod(SECRETS_FILE, 0o600)

    def set_secret(self, provider: str, api_key: str, endpoint: str = None):
        secrets = self.get_all_secrets()
        secrets[provider.lower()] = {
            "api_key": api_key,
            "endpoint": endpoint or "https://api.openai.com/v1/chat/completions"
        }
        raw = json.dumps(secrets).encode("utf-8")
        self._write(raw)

    def get_all_secrets(self) -> dict:
        if not os.path.exists(SECRETS_FILE):
            return {}
        try:
            with open(SECRETS_FILE, "rb") as f:
                data = f.read()
        except Exception:
            return {}
        # Try Fernet first (new format)
        try:
            decrypted = self._decrypt_fernet(data)
            return json.loads(decrypted.decode("utf-8"))
        except (InvalidToken, Exception):
            pass
        # Fall back to legacy XOR, then migrate to Fernet
        try:
            decrypted = self._crypt_legacy(data)
            secrets = json.loads(decrypted.decode("utf-8"))
            # Migrate to Fernet immediately
            raw = json.dumps(secrets).encode("utf-8")
            self._write(raw)
            return secrets
        except Exception:
            return {}

    def delete_secret(self, provider: str) -> bool:
        secrets = self.get_all_secrets()
        if provider.lower() not in secrets:
            return False
        del secrets[provider.lower()]
        raw = json.dumps(secrets).encode("utf-8")
        self._write(raw)
        return True

    def get_secret(self, provider: str) -> dict:
        return self.get_all_secrets().get(provider.lower(), {})


if __name__ == "__main__":
    pass
