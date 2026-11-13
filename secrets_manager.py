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

DEFAULT_ENDPOINTS = {
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
}


class SecretsVaultError(Exception):
    """The secrets vault exists but cannot be read or decrypted. Nothing is overwritten."""


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
        tmp = os.path.join(VAULT_DIR, ".secrets.%s.tmp" % os.urandom(8).hex())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, SECRETS_FILE)
        except BaseException:
            if os.path.lexists(tmp):
                os.unlink(tmp)
            raise

    def set_secret(self, provider: str, api_key: str, endpoint: str = None):
        name = provider.lower()
        endpoint = endpoint or DEFAULT_ENDPOINTS.get(name)
        if not endpoint:
            raise ValueError("no default endpoint for provider %r; pass the endpoint explicitly" % name)
        secrets = self.get_all_secrets()
        secrets[name] = {"api_key": api_key, "endpoint": endpoint}
        self._write(json.dumps(secrets).encode("utf-8"))

    def get_all_secrets(self) -> dict:
        if not os.path.lexists(SECRETS_FILE):
            return {}
        try:
            fd = os.open(SECRETS_FILE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as f:
                data = f.read()
        except OSError as e:
            raise SecretsVaultError("secrets vault cannot be read (%s)" % type(e).__name__) from None
        try:
            secrets = json.loads(self._decrypt_fernet(data).decode("utf-8"))
        except InvalidToken:
            try:
                secrets = json.loads(self._crypt_legacy(data).decode("utf-8"))
            except ValueError:
                raise SecretsVaultError("secrets vault cannot be decrypted with the current vault key") from None
            if not isinstance(secrets, dict):
                raise SecretsVaultError("secrets vault has an unexpected format")
            self._write(json.dumps(secrets).encode("utf-8"))
            return secrets
        except ValueError:
            raise SecretsVaultError("secrets vault decrypted but is not valid JSON") from None
        if not isinstance(secrets, dict):
            raise SecretsVaultError("secrets vault has an unexpected format")
        return secrets

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
