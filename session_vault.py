#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
session_vault.py - Sovereign Session Isolation & Storage (Track 4)
Provides per-session isolation, canary bounding, and encrypted local storage.
Standard library, plus cryptography (Fernet) for stored session files.
"""

import os
import json
import secrets
import hashlib
import hmac
from typing import Dict, Any, Optional

VAULT_DIR = os.path.expanduser("~/sovereign_core/vault")

class SovereignSessionVault:
    def __init__(self, master_secret: Optional[str] = None):
        os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
        # توليد أو تحميل المفتاح الرئيسي
        key_file = os.path.join(VAULT_DIR, ".vault_key")
        if master_secret:
            self.master_key = hashlib.sha256(master_secret.encode()).digest()
        elif os.path.exists(key_file):
            with open(key_file, "rb") as f:
                self.master_key = f.read()
        else:
            self.master_key = secrets.token_bytes(32)
            with open(key_file, "wb") as f:
                f.write(self.master_key)
            os.chmod(key_file, 0o600)

        self.sessions: Dict[str, Dict[str, Any]] = {}

    def _derive_session_key(self, session_id: str) -> bytes:
        return hmac.new(self.master_key, session_id.encode(), hashlib.sha256).digest()

    def create_session(self, metadata: Optional[Dict[str, Any]] = None) -> str:
        session_id = secrets.token_hex(16)
        session_canary = f"canary_{secrets.token_hex(8)}"
        self.sessions[session_id] = {
            "session_id": session_id,
            "session_canary": session_canary,
            "created_at": secrets.token_hex(4),
            "history": [],
            "metadata": metadata or {}
        }
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(session_id)

    def append_message(self, session_id: str, role: str, content: str):
        if session_id not in self.sessions:
            raise KeyError("Session does not exist")
        self.sessions[session_id]["history"].append({"role": role, "content": content})

    def _session_fernet(self, session_id: str):
        from cryptography.fernet import Fernet
        import base64
        return Fernet(base64.urlsafe_b64encode(self._derive_session_key(session_id)))

    def save_session_to_vault(self, session_id: str):
        if session_id not in self.sessions:
            raise KeyError("Session does not exist")

        raw_bytes = json.dumps(self.sessions[session_id], ensure_ascii=False).encode("utf-8")
        encrypted = self._session_fernet(session_id).encrypt(raw_bytes)

        file_path = os.path.join(VAULT_DIR, f"{session_id}.vault")
        tmp_path = os.path.join(VAULT_DIR, ".%s.tmp" % secrets.token_hex(8))
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, file_path)
        except BaseException:
            if os.path.lexists(tmp_path):
                os.unlink(tmp_path)
            raise

    def load_session_from_vault(self, session_id: str) -> Dict[str, Any]:
        """Read a stored session: Fernet, or the legacy XOR format written before it."""
        if not (len(session_id) == 32 and all(c in "0123456789abcdef" for c in session_id)):
            raise ValueError("invalid session id")
        fd = os.open(os.path.join(VAULT_DIR, f"{session_id}.vault"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            data = f.read()
        from cryptography.fernet import InvalidToken
        try:
            return json.loads(self._session_fernet(session_id).decrypt(data).decode("utf-8"))
        except InvalidToken:
            pass
        keystream = hashlib.sha256(self._derive_session_key(session_id) + b"stream").digest()
        sess = json.loads(bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(data)).decode("utf-8"))
        if not isinstance(sess, dict) or sess.get("session_id") != session_id:
            raise ValueError("session file does not decrypt to this session")
        return sess

    def purge_session(self, session_id: str):
        """مسح آمن للجلسة من الذاكرة والقرص"""
        if session_id in self.sessions:
            del self.sessions[session_id]

        file_path = os.path.join(VAULT_DIR, f"{session_id}.vault")
        if os.path.exists(file_path):
            # مسح الكتابة بالأصفار لضمان عدم الاسترجاع
            size = os.path.getsize(file_path)
            with open(file_path, "wb") as f:
                f.write(b"\x00" * size)
            os.remove(file_path)

    def purge_all(self):
        """مسح كامل الخزنة بشكل نهائي"""
        self.sessions.clear()
        for fname in os.listdir(VAULT_DIR):
            fpath = os.path.join(VAULT_DIR, fname)
            if os.path.isfile(fpath) and fname != ".vault_key":
                size = os.path.getsize(fpath)
                with open(fpath, "wb") as f:
                    f.write(b"\x00" * size)
                os.remove(fpath)

if __name__ == "__main__":
    vault = SovereignSessionVault()
    sid = vault.create_session({"client": "termux_native"})
    print(f"[VAULT READY] Created test session: {sid}")
    vault.append_message(sid, "user", "Test session content.")
    vault.save_session_to_vault(sid)
    print(f"[VAULT SAVED] Session persisted and encrypted.")
    vault.purge_session(sid)
    print(f"[VAULT PURGED] Session cleanly destroyed.")
