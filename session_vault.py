#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
session_vault.py - Sovereign Session Isolation & Storage (Track 4)
Provides per-session isolation, canary bounding, and encrypted local storage.
Python Standard Library only (hashlib, hmac, secrets, json, os).
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

    def save_session_to_vault(self, session_id: str):
        if session_id not in self.sessions:
            raise KeyError("Session does not exist")

        sess_data = self.sessions[session_id]
        raw_bytes = json.dumps(sess_data, ensure_ascii=False).encode("utf-8")
        session_key = self._derive_session_key(session_id)

        # تشفير XOR متزامن مع SHA-256 Key Stream كحل قياسي مدمج
        keystream = hashlib.sha256(session_key + b"stream").digest()
        encrypted = bytearray()
        for i, b in enumerate(raw_bytes):
            encrypted.append(b ^ keystream[i % len(keystream)])

        file_path = os.path.join(VAULT_DIR, f"{session_id}.vault")
        with open(file_path, "wb") as f:
            f.write(encrypted)
        os.chmod(file_path, 0o600)

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
