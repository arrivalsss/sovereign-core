#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sov_daemon.py - Autonomous Watchdog Daemon for Sovereign Core (Track 3)
Monitors proxy_gateway.py health and auto-restarts upon failure.
Python Standard Library only.
"""

import os
import sys
import time
import subprocess
import urllib.request
import urllib.error

CORE_DIR = os.path.expanduser("~/sovereign_core")
GATEWAY_SCRIPT = os.path.join(CORE_DIR, "proxy_gateway.py")
PID_FILE = os.path.join(CORE_DIR, "proxy.pid")
LOG_FILE = os.path.join(CORE_DIR, "proxy.log")
HEALTH_URL = "http://127.0.0.1:8080/"

def is_healthy():
    try:
        # فحص استجابة الخادم بطلب بسيط
        from session_vault import SovereignSessionVault; import hashlib
        token = hashlib.sha256(SovereignSessionVault().master_key + b"_loopback_auth").hexdigest()[:32]
        req = urllib.request.Request(
            HEALTH_URL,
            data=b'{"messages": [{"role": "user", "content": "ping"}]}',
            headers={"Content-Type": "application/json", "X-Sovereign-Token": token}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status in (200, 400, 403)
    except Exception:
        return False

def start_gateway():
    print("[DAEMON] Launching proxy_gateway...")
    with open(LOG_FILE, "a") as log:
        proc = subprocess.Popen(
            [sys.executable, GATEWAY_SCRIPT],
            cwd=CORE_DIR,
            stdout=log,
            stderr=subprocess.STDOUT
        )
    with open(PID_FILE, "w") as f:
        f.write(str(proc.pid))
    print(f"[DAEMON] proxy_gateway running with PID {proc.pid}")
    return proc

def perform_hygiene():
    vault_dir = os.path.join(CORE_DIR, "vault")
    if not os.path.exists(vault_dir):
        return
    cleaned = 0
    for fname in os.listdir(vault_dir):
        if fname.endswith(".vault") and not fname.startswith("."):
            try:
                os.remove(os.path.join(vault_dir, fname))
                cleaned += 1
            except Exception:
                pass
    if cleaned > 0:
        print(f"[DAEMON-HYGIENE] Auto-pruned {cleaned} ephemeral vaults.")

def main():
    print("[SOVEREIGN WATCHDOG ACTIVE - AUTO-HYGIENE ENABLED]")
    proc = None
    last_hygiene = time.time()
    while True:
        if time.time() - last_hygiene > 86400:
            perform_hygiene()
            last_hygiene = time.time()
        if not is_healthy():
            print("[DAEMON] Gateway unresponsive or down. Initiating restart...")
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            proc = start_gateway()
            time.sleep(2)
        time.sleep(5)

if __name__ == "__main__":
    main()
