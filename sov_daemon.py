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

BUSY_GRACE = 75  # seconds: longest legitimate request (2 x 30 s upstream + 15 s body read)


def log(msg):
    print("%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))


def check_health():
    """Return 'ok' if the gateway answered, 'down' if nothing listens, 'busy' otherwise."""
    try:
        from session_vault import SovereignSessionVault; import hashlib
        token = hashlib.sha256(SovereignSessionVault().master_key + b"_loopback_auth").hexdigest()[:32]
        req = urllib.request.Request(
            HEALTH_URL,
            data=b'{"messages": [{"role": "user", "content": "ping"}]}',
            headers={"Content-Type": "application/json", "X-Sovereign-Token": token}
        )
        with urllib.request.urlopen(req, timeout=3):
            return "ok"
    except urllib.error.HTTPError:
        return "ok"
    except urllib.error.URLError as e:
        return "down" if isinstance(e.reason, ConnectionRefusedError) else "busy"
    except ConnectionRefusedError:
        return "down"
    except Exception:
        return "busy"

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
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    print("[SOVEREIGN WATCHDOG ACTIVE - AUTO-HYGIENE ENABLED]")
    proc = None
    last_hygiene = time.time()
    busy_since = None
    while True:
        if time.time() - last_hygiene > 86400:
            perform_hygiene()
            last_hygiene = time.time()
        state = check_health()
        if state != "ok" and proc is not None and proc.poll() is not None:
            state = "down"
        if state == "ok":
            if busy_since is not None:
                log("[DAEMON] Gateway responsive again after %.0fs." % (time.time() - busy_since))
            busy_since = None
        elif state == "busy" and (busy_since is None or time.time() - busy_since < BUSY_GRACE):
            if busy_since is None:
                busy_since = time.time()
                log("[DAEMON] Gateway busy; waiting up to %ds before restart." % BUSY_GRACE)
        else:
            reason = "down" if state == "down" else "busy for %.0fs" % (time.time() - busy_since)
            log("[DAEMON] Gateway %s. Initiating restart..." % reason)
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            proc = start_gateway()
            busy_since = None
            time.sleep(2)
        time.sleep(5)

if __name__ == "__main__":
    main()
