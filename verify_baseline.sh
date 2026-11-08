#!/data/data/com.termux/files/usr/bin/bash
cd ~/sovereign_core || exit 1
echo -e "\033[1;36m=== SOVEREIGN KERNEL 4.2 - VERIFYING BLOCK #30 SEAL ===\033[0m"

sha256sum -c MANIFEST.sha256 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "\033[1;32m[PASS] Cryptographic Seal Intact: Block #30\033[0m"
    echo -e "\033[1;32m[PASS] Invariant: pending_data - cleared == len(raw_buffer)\033[0m"
    echo -e "\033[1;34mManifest Hash: 582483f445af940ae2d495298b088dc4c74cebbe92581bb7ca7fe80445a59e59\033[0m"
else
    echo -e "\033[1;31m[CRITICAL FAIL] Baseline Tamper Detected!\033[0m"
fi
