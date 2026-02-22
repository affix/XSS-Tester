#!/usr/bin/env bash
# setup.sh — Bootstrap the XSS Tester environment using uv
set -euo pipefail

echo "[*] Installing Python dependencies with uv"
uv pip install -r requirements.txt

echo "[*] Installing Playwright Chromium browser"
uv run playwright install chromium

echo ""
echo "[+] Setup complete."
echo "    Run:  uv run python main.py --help"
