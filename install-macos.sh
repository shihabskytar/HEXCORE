#!/bin/bash
# HEXCORE by SKYTAR — macOS install
# Requires Python 3.11+ (python.org or brew install python) and Xcode Command Line Tools for objdump/lldb:
#   xcode-select --install
set -e
python3 --version
python3 -m pip install --user capstone pefile reportlab 2>/dev/null || echo "Optional Python deps skipped — HEXCORE works with stdlib only."
echo "Run: python3 -m hexcore server   (then open http://127.0.0.1:8765)"
echo "Or:  python3 -m hexcore analyze /bin/ls"
