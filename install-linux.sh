#!/bin/bash
# HEXCORE by SKYTAR — Linux install (Python only, no root required for the tool itself)
# Optional system tools for full disassembly / tracing:
#   sudo apt install binutils strace ltrace gdb tshark   # Debian/Ubuntu
#   sudo dnf install binutils strace ltrace gdb wireshark-cli  # Fedora
set -e
python3 --version
python3 -m pip install --user capstone pefile pyelftools reportlab 2>/dev/null || echo "Optional Python deps skipped — HEXCORE works with stdlib only."
echo "Run: python3 -m hexcore server   (then open http://127.0.0.1:8765)"
echo "Or:  python3 -m hexcore analyze /bin/ls"
