# HEXCORE by SKYTAR — Windows install (PowerShell, run as normal user)
# Requires Python 3.11+ in PATH. Optional: winget install LLVM.LLVM  (for objdump)
# Optional: winget install Wireshark.Wireshark  (for tshark)
python --version
python -m pip install capstone pefile reportlab 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "Optional Python deps skipped — HEXCORE works with stdlib only." }
Write-Host "Run: python -m hexcore server   (then open http://127.0.0.1:8765)"
Write-Host "Or:  python -m hexcore analyze C:\path\to\app.exe"
