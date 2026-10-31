# HEXCORE by SKYTAR

**Start here:** [`TUTORIAL.md`](TUTORIAL.md) — full tutorial: how to use HEXCORE, use cases for hackers / cybersecurity specialists, and supported OS (Linux, Windows, macOS) with smart tips.

**Decode the Unknown. Understand the Core.**
https://www.shihabskytar.com — Creator: SKYTAR

HEXCORE is a next-generation, cross-platform cybersecurity research and reverse-engineering workstation for software engineers, security researchers, malware analysts, and authorized penetration-testing professionals.

> **Scope honesty, read this first:** This Phase 1 delivery is a real, modular, working platform in Python (stdlib core, web UI on localhost), tested on Linux in this environment. It is **not** a clone of Ghidra, IDA Pro, Binary Ninja, Wireshark or Sysinternals, and it does **not** claim to have been tested on Windows or macOS desktop installers — those platforms run the same Python code, and their install scripts are provided, but desktop packaging (Tauri/React) and native debugger integrations are Phase 2, not claimed here. Every adapter that needs an external tool labels itself unavailable when that tool is missing, instead of faking output.

## Architecture assessment (existing RE Lab Advanced)

- **Was:** a single 1,346-line Python file with PE/ELF/Mach-O/APK/MSI/CAB/ZIP parsers, strings, entropy, objdump disassembly, CFG, pseudo-C, findings, MCP (stdio), REPL, investigate, 3D graph, HTML/JSON reports.
- **Strengths kept:** read-only design, multi-format support, CFG/xref logic (including the objdump plain-hex fix), risk scoring, MCP bridge.
- **Weaknesses fixed in HEXCORE:** monolithic file → modular package; findings had no confidence / offset / VA / false-positive notes → v2 schema; no exports, relocations, certificate, packed/overlay, compiler hints → added; no network, malware, memory, plugin, report, or UI layer → added; no tests → added; no capability checks → every adapter now reports availability.

```
HEXCORE/
  hexcore/__init__.py      branding, version
  hexcore/config.py        local config, risk weights, consent flags
  hexcore/legacy.py        preserved RE Lab Advanced engine (backward compat)
  hexcore/engine.py        Analysis object, PE exports/relocations/cert, packed/overlay, compiler hints
  hexcore/security.py      v2 findings, ATT&CK mapping, YARA-like rules, IOC extraction
  hexcore/network.py       passive PCAP metadata (flows, DNS, HTTP)
  hexcore/memory.py        VA↔offset, hex slice/search, section map
  hexcore/decompiler.py    Ghidra/RetDec/Rizin/LLVM adapters with graceful fallback
  hexcore/dynamic.py       strace/ltrace/GDB/LLDB adapters, consent-gated
  hexcore/plugins.py       plugin loader with manifest + permission checks
  hexcore/reports.py       HTML / JSON / Markdown / PDF (reportlab or basic PDF)
  hexcore/mcp_server.py    22 read-only MCP tools, validated, resource-limited
  hexcore/server.py        localhost web API (127.0.0.1 only)
  hexcore/ui/index.html    dark workstation UI: nav, workspace, inspector, console, Ctrl+K palette, 2D CFG, 3D call graph
  hexcore/ui/icon.svg      original hexagonal core emblem (cyan / electric blue, graphite/navy)
  hexcore/plugins/example/ example read-only plugin
  tests/test_hexcore.py    unit + integration tests
  install-linux.sh / install-windows.ps1 / install-macos.sh
```

## Quick start

```bash
# Linux / macOS
python3 -m hexcore server          # open http://127.0.0.1:8765
python3 -m hexcore analyze /bin/ls --json report.json --html report.html
python3 -m hexcore investigate /bin/ls "free"
python3 -m hexcore graph /bin/ls --format html3d --out callgraph-3d.html
python3 -m hexcore pcap capture.pcap
python3 -m hexcore mcp              # MCP server over stdio
python3 -m hexcore legacy analyze app.exe   # original RE Lab Advanced CLI, preserved

# Windows (PowerShell)
python -m hexcore server
python -m hexcore analyze "C:\path\to\app.exe"
```

No dependencies are required for the core. Optional: `pip install capstone pefile pyelftools reportlab` for extra backends and nicer PDF. For full disassembly, install `objdump` (binutils on Linux, LLVM/MinGW on Windows, Xcode CLT on macOS).

## Implementation status

| Module | Status | Notes |
|---|---|---|
| PE/ELF/Mach-O, APK/DEX/IPA/MSI/CAB/ZIP | ✅ Implemented, tested | Legacy parsers + new PE exports/relocations/cert |
| Strings, entropy, imports/exports, dependencies | ✅ Implemented | Export parsing is best-effort for PE |
| Disassembly x86/x86-64 via objdump, Capstone if present | ✅ Implemented | ARM/MIPS/RISC-V only if the backend supports them; not claimed otherwise |
| CFG, xrefs, call graph (2D + 3D), pseudo-C | ✅ Implemented | Heuristic pseudo-C is labelled, not decompiler output |
| Security findings v2 (title, severity, confidence, VA, evidence, impact, fix, FP notes) | ✅ Implemented | Heuristics only, never a confirmed vulnerability / malware verdict |
| Malware triage: YARA-like rules, ATT&CK, IOCs, entropy/section anomalies | ✅ Implemented (lab) | Full YARA needs yara binary/package; Sigma needs telemetry input |
| Network: passive PCAP metadata, flows, DNS, HTTP | ✅ Implemented | PCAPNG is detected, full dissection needs tshark; no live capture |
| Memory: VA↔offset, hex slice/search, section map | ✅ Implemented (static) | Runtime memory is dynamic-only, consent-gated |
| Decompiler adapters: Ghidra/RetDec/Rizin/LLVM | ⚠️ Adapter only | Reports availability; Ghidra headless needs a project dir you provide |
| Dynamic: strace/ltrace/GDB/LLDB adapters | ⚠️ Adapter only, consent-gated | No VM/sandbox is created by HEXCORE; use a disposable VM. ETW/ProcMon and macOS Endpoint Security need native tooling/entitlements |
| UI: dark workstation, tabs, sidebar, inspector, console, Ctrl+K, drag-drop, 2D CFG, 3D graph | ✅ Implemented (web UI) | React/Tauri desktop packaging is Phase 2, not in this delivery |
| MCP: 22 tools, JSON schemas in code, audit via server logs | ✅ Implemented | No unrestricted filesystem access; export tools need an explicit output path |
| Plugins: manifest, permissions, error isolation | ✅ Implemented | Example plugin included; marketplace is Phase 2 |
| Reports: HTML/JSON/Markdown/PDF | ✅ Implemented | PDF is reportlab if installed, otherwise a basic valid PDF (labelled) |
| Tests | ✅ Implemented | `python -m unittest discover -s tests -v` |
| Cross-platform | ⚠️ Partially tested | Tested on Linux here. Windows/macOS use the same Python code; installers provided, desktop installers not yet tested there |

## Security & privacy

- Read-only by default. No patching, no licence bypass, no DRM circumvention, no credential theft, no stealth persistence, no exploitation.
- Local-first: the web UI talks only to localhost. No binary is uploaded to any external service by HEXCORE. AI features in the UI are limited to local summaries; if you paste a report into an external LLM, that is your decision and your data.
- Dynamic analysis requires explicit per-run consent and is refused otherwise.
- Archive extraction is not performed automatically on untrusted files; extract in your lab first.
- See `SECURITY.md`, `MCP.md`, `DEVELOPER.md` in this folder for the full policies.

## Developer docs

- `MCP.md` — tool list, schemas, and how to connect an agent.
- `SECURITY.md` — threat model, safe handling, and reporting a HEXCORE bug.
- `DEVELOPER.md` — how to add a parser, a security rule, a plugin, or a report template.
- `examples/RE-Lab-Engineering-Tutorial.md` — the original engineering tutorial, preserved.

## Licence / branding

**Copyright (c) 2026 SKYTAR. All Rights Reserved.**

HEXCORE is **proprietary, not open source**. No MIT, Apache-2.0, GPL, or
other open-source licence applies. See the full terms in [`LICENSE`](LICENSE):
viewing the repository does not grant a right to copy, modify, distribute,
or use HEXCORE in another product — that requires prior written permission
from SKYTAR, via https://www.shihabskytar.com

Product: HEXCORE by SKYTAR. Tagline: "Decode the Unknown. Understand the Core."
Do not use another cybersecurity company's branding or visual identity. The hexagonal emblem in `hexcore/ui/icon.svg` is original to HEXCORE, and
"HEXCORE", "HEXCORE by SKYTAR" and "SKYTAR" are brand identifiers of SKYTAR.
