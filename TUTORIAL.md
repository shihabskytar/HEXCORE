# HEXCORE — Full Tutorial: How to Use It, Use Cases & Supported OS

**HEXCORE by SKYTAR — Decode the Unknown. Understand the Core.**
https://www.shihabskytar.com — Creator: SKYTAR

> **Smart rule, before anything else:** HEXCORE is for software you own, wrote, or have **written permission** to test — your own app, a lab sample, a CTF challenge, a bug-bounty target in scope, or a sample your SOC / client gave you for triage. Never use it to crack a licence, bypass a trial, steal credentials, or test a system you do not have permission for. Work on a copy, in a VM, with network isolation for unknown samples.

---

## 0. What HEXCORE is in 60 seconds

HEXCORE turns a compiled file back into something a human can reason about:

```
Binary (EXE / APK / MSI / ELF / Mach-O / CAB / DEX / ZIP)
  → Parser (headers, sections, imports, exports)
  → Strings + entropy
  → Disassembly (objdump / Capstone)
  → CFG + call graph (2D + 3D)
  → Pseudo-C summary + security findings (with confidence)
  → Report (HTML / JSON / Markdown / PDF) + MCP for an AI agent
```

It does **not** execute a binary by default, patch it, or generate a licence key. Dynamic analysis is opt-in, consent-gated, and refused without `--allow-run`.

---

## 1. Install — supported OS

HEXCORE core needs only **Python 3.11+**. Everything else is optional and labelled if missing.

| OS | Install Python | Full disassembly | Dynamic tracing | Notes / smart pitfalls |
|---|---|---|---|---|
| **Linux** — Ubuntu / Debian / Kali / Fedora (tested here) | `sudo apt install python3 python3-pip` | `sudo apt install binutils` → `objdump` | `strace`, `ltrace`, `gdb` | Best lab OS. Kali already has most tools. Use a VM snapshot before unknown samples. |
| **Windows 10 / 11** | python.org, tick **Add Python to PATH**, restart terminal | LLVM (`winget install LLVM.LLVM`) or MinGW → `objdump` in PATH | WinDbg / ProcMon in your lab (HEXCORE labels them, it does not replace them) | PowerShell, not double-clicking `.py` files. If Windows blocks a download, right-click → Properties → Unblock. Do **not** disable Defender on your main machine — use a lab VM and exclude only the lab folder there. |
| **macOS** — Intel / Apple Silicon | python.org or `brew install python` | Xcode Command Line Tools: `xcode-select --install` → `objdump`, `lldb` | `lldb`, Instruments in your lab | Gatekeeper will block unsigned lab binaries — right-click → Open once, in the lab only. Apple Silicon vs Intel matters for disassembly: check the Mach-O `cputype` in the report. |
| **WSL (Windows + Linux)** | WSL2 + Ubuntu from Microsoft Store, then follow Linux steps | Same as Linux | Same as Linux, inside WSL | Good compromise on Windows: you get Linux `objdump`/`strace` without leaving Windows. |

### Quick install scripts (in this repo)

```bash
bash install-linux.sh        # Linux
bash install-macos.sh        # macOS
# Windows PowerShell:
#   .\install-windows.ps1
```

Optional Python extras (all optional, core works without them):

```bash
pip install capstone pefile pyelftools reportlab
```

### Verify the install

```bash
python3 --version
python3 -m hexcore analyze /bin/ls          # Linux/macOS, or any .exe on Windows
# Expected: Format, size, SHA-256, sections, strings, functions, findings
python3 -m hexcore server                   # open http://127.0.0.1:8765
```

If `objdump` is missing, HEXCORE still runs and says disassembly is unavailable — headers, sections, imports, strings and findings still work. That is by design, not a bug.

---

## 2. How to use it — the smart workflow

A hacker / specialist does not start by running everything. Start with a hypothesis, then use HEXCORE to prove or kill it.

### Step 1 — Identify (30 seconds)

```bash
python3 -m hexcore analyze sample.exe --json report.json
```

Read, in order: **format → architecture → hashes → sections → imports → findings**.
Ask: Is this PE32 or PE64? Is it packed (high-entropy section, WX section)? What libraries does it import? What does the risk score actually say, and at what confidence?

```bash
python3 -m hexcore legacy analyze sample.exe   # original RE Lab Advanced CLI, preserved
```

### Step 2 — Strings first, always

Strings are the fastest triage in the world. Before you read assembly, search for what the program talks about:

```bash
python3 -m hexcore investigate sample.exe "login"
python3 -m hexcore investigate sample.exe "http"
python3 -m hexcore investigate sample.exe "password"
```

In the web UI: **Binary Analysis → load file → Functions / Findings**, or use the MCP tool `search_strings`.

**Smart tip:** A string that looks like a secret is a *lead*, not a verdict. Check if it is actually used, where it is referenced (xrefs), and whether it is a test value, a default, or a real credential. Rotate it if it is real — do not publish it in a report.

### Step 3 — Follow the call graph, don't read linearly

```bash
python3 -m hexcore graph sample.exe --format dot > graph.dot
python3 -m hexcore graph sample.exe --format html3d --out callgraph-3d.html
# Open callgraph-3d.html in a browser: drag to rotate, scroll to zoom
```

Reading: a hub with many incoming edges is a shared helper (logging, allocation, crypto). A chain `feature → helper → import` is the story of that feature. A lone node far from the main cluster is worth a second look — dead code, an optional feature, or something hidden — but it is not proof of malice.

In the UI: **Call Graph (3D)** does the same thing, and **Control Flow Graph (2D)** shows blocks and jumps for one function at a time.

### Step 4 — Read one function properly

```bash
# CLI / MCP
python3 -m hexcore mcp
# then, as JSON-RPC:
#   get_function {"path":"sample.exe","name":"malloc"}
#   disassemble_function {"path":"sample.exe","name":"login"}
#   get_xrefs {"path":"sample.exe","address":"0x401000"}
```

In the UI: **Disassembler → click a row → Inspector** on the right shows address, mnemonic, operands and function. **Decompiler** shows the heuristic pseudo-C summary — labelled as heuristic, *not* Ghidra output. For a real decompilation, use the decompiler adapter:

```bash
# HEXCORE will tell you if Ghidra / Rizin / RetDec is installed, or not
python3 -m hexcore mcp
#   decompile_function {"path":"sample.exe","tool":"rizin"}
```

**Smart tip for stripped binaries:** if one function has 500+ instructions, HEXCORE warns you — several real functions are probably merged under one label. Use Ghidra for function recovery there, and treat the summary as a block, not a function.

### Step 5 — Findings: triage, don't panic

Every HEXCORE v2 finding has: title, severity, **confidence**, function, VA, evidence, impact, remediation, and false-positive notes. Triage like this:

| Confidence | What to do |
|---|---|
| High + High severity | Verify first, fix first. Example: a WX section, or `strcpy` on attacker-controlled input with no length check. |
| Medium | Check the call site. Is the length checked? Is the crypto used for security or just a checksum? |
| Low | Note it, move on unless other evidence piles up. Imports alone are not a vulnerability, and entropy alone is not malware. |

Example workflow for an unsafe import:

1. `investigate sample.exe "strcpy"` → which functions call it?
2. Read the caller in pseudo-C / disassembly → is the source length bounded?
3. Fix in **source** (e.g. `strcpy_s` / `strncpy_s` with a size, check the return), rebuild.
4. Prove it: `python3 -m hexcore compare sample-old.exe sample-new.exe` → `strcpy` should disappear from `imports_only_in_a`, and the risk score should drop.

### Step 6 — Dynamic analysis, only when you mean it

Default: HEXCORE **refuses** to run a sample. That is a safety feature.

```bash
# Linux, lab VM only, trusted sample only:
python3 -m hexcore legacy trace sample --allow-run
# Without --allow-run, you get a refusal, not a trace.
```

Checklist before any dynamic run:
- [ ] Snapshot the VM, so you can roll back.
- [ ] Network isolated or host-only, unless the test genuinely needs network.
- [ ] Sample hash recorded before and after.
- [ ] Timeout set (HEXCORE defaults to 10 seconds for traces).
- [ ] You know what the sample is supposed to do — if it does something else, stop and triage it statically first.

On Windows, use WinDbg / ProcMon in your lab; on macOS, LLDB / Instruments. HEXCORE's dynamic panel tells you which of those are present on your machine and which are not — it does not pretend to be them.

### Step 7 — Report like a professional

```bash
python3 -m hexcore analyze sample.exe --json report.json --html report.html --pdf report.pdf --markdown report.md
# Or via MCP:
#   export_report {"path":"sample.exe","format":"html","out":"report.html"}
```

A good report always contains: sample hashes, format, architecture, sections, imports/exports, functions, findings with confidence, methodology, limitations, and remediation. Never write “this is malware” from heuristics alone. Write “these indicators were observed, at this confidence, with this evidence, and this is what to verify next.”

---

## 3. Use cases — as a hacker / cybersecurity specialist

### Use case 1 — SOC triage: “Is this file suspicious?” (15 minutes)

1. Hash it, analyse it, read findings + IOCs (IPs, domains, URLs from strings).
2. Check section entropy, WX sections, anti-debug imports, persistence strings, ATT&CK mapping.
3. Extract IOCs, check them against your threat intel (HEXCORE does not do reputation lookup by itself — plug in your own service, see `SECURITY.md`).
4. Decide: benign, needs sandbox dynamic analysis, or escalate. Document confidence, not just a verdict.

**Commands:** `analyze`, `investigate`, MCP `get_security_findings`, MCP `analyze_binary`.

### Use case 2 — Your own app: “Why does this feature do that?”

The REA-style question, applied to your own code. Example: a calculator's `%` button, a game's speed rule, or your app's export function.

1. `investigate app.exe "export"` → matched strings + functions + 1-hop neighbours.
2. Follow the call chain in the 3D graph, read pseudo-C for each function.
3. Rebuild the rule in a small test program and check it against the original behaviour.
4. If the behaviour is a bug, fix it in source, then `compare` old vs new to prove the change.

**Commands:** `investigate`, `graph --format html3d`, `compare`.

### Use case 3 — Secure code review before release

Run HEXCORE on every release candidate in CI (as a script, not as a gate that blocks on heuristics alone):

```bash
python3 -m hexcore analyze app.exe --json ci-report.json
# Fail the build only on High-confidence, High-severity findings you have
# reviewed — otherwise, file the Medium/Low findings as tickets.
```

Look for: unsafe functions, weak crypto, hard-coded secrets, missing ASLR/DEP/CFG flags, WX sections. Fix in source, rebuild, compare.

### Use case 4 — Patch diffing / vulnerability research (authorized)

You have a vulnerable version and a patched version, with permission to test both.

```bash
python3 -m hexcore compare app-vuln.exe app-patched.exe --json diff.json
```

Look at: functions that changed, imports added/removed, strings that disappeared, and the call graph around the changed function. That diff is often where the vulnerability was — and where the fix is. This is how specialists learn a patch without reading the whole binary twice.

### Use case 5 — Android app pentest (in scope, with permission)

1. Analyse the APK: `python3 -m hexcore analyze app.apk` → entries, DEX header counts (strings, types, methods, classes), native `.so` list.
2. Extract a native `.so` and analyse *that* file separately — HEXCORE tells you to do this, it does not pretend an APK is a single executable.
3. For DEX code itself, use jadx / apktool in your lab for full decompilation; HEXCORE gives you the container, counts, and strings to start from.
4. For the manifest (binary AXML), use apktool / androguard for full decoding.

**Never** test an APK you do not have permission for, and never republish a modified APK.

### Use case 6 — Incident response: PCAP triage

```bash
python3 -m hexcore pcap capture.pcap
# Or in the UI: Network Analysis → load a .pcap file
```

You get: packet count, flows (src/dst/port/proto/count), DNS names, HTTP first lines (metadata only, no bodies, no credentials). Use it to answer: Who talked to whom? When? On what port? What DNS names were looked up? Then use Wireshark / tshark for full dissection. HEXCORE does not decrypt TLS and does not do live capture.

### Use case 7 — YARA lab / threat hunting

Write a simple rule in HEXCORE's YARA-like format (see `security.py` for the exact schema), test it against a lab sample, then promote it to real YARA in your lab:

```json
{"id": "test-rule", "name": "Suspicious string", "strings": [{"id": "s1", "text": "secret"}], "condition": "any"}
```

In the UI: **YARA Laboratory** tests a string against the loaded binary's strings (client-side, labelled as not full YARA). In the CLI / MCP, use the rule format above. A rule that matches is a lead for hunting, not a detection verdict on its own.

### Use case 8 — AI-assisted investigation (MCP)

```bash
python3 -m hexcore mcp
```

Connect a coding agent that supports MCP over stdio, then ask it, with evidence:

- “What does this function appear to do?” → `get_function`
- “Find references to this function.” → `get_xrefs`
- “Explain this call graph.” → `get_call_graph`
- “Summarise the binary architecture.” → `analyze_binary` + `list_sections`
- “Compare these two versions.” → `compare_binaries`
- “Explain this security finding.” → `get_security_findings`

**Rule for the agent:** it must only use evidence from the workspace, with addresses and confidence levels. If it cannot find evidence, it must say so — it must not fabricate disassembly, function names, or vulnerabilities. HEXCORE never uploads your binary to an external AI service; if you paste a report into an external LLM, that is your data decision.

### Use case 9 — CTF / learning lab

HEXCORE is ideal for learning because it is small enough to read: start with a program *you* wrote, compile it, analyse it, and compare what you wrote to what HEXCORE sees. Then try a CTF binary (with the challenge's permission, which is the point of a CTF):

1. Strings → what is it talking about?
2. Functions → where is the check / flag logic?
3. CFG → what branches lead to success?
4. Pseudo-C → can you reconstruct the logic in Python and test it?
5. Fix / rebuild the logic yourself — that is the skill, not just finding the flag.

### Use case 10 — Supply-chain / dependency audit

Analyse a release binary and its dependencies:

- What DLLs / `.so` files does it load? (`list_imports`, `dependencies`)
- Are any of those known-vulnerable versions? (Check against your own vulnerability database — HEXCORE lists the names, it does not do reputation lookup by itself.)
- Are sections, certificates, and hardening flags what you expect for a release build? (PE certificate directory, ASLR/DEP/CFG flags.)
- Did the new release add a new network import or a new persistence string that was not in the old release? (`compare`)

---

## 4. Supported OS — smart tips by platform

### Linux — the specialist's home turf

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install -y python3 binutils strace ltrace gdb
python3 -m hexcore server
```

- Use `objdump`, `readelf`, `strings`, `strace` alongside HEXCORE — they are the same tools HEXCORE wraps, and knowing them makes HEXCORE's output make sense.
- For ARM / MIPS / RISC-V binaries, you need a backend that supports that architecture (Capstone with that arch, or a cross `objdump`). HEXCORE will not pretend x86 disassembly works on ARM code.
- Kali + VM snapshot = the safest lab. Snapshot before, roll back after.

### Windows — where most targets live

```powershell
# PowerShell, as a normal user (not as Administrator, unless installing a tool needs it)
python --version
winget install LLVM.LLVM
objdump --version
python -m hexcore server
```

- Paths with spaces need quotes: `python -m hexcore analyze "C:\My Apps\app.exe"`.
- Execution Policy will block `.ps1` install scripts on some machines: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` in your lab, or right-click → Run with PowerShell.
- Defender SmartScreen may flag an unsigned lab binary — that is *its job*. In a lab VM, you can allow it there; do not turn off protection on your main machine to analyse a sample.
- For PE files, check: certificate directory, ASLR/DEP/CFG flags, imports, and whether the entry point is in the last section (a packed-binary hint).

### macOS — the one people forget

```bash
xcode-select --install
python3 -m hexcore server
```

- Mach-O is not PE or ELF: segments, load commands, and `cputype` matter. HEXCORE parses Mach-O headers and sections; for full disassembly, use the Mach-O backend in your lab.
- Apple Silicon (arm64) vs Intel (x86_64) binaries are different architectures — a Universal binary contains both, and HEXCORE will show you the first header it parses. Analyse each slice separately if you need both.
- Codesigning: a valid signature does not mean safe, and a missing signature does not mean malicious. HEXCORE reports certificate presence for PE; for Mach-O, check signing in your lab with `codesign -dv`.

### Cross-platform pitfalls (the “smart” part)

| Pitfall | Fix |
|---|---|
| Line endings (CRLF vs LF) in scripts | Use `python` (not `cmd`) to run HEXCORE; it handles both. For batch files, keep CRLF on Windows. |
| Path separators (`\` vs `/`) | Quote paths, use forward slashes in Python where possible, or `Path` objects. |
| Case sensitivity | Linux/macOS filesystems differ from Windows. `App.exe` ≠ `app.exe` on Linux. |
| Python version | HEXCORE needs 3.11+. `python` on some systems is still 2.x — use `python3` on Linux/macOS, `py -3` on Windows if needed. |
| Large binaries | HEXCORE caps disassembly at 10,000 instructions by default. For a huge binary, analyse one section / function at a time, or raise the limit in config explicitly. |
| Stripped binaries | Expect merged functions, missing names, and a warning on blocks over 500 instructions. Use Ghidra for recovery. |

---

## 5. Command cheat sheet

```bash
# Analyse
python3 -m hexcore analyze app.exe [--json r.json] [--html r.html] [--pdf r.pdf] [--markdown r.md]
python3 -m hexcore legacy analyze app.exe

# Investigate one feature
python3 -m hexcore investigate app.exe "login"
python3 -m hexcore legacy investigate app.exe "login"

# Graphs
python3 -m hexcore graph app.exe --format dot > graph.dot
python3 -m hexcore graph app.exe --format json
python3 -m hexcore graph app.exe --format html3d --out callgraph-3d.html
python3 -m hexcore html app.exe --out re-report.html   # also writes callgraph-3d.html

# Compare, PCAP, REPL, MCP, Server
python3 -m hexcore compare old.exe new.exe [--json diff.json]
python3 -m hexcore pcap capture.pcap
python3 -m hexcore repl
python3 -m hexcore mcp
python3 -m hexcore server [--port 8765]

# Legacy modes (preserved)
python3 -m hexcore legacy repl
python3 -m hexcore legacy trace sample --allow-run   # Linux, lab VM only
```

On Windows, replace `python3` with `python`.

---

## 6. Troubleshooting — smart, not lucky

| Symptom | Likely cause | Fix |
|---|---|---|
| `python: command not found` | Python not in PATH | Reinstall with “Add Python to PATH”, restart terminal |
| Window closes instantly | Double-clicking a `.py` file | Run from a terminal, or use `Run-RE-Lab-Windows.cmd` / the HEXCORE server |
| “Disassembly unavailable” | No `objdump` / Capstone | Install binutils / LLVM / Xcode CLT; headers/strings/findings still work |
| One huge function (500+ instr) | Stripped binary | Use Ghidra; treat the block as merged functions |
| No functions, but strings work | Container (APK/MSI/ZIP), not a raw exe | Extract the inner `.so` / `.exe` / DEX and analyse that |
| `trace` refuses | No `--allow-run`, or no `strace` | By design. Only in a lab VM, on a trusted sample, on Linux |
| MCP client gets no reply | You sent a notification (no `id`) | Send a request with an `id`; notifications get no response by design |
| PCAPNG shows only a note | Full PCAPNG needs tshark | Use `tshark -r file -T json` in your lab for full dissection |

---

## 7. Ethics, evidence, and reporting — the specialist's standard

1. **Permission first.** No permission = no test. A bug bounty scope, a client contract, a CTF, or your own code — pick one and stay inside it.
2. **Evidence, not vibes.** Every claim in a report needs an address, a string, an import, or a call chain. If you cannot point to it, do not claim it.
3. **Confidence is part of the finding.** High / Medium / Low is not decoration — it tells the reader how much to trust it and what to verify next.
4. **Do not publish secrets.** If you find a real credential, rotate it, tell the owner privately, and redact it from any public report.
5. **Responsible disclosure.** Report a vulnerability to the vendor through their official channel, give them time to fix it, and only then publish — with a reproduction on a version you were allowed to test.
6. **Keep the chain.** Record hash before, hash after, tool version, commands run, and VM snapshot name. A finding you cannot reproduce is a story, not evidence.

---

*Copyright (c) SKYTAR — https://www.shihabskytar.com*
*HEXCORE by SKYTAR — Decode the Unknown. Understand the Core.*
*This tutorial is for authorized security research, learning, and defensive analysis only.*
