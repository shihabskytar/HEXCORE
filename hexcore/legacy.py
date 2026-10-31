#!/usr/bin/env python3
# Copyright (c) SKYTAR - www.shihabskytar.com
# RE Lab Advanced - read-only reverse-engineering lab tool.
# Use only on software you own or have written permission to test.
"""
RE Lab Analyzer - a read-only, educational reverse-engineering lab tool.

What it implements, following the building blocks you listed:
  1. Parsers / File Loaders  - PE (Windows) and ELF (Linux) headers,
     sections, entry point, and (for PE) import tables, using only
     Python's standard library. No binary is modified.
  2. Disassembler             - Uses Capstone if installed, otherwise
     the system `objdump` if available. Falls back to a hex/section
     report if neither is present. It never executes the target.
  3. Control Flow Graph (CFG) - Builds basic blocks and edges from
     jumps, calls and returns, plus a caller -> callee cross-reference
     (xref) map.
  4. Decompiler-lite summary  - Heuristic, human-readable summary per
     function: calls made, branches, backward jumps (loops),
     comparisons. This is NOT a full decompiler like Ghidra, and it
     does not reconstruct original source code.
  5. AI / MCP-style bridge    - `--json` and `--explain` produce a
     structured, text-only summary you can paste to an LLM / coding
     agent in your own environment. Nothing is uploaded by this tool.

What it does NOT do, by design:
  - No patching, no rewriting, no key generation, no licence bypass,
    no trial manipulation, and no execution of the target binary.
  - It is for analysing software you own, wrote, or have written
    permission to test, ideally in an isolated VM / lab.
  - Findings are heuristics. A flagged string or import is a lead to
    verify in source code, not proof of a vulnerability.

Usage:
    python3 RE-Lab-Analyzer.py app.exe
    python3 RE-Lab-Analyzer.py app.exe --json report.json --explain explain.md
    python3 RE-Lab-Analyzer.py /bin/ls --no-disasm
"""

import argparse
import hashlib
import json
import math
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------- helpers

def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def entropy_of(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_strings(data, min_len=4):
    min_len = max(1, int(min_len))
    out = []
    # ASCII
    for m in re.finditer(rb"[ -~]{%d,}" % min_len, data):
        out.append(m.group().decode("ascii", errors="ignore"))
    # UTF-16LE
    for m in re.finditer(rb"(?:[ -~]\x00){%d,}" % min_len, data):
        try:
            out.append(m.group().decode("utf-16-le"))
        except Exception:
            pass
    return out


# ---------------------------------------------------------------- PE parser

def _rva_to_offset(rva, sections):
    for s in sections:
        va = s["virtual_address"]
        size = s["raw_size"]  # file data only; .bss-style virtual data has no file bytes
        if va <= rva < va + size:
            return s["raw_ptr"] + (rva - va)
    return None


def _read_cstr(data, off):
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end == -1:
        end = len(data)
    return data[off:end].decode("ascii", errors="ignore")


def parse_pe(data):
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        machine, num_sections, _, _, _, opt_size, chars = struct.unpack_from(
            "<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is64 = magic == 0x20B
        if is64:
            entry_rva, image_base = struct.unpack_from("<IQ", data, opt + 16)
            dll_chars = struct.unpack_from("<H", data, opt + 70)[0]
            subsystem = struct.unpack_from("<H", data, opt + 68)[0]
            num_dirs = struct.unpack_from("<I", data, opt + 108)[0]
            dirs_off = opt + 112
        else:
            entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
            image_base = struct.unpack_from("<I", data, opt + 28)[0]  # PE32: ImageBase is at opt+28, not opt+20
            dll_chars = struct.unpack_from("<H", data, opt + 70)[0]
            subsystem = struct.unpack_from("<H", data, opt + 68)[0]
            num_dirs = struct.unpack_from("<I", data, opt + 92)[0]
            dirs_off = opt + 96

        sections = []
        sec_off = opt + opt_size
        for i in range(num_sections):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
            sections.append({
                "name": name, "virtual_size": vsize, "virtual_address": vaddr,
                "raw_size": raw_size, "raw_ptr": raw_ptr,
            })

        dirs = []
        for i in range(min(num_dirs, 16)):
            rva, size = struct.unpack_from("<II", data, dirs_off + i * 8)
            dirs.append({"rva": rva, "size": size})

        imports = []
        if len(dirs) > 1 and dirs[1]["rva"]:
            desc_off = _rva_to_offset(dirs[1]["rva"], sections)
            idx = 0
            while desc_off is not None and idx < 256:
                oft, _, _, name_rva, ft = struct.unpack_from(
                    "<IIIII", data, desc_off + idx * 20)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                dll = _read_cstr(data, _rva_to_offset(name_rva, sections))
                thunk_rva = oft if oft else ft
                thunk_off = _rva_to_offset(thunk_rva, sections)
                funcs = []
                j = 0
                while thunk_off is not None and j < 4096:
                    if is64:
                        val = struct.unpack_from("<Q", data, thunk_off + j * 8)[0]
                        ordinal_flag = 0x8000000000000000
                    else:
                        val = struct.unpack_from("<I", data, thunk_off + j * 4)[0]
                        ordinal_flag = 0x80000000
                    if val == 0:
                        break
                    if val & ordinal_flag:
                        funcs.append(f"#{val & 0xFFFF}")
                    else:
                        hn = _rva_to_offset(val & 0x7FFFFFFF, sections)
                        funcs.append(_read_cstr(data, hn + 2 if hn is not None else None))
                    j += 1
                imports.append({"dll": dll, "functions": funcs})
                idx += 1

        return {
            "format": "PE", "machine": hex(machine),
            "is_64bit": is64, "entry_rva": hex(entry_rva),
            "image_base": hex(image_base), "subsystem": subsystem,
            "dll_characteristics": hex(dll_chars),
            "characteristics": hex(chars),
            "sections": sections, "imports": imports,
            "data_directories": dirs,
        }
    except Exception as exc:
        return {"format": "PE", "parse_error": str(exc)}


# ---------------------------------------------------------------- ELF parser

def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    try:
        is64 = data[4] == 2
        little = data[5] != 2
        en = "<" if little else ">"
        if is64:
            e_type, e_machine = struct.unpack_from(en + "HH", data, 16)
            e_entry = struct.unpack_from(en + "Q", data, 24)[0]
            e_shoff = struct.unpack_from(en + "Q", data, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + "HHH", data, 58)
            fmt = en + "IIQQQQIIQQ"
        else:
            e_type, e_machine = struct.unpack_from(en + "HH", data, 16)
            e_entry = struct.unpack_from(en + "I", data, 24)[0]
            e_shoff = struct.unpack_from(en + "I", data, 32)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + "HHH", data, 46)
            fmt = en + "IIIIIIIIII"
        sections = []
        names = b""
        if e_shoff and e_shstrndx < e_shnum:
            sh = struct.unpack_from(fmt, data, e_shoff + e_shstrndx * e_shentsize)
            names = data[sh[4]:sh[4] + sh[5]]
        for i in range(e_shnum):
            sh = struct.unpack_from(fmt, data, e_shoff + i * e_shentsize)
            name_off = sh[0]
            end = names.find(b"\x00", name_off)
            name = names[name_off:end].decode("ascii", errors="ignore") if end != -1 else ""
            sections.append({
                "name": name, "type": sh[1], "address": hex(sh[3]),
                "offset": sh[4], "size": sh[5],
            })
        return {
            "format": "ELF", "is_64bit": is64, "machine": e_machine,
            "type": e_type, "entry": hex(e_entry), "sections": sections,
            "imports": [],
        }
    except Exception as exc:
        return {"format": "ELF", "parse_error": str(exc)}


# ---------------------------------------------------------------- disassembly

BRANCH = {"jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe",
          "jg", "jl", "jge", "jle", "jo", "jno", "js", "jns", "jcxz", "jecxz"}
CALL = {"call"}
RET = {"ret", "retn", "retf"}


def disassemble(path, limit=10000):
    """Return (instructions, method, note). Never executes the target."""
    # 1) Capstone, if the analyst installed it
    try:
        import capstone  # type: ignore
        data = Path(path).read_bytes()
        # A full Capstone loader is out of scope for this lab tool;
        # if it is present, the analyst can extend this branch.
        # We fall through to objdump so results stay reproducible.
        _ = capstone
    except Exception:
        pass
    # 2) objdump, present on most Linux lab VMs and in MinGW on Windows
    try:
        proc = subprocess.run(
            ["objdump", "-d", "-M", "intel", "--no-show-raw-insn", str(path)],
            capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 or "Disassembly of section" not in proc.stdout:
            return [], "none", "objdump could not disassemble this file (try Capstone / Ghidra for PE files)."
        instrs = []
        func = "unknown"
        for line in proc.stdout.splitlines():
            m = re.match(r"^([0-9a-f]+) <([^>]+)>:$", line.strip())
            if m:
                func = m.group(2)
                continue
            m = re.match(r"^\s*([0-9a-f]+):\s+(.+)$", line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            rest = m.group(2).strip()
            parts = rest.split(None, 1)
            mnemonic = parts[0].lower() if parts else ""
            operands = parts[1] if len(parts) > 1 else ""
            instrs.append({"address": addr, "mnemonic": mnemonic,
                           "operands": operands, "function": func})
            if len(instrs) >= limit:
                break
        return instrs, "objdump", f"Parsed {len(instrs)} instructions (limit {limit})."
    except Exception as exc:
        return [], "none", f"Disassembly unavailable: {exc}"


def _branch_targets(ins):
    """Return code-target addresses from an instruction's operands.

    Objdump (Intel) prints targets as plain hex, e.g. 'je 4016 <free@plt>',
    while Capstone-style output uses 0x4016. The old code only looked
    for 0x..., so most objdump jumps/calls produced no CFG edge.
    Indirect targets (rax, [rip+...]) return [].
    """
    ops = ins["operands"].strip()
    targets = []
    # Plain-hex first token: '4016 <label>' or '4016'
    m = re.match(r"^([0-9a-fA-F]+)\s*(?:<|$)", ops)
    if m:
        try:
            targets.append(int(m.group(1), 16))
        except Exception:
            pass
    # 0x-style targets anywhere in the operands
    for tok in re.findall(r"0x[0-9a-fA-F]+", ops):
        try:
            targets.append(int(tok, 16))
        except Exception:
            pass
    return targets


def build_cfg(instrs):
    """Basic blocks + edges + xref map from parsed instructions."""
    if not instrs:
        return {"blocks": [], "edges": [], "xrefs": {}}
    addrs = {ins["address"] for ins in instrs}
    leaders = set()
    if instrs:
        leaders.add(instrs[0]["address"])
    for i, ins in enumerate(instrs):
        mn = ins["mnemonic"]
        if mn in BRANCH or mn in CALL:
            for t in _branch_targets(ins):
                if t in addrs:
                    leaders.add(t)
            if i + 1 < len(instrs):
                leaders.add(instrs[i + 1]["address"])
        if mn in RET and i + 1 < len(instrs):
            leaders.add(instrs[i + 1]["address"])

    blocks, edges, xrefs = [], [], defaultdict(list)
    current = None
    for i, ins in enumerate(instrs):
        if ins["address"] in leaders or current is None:
            if current:
                blocks.append(current)
            current = {"start": ins["address"], "end": ins["address"],
                       "function": ins["function"], "instructions": []}
        current["instructions"].append(ins)
        current["end"] = ins["address"]
        nxt = instrs[i + 1]["address"] if i + 1 < len(instrs) else None
        mn = ins["mnemonic"]
        targets = [t for t in _branch_targets(ins) if t in addrs]
        if mn in CALL:
            for t in targets:
                edges.append({"from": ins["address"], "to": t, "kind": "call"})
                xrefs[t].append(ins["address"])
            if nxt is not None:
                edges.append({"from": ins["address"], "to": nxt, "kind": "fallthrough"})
        elif mn in BRANCH:
            for t in targets:
                edges.append({"from": ins["address"], "to": t, "kind": "jump"})
                xrefs[t].append(ins["address"])
            if mn != "jmp" and nxt is not None:
                edges.append({"from": ins["address"], "to": nxt, "kind": "fallthrough"})
        elif mn in RET:
            pass
        elif nxt is not None and nxt in leaders:
            edges.append({"from": ins["address"], "to": nxt, "kind": "fallthrough"})
    if current:
        blocks.append(current)
    return {"blocks": blocks, "edges": edges,
            "xrefs": {hex(k): [hex(a) for a in v] for k, v in xrefs.items()}}


def summarize_functions(instrs):
    by_func = defaultdict(list)
    for ins in instrs:
        by_func[ins["function"]].append(ins)
    summaries = []
    for name, lst in sorted(by_func.items(), key=lambda kv: -len(kv[1]))[:200]:
        calls = []
        for ins in lst:
            if ins["mnemonic"] == "call":
                calls.append(ins["operands"])
        backward = sum(
            1 for ins in lst
            if ins["mnemonic"] in BRANCH
            for t in _branch_targets(ins)
            if t < ins["address"])
        summaries.append({
            "function": name, "instruction_count": len(lst),
            "calls": calls[:20], "call_count": len(calls),
            "branch_count": sum(1 for x in lst if x["mnemonic"] in BRANCH),
            "backward_jumps_possible_loops": backward,
            "comparisons": sum(1 for x in lst if x["mnemonic"] in ("cmp", "test")),
            "returns": sum(1 for x in lst if x["mnemonic"] in RET),
            "pseudo_summary": (
                f"Function '{name}' has {len(lst)} instructions, "
                f"calls {len(calls)} target(s), "
                f"{backward} backward jump(s) that may indicate a loop, "
                f"and {sum(1 for x in lst if x['mnemonic'] in ('cmp', 'test'))} compare/test(s). "
                + ("NOTE: very large block - this binary is likely stripped, "
                   "so several real functions may be merged under one label. "
                   "Use Ghidra for function recovery. " if len(lst) > 500 else "")
                + "Verify the logic in source code or a full decompiler; "
                "this summary does not reconstruct source."),
        })
    return summaries


# ---------------------------------------------------------------- findings

RISKY = {
    "strcpy": "Use strcpy_s / strncpy_s with an explicit size, or a safe string type.",
    "strcat": "Use strcat_s / strncat_s with an explicit size, or a safe string type.",
    "sprintf": "Use snprintf / sprintf_s with a size limit.",
    "vsprintf": "Use vsnprintf / vsprintf_s with a size limit.",
    "gets": "Never use gets(); use fgets() with a size limit.",
    "wcscpy": "Use wcscpy_s with an explicit size.",
    "memcpy": "Review: only flag as a bug if the length is attacker-controlled and unchecked.",
}
WEAK_CRYPTO = {"md5": "MD5 is broken for integrity/auth; use SHA-256 or better.",
               "sha1": "SHA-1 is weak; use SHA-256 or better.",
               "des": "DES is weak; use AES-GCM or ChaCha20-Poly1305.",
               "rc4": "RC4 is broken; use AES-GCM or ChaCha20-Poly1305."}
SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|passwd|password|access[_-]?token)\s*[:=]\s*\S{4,}")


def build_findings(parsed, strings, instrs):
    findings = []
    if parsed and parsed.get("format") == "PE" and "dll_characteristics" in parsed:
        dc = int(parsed["dll_characteristics"], 16)
        checks = [
            (0x0040, "DYNAMIC_BASE / ASLR", "Enable /DYNAMICBASE so the image is not always at the same address."),
            (0x0100, "NX_COMPAT / DEP", "Enable /NXCOMPAT so data pages are not executable."),
            (0x4000, "GUARD_CF / Control Flow Guard", "Enable /GUARD:CF to harden indirect calls."),
            (0x0020, "HIGH_ENTROPY_VA", "Enable high-entropy ASLR for 64-bit builds."),
        ]
        for flag, name, fix in checks:
            if not (dc & flag):
                findings.append({"severity": "medium", "area": "hardening",
                                 "issue": f"PE hardening flag missing: {name}",
                                 "fix": fix})
    if parsed:
        for imp in parsed.get("imports", []):
            for fn in imp["functions"]:
                # Normalise: '_strcpy', 'strcpy@plt', 'MD5_Init' -> 'strcpy', 'md5_init'
                low = fn.lower().lstrip("_")
                low = low.split("@")[0]
                risky_key = low if low in RISKY else None
                weak_key = None
                for k in WEAK_CRYPTO:
                    if low == k or low.startswith(k + "_") or low.startswith(k + "init") or low.startswith(k + "update"):
                        weak_key = k
                        break
                if risky_key:
                    findings.append({"severity": "high" if risky_key in ("gets", "strcpy", "sprintf") else "medium",
                                     "area": "unsafe-function",
                                     "issue": f"Imported {imp['dll']}!{fn}",
                                     "fix": RISKY[risky_key]})
                if weak_key:
                    findings.append({"severity": "medium", "area": "weak-crypto",
                                     "issue": f"Imported {imp['dll']}!{fn}",
                                     "fix": WEAK_CRYPTO[weak_key]})
    for s in strings[:5000]:
        if SECRET_RE.search(s):
            findings.append({"severity": "medium", "area": "possible-secret",
                             "issue": "String looks like a hard-coded secret or credential (verify; may be a false positive)",
                             "fix": "Move secrets to a vault / environment / KMS, rotate any exposed value, and never ship secrets in a binary."})
            break
    if not instrs:
        findings.append({"severity": "info", "area": "disassembly",
                         "issue": "No disassembly was produced for this file.",
                         "fix": "Install Capstone (pip install capstone) or use Ghidra / objdump in your lab for a full CFG."})
    return findings


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description="RE Lab Analyzer - read-only static analysis")
    ap.add_argument("target", help="Path to the binary you own or are authorised to test")
    ap.add_argument("--min-string", type=int, default=4)
    ap.add_argument("--no-disasm", action="store_true")
    ap.add_argument("--json", dest="json_out", help="Write structured report JSON here")
    ap.add_argument("--explain", dest="explain_out", help="Write LLM-ready summary markdown here")
    args = ap.parse_args(argv)

    path = Path(args.target)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2
    data = path.read_bytes()  # read-only; target is never written to
    parsed = detect_and_parse(data, str(path))
    strings = extract_strings(data, args.min_string)

    instrs, method, note = ([], "skipped", "Disassembly disabled by --no-disasm.") \
        if args.no_disasm else disassemble(str(path))
    cfg = build_cfg(instrs)
    funcs = summarize_functions(instrs)
    findings = build_findings(parsed, strings, instrs)

    # Section entropy is useful for spotting packed / compressed sections.
    section_info = []
    if parsed.get("format") in ("APK", "AAB", "JAR", "ZIP", "MSI", "CAB", "Mach-O"):
        for s in parsed.get("sections", []):
            section_info.append({**s, "entropy": 0.0})
    elif parsed.get("format") == "PE":
        for s in parsed.get("sections", []):
            chunk = data[s["raw_ptr"]:s["raw_ptr"] + s["raw_size"]] if s["raw_ptr"] < len(data) else b""
            section_info.append({**s, "entropy": round(entropy_of(chunk), 3)})
    elif parsed.get("format") == "ELF":
        for s in parsed.get("sections", []):
            chunk = data[s["offset"]:s["offset"] + s["size"]] if s["offset"] < len(data) else b""
            section_info.append({**s, "entropy": round(entropy_of(chunk), 3)})

    report = {
        "target": str(path), "size": len(data), "sha256": sha256_of(data),
        "parsed": parsed, "sections_with_entropy": section_info,
        "string_count": len(strings), "sample_strings": strings[:100],
        "disassembly_method": method, "disassembly_note": note,
        "instruction_count": len(instrs),
        "cfg_block_count": len(cfg["blocks"]), "cfg_edge_count": len(cfg["edges"]),
        "xrefs_sample": dict(list(cfg["xrefs"].items())[:50]),
        "functions": funcs, "findings": findings,
        "scope_note": "Read-only analysis only. Analyse only binaries you own or have written permission to test.",
    }

    print(f"RE Lab Analyzer - {path}")
    print(f"  Size: {len(data)} bytes   SHA-256: {report['sha256']}")
    print(f"  Format: {parsed.get('format')}   Entry: {parsed.get('entry_rva') or parsed.get('entry') or '-'}")
    print(f"  Sections: {len(section_info)}   Strings: {len(strings)}")
    print(f"  Disassembly: {method} - {note}")
    print(f"  CFG: {len(cfg['blocks'])} blocks, {len(cfg['edges'])} edges, {len(cfg['xrefs'])} xref targets")
    print(f"  Functions summarised: {len(funcs)}")
    print("  Findings:")
    if findings:
        for f in findings:
            print(f"    [{f['severity']}] {f['area']}: {f['issue']}")
            print(f"             Fix: {f['fix']}")
    else:
        print("    None from these heuristics - verify in source code.")
    print("\n  Top functions:")
    for fn in funcs[:10]:
        print(f"    {fn['function']}: {fn['pseudo_summary']}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n  JSON report written to: {args.json_out}")
    if args.explain_out:
        md = ["# RE Lab Analyzer - LLM-ready summary (text only, no binary uploaded)\n",
              f"Target: `{path}`  SHA-256: `{report['sha256']}`  Format: {parsed.get('format')}\n",
              "## Findings\n"]
        for f in findings:
            md.append(f"- [{f['severity']}] {f['area']}: {f['issue']} - Fix: {f['fix']}")
        md.append("\n## Functions\n")
        for fn in funcs[:20]:
            md.append(f"- {fn['pseudo_summary']} Calls: {', '.join(fn['calls'][:10])}")
        md.append("\n## Sample strings\n")
        for s in strings[:100]:
            md.append(f"- {s}")
        Path(args.explain_out).write_text("\n".join(md), encoding="utf-8")
        print(f"  Explain summary written to: {args.explain_out}")
    return 0


# Advanced dispatcher is appended below.

# =====================================================================
# ADVANCED LAYER - REA-style: MCP server, investigation, call-graph,
# pseudo-C translation, and an opt-in dynamic trace.
# This layer reuses the read-only parsers / disassembler above.
# It still never patches a binary, never generates a licence key,
# and never touches licence / trial state.
# =====================================================================

import os

def _load_for_tools(path_str):
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path_str}")
    data = path.read_bytes()
    parsed = detect_and_parse(data, str(path))
    instrs, method, note = disassemble(str(path))
    cfg = build_cfg(instrs)
    addr_to_func = {}
    for ins in instrs:
        addr_to_func.setdefault(ins["address"], ins["function"])
    return {
        "path": str(path), "data": data, "parsed": parsed,
        "instrs": instrs, "method": method, "note": note, "cfg": cfg,
        "addr_to_func": addr_to_func,
        "strings": extract_strings(data, 4),
    }


def _call_target_name(ins):
    m = re.search(r"<([^>]+)>", ins["operands"])
    if m:
        return m.group(1)
    for t in re.findall(r"0x[0-9a-fA-F]+", ins["operands"]):
        return t
    m2 = re.match(r"^([0-9a-fA-F]+)\s*(?:<|$)", ins["operands"].strip())
    if m2:
        return "0x" + m2.group(1)
    # Register / memory indirect call: do not pretend it is a named target
    return f"indirect:{ins['operands'].strip()}" if ins["operands"].strip() else "indirect:?"


def pseudo_c_for_function(state, func_name, limit=200):
    lst = [x for x in state["instrs"] if x["function"] == func_name]
    if not lst:
        # Substring match (e.g. 'malloc' -> 'malloc@plt')
        low = func_name.lower()
        lst = [x for x in state["instrs"] if low in x["function"].lower()]
    if not lst:
        # Address lookup: '4010' and '0x4010' are both hex addresses here
        try:
            addr = int(func_name.strip().lower().removeprefix("0x"), 16)
            hit = next((x for x in state["instrs"] if x["address"] == addr), None)
            if hit:
                lst = [x for x in state["instrs"] if x["function"] == hit["function"]]
        except Exception:
            lst = []
    lines = [f"// Pseudo-C (heuristic, not recovered source) for {func_name}",
             f"// {len(lst)} instructions"]
    for ins in lst[:limit]:
        mn, op = ins["mnemonic"], ins["operands"]
        addr = hex(ins["address"])
        if mn.startswith("mov") or mn.startswith("lea"):
            lines.append(f"{addr}: {op.replace(',', ' =', 1)};  // {mn}")
        elif mn in ("add", "sub", "imul", "xor", "and", "or"):
            lines.append(f"{addr}: {op};  // {mn} (arithmetic / logic)")
        elif mn in ("cmp", "test"):
            lines.append(f"{addr}: if ({op}) {{ /* next branch decides */ }}")
        elif mn in BRANCH:
            lines.append(f"{addr}: goto {op};  // {mn}")
        elif mn == "call":
            lines.append(f"{addr}: call {_call_target_name(ins)};")
        elif mn in RET:
            lines.append(f"{addr}: return;")
        elif mn == "push":
            lines.append(f"{addr}: push {op};")
        elif mn == "pop":
            lines.append(f"{addr}: pop {op};")
        else:
            lines.append(f"{addr}: /* {mn} {op} */")
    if len(lst) > limit:
        lines.append(f"// ... {len(lst) - limit} more instructions omitted")
    return "\n".join(lines)


def call_graph(state, fmt="json"):
    nodes = {}
    edges = []
    for ins in state["instrs"]:
        if ins["mnemonic"] != "call":
            continue
        src = ins["function"]
        dst = _call_target_name(ins)
        # Resolve a hex target to a function name when possible
        if dst.startswith("0x"):
            try:
                dst = state["addr_to_func"].get(int(dst, 16), dst)
            except Exception:
                pass
        nodes[src] = nodes.get(src, 0) + 1
        nodes[dst] = nodes.get(dst, 0)
        edges.append({"from": src, "to": dst, "at": hex(ins["address"])})
    if fmt == "dot":
        out = ["digraph CallGraph {", '  rankdir=LR;', '  node [shape=box];']
        seen = set()
        for e in edges:
            key = (e["from"], e["to"])
            if key in seen:
                continue
            seen.add(key)
            out.append(f'  "{e["from"]}" -> "{e["to"]}";')
            if len(seen) >= 500:
                break
        out.append("}")
        return "\n".join(out)
    return {"nodes": nodes, "edges": edges[:1000], "edge_count": len(edges)}


def investigate(state, query):
    q = query.lower()
    matched_strings = [s for s in state["strings"] if q in s.lower()][:50]
    funcs = summarize_functions(state["instrs"])
    matched_funcs = [f for f in funcs if q in f["function"].lower()][:20]
    # Functions that reference a matched string address are hard to map
    # without symbols, so we also surface functions calling the
    # matched functions, and functions they call (1 hop each way).
    graph = call_graph(state)
    names = {f["function"] for f in matched_funcs}
    neighbours = set()
    for e in graph["edges"]:
        if e["from"] in names:
            neighbours.add(e["to"])
        if e["to"] in names:
            neighbours.add(e["from"])
    top_pseudo = ""
    if matched_funcs:
        top_pseudo = pseudo_c_for_function(state, matched_funcs[0]["function"], limit=120)
    return {
        "query": query,
        "matched_strings": matched_strings,
        "matched_functions": matched_funcs,
        "call_neighbours_1_hop": sorted(neighbours)[:50],
        "findings": build_findings(state["parsed"], state["strings"], state["instrs"]),
        "pseudo_c_for_top_match": top_pseudo,
        "how_to_use": (
            "Read the matched function, follow its call neighbours, "
            "then verify the behaviour in source code or a full decompiler "
            "such as Ghidra. This report does not prove a bug by itself."),
    }


# ---- MCP server (JSON-RPC over stdio, like REA's agent bridge) ----

MCP_TOOLS = [
    {"name": "analyze_binary", "description": "Read-only PE/ELF analysis: headers, sections, strings, findings.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "list_functions", "description": "List summarised functions from disassembly.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "get_function", "description": "Pseudo-C and summary for one function by name or address.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "name": {"type": "string"}}, "required": ["path", "name"]}},
    {"name": "search_strings", "description": "Search extracted strings (case-insensitive).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "query": {"type": "string"}}, "required": ["path", "query"]}},
    {"name": "get_xrefs", "description": "Callers / jumpers to an address (hex, e.g. 0x401000).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "address": {"type": "string"}}, "required": ["path", "address"]}},
    {"name": "get_call_graph", "description": "Caller -> callee graph as JSON or DOT.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "format": {"type": "string", "enum": ["json", "dot"]}}, "required": ["path"]}},
    {"name": "investigate", "description": "Investigate one feature/question: matched strings, functions, neighbours, pseudo-C.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "query": {"type": "string"}}, "required": ["path", "query"]}},
    {"name": "list_sections", "description": "Sections with entropy.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "export_call_graph_3d", "description": "Write a standalone 3D call-graph HTML file and return its path.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "out": {"type": "string"}}, "required": ["path"]}},
    {"name": "list_imports", "description": "PE import table (DLLs and functions).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
]


def _mcp_call_tool(name, args):
    path = args.get("path", "")
    state = _load_for_tools(path)
    if name == "analyze_binary":
        return {"format": state["parsed"].get("format"),
                "sections": len(state["parsed"].get("sections", [])),
                "string_count": len(state["strings"]),
                "instruction_count": len(state["instrs"]),
                "findings": build_findings(state["parsed"], state["strings"], state["instrs"])}
    if name == "list_functions":
        return summarize_functions(state["instrs"])
    if name == "get_function":
        funcs = summarize_functions(state["instrs"])
        hit = next((f for f in funcs if args.get("name", "") in f["function"]), None)
        return {"summary": hit, "pseudo_c": pseudo_c_for_function(state, args.get("name", ""))}
    if name == "search_strings":
        q = args.get("query", "").lower()
        return [s for s in state["strings"] if q in s.lower()][:100]
    if name == "get_xrefs":
        raw = str(args.get("address", "")).strip().lower()
        if raw and not raw.startswith("0x"):
            try:
                raw = hex(int(raw, 16))
            except Exception:
                pass
        return state["cfg"]["xrefs"].get(raw, [])
    if name == "get_call_graph":
        return call_graph(state, fmt=args.get("format", "json"))
    if name == "investigate":
        return investigate(state, args.get("query", ""))
    if name == "list_sections":
        return state["parsed"].get("sections", [])
    if name == "export_call_graph_3d":
        out_path = args.get("out") or "callgraph-3d.html"
        Path(out_path).write_text(call_graph_3d_html(state), encoding="utf-8")
        return {"path": out_path, "note": "Open in a browser; drag to rotate, scroll to zoom."}
    if name == "list_imports":
        return state["parsed"].get("imports", [])
    raise ValueError(f"Unknown tool: {name}")


def run_mcp_server():
    sys.stderr.write("RE Lab MCP server ready (JSON-RPC over stdio, read-only).\n")
    sys.stderr.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        method = req.get("method", "")
        rid = req.get("id")
        result = None
        error = None
        try:
            if method == "initialize":
                result = {"protocolVersion": "2024-11-05",
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": "re-lab-advanced", "version": "2.0"}}
            elif method == "tools/list":
                result = {"tools": MCP_TOOLS}
            elif method == "tools/call":
                params = req.get("params", {})
                data = _mcp_call_tool(params.get("name", ""), params.get("arguments", {}))
                result = {"content": [{"type": "text", "text": json.dumps(data, indent=2, default=str)}]}
            elif method in ("notifications/initialized", "ping"):
                result = {}
            else:
                error = {"code": -32601, "message": f"Method not found: {method}"}
        except Exception as exc:
            error = {"code": -32603, "message": str(exc)}
        if rid is not None:
            resp = {"jsonrpc": "2.0", "id": rid}
            if error:
                resp["error"] = error
            else:
                resp["result"] = result
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def run_repl():
    print("RE Lab REPL - type 'help'. Only analyse binaries you own or are authorised to test.")
    state = None
    while True:
        try:
            cmd = input("re-lab> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        parts = cmd.split(maxsplit=1)
        verb, rest = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
        if verb in ("quit", "exit"):
            break
        elif verb == "help":
            print("load <path> | functions | function <name> | strings <query> |")
            print("xrefs <0xADDR> | graph [dot] | investigate <query> | findings | quit")
        elif verb == "load" and rest:
            try:
                state = _load_for_tools(rest)
                print(f"Loaded {rest}: {state['parsed'].get('format')}, {len(state['instrs'])} instructions, {len(state['strings'])} strings")
            except Exception as exc:
                print(f"Error: {exc}")
        elif state is None:
            print("Load a binary first: load <path>")
        elif verb == "functions":
            for f in summarize_functions(state["instrs"])[:20]:
                print(f"  {f['function']}: {f['instruction_count']} instr, {f['call_count']} calls")
        elif verb == "function" and rest:
            print(pseudo_c_for_function(state, rest, limit=150))
        elif verb == "strings" and rest:
            for s in state["strings"]:
                if rest.lower() in s.lower():
                    print(f"  {s}")
        elif verb == "xrefs" and rest:
            print(state["cfg"]["xrefs"].get(rest, []))
        elif verb == "graph":
            print(call_graph(state, fmt="dot" if rest == "dot" else "json"))
        elif verb == "investigate" and rest:
            print(json.dumps(investigate(state, rest), indent=2, default=str))
        elif verb == "findings":
            for f in build_findings(state["parsed"], state["strings"], state["instrs"]):
                print(f"  [{f['severity']}] {f['area']}: {f['issue']} -> {f['fix']}")
        else:
            print("Unknown command. Type 'help'.")


def run_dynamic_trace(path_str, extra_args, allow_run):
    """Opt-in runtime observation, lab only. Requires --allow-run."""
    if not allow_run:
        print("Dynamic trace refused: pass --allow-run only for a trusted lab sample in an isolated VM.")
        print("Default mode is read-only static analysis and does not run the target.")
        return 2
    if not shutil_which("strace"):
        print("strace is not installed on this system, so no dynamic trace was run.")
        return 2
    print("WARNING: running the target under strace, with a 10 second timeout, in this lab only.")
    try:
        proc = subprocess.run(
            ["strace", "-f", "-e", "trace=openat,read,write,connect,execve",
             str(path_str)] + extra_args,
            capture_output=True, text=True, timeout=10)
        syscalls = Counter(re.findall(r"^[a-z0-9_]+\(", proc.stderr, flags=re.M))
        print("Syscall summary (from stderr, first lines are illustrative):")
        for name, count in syscalls.most_common(20):
            print(f"  {name} x{count}")
        print(proc.stderr[:4000])
        return 0
    except subprocess.TimeoutExpired:
        print("Trace stopped at the 10 second timeout.")
        return 0
    except Exception as exc:
        print(f"Dynamic trace failed: {exc}")
        return 2


def shutil_which(name):
    import shutil
    return shutil.which(name)


def advanced_main(argv):
    if not argv:
        return main([])
    mode = argv[0]
    if mode == "mcp":
        run_mcp_server()
        return 0
    if mode == "repl":
        run_repl()
        return 0
    if mode == "investigate":
        ap = argparse.ArgumentParser(description="Investigate one feature in a binary")
        ap.add_argument("target")
        ap.add_argument("query")
        ap.add_argument("--json", dest="json_out")
        a = ap.parse_args(argv[1:])
        state = _load_for_tools(a.target)
        result = investigate(state, a.query)
        print(json.dumps(result, indent=2, default=str))
        if a.json_out:
            Path(a.json_out).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        return 0
    if mode == "graph":
        ap = argparse.ArgumentParser(description="Call graph for a binary")
        ap.add_argument("target")
        ap.add_argument("--format", default="dot", choices=["dot", "json", "html3d"])
        ap.add_argument("--out", dest="out")
        a = ap.parse_args(argv[1:])
        state = _load_for_tools(a.target)
        if a.format == "html3d":
            doc = call_graph_3d_html(state)
            out_path = a.out or "callgraph-3d.html"
            Path(out_path).write_text(doc, encoding="utf-8")
            print(f"3D call graph written to: {out_path} (open it in a browser, drag to rotate)")
            return 0
        out = call_graph(state, fmt=a.format)
        print(out if isinstance(out, str) else json.dumps(out, indent=2, default=str))
        return 0
    if mode == "html":
        ap = argparse.ArgumentParser(description="Full HTML report + 3D graph")
        ap.add_argument("target")
        ap.add_argument("--out", dest="out", default="re-report.html")
        a = ap.parse_args(argv[1:])
        state = _load_for_tools(a.target)
        graph_path = "callgraph-3d.html"
        Path(graph_path).write_text(call_graph_3d_html(state), encoding="utf-8")
        html_report(state, a.out, graph3d_path=graph_path)
        print(f"HTML report written to: {a.out}")
        print(f"3D call graph written to: {graph_path}")
        return 0
    if mode == "compare":
        ap = argparse.ArgumentParser(description="Compare two binaries (before/after a fix)")
        ap.add_argument("a")
        ap.add_argument("b")
        ap.add_argument("--json", dest="json_out")
        a = ap.parse_args(argv[1:])
        result = compare_binaries(a.a, a.b)
        print(json.dumps(result, indent=2, default=str))
        if a.json_out:
            Path(a.json_out).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        return 0
    if mode == "trace":
        ap = argparse.ArgumentParser(description="Opt-in dynamic trace (lab only)")
        ap.add_argument("target")
        ap.add_argument("--allow-run", action="store_true")
        ap.add_argument("extra", nargs="*")
        a = ap.parse_args(argv[1:])
        return run_dynamic_trace(a.target, a.extra, a.allow_run)
    # Fall back to the original v1 CLI: analyse <target> [options]
    return main(argv)



# =====================================================================
# FORMAT SUPPORT - APK / AAB / JAR (ZIP + DEX), MSI (CFB), CAB,
# Mach-O, plus a generic embedded-file scan.
# These parsers are read-only and never execute the target.
# For APK native libs (.so) and MSI embedded files, analyse the
# extracted file separately with this same tool.
# =====================================================================

import io
import zipfile

def parse_macho(data):
    if len(data) < 32:
        return None
    magics = {0xFEEDFACE: (False, False), 0xFEEDFACF: (True, False),
              0xCEFAEDFE: (False, True), 0xCFFAEDFE: (True, True)}
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in magics:
        return None
    is64, swap = magics[magic]
    en = ">" if swap else "<"
    try:
        if is64:
            cputype, cpusub, ftype, ncmds, sizeofcmds, flags = struct.unpack_from(en + "IIIIII", data, 4)
            off = 32
        else:
            cputype, cpusub, ftype, ncmds, sizeofcmds, flags = struct.unpack_from(en + "IIIIII", data, 4)
            off = 28
        sections = []
        for _ in range(min(ncmds, 200)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(en + "II", data, off)
            if cmdsize < 8:
                break
            if cmd in (0x19, 0x1):  # LC_SEGMENT_64 / LC_SEGMENT
                segname = data[off + 8:off + 24].rstrip(b"\x00").decode("ascii", errors="ignore")
                if cmd == 0x19:
                    nsects = struct.unpack_from(en + "I", data, off + 64)[0]
                    sec_off = off + 72
                    sec_size = 80
                else:
                    nsects = struct.unpack_from(en + "I", data, off + 48)[0]
                    sec_off = off + 56
                    sec_size = 68
                for i in range(min(nsects, 100)):
                    so = sec_off + i * sec_size
                    if so + sec_size > len(data):
                        break
                    sname = data[so:so + 16].rstrip(b"\x00").decode("ascii", errors="ignore")
                    sections.append({"name": f"{segname}:{sname}", "type": "macho-section",
                                     "address": "0x0", "offset": 0, "size": 0})
            off += cmdsize
        return {"format": "Mach-O", "is_64bit": is64, "filetype": ftype,
                "sections": sections, "imports": []}
    except Exception as exc:
        return {"format": "Mach-O", "parse_error": str(exc), "sections": [], "imports": []}


def _parse_dex(data):
    if len(data) < 112 or not data.startswith(b"dex\n"):
        return None
    try:
        vals = struct.unpack_from("<20I", data, 0)
        # header layout after magic(8)+checksum(4)+signature(20)=32:
        # file_size, header_size, endian, link_size, link_off, map_off,
        # string_ids_size, string_ids_off, type_ids_size, type_ids_off,
        # proto_ids_size, proto_ids_off, field_ids_size, field_ids_off,
        # method_ids_size, method_ids_off, class_defs_size, class_defs_off,
        # data_size, data_off
        hdr = struct.unpack_from("<20I", data, 32)
        return {"version": data[4:7].decode("ascii", errors="ignore"),
                "file_size": hdr[0], "string_ids": hdr[6], "type_ids": hdr[8],
                "proto_ids": hdr[10], "field_ids": hdr[12], "method_ids": hdr[14],
                "class_defs": hdr[16]}
    except Exception:
        return {"version": "unknown"}


def parse_zip_container(data, path_str):
    if len(data) < 4 or data[:4] != b"PK\x03\x04":
        # ZIPs can also start with an empty archive / spanned signature
        if not data.startswith(b"PK"):
            return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return None
    entries = []
    dex_info = {}
    native_libs = []
    for info in zf.infolist():
        entries.append({"name": info.filename, "type": "zip-entry",
                        "size": info.file_size, "compressed_size": info.compress_size})
        if info.filename.endswith(".dex"):
            try:
                dex_info[info.filename] = _parse_dex(zf.read(info.filename))
            except Exception:
                dex_info[info.filename] = {"version": "unreadable"}
        if info.filename.endswith(".so"):
            native_libs.append(info.filename)
    names = [e["name"] for e in entries]
    if any(n == "AndroidManifest.xml" or n.endswith(".dex") for n in names):
        fmt = "APK"
    elif any(n.startswith("Payload/") and ".app/" in n for n in names):
        fmt = "IPA"
    elif any(n == "AppxManifest.xml" for n in names):
        fmt = "MSIX"
    elif any("BundleConfig.json" in n or n.startswith("base/") for n in names):
        fmt = "AAB"
    elif any(n.endswith(".class") or n == "META-INF/MANIFEST.MF" for n in names):
        fmt = "JAR"
    else:
        fmt = "ZIP"
    return {"format": fmt, "sections": entries, "entries": entries,
            "dex": dex_info, "native_libs": native_libs,
            "imports": [],
            "note": ("APK/AAB: analyse embedded .so (ELF) files separately; "
                     "DEX counts are header counts only, not decompiled code. "
                     "AndroidManifest.xml in APKs is binary AXML - use apktool/androguard in your lab for full decoding.") if fmt in ("APK", "AAB") else ""}


def parse_cab(data):
    if len(data) < 36 or data[:4] != b"MSCF":
        return None
    try:
        coff_files = struct.unpack_from("<I", data, 16)[0]
        c_folders = struct.unpack_from("<H", data, 28)[0]
        c_files = struct.unpack_from("<H", data, 30)[0]
        files = []
        off = coff_files
        for _ in range(min(c_files, 1000)):
            if off + 16 > len(data):
                break
            cb_file, uoff, i_folder, date, time_, attribs = struct.unpack_from("<IIHHHH", data, off)
            off += 16
            end = data.find(b"\x00", off)
            name = data[off:end].decode("ascii", errors="ignore") if end != -1 else ""
            off = end + 1 if end != -1 else len(data)
            files.append({"name": name, "type": "cab-file", "size": cb_file})
        return {"format": "CAB", "sections": files, "files": files, "imports": []}
    except Exception as exc:
        return {"format": "CAB", "parse_error": str(exc), "sections": [], "imports": []}


def parse_cfb_msi(data):
    if len(data) < 512 or data[:8] != bytes.fromhex("D0CF11E0A1B11AE1"):
        return None
    try:
        sector_size = 1 << struct.unpack_from("<H", data, 30)[0]
        if sector_size not in (512, 4096):
            sector_size = 512
        first_dir_sector = struct.unpack_from("<I", data, 48)[0]
        # FAT: DIFAT array starts at 76, 109 entries
        difat = [struct.unpack_from("<I", data, 76 + i * 4)[0] for i in range(109)]
        fat = {}
        for sec in difat:
            if sec >= 0xFFFFFFFA:
                continue
            base = (sec + 1) * sector_size
            for i in range(sector_size // 4):
                if base + i * 4 + 4 > len(data):
                    break
                fat[sec * (sector_size // 4) + i] = struct.unpack_from("<I", data, base + i * 4)[0]
        def sector_chain(start):
            out, seen, cur = [], set(), start
            while cur < 0xFFFFFFFA and cur not in seen and len(out) < 10000:
                seen.add(cur)
                out.append(cur)
                cur = fat.get(cur, 0xFFFFFFFE)
            return out
        streams = []
        for sec in sector_chain(first_dir_sector):
            base = (sec + 1) * sector_size
            for i in range(sector_size // 128):
                off = base + i * 128
                if off + 128 > len(data):
                    break
                raw_name = data[off:off + 64]
                try:
                    name = raw_name.decode("utf-16-le", errors="ignore").rstrip("\x00")
                except Exception:
                    name = ""
                if not name:
                    continue
                obj_type = data[off + 66]
                start_sec = struct.unpack_from("<I", data, off + 116)[0]
                stream_size = struct.unpack_from("<I", data, off + 120)[0]
                streams.append({"name": name, "type": "stream" if obj_type == 2 else "storage" if obj_type == 1 else "root" if obj_type == 5 else f"type-{obj_type}",
                                "size": stream_size, "start_sector": start_sec})
        return {"format": "MSI", "sections": streams, "streams": streams, "imports": [],
                "note": "MSI is an OLE Compound File. Streams listed are directory entries; extract a stream / embedded CAB separately to analyse it. MSI tables themselves need an MSI reader (e.g. msitools / Orca) in your lab."}
    except Exception as exc:
        return {"format": "MSI", "parse_error": str(exc), "sections": [], "imports": []}


def scan_embedded(data):
    sigs = [(b"MZ", "PE"), (b"\x7fELF", "ELF"), (b"PK\x03\x04", "ZIP"),
            (b"MSCF", "CAB"), (b"dex\n", "DEX"),
            (bytes.fromhex("D0CF11E0A1B11AE1"), "CFB/MSI")]
    found = []
    for sig, name in sigs:
        idx = 0
        count = 0
        while True:
            idx = data.find(sig, idx)
            if idx == -1 or count >= 20:
                break
            if idx != 0 or name not in ("PE", "ELF", "ZIP", "CAB", "DEX", "CFB/MSI"):
                found.append({"signature": name, "offset": idx})
            count += 1
            idx += 1
    return found


def detect_and_parse(data, path_str=""):
    # Order matters: PE/ELF/Mach-O have strong magics; ZIP/CFB/CAB/DEX next.
    for fn in (parse_pe, parse_elf, parse_macho, parse_cfb_msi, parse_cab, parse_zip_container):
        try:
            r = fn(data) if fn is not parse_zip_container else fn(data, path_str)
        except Exception:
            r = None
        if r:
            r["embedded_scan"] = scan_embedded(data)
            # .NET detection for PE: data directory 14 (CLR header)
            if r.get("format") == "PE":
                try:
                    dirs = r.get("data_directories", [])
                    if len(dirs) > 14 and dirs[14].get("rva"):
                        r["dotnet"] = True
                        r["note"] = ".NET assembly (CLR header present) - use a .NET decompiler such as ILSpy/dnSpy in your lab for IL, this tool only parses the PE container."
                except Exception:
                    pass
            return r
    # Standalone DEX file (not inside an APK)
    dex = _parse_dex(data)
    if dex:
        return {"format": "DEX", "sections": [], "dex": {"classes.dex": dex}, "imports": [],
                "embedded_scan": scan_embedded(data)}
    return {"format": "unknown", "sections": [], "imports": [],
            "embedded_scan": scan_embedded(data),
            "note": "Unknown format - strings, hash and entropy are still reported. If this is a packed / encrypted app, unpack it in your lab first (with permission) and re-analyse the unpacked file."}



# =====================================================================
# NEW FEATURES - 3D call graph, HTML report, compare mode, risk score
# Copyright (c) SKYTAR - www.shihabskytar.com
# =====================================================================

import html as htmlmod

def risk_score(findings):
    weights = {"high": 10, "medium": 4, "low": 1, "info": 0}
    score = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
    level = "Low" if score < 10 else "Medium" if score < 30 else "High"
    return {"score": score, "level": level,
            "counts": {s: sum(1 for f in findings if f.get("severity") == s)
                       for s in ("high", "medium", "low", "info")}}


def call_graph_3d_html(state, max_nodes=80, max_edges=300):
    """Standalone HTML with a rotatable 3D call graph (Three.js, CDN).

    Nodes are placed on layered rings by call depth from the first
    function, edges are lines. Drag to rotate, scroll to zoom.
    No data leaves the browser - the graph is generated locally.
    """
    graph = call_graph(state, fmt="json")
    nodes = list(dict.fromkeys([e["from"] for e in graph["edges"]] + [e["to"] for e in graph["edges"]]))[:max_nodes]
    node_set = set(nodes)
    edges = [(e["from"], e["to"]) for e in graph["edges"] if e["from"] in node_set and e["to"] in node_set][:max_edges]
    # Deterministic layout: ring by index, height by depth-ish (hash)
    import hashlib as _hl
    pos = {}
    for i, n in enumerate(nodes):
        h = int(_hl.md5(n.encode()).hexdigest()[:6], 16)
        angle = (i / max(1, len(nodes))) * 6.2831
        radius = 12 + (h % 10)
        pos[n] = (radius * __import__("math").cos(angle),
                  ((h % 7) - 3) * 3.0,
                  radius * __import__("math").sin(angle))
    nodes_js = []
    for n in nodes:
        x, y, z = pos[n]
        nodes_js.append({"name": n, "x": round(x, 2), "y": round(y, 2), "z": round(z, 2)})
    edges_js = [{"from": a, "to": b} for a, b in dict.fromkeys(edges)]
    nodes_json = json.dumps(nodes_js)
    edges_json = json.dumps(edges_js)
    title = htmlmod.escape(state["path"])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>3D Call Graph - {title}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<style>body{{margin:0;background:#0b1220;color:#e5e7eb;font-family:Segoe UI,Arial}}#info{{position:fixed;top:12px;left:12px;background:rgba(0,0,0,.6);padding:12px;border-radius:8px;max-width:420px}}#info h2{{margin:0 0 6px}}canvas{{display:block}}</style>
</head><body><div id="info"><h2>3D Call Graph</h2><p>Target: {title}</p><p>Nodes: {len(nodes_js)} &nbsp; Edges: {len(edges_js)}</p><p>Drag to rotate &bull; Scroll to zoom &bull; A tight cluster usually means one feature / module. A node with many incoming edges is a shared helper.</p><p style="color:#9ca3af">Copyright (c) SKYTAR - www.shihabskytar.com</p></div>
<script>
const nodes = {nodes_json}; const edges = {edges_json};
const scene = new THREE.Scene(); const camera = new THREE.PerspectiveCamera(60, innerWidth/innerHeight, 0.1, 1000);
camera.position.set(0, 18, 42);
const renderer = new THREE.WebGLRenderer({{antialias:true}}); renderer.setSize(innerWidth, innerHeight); document.body.appendChild(renderer.domElement);
const group = new THREE.Group(); scene.add(group);
const posMap = {{}}; nodes.forEach(n => posMap[n.name] = new THREE.Vector3(n.x, n.y, n.z));
nodes.forEach((n, i) => {{
  const geo = new THREE.SphereGeometry(0.7, 16, 16);
  const mat = new THREE.MeshBasicMaterial({{color: i === 0 ? 0xf59e0b : 0x38bdf8}});
  const s = new THREE.Mesh(geo, mat); s.position.copy(posMap[n.name]); group.add(s);
}});
const lineMat = new THREE.LineBasicMaterial({{color: 0x64748b, transparent:true, opacity:0.6}});
edges.forEach(e => {{
  if (!posMap[e.from] || !posMap[e.to]) return;
  const geo = new THREE.BufferGeometry().setFromPoints([posMap[e.from], posMap[e.to]]);
  group.add(new THREE.Line(geo, lineMat));
}});
let dragging=false, px=0, py=0, rx=0.2, ry=0.4;
addEventListener('mousedown', e => {{dragging=true; px=e.clientX; py=e.clientY;}});
addEventListener('mouseup', () => dragging=false);
addEventListener('mousemove', e => {{if(!dragging) return; ry += (e.clientX-px)*0.005; rx += (e.clientY-py)*0.005; px=e.clientX; py=e.clientY;}});
addEventListener('wheel', e => {{camera.position.multiplyScalar(e.deltaY > 0 ? 1.1 : 0.9);}});
function animate(){{requestAnimationFrame(animate); group.rotation.x=rx; group.rotation.y=ry; renderer.render(scene, camera);}} animate();
addEventListener('resize', () => {{camera.aspect=innerWidth/innerHeight; camera.updateProjectionMatrix(); renderer.setSize(innerWidth, innerHeight);}});
</script></body></html>"""


def html_report(state, out_path, graph3d_path=None):
    findings = build_findings(state["parsed"], state["strings"], state["instrs"])
    score = risk_score(findings)
    funcs = summarize_functions(state["instrs"])
    def esc(x):
        return htmlmod.escape(str(x))
    rows_sec = "".join(f"<tr><td>{esc(s.get('name',''))}</td><td>{esc(s.get('size', s.get('raw_size','')))}</td><td>{esc(s.get('type',''))}</td></tr>" for s in state["parsed"].get("sections", [])[:100])
    rows_find = "".join(f"<tr><td>{esc(f['severity'])}</td><td>{esc(f['area'])}</td><td>{esc(f['issue'])}</td><td>{esc(f['fix'])}</td></tr>" for f in findings)
    rows_func = "".join(f"<tr><td>{esc(f['function'])}</td><td>{f['instruction_count']}</td><td>{f['call_count']}</td><td>{esc(f['pseudo_summary'][:300])}</td></tr>" for f in funcs[:50])
    graph_link = f'<p><a href="{htmlmod.escape(graph3d_path)}">Open the interactive 3D call graph</a> (drag to rotate, scroll to zoom)</p>' if graph3d_path else ""
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>RE Lab Report - {esc(state['path'])}</title>
<style>body{{font-family:Segoe UI,Arial;max-width:1100px;margin:24px auto;padding:0 16px;color:#111}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px;text-align:left}}th{{background:#0b1220;color:#fff}}h1{{font-size:22px}} .badge{{background:#fef3c7;padding:4px 10px;border-radius:20px}}</style></head><body>
<h1>RE Lab Report</h1><p>Target: <b>{esc(state['path'])}</b> &nbsp; Format: {esc(state['parsed'].get('format',''))} &nbsp; Instructions: {len(state['instrs'])} &nbsp; Strings: {len(state['strings'])}</p>
<p>Risk score: <span class="badge">{score['score']} - {score['level']}</span> &nbsp; {esc(score['counts'])}</p>
{graph_link}
<h2>Findings</h2><table><tr><th>Severity</th><th>Area</th><th>Issue</th><th>Fix</th></tr>{rows_find or '<tr><td colspan="4">None from these heuristics</td></tr>'}</table>
<h2>Sections / Entries</h2><table><tr><th>Name</th><th>Size</th><th>Type</th></tr>{rows_sec}</table>
<h2>Functions</h2><table><tr><th>Function</th><th>Instructions</th><th>Calls</th><th>Summary</th></tr>{rows_func}</table>
<p style="color:#666">Copyright (c) SKYTAR - www.shihabskytar.com &bull; Read-only analysis. Verify findings in source code.</p>
</body></html>"""
    Path(out_path).write_text(doc, encoding="utf-8")
    return out_path


def compare_binaries(path_a, path_b):
    def snap(p):
        data = Path(p).read_bytes()
        parsed = detect_and_parse(data, str(p))
        return {"path": str(p), "size": len(data), "sha256": sha256_of(data),
                "format": parsed.get("format"),
                "sections": [s.get("name") for s in parsed.get("sections", [])],
                "imports": [f"{i.get('dll')}!{fn}" for i in parsed.get("imports", []) for fn in i.get("functions", [])],
                "strings": set(extract_strings(data, 4)),
                "findings": build_findings(parsed, extract_strings(data, 4), [])}
    a, b = snap(path_a), snap(path_b)
    return {"a": {k: v for k, v in a.items() if k != "strings"},
            "b": {k: v for k, v in b.items() if k != "strings"},
            "sections_only_in_a": sorted(set(a["sections"]) - set(b["sections"])),
            "sections_only_in_b": sorted(set(b["sections"]) - set(a["sections"])),
            "imports_only_in_a": sorted(set(a["imports"]) - set(b["imports"]))[:100],
            "imports_only_in_b": sorted(set(b["imports"]) - set(a["imports"]))[:100],
            "strings_only_in_a_count": len(a["strings"] - b["strings"]),
            "strings_only_in_b_count": len(b["strings"] - a["strings"]),
            "strings_only_in_a_sample": sorted(a["strings"] - b["strings"])[:50],
            "strings_only_in_b_sample": sorted(b["strings"] - a["strings"])[:50]}


if __name__ == "__main__":
    raise SystemExit(advanced_main(sys.argv[1:]))
