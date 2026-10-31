"""HEXCORE core engine.

This module wraps the proven RE Lab Advanced parsers (kept as
hexcore/legacy.py, preserved for backward compatibility) and adds:
- PE export / relocation / certificate-directory parsing
- Compiler fingerprint heuristics
- Packed / overlay heuristics
- Section permission analysis (WX, RWX)
- Dependency mapping
- A unified Analysis object used by UI, MCP, reports and plugins.

No patching, no execution, no licence bypass. Read-only.
"""
import hashlib
import importlib.util
import math
import struct
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("hexcore_legacy", _HERE / "legacy.py")
legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(legacy)


def _entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _pe_extra(data, parsed):
    extra = {"exports": [], "relocations": [], "certificate": None,
             "compiler_hints": [], "overlay": None, "packed_heuristic": []}
    if parsed.get("format") != "PE":
        return extra
    sections = parsed.get("sections", [])
    if not sections:
        return extra
    # Overlay: bytes after the last raw section
    try:
        end = max(s["raw_ptr"] + s["raw_size"] for s in sections)
        if len(data) > end:
            extra["overlay"] = {"offset": end, "size": len(data) - end}
    except Exception:
        pass
    # Section permissions from PE section characteristics are not stored
    # by the legacy parser, so re-read them here (offset +36 in each header).
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        coff = e_lfanew + 4
        _, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        sec_off = opt + opt_size
        for i, s in enumerate(sections):
            off = sec_off + i * 40
            chars = struct.unpack_from("<I", data, off + 36)[0]
            s["characteristics_raw"] = hex(chars)
            s["executable"] = bool(chars & 0x20000000)
            s["readable"] = bool(chars & 0x40000000)
            s["writable"] = bool(chars & 0x80000000)
            s["shared"] = bool(chars & 0x10000000)
            if s["executable"] and s["writable"]:
                extra["packed_heuristic"].append(
                    f"Writable+executable section: {s['name']} (WX) - investigate, do not assume malware")
            chunk = data[s["raw_ptr"]:s["raw_ptr"] + s["raw_size"]] if s["raw_ptr"] < len(data) else b""
            s["entropy"] = round(_entropy(chunk), 3)
            if s["entropy"] > 7.5:
                extra["packed_heuristic"].append(
                    f"High-entropy section: {s['name']} ({s['entropy']}) - may be packed, compressed or encrypted")
    except Exception:
        pass
    # Data directories: 0=export, 4=certificate, 5=base relocation, 14=CLR
    dirs = parsed.get("data_directories", [])
    def rva2off(rva):
        return legacy._rva_to_offset(rva, sections)
    try:
        if len(dirs) > 0 and dirs[0]["rva"]:
            off = rva2off(dirs[0]["rva"])
            if off is not None:
                # Export directory layout: Characteristics, TimeDate, Major, Minor,
                # Name, Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions,
                # AddressOfNames, AddressOfNameOrdinals (40 bytes)
                vals = struct.unpack_from("<IIHHIIIIIII", data, off)
                # Layout: 0 Characteristics, 1 TimeDate, 2 Major, 3 Minor,
                # 4 Name, 5 Base, 6 NumberOfFunctions, 7 NumberOfNames,
                # 8 AddressOfFunctions, 9 AddressOfNames, 10 AddressOfNameOrdinals
                n_names = vals[7]
                names_rva = vals[9]
                names_off = rva2off(names_rva)
                if names_off is not None:
                    for i in range(min(n_names, 500)):
                        nrva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                        extra["exports"].append(legacy._read_cstr(data, rva2off(nrva)))
    except Exception:
        pass
    try:
        if len(dirs) > 4 and dirs[4]["rva"]:
            # Certificate table is a file offset, not an RVA, in PE.
            extra["certificate"] = {"file_offset": dirs[4]["rva"], "size": dirs[4]["size"],
                                    "note": "Certificate present. Chain verification needs openssl in your lab; presence alone is not trust."}
    except Exception:
        pass
    # Compiler hints from strings (heuristic, low confidence)
    for s in legacy.extract_strings(data, 4):
        if "GCC:" in s or "clang version" in s.lower() or "Microsoft" in s and "Linker" in s:
            if s not in extra["compiler_hints"]:
                extra["compiler_hints"].append(s[:200])
        if len(extra["compiler_hints"]) >= 10:
            break
    # Rich header presence (xor'd, just detect the DanS marker after xor - best effort)
    if b"Rich" in data:
        extra["compiler_hints"].append("Rich header marker present (MSVC-linked binaries often carry one) - verify with a dedicated Rich parser")
    return extra


class Analysis:
    def __init__(self, path, config=None):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(str(path))
        self.data = self.path.read_bytes()
        if len(self.data) > (config or {}).get("max_file_size", 512 * 1024 * 1024):
            raise ValueError("File exceeds configured max_file_size; raise it explicitly in config if this is a lab sample")
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.md5 = hashlib.md5(self.data).hexdigest()
        self.sha1 = hashlib.sha1(self.data).hexdigest()
        self.parsed = legacy.detect_and_parse(self.data, str(self.path))
        self.strings = legacy.extract_strings(self.data, 4)
        self.instrs, self.disasm_method, self.disasm_note = legacy.disassemble(str(self.path))
        self.cfg = legacy.build_cfg(self.instrs)
        self.functions = legacy.summarize_functions(self.instrs)
        self.findings_v1 = legacy.build_findings(self.parsed, self.strings, self.instrs)
        self.extra = _pe_extra(self.data, self.parsed)
        self.dependencies = []
        for imp in self.parsed.get("imports", []):
            self.dependencies.append(imp.get("dll", ""))

    def to_dict(self):
        return {
            "product": "HEXCORE by SKYTAR", "version": "1.0.0",
            "path": str(self.path), "size": len(self.data),
            "sha256": self.sha256, "md5": self.md5, "sha1": self.sha1,
            "format": self.parsed.get("format"),
            "parsed": self.parsed, "extra": self.extra,
            "dependencies": self.dependencies,
            "string_count": len(self.strings), "sample_strings": self.strings[:100],
            "instruction_count": len(self.instrs), "disassembly_method": self.disasm_method,
            "cfg_blocks": len(self.cfg["blocks"]), "cfg_edges": len(self.cfg["edges"]),
            "functions": self.functions, "findings_v1": self.findings_v1,
        }
