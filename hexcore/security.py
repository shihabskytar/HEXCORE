"""HEXCORE security engine v2.

Every finding has: title, severity, confidence, affected_function,
file_offset, virtual_address, explanation, evidence, impact,
remediation, false_positive_notes.
Heuristic indicators are NEVER presented as confirmed vulnerabilities
or as malware verdicts. Confidence is explicit.
"""
import re

# ATT&CK mapping for suspicious API combinations (heuristic, defensive)
ATTCK = {
    "VirtualAlloc+WriteProcessMemory+CreateRemoteThread": ("T1055", "Process Injection"),
    "CreateRemoteThread": ("T1055", "Process Injection"),
    "SetWindowsHookEx": ("T1056", "Input Capture"),
    "RegSetValueEx+Run": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "CreateService": ("T1543.003", "Windows Service"),
    "URLDownloadToFile": ("T1105", "Ingress Tool Transfer"),
    "InternetOpenUrl": ("T1105", "Ingress Tool Transfer"),
    "IsDebuggerPresent": ("T1622", "Debugger Evasion"),
    "CheckRemoteDebuggerPresent": ("T1622", "Debugger Evasion"),
    "NtQueryInformationProcess": ("T1622", "Debugger Evasion"),
}

ANTI_DEBUG = {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
              "outputdebugstring", "getTickCount", "queryperformancecounter"}
PERSISTENCE_STRINGS = [r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                       r"\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
                       r"schtasks", r"CreateService"]
NETWORK_APIS = {"internetopen", "internetopenurl", "urldownloadtofile", "wininet", "socket", "connect", "getaddrinfo", "wsasend", "wsarecv"}
SUSPICIOUS_APIS = {"virtualalloc", "writeprocessmemory", "createremotethread", "virtualprotect",
                   "ntunmapviewofsection", "setwindowshookex", "shellexecute", "winexec", "system", "popen"}


def _norm(fn):
    return fn.lower().lstrip("_").split("@")[0]


def _find_function_for_import(analysis, dll_fn):
    # Best effort: a function whose calls contain the import name
    for f in getattr(analysis, "functions", []):
        for c in f.get("calls", []):
            if dll_fn.lower() in c.lower():
                return f["function"]
    return ""


def v2_findings(analysis):
    out = []

    def add(title, severity, confidence, area, explanation, evidence,
            impact, remediation, fp, func="", offset=None, va=""):
        out.append({"title": title, "severity": severity, "confidence": confidence,
                    "area": area, "affected_function": func, "file_offset": offset,
                    "virtual_address": va, "explanation": explanation,
                    "evidence": evidence, "impact": impact,
                    "remediation": remediation, "false_positive_notes": fp})

    # Convert v1 findings, preserving their fix guidance
    for f in getattr(analysis, "findings_v1", []):
        add(title=f"{f['area']}: {f['issue']}", severity=f["severity"],
            confidence="medium" if f["severity"] in ("high", "medium") else "low",
            area=f["area"], explanation="Heuristic static indicator from the legacy engine.",
            evidence=f["issue"], impact="Depends on context; verify in source code.",
            remediation=f["fix"], fp="A flagged import or string alone is not a vulnerability.")

    # Section permissions
    for s in analysis.parsed.get("sections", []):
        if isinstance(s, dict) and s.get("executable") and s.get("writable"):
            add("Writable and executable section", "high", "high", "memory-permissions",
                "A section is both writable and executable (WX). This can allow code injection if attacker-controlled data reaches it.",
                f"Section {s.get('name')}", "WX memory can be abused for code execution.",
                "Split code and data sections; mark code RX and data RW, never RWX, unless a JIT genuinely requires it.",
                "Some JITs, packers and self-modifying code legitimately use WX briefly; check why it exists.")
        if isinstance(s, dict) and s.get("entropy", 0) and s["entropy"] > 7.5:
            add("High-entropy section", "medium", "low", "packed-heuristic",
                "Entropy above 7.5 often indicates packing, compression or encryption, but also occurs in compressed resources.",
                f"Section {s.get('name')} entropy {s['entropy']}",
                "Packed code hides logic from static analysis and is common in both legitimate protectors and malware.",
                "Unpack in a lab (with permission) and re-analyse; do not treat entropy alone as a malware verdict.",
                "Compressed images, encrypted resources and installers also have high entropy.")

    # Import-based indicators (including legacy unsafe/weak lists, normalised)
    try:
        from .engine import legacy as _legacy
        _RISKY = _legacy.RISKY
        _WEAK = _legacy.WEAK_CRYPTO
    except Exception:
        _RISKY, _WEAK = {}, {}
    all_imports = []
    for imp in analysis.parsed.get("imports", []):
        for fn in imp.get("functions", []):
            all_imports.append((_norm(fn), imp.get("dll", ""), fn))
    names = {n for n, _, _ in all_imports}
    for norm, dll, orig in all_imports:
        if norm in _RISKY:
            add("Unsafe function imported", "high" if norm in ("gets", "strcpy", "sprintf") else "medium",
                "high", "unsafe-function",
                "An unsafe C function with no bounds checking is imported.",
                f"{dll}!{orig}", "Buffer overflow if lengths are attacker-controlled.",
                _RISKY[norm], "Check call sites; a safe use with a proven length bound may still be flagged.")
        for _wk in _WEAK:
            if norm == _wk or norm.startswith(_wk + "_"):
                add("Weak cryptographic algorithm imported", "medium", "medium", "weak-crypto",
                    "A weak or broken cryptographic algorithm is imported.",
                    f"{dll}!{orig}", "Weak crypto can allow forgery or recovery of plaintext.",
                    _WEAK[_wk], "Check whether it is used for security or only for checksums/non-security purposes.")
                break
        if norm in ANTI_DEBUG:
            add("Anti-debugging API imported", "medium", "medium", "anti-debug",
                "The binary imports an API commonly used to detect a debugger.",
                f"{dll}!{orig}", "May hinder analysis; not proof of malicious intent.",
                "Review why the check exists; legitimate anti-tamper code also uses it.",
                "Many legitimate apps check for debuggers for anti-cheat / anti-tamper reasons.")
        if norm in NETWORK_APIS:
            add("Network-capable API imported", "low", "medium", "network",
                "The binary can make network connections. Check what hosts it contacts, in a lab, before judging it.",
                f"{dll}!{orig}", "Network capability alone is normal for updaters, browsers and cloud apps.",
                "Audit destinations, TLS use and data sent; block unknown hosts in the lab.",
                "Most modern apps are network-capable by design.")
        if norm in SUSPICIOUS_APIS:
            add("Potentially dangerous API imported", "medium", "low", "suspicious-api",
                "An API that can be abused for injection, execution or hooking is imported.",
                f"{dll}!{orig}", "Depends entirely on how arguments are built and validated.",
                "Audit call sites, validate inputs, and prefer safer alternatives where possible.",
                "These APIs are also used by legitimate debuggers, injectors for testing, and system tools.")
    # ATT&CK combos
    if {"virtualalloc", "writeprocessmemory", "createremotethread"} <= names:
        add("Process-injection API combination (T1055)", "high", "low", "attck",
            "VirtualAlloc + WriteProcessMemory + CreateRemoteThread together match the classic process-injection pattern.",
            "Imports: VirtualAlloc, WriteProcessMemory, CreateRemoteThread",
            "If abused, code can run inside another process and evade detection.",
            "Audit every call site; if this is not a legitimate injector/debugger, remove the combination.",
            "Legitimate debuggers, game overlays and some security tools use this pattern. Do not label it malware on imports alone.")
    # Persistence strings
    for s in analysis.strings:
        for pat in PERSISTENCE_STRINGS:
            if re.search(pat, s, re.I):
                add("Persistence-related string", "medium", "low", "persistence",
                    "A string referencing a startup location or service creation was found.",
                    s[:200], "Persistence is a normal feature for updaters and a classic malware technique.",
                    "Check whether the program legitimately needs to start at login, and document it.",
                    "Updaters, launchers and many legitimate apps persist by design.")
                break
    return out


def yara_like_scan(analysis, rules):
    """Simple, honest YARA-like engine: rules are dicts with:
    {id, name, strings: [{id, text|regex|hex}], condition: 'any'|'all'|'N of them',
     tags, attck}
    It does NOT claim to be YARA. Full YARA needs the yara Python package
    or the yara binary in your lab; see README.
    """
    hits = []
    blob = analysis.data
    for rule in rules:
        matched = []
        for st in rule.get("strings", []):
            if "text" in st and st["text"].encode() in blob:
                matched.append(st["id"])
            elif "regex" in st and re.search(st["regex"].encode(), blob):
                matched.append(st["id"])
            elif "hex" in st:
                try:
                    pat = bytes.fromhex(st["hex"].replace(" ", ""))
                    if pat in blob:
                        matched.append(st["id"])
                except Exception:
                    pass
        cond = rule.get("condition", "any")
        ok = False
        if cond == "any":
            ok = bool(matched)
        elif cond == "all":
            ok = len(matched) == len(rule.get("strings", []))
        elif cond.endswith(" of them"):
            try:
                ok = len(matched) >= int(cond.split()[0])
            except Exception:
                ok = False
        if ok:
            hits.append({"rule": rule.get("id"), "name": rule.get("name"),
                         "tags": rule.get("tags", []), "attck": rule.get("attck", ""),
                         "matched_strings": matched})
    return hits


def extract_iocs(analysis):
    text = "\n".join(analysis.strings)
    iocs = {
        "ipv4": sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))[:100],
        "domains": sorted(set(re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|xyz|top|ru|cn)\b", text, re.I)))[:100],
        "urls": sorted(set(re.findall(r"https?://[^\s\"'<>]+", text)))[:100],
        "registry_keys": sorted(set(re.findall(r"HKEY_[A-Z_]+\\[^\s\"']+", text)))[:100],
        "emails": sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))[:100],
    }
    return iocs
