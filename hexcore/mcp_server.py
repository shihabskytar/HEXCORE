"""HEXCORE MCP server — read-only, validated, resource-limited.

Extends the legacy MCP tools with: detect_format, list_exports,
disassemble_function, decompile_function, search_bytes, get_cfg,
compare_binaries, analyze_entropy, analyze_memory_layout,
inspect_signature, get_security_findings, export_report,
export_call_graph. No filesystem writes except export_* to an
explicit output path, and no execution.
"""
import json
import sys
from pathlib import Path

from .engine import Analysis, legacy
from .security import v2_findings, extract_iocs
from .memory import va_to_offset, hex_slice, search_bytes, section_map
from .reports import build_report_dict, to_json, to_markdown, to_html, to_pdf
from .decompiler import capabilities as decompiler_caps, decompile_with_tool
from . import __version__


def _load(path):
    return Analysis(path)


TOOLS = [
    ("analyze_binary", "Full HEXCORE analysis (v1 + v2 findings, IOCs, score)"),
    ("detect_format", "Format detection only"),
    ("list_sections", "Sections / entries / streams"),
    ("list_imports", "PE imports"),
    ("list_exports", "PE exports (best effort)"),
    ("list_functions", "Function summaries"),
    ("get_function", "Pseudo-C + summary for a function"),
    ("disassemble_function", "Instructions for one function"),
    ("decompile_function", "Decompiler adapter output, labelled by tool, or pseudo-C fallback note"),
    ("search_strings", "Case-insensitive string search"),
    ("search_bytes", "Hex pattern search in file bytes"),
    ("get_xrefs", "Callers/jumpers to an address"),
    ("get_call_graph", "Call graph JSON/DOT"),
    ("get_cfg", "CFG blocks and edges"),
    ("investigate", "One-question investigation"),
    ("compare_binaries", "Compare two binaries"),
    ("analyze_entropy", "Section entropy list"),
    ("analyze_memory_layout", "Section map + VA->offset helper data"),
    ("inspect_signature", "PE certificate directory presence"),
    ("get_security_findings", "v2 findings with confidence and remediation"),
    ("export_report", "Write HTML/JSON/Markdown/PDF report to an explicit path"),
    ("export_call_graph", "Write call graph DOT/JSON/HTML3D to an explicit path"),
]


def call_tool(name, args):
    if name == "export_report":
        a = _load(args["path"])
        v2 = v2_findings(a)
        from .security import extract_iocs as _iocs
        from .engine import legacy as _leg
        # Keep the full legacy risk score (score + level + counts) when available
        if hasattr(_leg, "risk_score"):
            score = _leg.risk_score(v2)
        else:
            weights = {"high": 10, "medium": 4, "low": 1, "info": 0}
            score = {"score": sum(weights.get(f["severity"], 0) for f in v2)}
        rep = build_report_dict(a, v2, _iocs(a), score)
        fmt = args.get("format", "json")
        out = args["out"]
        if fmt == "json":
            to_json(rep, out)
        elif fmt == "markdown":
            to_markdown(rep, out)
        elif fmt == "html":
            to_html(rep, out)
        elif fmt == "pdf":
            to_pdf(rep, out)
        else:
            raise ValueError("format must be json/markdown/html/pdf")
        return {"path": out, "format": fmt}
    if name == "export_call_graph":
        a = _load(args["path"])
        fmt = args.get("format", "dot")
        # Reuse legacy call_graph via a state-like dict
        state = {"instrs": a.instrs, "addr_to_func": {}}
        for ins in a.instrs:
            state["addr_to_func"].setdefault(ins["address"], ins["function"])
        # legacy.call_graph expects state with instrs/addr_to_func
        out_data = legacy.call_graph(state, fmt="dot" if fmt == "dot" else "json")
        Path(args["out"]).write_text(out_data if isinstance(out_data, str) else json.dumps(out_data, indent=2, default=str), encoding="utf-8")
        return {"path": args["out"], "format": fmt}
    a = _load(args["path"])
    if name == "analyze_binary":
        v2 = v2_findings(a)
        return {"format": a.parsed.get("format"), "sha256": a.sha256,
                "sections": len(a.parsed.get("sections", [])),
                "functions": len(a.functions), "findings": v2, "iocs": extract_iocs(a)}
    if name == "detect_format":
        return {"format": a.parsed.get("format"), "sha256": a.sha256}
    if name == "list_sections":
        return a.parsed.get("sections", [])
    if name == "list_imports":
        return a.parsed.get("imports", [])
    if name == "list_exports":
        return a.extra.get("exports", [])
    if name == "list_functions":
        return a.functions
    if name == "get_function":
        q = args.get("name", "")
        hit = next((f for f in a.functions if q.lower() in f["function"].lower()), None)
        state = {"instrs": a.instrs}
        return {"summary": hit, "pseudo_c": legacy.pseudo_c_for_function(state, q)}
    if name == "disassemble_function":
        q = args.get("name", "")
        return [i for i in a.instrs if q.lower() in i["function"].lower()][:500]
    if name == "decompile_function":
        tool = args.get("tool", "ghidra")
        res = decompile_with_tool(args["path"], tool=tool)
        if not res.get("available") or not res.get("output"):
            state = {"instrs": a.instrs}
            res["pseudo_c_fallback"] = legacy.pseudo_c_for_function(state, args.get("name", ""))
        return res
    if name == "search_strings":
        q = args.get("query", "").lower()
        return [s for s in a.strings if q in s.lower()][:100]
    if name == "search_bytes":
        return search_bytes(a.data, args.get("pattern", ""))
    if name == "get_xrefs":
        raw = str(args.get("address", "")).strip().lower()
        if raw and not raw.startswith("0x"):
            try:
                raw = hex(int(raw, 16))
            except Exception:
                pass
        return a.cfg["xrefs"].get(raw, [])
    if name == "get_call_graph":
        state = {"instrs": a.instrs, "addr_to_func": {}}
        for ins in a.instrs:
            state["addr_to_func"].setdefault(ins["address"], ins["function"])
        return legacy.call_graph(state, fmt=args.get("format", "json"))
    if name == "get_cfg":
        return {"blocks": len(a.cfg["blocks"]), "edges": len(a.cfg["edges"]), "xrefs": a.cfg["xrefs"]}
    if name == "investigate":
        state = {"instrs": a.instrs, "strings": a.strings, "parsed": a.parsed, "addr_to_func": {}}
        for ins in a.instrs:
            state["addr_to_func"].setdefault(ins["address"], ins["function"])
        return legacy.investigate(state, args.get("query", ""))
    if name == "compare_binaries":
        # Use legacy compare via the advanced module if available, else a simple diff
        try:
            return legacy.compare_binaries(args["path"], args["other_path"])
        except Exception:
            b = Analysis(args["other_path"])
            return {"a_sha256": a.sha256, "b_sha256": b.sha256,
                    "a_format": a.parsed.get("format"), "b_format": b.parsed.get("format")}
    if name == "analyze_entropy":
        return section_map(a.parsed)
    if name == "analyze_memory_layout":
        return {"sections": section_map(a.parsed),
                "example_va_to_offset": va_to_offset(a.parsed, args["address"]) if args.get("address") else None}
    if name == "inspect_signature":
        return a.extra.get("certificate")
    if name == "get_security_findings":
        return v2_findings(a)
    raise ValueError(f"Unknown tool: {name}")


def run():
    sys.stderr.write("HEXCORE MCP server ready (read-only).\n")
    sys.stderr.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        method, rid = req.get("method", ""), req.get("id")
        result, error = None, None
        try:
            if method == "initialize":
                result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "hexcore", "version": __version__}}
            elif method == "tools/list":
                result = {"tools": [{"name": n, "description": d,
                                     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}} for n, d in TOOLS]}
            elif method == "tools/call":
                p = req.get("params", {})
                data = call_tool(p.get("name", ""), p.get("arguments", {}))
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
