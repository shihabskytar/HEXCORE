"""HEXCORE local web server — serves the dark UI and a local API.

Local-first: binds to 127.0.0.1 only by default. The UI sends a file's
bytes to this local server (base64) for analysis; nothing is sent to
any external service. For large files, prefer the CLI with a file path.
"""
import base64
import json
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .engine import Analysis
from .security import v2_findings, extract_iocs, yara_like_scan
from .network import parse_pcap
from .decompiler import capabilities as decompiler_caps
from .dynamic import capabilities as dynamic_caps
from . import __version__

UI_DIR = Path(__file__).resolve().parent / "ui"


def _analyze_path(path, config=None):
    a = Analysis(path, config=config)
    v2 = v2_findings(a)
    weights = {"high": 10, "medium": 4, "low": 1, "info": 0}
    score = {"score": sum(weights.get(f["severity"], 0) for f in v2),
             "counts": {s: sum(1 for f in v2 if f["severity"] == s) for s in ("high", "medium", "low", "info")}}
    _state = {"instrs": a.instrs, "addr_to_func": {}}
    for _ins in a.instrs:
        _state["addr_to_func"].setdefault(_ins["address"], _ins["function"])
    from .engine import legacy as _legacy
    return {"product": "HEXCORE by SKYTAR", "version": __version__,
            "path": str(a.path), "size": len(a.data), "sha256": a.sha256,
            "format": a.parsed.get("format"), "sections": a.parsed.get("sections", []),
            "imports": a.parsed.get("imports", []), "exports": a.extra.get("exports", []),
            "dependencies": a.dependencies, "extra": a.extra,
            "strings": a.strings[:500], "string_count": len(a.strings),
            "functions": a.functions[:100], "function_count": len(a.functions),
            "cfg": {"blocks": len(a.cfg["blocks"]), "edges": len(a.cfg["edges"]),
                    "block_list": [{"start": hex(b["start"]), "end": hex(b["end"]),
                                    "function": b["function"],
                                    "instruction_count": len(b.get("instructions", []))}
                                   for b in a.cfg["blocks"][:100]],
                    "edge_list": a.cfg["edges"][:500]},
            "call_graph": _legacy.call_graph(_state, fmt="json"),
            "findings": v2, "iocs": extract_iocs(a), "risk_score": score,
            "disassembly": [{"address": hex(i["address"]), "mnemonic": i["mnemonic"],
                             "operands": i["operands"], "function": i["function"]} for i in a.instrs[:1000]]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            f = UI_DIR / "index.html"
            body = f.read_bytes() if f.is_file() else b"<h1>HEXCORE UI missing</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/health":
            return self._json({"product": "HEXCORE by SKYTAR", "version": __version__,
                               "decompiler": decompiler_caps(), "dynamic": dynamic_caps()})
        if parsed.path == "/api/capabilities":
            return self._json({"decompiler": decompiler_caps(), "dynamic": dynamic_caps(),
                               "note": "Unavailable tools are labelled, not faked. Install the tool in your lab to enable that adapter."})
        self._json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", 0))
        except Exception:
            length = 0
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            return self._json({"error": "Invalid JSON"}, 400)
        try:
            if parsed.path == "/api/analyze":
                # Path mode: local CLI-style, for files already on disk in the lab
                return self._json(_analyze_path(payload.get("path", "")))
            if parsed.path == "/api/analyze-bytes":
                data = base64.b64decode(payload.get("data_b64", ""))
                suffix = payload.get("filename", "sample.bin")
                with tempfile.NamedTemporaryFile(delete=False, suffix="-" + Path(suffix).name) as tf:
                    tf.write(data)
                    tmp = tf.name
                try:
                    result = _analyze_path(tmp)
                    result["path"] = payload.get("filename", "uploaded-sample")
                    return self._json(result)
                finally:
                    Path(tmp).unlink(missing_ok=True)
            if parsed.path == "/api/pcap":
                data = base64.b64decode(payload.get("data_b64", ""))
                return self._json(parse_pcap(data))
            if parsed.path == "/api/yara":
                a = Analysis(payload.get("path", ""))
                return self._json({"hits": yara_like_scan(a, payload.get("rules", []))})
        except Exception as exc:
            return self._json({"error": str(exc)}, 400)
        return self._json({"error": "Not found"}, 404)


def serve(host="127.0.0.1", port=8765):
    print(f"HEXCORE by SKYTAR — http://{host}:{port}  (local only, press Ctrl+C to stop)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
