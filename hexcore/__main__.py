"""HEXCORE CLI — backward compatible with RE Lab Advanced commands.

Usage:
  python -m hexcore analyze app.exe [--json report.json]
  python -m hexcore investigate app.exe "login"
  python -m hexcore graph app.exe --format dot|json|html3d [--out file]
  python -m hexcore html app.exe [--out report.html]
  python -m hexcore compare old.exe new.exe
  python -m hexcore repl
  python -m hexcore mcp
  python -m hexcore server [--port 8765]
  python -m hexcore pcap capture.pcap
  python -m hexcore legacy <original RE Lab Advanced arguments>
"""
import sys

from .engine import Analysis, legacy
from .security import v2_findings, extract_iocs
from .reports import build_report_dict, to_json, to_markdown, to_html, to_pdf
from .network import parse_pcap
from .config import load_config


def _print_analysis(path):
    try:
        a = Analysis(path)
    except FileNotFoundError:
        print(f"Error: file not found: {path}")
        raise SystemExit(2)
    except Exception as exc:
        print(f"Error: could not analyse {path}: {exc}")
        raise SystemExit(2)
    v2 = v2_findings(a)
    print(f"HEXCORE by SKYTAR — {path}")
    print(f"  Format: {a.parsed.get('format')}  Size: {len(a.data)}  SHA-256: {a.sha256}")
    print(f"  Sections: {len(a.parsed.get('sections', []))}  Strings: {len(a.strings)}  Functions: {len(a.functions)}")
    print(f"  Findings (v2): {len(v2)}")
    for f in v2[:50]:
        print(f"    [{f['severity']}/{f['confidence']}] {f['title']} — {f['explanation'][:120]}")
    return a, v2


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    mode = argv[0]
    if mode == "server":
        from .server import serve
        port = 8765
        if "--port" in argv:
            try:
                port = int(argv[argv.index("--port") + 1])
            except Exception:
                print("Error: --port needs a number, e.g. --port 8765")
                return 2
        serve(port=port)
        return 0
    if mode == "mcp":
        from .mcp_server import run
        run()
        return 0
    if mode == "legacy":
        return legacy.advanced_main(argv[1:])
    if mode == "analyze":
        import argparse
        ap = argparse.ArgumentParser()
        ap.add_argument("target")
        ap.add_argument("--json", dest="json_out")
        ap.add_argument("--markdown", dest="md_out")
        ap.add_argument("--html", dest="html_out")
        ap.add_argument("--pdf", dest="pdf_out")
        a = ap.parse_args(argv[1:])
        analysis, v2 = _print_analysis(a.target)
        weights = {"high": 10, "medium": 4, "low": 1, "info": 0}
        score = {"score": sum(weights.get(f["severity"], 0) for f in v2)}
        rep = build_report_dict(analysis, v2, extract_iocs(analysis), score)
        if a.json_out:
            to_json(rep, a.json_out); print(f"JSON: {a.json_out}")
        if a.md_out:
            to_markdown(rep, a.md_out); print(f"Markdown: {a.md_out}")
        if a.html_out:
            to_html(rep, a.html_out); print(f"HTML: {a.html_out}")
        if a.pdf_out:
            to_pdf(rep, a.pdf_out); print(f"PDF: {a.pdf_out}")
        return 0
    if mode == "pcap":
        from pathlib import Path
        data = Path(argv[1]).read_bytes()
        import json as _j
        print(_j.dumps(parse_pcap(data), indent=2, default=str)[:8000])
        return 0
    # Delegate all other legacy modes (investigate, graph, html, compare, repl, trace, etc.)
    return legacy.advanced_main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
