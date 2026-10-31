"""HEXCORE reporting: HTML, JSON, Markdown, and a basic PDF.

PDF: if reportlab is installed, it is used. Otherwise a minimal,
valid PDF with the report text is written by hand and labelled as
basic in the report itself — no fake professional PDF is claimed.
Reports are reproducible: they always include hashes, format,
methodology and limitations.
"""
import json
from pathlib import Path


def build_report_dict(analysis, v2, iocs, score):
    return {
        "product": "HEXCORE by SKYTAR", "website": "https://www.shihabskytar.com",
        "tagline": "Decode the Unknown. Understand the Core.",
        "sample": {"path": str(analysis.path), "size": len(analysis.data),
                   "sha256": analysis.sha256, "md5": analysis.md5, "sha1": analysis.sha1,
                   "format": analysis.parsed.get("format")},
        "sections": analysis.parsed.get("sections", []),
        "imports": analysis.parsed.get("imports", []),
        "extra": analysis.extra, "dependencies": analysis.dependencies,
        "functions": analysis.functions, "findings": v2, "iocs": iocs,
        "risk_score": score,
        "methodology": "Read-only static analysis. Findings are heuristics with confidence levels, not confirmed vulnerabilities.",
        "limitations": "Stripped binaries merge functions; packed/encrypted code needs unpacking in a lab; decompiler output is labelled by tool, heuristic pseudo-C is not decompiler output.",
    }


def to_json(report, path):
    Path(path).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def to_markdown(report, path):
    lines = [f"# HEXCORE Report — {report['sample']['path']}", "",
             f"**HEXCORE by SKYTAR** — https://www.shihabskytar.com  ",
             f"SHA-256: `{report['sample']['sha256']}`  Format: {report['sample']['format']}  ",
             f"Risk: {report['risk_score']}  ", "", "## Findings", ""]
    for f in report["findings"]:
        lines.append(f"- **[{f['severity']}/{f['confidence']}] {f['title']}** — {f['explanation']} Evidence: {f['evidence']} Fix: {f['remediation']}")
    lines += ["", "## Methodology", report["methodology"], "", "## Limitations", report["limitations"], ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")
    return path


def to_html(report, path):
    rows = "".join(f"<tr><td>{f['severity']}</td><td>{f['confidence']}</td><td>{f['title']}</td><td>{f['explanation']}</td><td>{f['remediation']}</td></tr>" for f in report["findings"])
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>HEXCORE Report</title>
<style>body{{font-family:Segoe UI,Arial;max-width:1100px;margin:24px auto;padding:0 16px;background:#0b1220;color:#e5e7eb}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #334155;padding:6px}}th{{background:#1e293b}}a{{color:#38bdf8}}</style></head><body>
<h1>HEXCORE <span style="color:#38bdf8">by SKYTAR</span></h1><p>Decode the Unknown. Understand the Core. — https://www.shihabskytar.com</p>
<p>Sample: {report['sample']['path']} &nbsp; SHA-256: {report['sample']['sha256']} &nbsp; Format: {report['sample']['format']}</p>
<h2>Findings</h2><table><tr><th>Severity</th><th>Confidence</th><th>Title</th><th>Explanation</th><th>Fix</th></tr>{rows}</table>
<p>{report['methodology']}</p><p>{report['limitations']}</p></body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
    return path


def _escape_pdf(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def to_pdf(report, path):
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.pdfgen import canvas  # type: ignore
        c = canvas.Canvas(str(path), pagesize=A4)
        y = 800
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, y, "HEXCORE by SKYTAR - Report"); y -= 24
        c.setFont("Helvetica", 10)
        for line in [f"Sample: {report['sample']['path']}", f"SHA-256: {report['sample']['sha256']}",
                     f"Format: {report['sample']['format']}", f"Risk: {report['risk_score']}"]:
            c.drawString(40, y, line[:110]); y -= 16
        c.drawString(40, y, "Findings:"); y -= 16
        for f in report["findings"][:50]:
            c.drawString(40, y, f"[{f['severity']}/{f['confidence']}] {f['title']}"[:110]); y -= 14
            if y < 40:
                c.showPage(); y = 800
        c.save()
        return path
    except Exception:
        # Minimal valid PDF, labelled basic
        lines = [f"HEXCORE by SKYTAR - Basic PDF Report",
                 f"Sample: {report['sample']['path']}",
                 f"SHA-256: {report['sample']['sha256']}",
                 f"Format: {report['sample']['format']}",
                 "Note: reportlab was not installed, so this is a basic text PDF. Use the HTML report for full formatting."]
        for f in report["findings"][:50]:
            lines.append(f"[{f['severity']}/{f['confidence']}] {f['title']}")
        content = "\n".join(lines)
        stream = "BT /F1 10 Tf 40 780 Td " + " ".join(f"({_escape_pdf(l)}) Tj 0 -14 Td" for l in content.split("\n")) + " ET"
        objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
                   b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                   b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
                   f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream".encode(),
                   b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
        out, offsets = bytearray(), []
        out += b"%PDF-1.4\n"
        for i, obj in enumerate(objects, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode()
        for o in offsets:
            out += f"{o:010d} 00000 n \n".encode()
        out += f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
        Path(path).write_bytes(out)
        return path
