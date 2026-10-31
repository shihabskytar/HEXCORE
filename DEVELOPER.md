# HEXCORE Developer Guide

## Add a new format parser
1. Write `parse_<format>(data)` in `hexcore/engine.py` (or a new module) returning `{"format": ..., "sections": [...], "imports": [...]}`.
2. Add it to `detect_and_parse` in `hexcore/legacy.py` (or to the engine's dispatch if you refactor it).
3. Add a test in `tests/test_hexcore.py` with a minimal crafted file and a truncated file (must not crash).

## Add a security rule
Add a branch in `hexcore/security.py:v2_findings` with title, severity, confidence, explanation, evidence, impact, remediation, and false-positive notes. Never present a heuristic as a confirmed vulnerability.

## Add a plugin
Create `hexcore/plugins/<id>/manifest.json` + `plugin.py` with `register()` returning tools/rules. See `hexcore/plugins/example/`. Sensitive permissions need config approval.

## Add a report template
Add a function in `hexcore/reports.py` and wire it into `hexcore/__main__.py:analyze` and `hexcore/mcp_server.py:export_report`.

## Run tests
```bash
python -m unittest discover -s tests -v
python -m hexcore analyze /bin/ls --json /tmp/report.json
python -m hexcore server   # then open http://127.0.0.1:8765
```
