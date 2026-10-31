# HEXCORE MCP — Read-only analysis API

Start: `python -m hexcore mcp` (JSON-RPC over stdio, read-only).

Tools (22): analyze_binary, detect_format, list_sections, list_imports, list_exports, list_functions, get_function, disassemble_function, decompile_function, search_strings, search_bytes, get_xrefs, get_call_graph, get_cfg, investigate, compare_binaries, analyze_entropy, analyze_memory_layout, inspect_signature, get_security_findings, export_report, export_call_graph.

Rules:
- Every tool takes a `path` to a file already on disk in the lab. No tool lists directories or reads arbitrary files except the path given.
- `export_*` tools write only to the explicit `out` path given in the call.
- No tool executes the target, patches it, or uploads it.
- Responses include evidence (addresses, function names, confidence) and never fabricate disassembly or vulnerabilities.
- Resource limits: disassembly is capped (10,000 instructions in the legacy engine), string lists are capped, and decompiler adapters time out.

Example:
```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigate","arguments":{"path":"app.exe","query":"login"}}}
```
