"""HEXCORE decompiler adapters — graceful fallback, never fake output.

If Ghidra, RetDec, Rizin or LLVM tools are installed, they are invoked
with a timeout and their output is labelled with the tool name.
Otherwise the tool returns the heuristic pseudo-C from the core engine
and clearly says so. Heuristic pseudo-C is NOT decompiler output.
"""
import shutil
import subprocess


def capabilities():
    tools = {}
    for name, bins in {
        "ghidra": ["ghidraRun", "ghidra"],
        "retdec": ["retdec-decompiler", "retdec"],
        "rizin": ["rizin", "radare2", "r2"],
        "llvm_objdump": ["llvm-objdump"],
        "objdump": ["objdump"],
        "capstone": [],
    }.items():
        tools[name] = next((shutil.which(b) for b in bins if shutil.which(b)), None)
    try:
        import capstone  # noqa
        tools["capstone"] = "python-capstone"
    except Exception:
        tools["capstone"] = None
    return tools


def decompile_with_tool(path, tool="ghidra", timeout=60):
    caps = capabilities()
    exe = caps.get(tool)
    if not exe:
        return {"tool": tool, "available": False,
                "note": f"{tool} is not installed on this system. Use the heuristic pseudo-C in the core report, or install {tool} and retry.",
                "output": ""}
    try:
        if tool == "rizin":
            cmd = [exe, "-AA", "-qc", "pdf", str(path)]
        elif tool == "retdec":
            cmd = [exe, str(path)]
        elif tool == "llvm_objdump":
            cmd = [exe, "-d", str(path)]
        else:
            # Ghidra headless needs a project dir; do not guess one silently.
            return {"tool": tool, "available": True,
                    "note": "Ghidra headless requires a project directory and an analysis script. Run analyzeHeadless yourself in your lab and import its output; HEXCORE does not silently invent Ghidra output.",
                    "output": ""}
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"tool": tool, "available": True, "returncode": proc.returncode,
                "output": (proc.stdout or proc.stderr)[:20000]}
    except subprocess.TimeoutExpired:
        return {"tool": tool, "available": True, "error": "Decompiler timed out"}
    except Exception as exc:
        return {"tool": tool, "available": False, "error": str(exc)}
