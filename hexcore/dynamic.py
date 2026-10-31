"""HEXCORE dynamic analysis adapters — explicit consent only.

No binary is executed unless the caller passes allow_run=True AND the
config allows execution AND the run is in a lab/VM context the user
has confirmed. Every adapter first reports capability, then refuses
if the tool is missing or consent is absent. Network isolation,
disposable VMs and resource limits are the user's lab responsibility
and are labelled as such in reports — HEXCORE does not claim to
provide a sandbox it does not actually create.
"""
import shutil
import subprocess
import sys


def capabilities():
    caps = {}
    for name in ["strace", "ltrace", "gdb", "lldb", "tshark", "procmon", "windbg"]:
        caps[name] = shutil.which(name)
    caps["platform"] = sys.platform
    caps["etw_note"] = "ETW / Process Monitor integration on Windows requires ProcMon / ETW tooling and admin rights in your lab; not available from Python alone." if sys.platform.startswith("win") else "Not a Windows host."
    caps["endpoint_security_note"] = "macOS Endpoint Security requires a signed, entitled system extension; not available from Python alone." if sys.platform == "darwin" else "Not a macOS host."
    return caps


def run_trace(path, allow_run=False, timeout=10, extra_args=None):
    if not allow_run:
        return {"executed": False, "reason": "Execution refused: allow_run was not set. Dynamic analysis requires explicit per-run consent."}
    if sys.platform.startswith("linux") and shutil.which("strace"):
        cmd = ["strace", "-f", "-e", "trace=openat,read,write,connect,execve", str(path)] + (extra_args or [])
    elif sys.platform.startswith("linux") and shutil.which("ltrace"):
        cmd = ["ltrace", "-f", str(path)] + (extra_args or [])
    else:
        return {"executed": False, "reason": f"No supported tracer on this platform ({sys.platform}). Install strace/ltrace (Linux), WinDbg/ProcMon (Windows) or LLDB (macOS) in your lab."}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"executed": True, "tool": cmd[0], "returncode": proc.returncode,
                "stdout": proc.stdout[:5000], "stderr": proc.stderr[:20000],
                "note": "Trace was run in the caller's environment. HEXCORE did not create a VM or network isolation for this run; use a disposable VM for unknown samples."}
    except subprocess.TimeoutExpired:
        return {"executed": False, "reason": "Trace stopped at timeout", "timeout": timeout}
    except Exception as exc:
        return {"executed": False, "reason": str(exc)}
