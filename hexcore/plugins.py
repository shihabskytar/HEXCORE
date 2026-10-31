"""HEXCORE plugin system.

A plugin is a folder with manifest.json and plugin.py:
  manifest: {id, name, version, description, permissions: [...], entry: "plugin.py"}
  plugin.py: def register(): return {"tools": {"tool_name": callable}, "rules": [...]}

Plugins are loaded with error isolation: one failing plugin never
breaks the core. Plugins requesting 'filesystem_write' or 'execute'
must be explicitly enabled in config; otherwise they load read-only
or not at all. No plugin is loaded from an untrusted path by default.
"""
import importlib.util
import json
from pathlib import Path


def load_plugins(dirs, config=None):
    cfg = config or {}
    loaded, errors = [], []
    for d in dirs:
        base = Path(d)
        if not base.is_dir():
            continue
        for folder in sorted(base.iterdir()):
            if not folder.is_dir():
                continue
            manifest_path = folder / "manifest.json"
            if not manifest_path.is_file():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                perms = set(manifest.get("permissions", []))
                if perms & {"filesystem_write", "execute"} and not cfg.get("plugins_allow_sensitive", False):
                    errors.append({"plugin": manifest.get("id"), "error": "Sensitive permissions require plugins_allow_sensitive=true in config"})
                    continue
                entry = folder / manifest.get("entry", "plugin.py")
                spec = importlib.util.spec_from_file_location(f"hexcore_plugin_{manifest.get('id')}", entry)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                reg = mod.register() if hasattr(mod, "register") else {}
                loaded.append({"manifest": manifest, "tools": list((reg.get("tools") or {}).keys()),
                               "module": mod})
            except Exception as exc:
                errors.append({"plugin": str(folder), "error": str(exc)})
    return {"loaded": loaded, "errors": errors}


def call_plugin_tool(loaded, tool_name, *args, **kwargs):
    for p in loaded:
        tools = p["module"].register().get("tools", {}) if hasattr(p["module"], "register") else {}
        if tool_name in tools:
            return tools[tool_name](*args, **kwargs)
    raise KeyError(f"Plugin tool not found: {tool_name}")
