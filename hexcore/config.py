"""HEXCORE configuration. Local-first, no telemetry, no uploads by default."""
import json
from pathlib import Path

DEFAULTS = {
    "brand": "HEXCORE by SKYTAR",
    "website": "https://www.shihabskytar.com",
    "max_file_size": 512 * 1024 * 1024,
    "max_instructions": 10000,
    "max_strings": 5000,
    "disassembly_timeout": 30,
    "dynamic_timeout": 10,
    "risk_weights": {"high": 10, "medium": 4, "low": 1, "info": 0},
    "allow_execution": False,  # dynamic analysis requires explicit per-run consent
    "allow_network_upload": False,
    "plugins_enabled": True,
    "plugin_dirs": ["hexcore/plugins"],
}


def load_config(path=None):
    cfg = dict(DEFAULTS)
    p = Path(path) if path else Path("hexcore-config.json")
    if p.is_file():
        try:
            cfg.update(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            pass
    return cfg


def save_config(cfg, path="hexcore-config.json"):
    Path(path).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return path
