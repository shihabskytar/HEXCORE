"""HEXCORE memory / structure module — static layout only.
Distinguishes static VA/file-offset mapping from runtime memory, which
is only available via the dynamic adapters (with explicit consent).
"""
from .engine import legacy


def va_to_offset(parsed, va):
    """Virtual address (int or hex string) -> file offset, or None."""
    if isinstance(va, str):
        va = int(va.strip().lower().removeprefix("0x"), 16)
    # PE: VA = ImageBase + RVA
    if parsed.get("format") == "PE":
        base = 0
        try:
            base = int(parsed.get("image_base", "0"), 16)
        except Exception:
            base = 0
        rva = va - base if va >= base else va
        return legacy._rva_to_offset(rva, parsed.get("sections", []))
    for s in parsed.get("sections", []):
        if isinstance(s, dict) and "address" in s:
            try:
                addr = int(s["address"], 16)
            except Exception:
                continue
            if addr <= va < addr + s.get("size", 0):
                return s.get("offset", 0) + (va - addr)
    return None


def hex_slice(data, offset, length=256):
    if offset < 0 or offset >= len(data):
        return {"error": "Offset out of range", "offset": offset}
    chunk = data[offset:offset + length]
    hex_text = " ".join(f"{b:02x}" for b in chunk)
    ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return {"offset": offset, "length": len(chunk), "hex": hex_text, "ascii": ascii_text}


def search_bytes(data, pattern_hex):
    try:
        pat = bytes.fromhex(pattern_hex.replace(" ", ""))
    except Exception as exc:
        return {"error": f"Invalid hex pattern: {exc}"}
    hits, idx = [], 0
    while True:
        idx = data.find(pat, idx)
        if idx == -1 or len(hits) >= 100:
            break
        hits.append(idx)
        idx += 1
    return {"pattern": pattern_hex, "hits": hits}


def section_map(parsed):
    out = []
    for s in parsed.get("sections", []):
        if not isinstance(s, dict):
            continue
        out.append({"name": s.get("name"), "virtual_address": s.get("virtual_address") or s.get("address"),
                    "size": s.get("raw_size") or s.get("size"),
                    "executable": s.get("executable"), "writable": s.get("writable"),
                    "readable": s.get("readable"), "entropy": s.get("entropy")})
    return out
