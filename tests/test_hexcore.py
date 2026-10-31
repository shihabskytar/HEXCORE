"""HEXCORE unit + integration tests. Run: python -m unittest discover -s tests -v"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hexcore.engine import Analysis, legacy
from hexcore.security import v2_findings, extract_iocs, yara_like_scan
from hexcore.network import parse_pcap
from hexcore.memory import va_to_offset, search_bytes


def make_pe32():
    data = bytearray(1024)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 128)
    data[128:132] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 132, 0x14C, 1, 0, 0, 0, 224, 0)
    opt = 152
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<H", data, opt + 70, 0x8140)
    struct.pack_into("<I", data, opt + 92, 16)
    sec = opt + 224
    data[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, sec + 8, 0x100, 0x1000, 0x200, 512)
    return bytes(data)


class TestEngine(unittest.TestCase):
    def test_pe32_image_base(self):
        p = legacy.parse_pe(make_pe32())
        self.assertEqual(p["image_base"], "0x400000")

    def test_cfg_plain_hex_targets(self):
        instrs = [{"address": 0x4010, "mnemonic": "je", "operands": "4016 <free@plt>", "function": "f"},
                  {"address": 0x4016, "mnemonic": "ret", "operands": "", "function": "f"}]
        cfg = legacy.build_cfg(instrs)
        self.assertTrue(any(e["kind"] == "jump" and e["to"] == 0x4016 for e in cfg["edges"]))

    def test_risky_import_normalisation(self):
        class Fake:
            parsed = {"format": "PE", "imports": [{"dll": "msvcrt.dll", "functions": ["strcpy@plt", "MD5_Init"]}], "sections": []}
            strings = []
            functions = []
            instrs = []
        findings = v2_findings(Fake())
        areas = [f["area"] for f in findings]
        self.assertIn("unsafe-function", areas)
        self.assertIn("weak-crypto", areas)

    def test_pcap(self):
        # Minimal PCAP: global header + one Ethernet/IP/TCP packet (truncated payload is fine)
        import io
        gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        pkt = b"\x00" * 14 + bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]) + b"\x00" * 20
        ph = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
        res = parse_pcap(gh + ph + pkt)
        self.assertEqual(res["format"], "PCAP")
        self.assertEqual(res["packet_count"], 1)

    def test_search_bytes_and_iocs(self):
        self.assertEqual(search_bytes(b"hello\x00world", "68656c6c6f")["hits"], [0])
        class Fake:
            strings = ["Visit https://example.com/path and 192.0.2.1 for details"]
        iocs = extract_iocs(Fake())
        self.assertIn("192.0.2.1", iocs["ipv4"])
        self.assertIn("https://example.com/path", iocs["urls"])

    def test_yara_like(self):
        class Fake:
            data = b"hello secret-key-123"
        hits = yara_like_scan(Fake(), [{"id": "t1", "name": "test", "strings": [{"id": "s1", "text": "secret"}], "condition": "any"}])
        self.assertEqual(len(hits), 1)

    def test_pe_export_indices(self):
        # Minimal PE64 with one export named MyFunc
        data = bytearray(4096)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 128)
        data[128:132] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", data, 132, 0x8664, 1, 0, 0, 0, 240, 0)
        opt = 152
        struct.pack_into("<H", data, opt, 0x20B)
        struct.pack_into("<I", data, opt + 16, 0x1000)
        struct.pack_into("<Q", data, opt + 24, 0x140000000)
        struct.pack_into("<H", data, opt + 68, 3)
        struct.pack_into("<H", data, opt + 70, 0x8140)
        struct.pack_into("<I", data, opt + 108, 16)
        struct.pack_into("<II", data, opt + 112, 0x1000, 200)
        sec = opt + 240
        data[sec:sec + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", data, sec + 8, 0x200, 0x1000, 0x400, 512)
        struct.pack_into("<IIHHIIIIIII", data, 512, 0, 0, 0, 0, 0x1100, 1, 2, 1, 0x1080, 0x1090, 0x10A0)
        struct.pack_into("<I", data, 640, 0x2000)
        struct.pack_into("<I", data, 656, 0x1110)
        data[768:776] = b"test.dll\x00"
        data[784:791] = b"MyFunc\x00"
        struct.pack_into("<H", data, 672, 0)
        from hexcore.engine import _pe_extra
        parsed = legacy.parse_pe(bytes(data))
        self.assertEqual(_pe_extra(bytes(data), parsed)["exports"], ["MyFunc"])

    def test_analysis_on_ls(self):
        a = Analysis("/bin/ls")
        self.assertEqual(a.parsed.get("format"), "ELF")
        self.assertEqual(len(a.sha256), 64)


if __name__ == "__main__":
    unittest.main()
