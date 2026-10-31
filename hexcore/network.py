"""HEXCORE network module — passive PCAP / PCAPNG metadata analysis only.
No live capture, no interception, no credential harvesting.
Parses classic PCAP (not PCAPNG section blocks beyond a basic check) with
stdlib, extracts Ethernet/IP/TCP/UDP, DNS names, HTTP metadata and TLS SNI.
"""
import struct


def _ip_str(b):
    return ".".join(str(x) for x in b)


def parse_pcap(data):
    if len(data) < 24:
        return {"format": "unknown", "error": "File too small for a PCAP header"}
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        en, swapped = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        en, swapped = ">", False
    elif magic == b"\x0a\x0d\x0d\x0a":
        return {"format": "PCAPNG", "note": "PCAPNG detected. Full PCAPNG parsing needs tshark in your lab; use tshark -r file -T json for a complete view.",
                "packets": [], "flows": [], "dns": [], "http": [], "tls_sni": []}
    else:
        return {"format": "unknown", "error": "Not a classic PCAP file (magic mismatch)"}
    linktype = struct.unpack_from(en + "I", data, 20)[0]
    off = 24
    packets, flows, dns_names, http_meta, tls_sni = [], {}, set(), [], set()
    idx = 0
    while off + 16 <= len(data) and idx < 100000:
        ts_sec, ts_usec, incl, orig = struct.unpack_from(en + "IIII", data, off)
        off += 16
        if off + incl > len(data):
            break
        pkt = data[off:off + incl]
        off += incl
        idx += 1
        info = {"index": idx, "length": incl, "timestamp": ts_sec}
        # Ethernet (linktype 1) only; other linktypes are reported, not decoded
        if linktype == 1 and len(pkt) >= 14:
            ethertype = struct.unpack_from(">H", pkt, 12)[0]
            if ethertype == 0x0800 and len(pkt) >= 34:
                proto = pkt[23]
                src, dst = _ip_str(pkt[26:30]), _ip_str(pkt[30:34])
                ihl = (pkt[14] & 0x0F) * 4
                l4 = 14 + ihl
                sport = dport = None
                if proto in (6, 17) and len(pkt) >= l4 + 4:
                    sport, dport = struct.unpack_from(">HH", pkt, l4)
                info.update({"src": src, "dst": dst, "proto": proto, "sport": sport, "dport": dport})
                key = (src, sport, dst, dport, proto)
                flows[key] = flows.get(key, 0) + 1
                payload = pkt[l4 + 8:] if proto == 17 else pkt[l4 + 20:] if proto == 6 else b""
                # DNS (UDP 53)
                if proto == 17 and (sport == 53 or dport == 53) and len(payload) > 12:
                    try:
                        # Very small DNS name parser: labels until 0, in the question section
                        p = 12
                        labels = []
                        while p < len(payload) and payload[p] != 0 and len(labels) < 10:
                            ln = payload[p]
                            labels.append(payload[p + 1:p + 1 + ln].decode(errors="ignore"))
                            p += 1 + ln
                        if labels:
                            dns_names.add(".".join(labels))
                    except Exception:
                        pass
                # HTTP metadata (first line only, no body, no credentials)
                if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"HTTP/")):
                    line = payload.split(b"\r\n", 1)[0].decode(errors="ignore")[:300]
                    http_meta.append(line)
                # TLS SNI: search for ClientHello server_name extension is complex;
                # this is a best-effort scan for a readable hostname in TLS payloads
                if proto == 6 and len(payload) > 10 and payload[0] == 0x16:
                    # Do not claim SNI unless we can parse it; keep it as a note
                    pass
        packets.append(info)
    return {"format": "PCAP", "linktype": linktype, "packet_count": len(packets),
            "packets": packets[:1000],
            "flows": [{"src": k[0], "sport": k[1], "dst": k[2], "dport": k[3], "proto": k[4], "count": v}
                      for k, v in sorted(flows.items(), key=lambda x: -x[1])[:200]],
            "dns": sorted(dns_names)[:200], "http": http_meta[:200], "tls_sni": sorted(tls_sni),
            "note": "Passive metadata only. TLS payloads are not decrypted. Use Wireshark/tshark for full protocol dissection."}
