"""The engine room: parses a pcap into PacketRecords, builds stats,
reconstructs TCP streams, carves transferred files, and hunts IOCs.

Everything here is pure-python / offline -- no network calls.
"""

import os
import re
import hashlib
import base64
from collections import defaultdict, Counter

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw

from .models import PacketRecord
from . import indicators as ind

CRED_PATTERN = re.compile(rb'(user(name)?|pass(word)?|login|pwd)\s*[:=]\s*[^\s&"\']{2,}', re.I)
BASIC_AUTH_PATTERN = re.compile(rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.I)
CONTENT_DISPOSITION = re.compile(rb'[Cc]ontent-[Dd]isposition:[^\r\n]*filename=["\']?([^"\';\r\n]+)')
USER_AGENT = re.compile(rb"User-Agent:\s*([^\r\n]+)", re.I)
HOST_HEADER = re.compile(rb"Host:\s*([^\r\n]+)", re.I)


def defang(s: str) -> str:
    return (s or "").replace(".", "[.]").replace("http://", "hxxp://").replace("https://", "hxxps://")


class TCPStream:
    """One reconstructed TCP conversation, client->server and server->client
    bytes kept separate and interleaved-by-time, like Wireshark's Follow
    TCP Stream."""
    def __init__(self, stream_id, key):
        self.id = stream_id
        self.key = key  # (ip_a, port_a, ip_b, port_b) - ip_a/port_a = first-seen sender
        self.segments = []  # list[(direction, time, bytes)]  direction: 'C' or 'S'
        self.packet_nos = []

    def add(self, direction, time, data, pkt_no):
        if data:
            self.segments.append((direction, time, data))
        self.packet_nos.append(pkt_no)

    def rendered_text(self):
        out = []
        for direction, t, data in self.segments:
            arrow = ">>>" if direction == "C" else "<<<"
            try:
                text = data.decode(errors="replace")
            except Exception:
                text = repr(data)
            out.append(f"{arrow} {text}")
        return "\n".join(out)

    def all_bytes(self):
        return b"".join(seg[2] for seg in self.segments)


class PcapAnalysis:
    def __init__(self, path):
        self.path = path
        self.packets = []
        self.total = 0
        self.start_t = None
        self.end_t = None
        self.proto_counts = Counter()
        self.talkers = Counter()
        self.talker_bytes = Counter()
        self.iocs = []
        self.streams = {}          # stream_id -> TCPStream
        self._stream_lookup = {}   # 5tuple-ish key -> stream_id
        self.dns_queries = []      # list[(time, packet_no, qname, src)]
        self.carved_files = []     # list[dict: name, ext, sha256, size, packet_no, src, dst]

    # ---------------- loading ----------------
    def load(self, progress_cb=None):
        pkts = rdpcap(self.path)
        self.total = len(pkts)
        for i, p in enumerate(pkts):
            rec = PacketRecord(i + 1, p)
            self.packets.append(rec)
            self.proto_counts[rec.proto] += 1
            if rec.src != "-" and rec.dst != "-":
                key = (rec.src, rec.dst)
                self.talkers[key] += 1
                self.talker_bytes[key] += rec.length
            if self.start_t is None or rec.time < self.start_t:
                self.start_t = rec.time
            if self.end_t is None or rec.time > self.end_t:
                self.end_t = rec.time
            if rec.is_tcp and rec.raw_payload:
                self._track_stream(rec)
            if rec.proto == "DNS":
                qname = rec.info.replace("DNS query ", "")
                self.dns_queries.append((rec.time, rec.no, qname, rec.src))
            if progress_cb and i % 200 == 0:
                progress_cb(i + 1, self.total)

        self._carve_files()
        self._hunt_iocs()

    def duration(self):
        if self.start_t and self.end_t:
            return self.end_t - self.start_t
        return 0.0

    def top_talkers(self, n=15):
        return self.talkers.most_common(n)

    # ---------------- TCP stream reconstruction ----------------
    def _track_stream(self, rec):
        a = (rec.src, rec.sport)
        b = (rec.dst, rec.dport)
        canon = tuple(sorted([a, b]))
        if canon not in self._stream_lookup:
            sid = len(self.streams)
            self._stream_lookup[canon] = sid
            self.streams[sid] = TCPStream(sid, (a[0], a[1], b[0], b[1]))
        sid = self._stream_lookup[canon]
        stream = self.streams[sid]
        direction = "C" if a == (stream.key[0], stream.key[1]) else "S"
        stream.add(direction, rec.time, rec.raw_payload, rec.no)
        rec.stream_id = sid

    def stream_summary(self):
        out = []
        for sid, s in self.streams.items():
            total_bytes = sum(len(seg[2]) for seg in s.segments)
            out.append({
                "id": sid, "client": f"{s.key[0]}:{s.key[1]}",
                "server": f"{s.key[2]}:{s.key[3]}",
                "segments": len(s.segments), "bytes": total_bytes,
            })
        return out

    # ---------------- file carving ----------------
    def _carve_files(self):
        # Carve per individual message (segment), not the whole joined
        # stream -- otherwise request bytes mask the response's magic bytes.
        for sid, s in self.streams.items():
            for direction, t, raw in s.segments:
                if not raw:
                    continue
                m = CONTENT_DISPOSITION.search(raw)
                name = m.group(1).decode(errors="ignore").strip() if m else None

                parts = raw.split(b"\r\n\r\n", 1)
                body = parts[1] if len(parts) > 1 and (m or parts[0].startswith((b"HTTP/", b"GET ", b"POST", b"PUT "))) else raw
                if not body:
                    continue

                sig_label, ext = None, None
                for magic, label, e in ind.FILE_SIGNATURES:
                    if body.startswith(magic) or magic in body[:64]:
                        sig_label, ext = label, e
                        break

                if not name and not sig_label:
                    continue
                if not name:
                    name = f"stream{sid}_carved{ext or ''}"

                sha256 = hashlib.sha256(body).hexdigest()
                self.carved_files.append({
                    "name": name, "signature": sig_label or "unknown",
                    "sha256": sha256, "size": len(body),
                    "stream_id": sid, "client": f"{s.key[0]}:{s.key[1]}",
                    "server": f"{s.key[2]}:{s.key[3]}", "body": body,
                })

    def export_carved_file(self, index, out_dir):
        f = self.carved_files[index]
        safe_name = re.sub(r'[^\w.\-]', '_', f["name"])
        path = os.path.join(out_dir, safe_name)
        with open(path, "wb") as fh:
            fh.write(f["body"])
        return path

    # ---------------- DNS stats ----------------
    def dns_stats(self):
        counter = Counter(q[2] for q in self.dns_queries)
        return counter.most_common()

    # ---------------- IOC hunting ----------------
    def _hunt_iocs(self):
        syn_counts = Counter()
        for rec in self.packets:
            payload = rec.raw_payload
            if payload:
                for m in CRED_PATTERN.finditer(payload):
                    snippet = payload[max(0, m.start() - 5):m.end() + 15]
                    self._add_ioc("high", "Cleartext credential",
                                   snippet.decode(errors="replace").strip(), rec)

                for m in BASIC_AUTH_PATTERN.finditer(payload):
                    try:
                        decoded = base64.b64decode(m.group(1) + b"===").decode(errors="replace")
                    except Exception:
                        decoded = "(failed to decode)"
                    self._add_ioc("high", "HTTP Basic Auth (base64-decoded)", decoded, rec)

                ua_match = USER_AGENT.search(payload)
                if ua_match:
                    ua = ua_match.group(1).decode(errors="ignore").strip()
                    flagged = any(mal.lower() in ua.lower() for mal in ind.KNOWN_MALWARE_UA)
                    self._add_ioc("high" if flagged else "low",
                                  "User-Agent" + (" (known-bad pattern)" if flagged else ""),
                                  ua, rec)

                fn_match = CONTENT_DISPOSITION.search(payload)
                if fn_match:
                    fname = fn_match.group(1).decode(errors="ignore")
                    ext_flag = fname.lower().endswith(ind.SUSPICIOUS_EXT)
                    self._add_ioc("high" if ext_flag else "med",
                                  "File transfer (Content-Disposition)", fname, rec)

                if rec.proto == "HTTP":
                    low = payload.lower()
                    for ext in ind.SUSPICIOUS_EXT:
                        if ext.encode() in low:
                            self._add_ioc("med", f"Suspicious extension ({ext})", rec.info, rec)
                            break

                low = payload.lower()
                for dom in ind.SUSPICIOUS_DOMAINS:
                    if dom.encode() in low:
                        self._add_ioc("high", "Known C2-channel domain reference", dom, rec)

            if rec.proto == "DNS" and rec.info.startswith("DNS query"):
                qname = rec.info.replace("DNS query ", "")
                for dom in ind.SUSPICIOUS_DOMAINS:
                    if dom in qname.lower():
                        self._add_ioc("high", "DNS query to C2-style domain", qname, rec)

            if rec.is_tcp and rec.flags == "S":
                syn_counts[rec.src] += 1

            if rec.dport in ind.PLAINTEXT_PROTO_PORTS and rec.is_tcp and rec.raw_payload:
                proto_name = ind.PLAINTEXT_PROTO_PORTS[rec.dport]
                if proto_name in ("FTP", "Telnet", "POP3", "IMAP", "TFTP"):
                    self._add_ioc("low", f"Insecure protocol in use ({proto_name})",
                                  f"{rec.src} -> {rec.dst}:{rec.dport}", rec)

        for src, count in syn_counts.items():
            if count >= 20:
                self.iocs.append({
                    "risk": "med", "kind": "Possible SYN scan",
                    "detail": f"{src} sent {count} SYN packets", "packet_no": "-",
                    "src": src, "dst": "-", "count": 1,
                })

        for f in self.carved_files:
            if f["name"].lower().endswith(ind.SUSPICIOUS_EXT) or "private key" in f["signature"].lower() \
                    or "PE executable" in f["signature"] or "ELF" in f["signature"]:
                self.iocs.append({
                    "risk": "high", "kind": f"Carved file: {f['signature']}",
                    "detail": f"{f['name']} sha256={f['sha256'][:16]}...",
                    "packet_no": "-", "src": f["client"], "dst": f["server"], "count": 1,
                })

        self._dedupe_iocs()

    def _add_ioc(self, risk, kind, detail, rec):
        self.iocs.append({
            "risk": risk, "kind": kind, "detail": detail,
            "packet_no": rec.no, "src": rec.src, "dst": rec.dst,
        })

    def _dedupe_iocs(self):
        seen, deduped = {}, []
        for ioc in self.iocs:
            key = (ioc["kind"], ioc["detail"])
            if key in seen:
                seen[key]["count"] = seen[key].get("count", 1) + 1
            else:
                ioc["count"] = ioc.get("count", 1)
                seen[key] = ioc
                deduped.append(ioc)
        self.iocs = deduped

    # ---------------- session save/load (lightweight cache, not full re-hydration) ----------------
    def to_session_dict(self):
        return {
            "path": self.path,
            "total": self.total,
            "duration": self.duration(),
            "proto_counts": dict(self.proto_counts),
            "top_talkers": [
                {"src": s, "dst": d, "packets": c, "bytes": self.talker_bytes[(s, d)]}
                for (s, d), c in self.top_talkers(50)
            ],
            "iocs": self.iocs,
            "dns_top": self.dns_stats()[:50],
            "carved_files": [{k: v for k, v in f.items() if k != "body"} for f in self.carved_files],
        }
