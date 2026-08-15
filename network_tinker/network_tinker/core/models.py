"""Lightweight per-packet record extracted from a scapy packet.

Kept intentionally small/flat (not the raw scapy object) so we can hold
hundreds of thousands of these in memory without choking the GUI.
"""

from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw


class PacketRecord:
    __slots__ = ("no", "time", "src", "dst", "sport", "dport", "proto",
                 "length", "flags", "info", "raw_payload", "stream_id", "is_tcp")

    def __init__(self, no, pkt):
        self.no = no
        self.time = float(pkt.time)
        self.length = len(pkt)
        self.src = self.dst = "-"
        self.sport = self.dport = None
        self.proto = "OTHER"
        self.flags = ""
        self.info = ""
        self.raw_payload = b""
        self.stream_id = None  # filled in by StreamTracker
        self.is_tcp = False    # true even if proto gets relabeled to HTTP/etc below

        ip_layer = None
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]

        if ip_layer is not None:
            self.src = ip_layer.src
            self.dst = ip_layer.dst

        if pkt.haslayer(TCP):
            self.proto = "TCP"
            self.is_tcp = True
            self.sport, self.dport = pkt[TCP].sport, pkt[TCP].dport
            self.flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            self.proto = "UDP"
            self.sport, self.dport = pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            self.proto = "ICMP"
        elif ip_layer is not None:
            self.proto = "IP"

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                self.info = f"DNS query {qname}"
                self.proto = "DNS"
            except Exception:
                pass

        if pkt.haslayer(Raw):
            self.raw_payload = bytes(pkt[Raw].load)
            head = self.raw_payload[:4]
            if head in (b"GET ", b"POST", b"HTTP", b"HEAD", b"PUT "):
                self.proto = "HTTP"
                try:
                    firstline = self.raw_payload.split(b"\r\n", 1)[0].decode(errors="ignore")
                    self.info = firstline
                except Exception:
                    pass

        if not self.info:
            port_bit = f" {self.sport}->{self.dport}" if self.sport else ""
            self.info = f"{self.proto}{port_bit} len={self.length}"

    def five_tuple(self):
        return (self.src, self.sport, self.dst, self.dport, self.proto)

    def as_dict(self):
        return {
            "no": self.no, "time": self.time, "src": self.src, "dst": self.dst,
            "sport": self.sport, "dport": self.dport, "proto": self.proto,
            "length": self.length, "flags": self.flags, "info": self.info,
            "stream_id": self.stream_id,
        }
