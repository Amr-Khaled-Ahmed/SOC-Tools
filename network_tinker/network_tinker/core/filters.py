"""A small tcpdump/BPF-inspired filter language for filtering PacketRecords.

Supported atoms:  host X | src X | dst X | port N | tcp | udp | icmp | dns | http
Combine with:     and / or / not / ( )

This is intentionally NOT full BPF -- it's the 20% of syntax that covers
95% of day-to-day triage, matching what's in the SOC101 tcpdump notes.
"""

import re


def apply_filter(packets, expr):
    expr = (expr or "").strip()
    if not expr:
        return packets

    tokens = re.findall(r'\(|\)|\bnot\b|\band\b|\bor\b|"[^"]+"|\S+', expr, re.I)

    def match_atom(rec, atom_tokens):
        kw = atom_tokens[0].lower()
        if kw in ("tcp", "udp", "icmp", "dns", "http"):
            return rec.proto.lower() == kw
        if kw in ("host", "src", "dst") and len(atom_tokens) >= 2:
            val = atom_tokens[1]
            if kw == "host":
                return val in (rec.src, rec.dst)
            if kw == "src":
                return val == rec.src
            if kw == "dst":
                return val == rec.dst
        if kw == "port" and len(atom_tokens) >= 2:
            try:
                p = int(atom_tokens[1])
            except ValueError:
                return False
            return p in (rec.sport, rec.dport)
        return False

    def build_py_expr(toks):
        out, i = [], 0
        while i < len(toks):
            t = toks[i]
            tl = t.lower()
            if tl in ("and", "or", "not", "(", ")"):
                out.append(tl)
                i += 1
            elif tl in ("tcp", "udp", "icmp", "dns", "http"):
                out.append(f"M(['{tl}'])")
                i += 1
            elif tl in ("host", "src", "dst", "port") and i + 1 < len(toks):
                val = toks[i + 1].strip('"')
                out.append(f"M(['{tl}', '{val}'])")
                i += 2
            else:
                i += 1
        return " ".join(out)

    py_expr = build_py_expr(tokens)
    if not py_expr:
        return packets

    results = []
    for rec in packets:
        def M(atom_tokens, rec=rec):
            return match_atom(rec, atom_tokens)
        try:
            if eval(py_expr, {"__builtins__": {}}, {"M": M}):
                results.append(rec)
        except Exception:
            return packets  # bad filter -> fail open to "show everything"
    return results


def to_tcpdump_equivalent(expr):
    """Cosmetic helper: the filter language already *is* tcpdump BPF syntax,
    so this just echoes back what you'd type on the CLI, for copy/paste."""
    expr = (expr or "").strip()
    if not expr:
        return "tcpdump -r capture.pcap"
    return f"tcpdump -r capture.pcap '{expr}'"
