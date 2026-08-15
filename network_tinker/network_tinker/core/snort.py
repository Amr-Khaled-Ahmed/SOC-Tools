"""Snort rule generation helpers.

Builds valid Snort rule syntax:
    action protocol src_ip src_port -> dst_ip dst_port (rule options)

Both a manual "fill in the fields" builder and a couple of one-click
generators for the patterns that show up constantly in the SOC101 Snort
challenge (LFI detection, brute-force detection, private key exfil, etc).
"""

_sid_counter = [1000001]


def next_sid():
    sid = _sid_counter[0]
    _sid_counter[0] += 1
    return sid


def build_rule(action="alert", protocol="tcp", src_ip="any", src_port="any",
                dst_ip="any", dst_port="any", msg="", content=None,
                pcre=None, sid=None, rev=1, extra_opts=None):
    sid = sid or next_sid()
    opts = []
    if msg:
        opts.append(f'msg:"{msg}"')
    if content:
        opts.append(f'content:"{content}"')
    if pcre:
        opts.append(f'pcre:"{pcre}"')
    if extra_opts:
        opts.extend(extra_opts)
    opts.append(f"sid:{sid}")
    opts.append(f"rev:{rev}")
    opt_str = "; ".join(opts) + ";"
    return f"{action} {protocol} {src_ip} {src_port} -> {dst_ip} {dst_port} ({opt_str})"


def rule_from_packet(rec, action="alert", msg=None, content_from_payload=True):
    """Generate a starter rule from a selected PacketRecord."""
    if getattr(rec, "is_tcp", False):
        proto = "tcp"
    elif rec.proto.lower() in ("udp", "icmp"):
        proto = rec.proto.lower()
    else:
        proto = "ip"
    msg = msg or f"Traffic matching packet #{rec.no} pattern"
    content = None
    if content_from_payload and rec.raw_payload:
        snippet = rec.raw_payload[:40]
        try:
            content = snippet.decode()
            if not content.isprintable():
                content = None
        except Exception:
            content = None
    return build_rule(action=action, protocol=proto, dst_port=rec.dport or "any",
                       msg=msg, content=content)


def rule_lfi_detection(dst_port=80):
    return build_rule(action="alert", protocol="tcp", dst_port=dst_port,
                       msg="Possible LFI attempt - directory traversal in URI",
                       content="../")


def rule_bruteforce_401(dst_port=80, threshold_count=10, threshold_seconds=30):
    return build_rule(action="alert", protocol="tcp", src_port="any", dst_port=dst_port,
                       msg=f"Possible brute force - {threshold_count} HTTP 401 in {threshold_seconds}s",
                       content="401 Unauthorized",
                       extra_opts=[f"detection_filter:track by_src, count {threshold_count}, "
                                   f"seconds {threshold_seconds}"])


def rule_successful_login_302(dst_port=80):
    return build_rule(action="alert", protocol="tcp", dst_port=dst_port,
                       msg="Successful login redirect (HTTP 302) to admin portal",
                       content="302 Found")


def rule_ssh_key_exfil():
    return build_rule(action="alert", protocol="tcp", dst_port=80,
                       msg="Possible OpenSSH private key exfiltration over HTTP",
                       content="BEGIN OPENSSH PRIVATE KEY")


def rule_outbound_ftp(internal_net="192.168.1.0/24"):
    return build_rule(action="alert", protocol="tcp", src_ip=f"!{internal_net}",
                       dst_port=21, msg="Outbound FTP connection to external host")
