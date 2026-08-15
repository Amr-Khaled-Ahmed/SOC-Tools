"""Static indicator lists used by the IOC hunter.

These are intentionally small, curated, offline lists (no API calls / no
internet dependency at runtime) -- edit freely to tune false positives for
whatever challenge pcap you're working through.
"""

SUSPICIOUS_EXT = (".dll", ".exe", ".bin", ".ps1", ".scr", ".vbs", ".bat",
                   ".jar", ".hta", ".sh", ".elf")

# Domains/services commonly abused as C2 / exfil channels because they're
# hard to block outright (legit services being tunneled through).
SUSPICIOUS_DOMAINS = (
    "t.me", "telegram.org", "api.telegram.org",
    "pastebin.com", "raw.githubusercontent.com",
    "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    "ngrok.io", "ngrok-free.app", "duckdns.org", "no-ip.", "dynu.com",
    "requestbin", "webhook.site", "transfer.sh", "anonfiles.com",
)

KNOWN_MALWARE_UA = (
    "SSLoad", "Cobalt Strike", "AsyncRAT", "Empire", "Havoc", "Brute Ratel",
    "sqlmap", "Metasploit", "Nikto", "gobuster", "wfuzz", "hydra",
    "python-requests", "curl/7.1", "Go-http-client",
)

# Ports that are "well known" but rarely legitimate to see raw plaintext
# creds traverse -- used for the "insecure protocol" IOC category.
PLAINTEXT_PROTO_PORTS = {
    21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP",
    69: "TFTP",
}

CRED_KEYWORDS = (b"user", b"pass", b"login", b"pwd", b"passwd", b"credential")

# Magic bytes -> (label, extension) for file carving when Content-Disposition
# is absent and we have to sniff the payload itself.
FILE_SIGNATURES = [
    (b"MZ", "PE executable", ".exe"),
    (b"\x7fELF", "ELF binary", ".elf"),
    (b"%PDF", "PDF document", ".pdf"),
    (b"PK\x03\x04", "ZIP/Office archive", ".zip"),
    (b"\x89PNG", "PNG image", ".png"),
    (b"\xff\xd8\xff", "JPEG image", ".jpg"),
    (b"GIF8", "GIF image", ".gif"),
    (b"-----BEGIN OPENSSH PRIVATE KEY", "OpenSSH private key", ".pem"),
    (b"-----BEGIN RSA PRIVATE KEY", "RSA private key", ".pem"),
    (b"-----BEGIN CERTIFICATE", "X.509 certificate", ".crt"),
]
