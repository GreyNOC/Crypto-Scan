"""
GreyNOC CryptoScan — SSH transport discovery surface.

SSH announces its entire crypto negotiation set in the clear: the
SSH_MSG_KEXINIT packet (RFC 4253 §7.1), sent before any encryption, carries the
server's full name-lists for key exchange, host-key, cipher and MAC algorithms.
An authorized in-process probe reads them with nothing but a stdlib socket — so
unlike the single-handshake TLS view, SSH gives us the server's *complete*
offered set in one shot. SSH key exchange is a major harvest-now-decrypt-later
surface, which makes this high value.

AUTHORIZED TESTING ONLY. This performs the standard SSH version exchange and
reads the server's KEXINIT — the same bytes any client sees — and never
authenticates or completes the handshake. The operator is responsible for
authorization to scan the target.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .classifier import Finding, AssetType, classify

_MSG_KEXINIT = 20
_BANNER_MAX = 8192
_PACKET_MAX = 70000  # RFC 4253 caps uncompressed packets; guard hostile lengths

# SSH algorithm string -> (registry token, role, key_establishment). Only the
# security-relevant + PQ ones; unknown strings are surfaced as unclassified.
# Every token here resolves in primitives.py (asserted by a test).
SSH_ALGO_MAP: dict[str, tuple[str, str, bool]] = {
    # --- key exchange (RFC 4253/4419/5656/8731/8268/9941, OpenSSH) ----------
    "curve25519-sha256": ("X25519", "kex", True),
    "curve25519-sha256@libssh.org": ("X25519", "kex", True),
    "ecdh-sha2-nistp256": ("ECDH", "kex", True),
    "ecdh-sha2-nistp384": ("ECDH", "kex", True),
    "ecdh-sha2-nistp521": ("ECDH", "kex", True),
    "diffie-hellman-group14-sha256": ("DH", "kex", True),
    "diffie-hellman-group14-sha1": ("DH", "kex", True),
    "diffie-hellman-group16-sha512": ("DH", "kex", True),
    "diffie-hellman-group18-sha512": ("DH", "kex", True),
    "diffie-hellman-group1-sha1": ("DH", "kex", True),
    "diffie-hellman-group-exchange-sha256": ("DH", "kex", True),
    "diffie-hellman-group-exchange-sha1": ("DH", "kex", True),
    # PQ hybrids (pq-safe)
    "sntrup761x25519-sha512": ("SNTRUP761X25519", "kex", True),
    "sntrup761x25519-sha512@openssh.com": ("SNTRUP761X25519", "kex", True),
    "mlkem768x25519-sha256": ("X25519MLKEM768", "kex", True),
    "mlkem768nistp256-sha256": ("MLKEM768NISTP256", "kex", True),
    "mlkem1024nistp384-sha384": ("MLKEM1024NISTP384", "kex", True),
    # --- host key (RFC 8709/8332/5656) --------------------------------------
    "ssh-ed25519": ("EdDSA", "hostkey", False),
    "ssh-ed25519-cert-v01@openssh.com": ("EdDSA", "hostkey", False),
    "ssh-ed448": ("Ed448", "hostkey", False),
    "rsa-sha2-256": ("RSA", "hostkey", False),
    "rsa-sha2-512": ("RSA", "hostkey", False),
    "rsa-sha2-256-cert-v01@openssh.com": ("RSA", "hostkey", False),
    "rsa-sha2-512-cert-v01@openssh.com": ("RSA", "hostkey", False),
    "ssh-rsa": ("RSA", "hostkey", False),
    "ssh-rsa-cert-v01@openssh.com": ("RSA", "hostkey", False),
    "ecdsa-sha2-nistp256": ("ECDSA", "hostkey", False),
    "ecdsa-sha2-nistp384": ("ECDSA", "hostkey", False),
    "ecdsa-sha2-nistp521": ("ECDSA", "hostkey", False),
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": ("ECDSA", "hostkey", False),
    "ssh-dss": ("DSA", "hostkey", False),
    "sk-ssh-ed25519@openssh.com": ("EdDSA", "hostkey", False),
    "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA", "hostkey", False),
    # --- ciphers (RFC 4253/4344/5647/8439, OpenSSH) -------------------------
    "chacha20-poly1305@openssh.com": ("ChaCha20", "cipher", False),
    "aes256-gcm@openssh.com": ("AES-256", "cipher", False),
    "aes128-gcm@openssh.com": ("AES-128", "cipher", False),
    "aes256-ctr": ("AES-256", "cipher", False),
    "aes192-ctr": ("AES-192", "cipher", False),
    "aes128-ctr": ("AES-128", "cipher", False),
    "aes256-cbc": ("AES-256", "cipher", False),
    "aes192-cbc": ("AES-192", "cipher", False),
    "aes128-cbc": ("AES-128", "cipher", False),
    "3des-cbc": ("3DES", "cipher", False),
    "des-cbc": ("DES", "cipher", False),
    "arcfour": ("RC4", "cipher", False),
    "arcfour128": ("RC4", "cipher", False),
    "arcfour256": ("RC4", "cipher", False),
    # --- MACs (RFC 4253/6668, OpenSSH) --------------------------------------
    "hmac-sha2-256": ("HMAC", "mac", False),
    "hmac-sha2-512": ("HMAC", "mac", False),
    "hmac-sha2-256-etm@openssh.com": ("HMAC", "mac", False),
    "hmac-sha2-512-etm@openssh.com": ("HMAC", "mac", False),
    "hmac-sha1": ("SHA-1", "mac", False),
    "hmac-sha1-etm@openssh.com": ("SHA-1", "mac", False),
    "hmac-md5": ("MD5", "mac", False),
    "hmac-md5-etm@openssh.com": ("MD5", "mac", False),
    "umac-128@openssh.com": ("UMAC", "mac", False),
    "umac-128-etm@openssh.com": ("UMAC", "mac", False),
    "umac-64@openssh.com": ("UMAC", "mac", False),
    "umac-64-etm@openssh.com": ("UMAC", "mac", False),
}

# Finite-field DH MODP group -> modulus bits, so a sub-112-bit group escalates.
_DH_GROUP_BITS = {
    "group1-": "1024", "group14-": "2048", "group15-": "3072",
    "group16-": "4096", "group17-": "6144", "group18-": "8192",
}

# Non-crypto KEXINIT markers — not algorithms; ext-info/kex-strict (the latter a
# POSITIVE anti-Terrapin hardening signal, CVE-2023-48795). Never scored.
_NON_CRYPTO = {"ext-info-c", "ext-info-s",
               "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"}


def _sanitize_banner(raw: str) -> str:
    """Neutralize a server-supplied identification banner before it reaches a
    terminal, a log, or the JSON/report output. A hostile server can embed ANSI
    escape / control sequences in its SSH- line (CWE-150 terminal injection); RFC
    4253 §4.2 forbids control characters in the identification string anyway, so
    keep only printable characters (spaces included) and cap the length."""
    return "".join(c for c in raw if c.isprintable())[:255]


@dataclass
class SSHObservation:
    host: str
    port: int
    banner: str | None = None
    kex_algorithms: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    encryption_algorithms: list[str] = field(default_factory=list)
    mac_algorithms: list[str] = field(default_factory=list)
    error: str | None = None


def _read_until_banner(sock: socket.socket, timeout: float) -> tuple[str, bytes]:
    """Read the server identification line(s); return (banner, leftover bytes).

    A server MAY send other lines before its 'SSH-' banner, and MAY pipeline its
    KEXINIT right after. We split at the banner's CRLF and keep the remainder.
    """
    buf = b""
    sock.settimeout(timeout)
    # Keep reading until we have a fully CRLF-terminated 'SSH-' line. split()'s
    # last segment may be a not-yet-terminated fragment, so exclude it ([:-1]) —
    # otherwise a partial banner (e.g. b"pre\r\nSSH-2.0-Op" still in flight) would
    # be accepted truncated and mis-slice the leftover byte stream (RFC 4253 §4.2:
    # the id string is CR LF terminated).
    while not any(line.startswith(b"SSH-")
                  for line in buf.split(b"\r\n")[:-1]):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > _BANNER_MAX:
            break
    # Find the SSH- line and the bytes after its CRLF.
    lines = buf.split(b"\r\n")
    banner = ""
    consumed = 0
    for line in lines:
        consumed += len(line) + 2
        if line.startswith(b"SSH-"):
            banner = _sanitize_banner(line.decode("latin-1", "replace"))
            break
    leftover = buf[consumed:] if consumed <= len(buf) else b""
    return banner, leftover


def _read_packet(sock: socket.socket, leftover: bytes,
                 timeout: float) -> bytes | None:
    """Read one cleartext SSH binary packet; return its payload (RFC 4253 §6).

    Pre-KEX there is no MAC and no encryption: packet_length(4) +
    padding_length(1) + payload + padding.
    """
    sock.settimeout(timeout)
    buf = bytearray(leftover)
    while len(buf) < 4:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    pkt_len = struct.unpack(">I", bytes(buf[:4]))[0]
    if pkt_len < 2 or pkt_len > _PACKET_MAX:
        return None
    while len(buf) < 4 + pkt_len:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    pad_len = buf[4]
    payload_len = pkt_len - pad_len - 1
    if payload_len < 1:   # malformed padding_length -> no usable payload
        return None
    return bytes(buf[5:5 + payload_len])


def _name_lists(payload: bytes) -> list[list[str]] | None:
    """Parse the 10 name-lists out of a KEXINIT payload, or None if not one."""
    if not payload or payload[0] != _MSG_KEXINIT:
        return None
    off = 1 + 16  # msg type + 16-byte cookie
    lists: list[list[str]] = []
    try:
        for _ in range(10):
            (length,) = struct.unpack_from(">I", payload, off)
            off += 4
            raw = payload[off:off + length].decode("ascii", "replace")
            off += length
            lists.append([a for a in raw.split(",") if a])
    except struct.error:
        return None
    return lists


def probe(host: str, port: int = 22, timeout: float = 8.0) -> SSHObservation:
    """Read the server's SSH version banner + KEXINIT name-lists. Never raises."""
    obs = SSHObservation(host=host, port=port)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner, leftover = _read_until_banner(sock, timeout)
            obs.banner = banner or None
            sock.sendall(b"SSH-2.0-GreyNOC_CryptoScan\r\n")
            # Read packets until the KEXINIT (some servers send it immediately).
            for _ in range(4):
                payload = _read_packet(sock, leftover, timeout)
                leftover = b""
                if payload is None:
                    break
                lists = _name_lists(payload)
                if lists is not None:
                    obs.kex_algorithms = lists[0]
                    obs.host_key_algorithms = lists[1]
                    # encryption/mac c2s == s2c almost always; use c2s.
                    obs.encryption_algorithms = lists[2]
                    obs.mac_algorithms = lists[4]
                    break
    except Exception as exc:  # noqa: BLE001 — probe must never raise
        obs.error = f"{type(exc).__name__}: {exc}"
    return obs


def _dh_parameter(algo: str) -> str | None:
    for marker, bits in _DH_GROUP_BITS.items():
        if marker in algo:
            return bits
    return None


# ECDH/ECDSA SSH names embed the NIST curve (ecdh-sha2-nistp384, RFC 5656). Map
# it to the CURVE_FACTS key so P-384/P-521 report their true 192/256-bit strength
# instead of the ECDH/ECDSA facts' 128-bit nominal. curve25519 is its own X25519
# token (already 128-bit), so it needs no mapping here.
_EC_CURVES = {"nistp256": "secp256r1", "nistp384": "secp384r1",
              "nistp521": "secp521r1"}


def _ec_parameter(algo: str) -> str | None:
    for marker, curve in _EC_CURVES.items():
        if marker in algo:
            return curve
    return None


def _algo_parameter(token: str, algo: str) -> str | None:
    """Strength parameter (modulus bits or curve) recoverable from an SSH algo
    name, so the classifier reports the true key strength rather than a nominal."""
    if token == "DH":
        return _dh_parameter(algo)
    if token in ("ECDH", "ECDSA"):
        return _ec_parameter(algo)
    return None


def scan(host: str, port: int = 22, timeout: float = 8.0, *,
         obs: "SSHObservation | None" = None) -> list[Finding]:
    """Probe an SSH endpoint and emit classified Findings for its full offered
    algorithm set. Pass a pre-fetched ``obs`` to avoid re-probing."""
    if obs is None:
        obs = probe(host, port, timeout)
    findings: list[Finding] = []
    if obs.error and not obs.kex_algorithms:
        return findings
    locator = f"{host}:{port}"
    seen: set[str] = set()

    def emit(algo: str, role: str):
        if algo in _NON_CRYPTO:
            return
        entry = SSH_ALGO_MAP.get(algo)
        if not entry:
            return  # unknown string -> no fabrication, skip
        token, _role, key_est = entry
        f = classify(
            token, AssetType.SSH_ENDPOINT, locator,
            evidence=algo,
            key_establishment=key_est,
            parameter=_algo_parameter(token, algo),
            extra={"role": role, "banner": obs.banner},
        )
        if f and f.fingerprint not in seen:
            seen.add(f.fingerprint)
            findings.append(f)
        # A '-sha1' KEX transcript or ssh-rsa (SHA-1 signature) also surfaces a
        # SHA-1 legacy finding — the deprecated hash, distinct from the primitive.
        if algo.endswith("-sha1") or algo.startswith("ssh-rsa") or "sha1" in algo:
            s = classify("SHA-1", AssetType.SSH_ENDPOINT, locator,
                         evidence=f"{algo} (SHA-1)",
                         extra={"role": role + "-hash", "banner": obs.banner})
            if s and s.fingerprint not in seen:
                seen.add(s.fingerprint)
                findings.append(s)

    for algo in obs.kex_algorithms:
        emit(algo, "kex")
    for algo in obs.host_key_algorithms:
        emit(algo, "hostkey")
    for algo in obs.encryption_algorithms:
        emit(algo, "cipher")
    for algo in obs.mac_algorithms:
        emit(algo, "mac")
    return findings
