"""
GreyNOC CryptoScan — live TLS 1.3 key-exchange group probe.

v0.1.0 could not see the negotiated TLS 1.3 key-agreement group: the cipher
suite name (`TLS_AES_256_GCM_SHA384`) does not encode it, so HNDL exposure on a
TLS 1.3 endpoint was inferred from the certificate, not the live group. This
module closes that gap. It hand-builds a minimal TLS 1.3 ClientHello, sends it
over a raw socket, and reads the server's ServerHello / HelloRetryRequest to
learn the *selected* group — and whether the server supports a post-quantum
hybrid such as X25519MLKEM768.

Design notes
------------
- Only the server's 2-byte `selected_group` is load-bearing, so we send a
  syntactically valid 32-byte dummy X25519 key_share for the groups we offer.
  No real key generation, hence no dependency on `cryptography` here.
- We offer the hybrids first (client preference) but a key_share only for
  X25519; a server that prefers a hybrid answers with a HelloRetryRequest
  naming that hybrid — which is exactly the PQC-readiness signal we want.
- AUTHORIZED TESTING ONLY. This is a standard, non-exploitative handshake start;
  the operator is responsible for authorization to scan the target.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum

# TLS record / handshake / extension type codes (RFC 8446).
_CT_CHANGE_CIPHER_SPEC = 0x14
_CT_ALERT = 0x15
_CT_HANDSHAKE = 0x16
_HS_CLIENT_HELLO = 0x01
_HS_SERVER_HELLO = 0x02
_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_KEY_SHARE = 0x0033
_LEGACY_VERSION = 0x0303  # TLS 1.2, per RFC 8446 record/legacy fields
_TLS13_VERSION = 0x0304

# HelloRetryRequest is a ServerHello whose random equals SHA-256("HelloRetry
# Request") — the sentinel from RFC 8446 §4.1.3.
_HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


class NamedGroup(IntEnum):
    """IANA TLS Supported Groups codepoints (verified against the IANA registry,
    RFC 8446/7919/7748 and draft-ietf-tls-ecdhe-mlkem)."""
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001D
    x448 = 0x001E
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    # Post-quantum hybrids.
    SecP256r1MLKEM768 = 0x11EB
    X25519MLKEM768 = 0x11EC
    SecP384r1MLKEM1024 = 0x11ED
    X25519Kyber768Draft00 = 0x6399  # obsolete draft group

    @classmethod
    def from_code(cls, code: int) -> "NamedGroup | None":
        try:
            return cls(code)
        except ValueError:
            return None

    @property
    def is_hybrid_pqc(self) -> bool:
        return self in (NamedGroup.SecP256r1MLKEM768, NamedGroup.X25519MLKEM768,
                        NamedGroup.SecP384r1MLKEM1024,
                        NamedGroup.X25519Kyber768Draft00)

    @property
    def classifier_token(self) -> str:
        """Registry token for this group (see primitives.py)."""
        return {
            NamedGroup.x25519: "x25519",
            NamedGroup.x448: "ecdh",
            NamedGroup.secp256r1: "ecdh",
            NamedGroup.secp384r1: "ecdh",
            NamedGroup.secp521r1: "ecdh",
            NamedGroup.ffdhe2048: "ffdhe2048",
            NamedGroup.ffdhe3072: "ffdhe3072",
            NamedGroup.SecP256r1MLKEM768: "secp256r1mlkem768",
            NamedGroup.X25519MLKEM768: "x25519mlkem768",
            NamedGroup.SecP384r1MLKEM1024: "secp384r1mlkem1024",
            NamedGroup.X25519Kyber768Draft00: "x25519kyber768draft00",
        }[self]

    @property
    def curve_parameter(self) -> str:
        """Curve/group name to record as the finding parameter (provenance)."""
        return self.name


# A realistic, browser-like offer: hybrids first (client preference), then the
# classical groups. We only ship a key_share for x25519.
_DEFAULT_OFFER = (
    NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768,
    NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1,
    NamedGroup.x448, NamedGroup.secp521r1, NamedGroup.ffdhe2048,
)


@dataclass
class ServerHelloResult:
    is_server_hello: bool = False
    is_hrr: bool = False
    negotiated_version: int | None = None  # 0x0304 if TLS 1.3
    selected_group: int | None = None
    cipher_suite: int | None = None
    alert: tuple[int, int] | None = None   # (level, description) if an Alert
    error: str | None = None


# TLS 1.3 cipher suites (IANA TLS Cipher Suites registry / RFC 8446 §B.4).
TLS13_CIPHER_SUITES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}


@dataclass
class TLS13Observation:
    host: str
    port: int
    negotiated_group: NamedGroup | None = None
    negotiated_group_code: int | None = None  # raw code even if unknown to us
    supports_pqc_hybrid: bool = False
    is_tls13: bool = False
    accepted_groups: list[NamedGroup] = field(default_factory=list)
    accepted_cipher_suites: list[str] = field(default_factory=list)
    error: str | None = None


# --- wire helpers ----------------------------------------------------------

def _vec(data: bytes, len_bytes: int) -> bytes:
    """Length-prefix `data` with a `len_bytes`-wide big-endian length."""
    return len(data).to_bytes(len_bytes, "big") + data


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">H", ext_type) + _vec(data, 2)


def build_client_hello(server_name: str,
                       groups: "tuple[NamedGroup, ...]" = _DEFAULT_OFFER,
                       *, key_share_groups: "tuple[NamedGroup, ...]" =
                       (NamedGroup.x25519,),
                       cipher_suites: "tuple[int, ...]" =
                       (0x1301, 0x1302, 0x1303)) -> bytes:
    """Build a complete TLS record carrying a TLS 1.3 ClientHello."""
    # Deterministic 32-byte client random (no Math.random / Date dependency;
    # the value is not security-relevant for a probe).
    client_random = hashlib.sha256(b"greynoc-cryptoscan-probe").digest()

    # server_name extension: ServerNameList -> entry(type=0 host_name + name).
    # Clamp to the DNS max (253) so a pathological hostname can't overflow the
    # 2-byte length vector.
    name_bytes = server_name.encode("ascii", "ignore")[:253]
    sni_entry = b"\x00" + _vec(name_bytes, 2)
    sni_ext = _extension(_EXT_SERVER_NAME, _vec(sni_entry, 2))

    # supported_versions: list of one -> TLS 1.3
    sv_ext = _extension(_EXT_SUPPORTED_VERSIONS,
                        _vec(struct.pack(">H", _TLS13_VERSION), 1))

    # supported_groups
    groups_bytes = b"".join(struct.pack(">H", int(g)) for g in groups)
    sg_ext = _extension(_EXT_SUPPORTED_GROUPS, _vec(groups_bytes, 2))

    # signature_algorithms (common set; required for a valid CH)
    sig_algs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0601, 0x0806]
    sa_bytes = b"".join(struct.pack(">H", s) for s in sig_algs)
    sa_ext = _extension(_EXT_SIGNATURE_ALGORITHMS, _vec(sa_bytes, 2))

    # key_share: a syntactically valid 32-byte dummy share per key_share_group
    entries = b""
    for g in key_share_groups:
        entries += struct.pack(">H", int(g)) + _vec(b"\x2a" * 32, 2)
    ks_ext = _extension(_EXT_KEY_SHARE, _vec(entries, 2))

    extensions = sni_ext + sv_ext + sg_ext + sa_ext + ks_ext

    suites = b"".join(struct.pack(">H", c) for c in cipher_suites)
    body = (struct.pack(">H", _LEGACY_VERSION)
            + client_random
            + _vec(b"", 1)               # legacy_session_id (empty)
            + _vec(suites, 2)
            + _vec(b"\x00", 1)           # compression: null
            + _vec(extensions, 2))
    handshake = struct.pack(">B", _HS_CLIENT_HELLO) + _vec(body, 3)
    record = (struct.pack(">B", _CT_HANDSHAKE)
              + struct.pack(">H", _LEGACY_VERSION)
              + _vec(handshake, 2))
    return record


def parse_server_hello(handshake_body: bytes) -> ServerHelloResult:
    """Parse a ServerHello/HelloRetryRequest handshake body (after the 4-byte
    handshake header has been stripped)."""
    r = ServerHelloResult(is_server_hello=True)
    try:
        off = 0
        off += 2  # legacy_version
        random = handshake_body[off:off + 32]
        off += 32
        r.is_hrr = random == _HRR_RANDOM
        sid_len = handshake_body[off]
        off += 1 + sid_len
        r.cipher_suite = struct.unpack_from(">H", handshake_body, off)[0]
        off += 2
        off += 1  # legacy_compression_method
        ext_total = struct.unpack_from(">H", handshake_body, off)[0]
        off += 2
        end = off + ext_total
        if end > len(handshake_body):
            raise ValueError("extensions overrun handshake body")
        while off + 4 <= end:
            etype, elen = struct.unpack_from(">HH", handshake_body, off)
            off += 4
            if off + elen > end:
                # A hostile/truncated server must not be able to spoof a group
                # by claiming an extension length past the buffer.
                raise ValueError("extension length overruns")
            edata = handshake_body[off:off + elen]
            off += elen
            if etype == _EXT_SUPPORTED_VERSIONS and len(edata) >= 2:
                r.negotiated_version = struct.unpack(">H", edata[:2])[0]
            elif etype == _EXT_KEY_SHARE and len(edata) >= 2:
                # ServerHello: group(2)+keylen(2)+key; HRR: group(2). The first
                # two bytes are the selected group in both shapes.
                r.selected_group = struct.unpack(">H", edata[:2])[0]
        if r.negotiated_version is None:
            r.negotiated_version = _LEGACY_VERSION
    except (IndexError, struct.error, ValueError) as exc:
        # Never trust a partially-parsed ServerHello: clear everything so a
        # malformed message can't surface a fabricated group/version.
        r.error = f"parse: {type(exc).__name__}"
        r.is_server_hello = False
        r.selected_group = None
        r.negotiated_version = None
    return r


def _read_handshake(host: str, port: int, client_hello: bytes,
                    timeout: float) -> ServerHelloResult:
    """Send a ClientHello and parse the first ServerHello/HRR (or Alert)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(client_hello)
            buf = bytearray()
            handshake = bytearray()
            # Absolute wall-clock deadline: socket.recv timeouts are per-call, so
            # a server dribbling one byte per timeout could otherwise stall the
            # probe ~16x. The read cap is a secondary flood guard.
            end_at = time.monotonic() + timeout
            reads = 0
            while reads < 64:
                remaining = end_at - time.monotonic()
                if remaining <= 0:
                    return ServerHelloResult(error="timeout")
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                reads += 1
                # Drain whole records from buf.
                made_progress = True
                while made_progress:
                    made_progress = False
                    if len(buf) < 5:
                        break
                    ctype = buf[0]
                    rec_len = struct.unpack_from(">H", buf, 3)[0]
                    if len(buf) < 5 + rec_len:
                        break  # wait for the rest of the record
                    payload = bytes(buf[5:5 + rec_len])
                    del buf[:5 + rec_len]
                    made_progress = True
                    if ctype == _CT_CHANGE_CIPHER_SPEC:
                        continue
                    if ctype == _CT_ALERT:
                        lvl = payload[0] if payload else 0
                        desc = payload[1] if len(payload) > 1 else 0
                        return ServerHelloResult(alert=(lvl, desc))
                    if ctype == _CT_HANDSHAKE:
                        handshake += payload
                        if len(handshake) >= 4:
                            hs_type = handshake[0]
                            hs_len = int.from_bytes(handshake[1:4], "big")
                            if len(handshake) >= 4 + hs_len:
                                if hs_type == _HS_SERVER_HELLO:
                                    return parse_server_hello(
                                        bytes(handshake[4:4 + hs_len]))
                                # Not a ServerHello (shouldn't happen first).
                                return ServerHelloResult(
                                    is_server_hello=False,
                                    error=f"unexpected hs {hs_type}")
            return ServerHelloResult(error="no ServerHello")
    except (OSError, socket.timeout) as exc:
        return ServerHelloResult(error=f"{type(exc).__name__}: {exc}")


def probe(host: str, port: int = 443, timeout: float = 8.0) -> TLS13Observation:
    """Probe a TLS endpoint for its negotiated TLS 1.3 group + PQC hybrid
    readiness. Returns a TLS13Observation; never raises."""
    obs = TLS13Observation(host=host, port=port)
    try:
        res = _read_handshake(host, port, build_client_hello(host), timeout)
    except Exception as exc:  # noqa: BLE001 — probe must never raise
        obs.error = f"{type(exc).__name__}: {exc}"
        return obs
    if res.error:
        # Any error -> discard. parse_server_hello already nulls partial state,
        # but never trust a result that also carries an error.
        obs.error = res.error
        return obs
    if res.alert is not None:
        obs.error = f"alert {res.alert[1]}"
        return obs
    obs.is_tls13 = res.negotiated_version == _TLS13_VERSION
    if res.selected_group is not None:
        obs.negotiated_group_code = res.selected_group
        obs.negotiated_group = NamedGroup.from_code(res.selected_group)
        if obs.negotiated_group is not None:
            obs.accepted_groups.append(obs.negotiated_group)
            obs.supports_pqc_hybrid = obs.negotiated_group.is_hybrid_pqc
    # If the server didn't already pick a hybrid, ask explicitly whether it
    # supports one (offer hybrids only; HRR/ServerHello => supported).
    if obs.is_tls13 and not obs.supports_pqc_hybrid:
        hy = (NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768,
              NamedGroup.SecP384r1MLKEM1024)
        ch = build_client_hello(host, groups=hy,
                                key_share_groups=(NamedGroup.x25519,))
        hres = _read_handshake(host, port, ch, timeout)
        g = (NamedGroup.from_code(hres.selected_group)
             if hres.selected_group is not None else None)
        if g is not None and g.is_hybrid_pqc:
            obs.supports_pqc_hybrid = True
            if g not in obs.accepted_groups:
                obs.accepted_groups.append(g)
    # Enumerate the server's full accepted TLS 1.3 cipher-suite set by offering
    # each suite alone (closes the single-handshake limitation for TLS 1.3).
    if obs.is_tls13:
        obs.accepted_cipher_suites = _enumerate_tls13_ciphers(host, port, timeout)
    return obs


def _enumerate_tls13_ciphers(host: str, port: int, timeout: float) -> list[str]:
    accepted: list[str] = []
    # Tighter per-handshake timeout so enumeration can't dominate the scan.
    each = min(timeout, 4.0)
    for code, name in TLS13_CIPHER_SUITES.items():
        try:
            ch = build_client_hello(host, cipher_suites=(code,))
            res = _read_handshake(host, port, ch, each)
        except Exception:  # noqa: BLE001 — enumeration is advisory
            break
        if res.error is not None:
            # Transport/connect failure -> the host won't do better for the
            # other suites; stop rather than burn a timeout per suite.
            break
        if res.cipher_suite == code:
            accepted.append(name)
    return accepted
