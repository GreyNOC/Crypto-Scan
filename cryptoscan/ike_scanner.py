"""
GreyNOC CryptoScan — IPsec / IKEv2 discovery surface.

Sends an authorized IKE_SA_INIT request (RFC 7296) over UDP and reads the
responder's reply to learn the cryptography an IPsec gateway negotiates: the
encryption / PRF / integrity transforms and — most importantly — the
Diffie-Hellman key-exchange group, which is the harvest-now-decrypt-later
signal. PQ key exchange (ML-KEM groups, draft-ietf-ipsecme-ikev2-mlkem) is
detected as PQ-safe.

The responder echoes the single transform set it chose, so this reports the
*negotiated* proposal (like a single TLS handshake) plus, where the responder
asks for a different group via INVALID_KE_PAYLOAD, that preferred group.

AUTHORIZED TESTING ONLY. This is the standard, non-exploitative first message of
an IKEv2 negotiation; it is never completed and never authenticates. The
operator is responsible for authorization to scan the target.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

from .classifier import Finding, AssetType, classify

# IKEv2 constants (RFC 7296; verified against the IANA IKEv2 Parameters registry).
_VERSION = 0x20
_EXCH_IKE_SA_INIT = 34
_FLAG_INITIATOR = 0x08
_FLAG_RESPONSE = 0x20
_PL_SA, _PL_KE, _PL_NONCE, _PL_NOTIFY = 33, 34, 40, 41
_TT_ENCR, _TT_PRF, _TT_INTEG, _TT_DH = 1, 2, 3, 4
_ATTR_KEY_LENGTH = 0x800E  # AF=1 | type 14
_N_NO_PROPOSAL_CHOSEN, _N_INVALID_KE_PAYLOAD = 14, 17

# Transform Type 4: Diffie-Hellman group / key-exchange method -> (token, param).
DH_GROUPS: dict[int, tuple[str, str | None]] = {
    1: ("DH", "768"), 2: ("DH", "1024"), 5: ("DH", "1536"),
    14: ("DH", "2048"), 15: ("DH", "3072"), 16: ("DH", "4096"),
    17: ("DH", "6144"), 18: ("DH", "8192"),
    19: ("ECDH", "secp256r1"), 20: ("ECDH", "secp384r1"),
    21: ("ECDH", "secp521r1"), 25: ("ECDH", "secp192r1"),
    26: ("ECDH", "secp224r1"),
    27: ("ECDH", "brainpoolp224r1"), 28: ("ECDH", "brainpoolp256r1"),
    29: ("ECDH", "brainpoolp384r1"), 30: ("ECDH", "brainpoolp512r1"),
    31: ("X25519", "x25519"), 32: ("X448", "x448"),
    # PQ key exchange (IANA, draft-ietf-ipsecme-ikev2-mlkem — pre-RFC codepoints).
    35: ("ml-kem-512", None), 36: ("ml-kem-768", None), 37: ("ml-kem-1024", None),
}
DH_GROUP_NAMES: dict[int, str] = {
    1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048",
    15: "MODP-3072", 16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192",
    19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 25: "ECP-192", 26: "ECP-224",
    27: "brainpoolP224r1", 28: "brainpoolP256r1", 29: "brainpoolP384r1",
    30: "brainpoolP512r1", 31: "Curve25519", 32: "Curve448",
    35: "ML-KEM-512", 36: "ML-KEM-768", 37: "ML-KEM-1024",
}

# Transform Type 1: encryption. AES key size comes from the Key Length attribute,
# never the transform id, so AES ids map to a sentinel resolved during parse.
_ENCR: dict[int, str] = {
    2: "DES", 3: "3DES", 11: "null",
    12: "AES", 13: "AES", 14: "AES", 15: "AES", 16: "AES",
    18: "AES", 19: "AES", 20: "AES", 28: "ChaCha20",
}
# Transform Type 2 (PRF) / Type 3 (INTEG): id -> token (the security-relevant part).
_PRF: dict[int, str] = {1: "MD5", 2: "SHA-1", 4: "AES-XCBC", 5: "HMAC",
                        6: "HMAC", 7: "HMAC", 8: "AES-XCBC"}
_INTEG: dict[int, str] = {1: "MD5", 2: "SHA-1", 5: "AES-XCBC",
                          12: "HMAC", 13: "HMAC", 14: "HMAC"}

# Dummy key_exchange data sizes (bytes) for building a KE payload per group.
_KE_SIZES: dict[int, int] = {
    1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024,
    19: 64, 20: 96, 21: 132, 25: 48, 26: 56, 31: 32, 32: 56,
}


@dataclass
class IKEObservation:
    host: str
    port: int
    is_response: bool = False
    encryption: tuple[str, int | None] | None = None  # (token, keybits)
    prf: str | None = None
    integ: str | None = None
    dh_group: int | None = None
    notify: int | None = None      # notify message type if the reply was a Notify
    preferred_group: int | None = None  # from INVALID_KE_PAYLOAD
    error: str | None = None


# --- wire builders ---------------------------------------------------------

def _payload(next_type: int, body: bytes) -> bytes:
    return struct.pack(">BBH", next_type, 0, 4 + len(body)) + body


def _transform(ttype: int, tid: int, last: bool, keybits: int | None = None) -> bytes:
    attrs = struct.pack(">HH", _ATTR_KEY_LENGTH, keybits) if keybits else b""
    hdr = struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs),
                      ttype, 0, tid)
    return hdr + attrs


def _sa_payload(next_type: int) -> bytes:
    """A single broad proposal so the responder can pick its preferred set."""
    transforms = [
        _transform(_TT_ENCR, 20, False, 256),   # AES-256-GCM-16
        _transform(_TT_ENCR, 12, False, 256),   # AES-256-CBC
        _transform(_TT_ENCR, 12, False, 128),   # AES-128-CBC
        _transform(_TT_ENCR, 3, False),          # 3DES
        _transform(_TT_PRF, 5, False),           # HMAC-SHA2-256
        _transform(_TT_PRF, 7, False),           # HMAC-SHA2-512
        _transform(_TT_PRF, 2, False),           # HMAC-SHA1
        _transform(_TT_INTEG, 12, False),        # HMAC-SHA2-256-128
        _transform(_TT_INTEG, 2, False),         # HMAC-SHA1-96
        _transform(_TT_DH, 14, False),           # MODP-2048
        _transform(_TT_DH, 19, False),           # ECP-256
        _transform(_TT_DH, 31, True),            # Curve25519 (last)
    ]
    body = b"".join(transforms)
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(body), 1, 1, 0,
                           len(transforms)) + body
    return _payload(next_type, proposal)


def build_ike_sa_init(ke_group: int = 14) -> bytes:
    sa = _sa_payload(_PL_KE)
    ke_data = b"\x42" * _KE_SIZES.get(ke_group, 256)
    ke = _payload(_PL_NONCE, struct.pack(">HH", ke_group, 0) + ke_data)
    nonce = _payload(0, os.urandom(32))
    body = sa + ke + nonce
    header = struct.pack(">8s8sBBBBII", os.urandom(8), b"\x00" * 8, _PL_SA,
                         _VERSION, _EXCH_IKE_SA_INIT, _FLAG_INITIATOR, 0,
                         28 + len(body))
    return header + body


# --- wire parser -----------------------------------------------------------

def _parse_sa(body: bytes) -> list[tuple[int, int, int | None]]:
    """Parse the responder's chosen proposal -> [(ttype, tid, keybits)]."""
    out: list[tuple[int, int, int | None]] = []
    try:
        _last, _r, _plen, _pnum, _proto, spisize, ntrans = \
            struct.unpack_from(">BBHBBBB", body, 0)
    except struct.error:
        return out
    off = 8 + spisize
    for _ in range(ntrans):
        if off + 8 > len(body):
            break
        _l, _r2, tlen, ttype, _r3, tid = struct.unpack_from(">BBHBBH", body, off)
        if tlen < 8:
            break
        keybits = None
        attr = body[off + 8:off + tlen]
        if len(attr) >= 4:
            atype, aval = struct.unpack_from(">HH", attr, 0)
            if atype == _ATTR_KEY_LENGTH:
                keybits = aval
        out.append((ttype, tid, keybits))
        off += tlen
    return out


def parse_response(data: bytes) -> IKEObservation | None:
    """Parse an IKE_SA_INIT response (or Notify) into an observation."""
    if len(data) < 28:
        return None
    (_ispi, _rspi, next_p, ver, exch, flags, _mid, _len) = \
        struct.unpack_from(">8s8sBBBBII", data, 0)
    if exch != _EXCH_IKE_SA_INIT:
        return None
    obs = IKEObservation(host="", port=0,
                         is_response=bool(flags & _FLAG_RESPONSE))
    off, cur = 28, next_p
    while cur != 0 and off + 4 <= len(data):
        n_next, _crit, plen = struct.unpack_from(">BBH", data, off)
        if plen < 4 or off + plen > len(data):
            break
        body = data[off + 4:off + plen]
        if cur == _PL_SA:
            for ttype, tid, keybits in _parse_sa(body):
                if ttype == _TT_ENCR:
                    obs.encryption = (_ENCR.get(tid, "AES"), keybits)
                elif ttype == _TT_PRF:
                    obs.prf = _PRF.get(tid)
                elif ttype == _TT_INTEG:
                    obs.integ = _INTEG.get(tid)
                elif ttype == _TT_DH:
                    obs.dh_group = tid
        elif cur == _PL_KE and len(body) >= 2:
            obs.dh_group = obs.dh_group or struct.unpack_from(">H", body, 0)[0]
        elif cur == _PL_NOTIFY and len(body) >= 4:
            _proto, spisize, ntype = struct.unpack_from(">BBH", body, 0)
            obs.notify = ntype
            nd = body[4 + spisize:]
            if ntype == _N_INVALID_KE_PAYLOAD and len(nd) >= 2:
                obs.preferred_group = struct.unpack_from(">H", nd, 0)[0]
        off += plen
        cur = n_next
    return obs


def probe(host: str, port: int = 500, timeout: float = 5.0) -> IKEObservation:
    """Send one IKE_SA_INIT and parse the responder's reply. Never raises."""
    obs = IKEObservation(host=host, port=port)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(build_ike_sa_init(), (host, port))
        data, _addr = sock.recvfrom(8192)
        parsed = parse_response(data)
        if parsed is None:
            obs.error = "not an IKEv2 response"
        else:
            parsed.host, parsed.port = host, port
            obs = parsed
    except Exception as exc:  # noqa: BLE001 — probe must never raise
        obs.error = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            sock.close()
    return obs


def _aes_token(keybits: int | None) -> str:
    return {128: "AES-128", 192: "AES-192", 256: "AES-256"}.get(keybits or 0,
                                                                "AES-128")


def scan(host: str, port: int = 500, timeout: float = 5.0) -> list[Finding]:
    """Probe an IKEv2 endpoint and emit classified Findings."""
    obs = probe(host, port, timeout)
    findings: list[Finding] = []
    if obs.error and obs.dh_group is None and obs.preferred_group is None:
        return findings
    locator = f"{host}:{port}"
    seen: set[str] = set()

    def emit(token, role, *, key_est=False, parameter=None, evidence=None):
        if not token:
            return
        f = classify(token, AssetType.IKE_ENDPOINT, locator,
                     evidence=evidence or token, key_establishment=key_est,
                     parameter=parameter, extra={"role": role})
        if f and f.fingerprint not in seen:
            seen.add(f.fingerprint)
            findings.append(f)

    # The Diffie-Hellman group is the HNDL key-establishment signal.
    group = obs.dh_group or obs.preferred_group
    if group is not None and group in DH_GROUPS:
        token, param = DH_GROUPS[group]
        emit(token, "ike-kex", key_est=True, parameter=param,
             evidence=DH_GROUP_NAMES.get(group, str(group)))
    if obs.encryption is not None:
        tok, keybits = obs.encryption
        if tok == "AES":
            tok = _aes_token(keybits)
        emit(tok, "ike-encryption", evidence=tok)
    emit(obs.prf, "ike-prf")
    emit(obs.integ, "ike-integrity")
    return findings
