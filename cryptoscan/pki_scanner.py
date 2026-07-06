"""
GreyNOC CryptoScan — PKI / certificate & key-file discovery surface.

Extends static discovery from source/manifests to the actual cryptographic
artifacts in a tree: X.509 certificates (PEM/DER/PKCS#7), CSRs, and private/
public key files. Each carries a real key algorithm + size/curve and (for certs)
a signature algorithm — concrete crypto, not a pattern guess. This covers the
certificate side of the S/MIME / PKI surface.

Read-only and offline; nothing is executed. Encrypted private keys are detected
but not decrypted (no passwords are tried).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, ec, dsa, ed25519, ed448, x25519, x448, dh)
from cryptography.hazmat.primitives.serialization import pkcs7

from .classifier import Finding, AssetType, classify
from .primitives import lookup
from .code_scanner import SKIP_DIRS, MAX_FILE_BYTES, _is_reparse

PKI_EXTS = {".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p7s",
            ".key", ".pub", ".csr"}

# Cap certs parsed from one file: a 2 MB PEM/PKCS#7 bundle can pack tens of
# thousands of tiny certs, amplifying into a huge object/finding list.
MAX_CERTS_PER_FILE = 1000


def _key_token(pubkey) -> tuple[str, str | None]:
    """(registry token, strength parameter) for a public key object."""
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", str(pubkey.key_size)
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return "ECDSA", pubkey.curve.name
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "EdDSA", "ed25519"
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return "Ed448", "ed448"
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", str(pubkey.key_size)
    # Key-agreement key files are HNDL crown jewels — must not be dropped.
    if isinstance(pubkey, x25519.X25519PublicKey):
        return "X25519", "x25519"
    if isinstance(pubkey, x448.X448PublicKey):
        return "X448", "x448"
    if isinstance(pubkey, dh.DHPublicKey):
        return "DH", str(pubkey.key_size)
    return type(pubkey).__name__, None


def _iter_pki_files(root: Path):
    # os.walk(followlinks=False) + reparse-point pruning (_is_reparse covers
    # symlinks AND Windows junctions) so a directory link can neither escape the
    # scan root (reading key material outside it) nor spin an unbounded loop;
    # SKIP_DIRS is pruned by child name (relative to root, never absolute).
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not _is_reparse(dp / d)]
        for fn in filenames:
            p = dp / fn
            if p.suffix.lower() not in PKI_EXTS:
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            # stat() follows a file symlink; S_ISREG keeps only regular targets,
            # so symlinked cert stores (e.g. /etc/ssl/certs) still scan.
            if stat.S_ISREG(st.st_mode) and 0 < st.st_size <= MAX_FILE_BYTES:
                yield p


def _load_certs(data: bytes) -> list[x509.Certificate]:
    """Parse all X.509 certs from a blob (PEM bundle, DER, or PKCS#7)."""
    for loader in (
        lambda d: x509.load_pem_x509_certificates(d),
        lambda d: [x509.load_der_x509_certificate(d)],
        lambda d: pkcs7.load_pem_pkcs7_certificates(d),
        lambda d: pkcs7.load_der_pkcs7_certificates(d),
    ):
        try:
            certs = loader(data)
            if certs:
                return certs[:MAX_CERTS_PER_FILE]
        except Exception:  # noqa: BLE001 — try the next format
            continue
    return []


def _sig_token(sig: str) -> str | None:
    """Map a certificate signatureAlgorithm OID name to a registry token.

    Prefers an exact registry entry (which deliberately reports a legacy digest,
    e.g. ``sha1WithRSAEncryption`` -> SHA-1). Otherwise falls back to the
    asymmetric family, so an unrecognized digest suffix (``ecdsa-with-SHA512``,
    ``dsa-with-sha256``, ``sha3-256WithRSAEncryption``, ...) never silently
    suppresses the Shor-broken signature finding — the false-negative direction.
    """
    if not sig:
        return None
    s = sig.lower()
    if lookup(s) is not None:
        return s
    # A post-quantum signature is trusted only via an exact registry hit (above).
    # Never let the 'dsa'/'rsa' substring heuristic below misread ML-DSA/SLH-DSA
    # as classical DSA — an unknown PQ variant falls through to None (unknown),
    # not a fabricated classical family.
    if any(p in s for p in ("ml-dsa", "mldsa", "slh-dsa", "slhdsa", "dilithium",
                            "sphincs", "falcon", "ml-kem", "mlkem", "kyber")):
        return None
    if "ecdsa" in s:
        return "ECDSA"
    if "ed25519" in s:
        return "EdDSA"
    if "ed448" in s:
        return "Ed448"
    if "dsa" in s:          # non-EC DSA (ecdsa is handled above)
        return "DSA"
    if "rsa" in s:
        return "RSA"
    return None


def _cert_key_establishment(cert: x509.Certificate) -> bool:
    """True when the cert's KeyUsage marks it for key transport / agreement
    (keyEncipherment / dataEncipherment / keyAgreement) — an HNDL-exposed
    key-establishment certificate, distinct from a signature/auth-only one
    (e.g. a TLS 1.3 leaf), which stays HIGH rather than a HNDL CRITICAL."""
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        return bool(ku.key_encipherment or ku.data_encipherment
                    or ku.key_agreement)
    except Exception:  # noqa: BLE001 — absent/invalid KeyUsage: treat as auth-only
        return False


def _cert_ec_key_agreement(cert: x509.Certificate) -> bool:
    """True when an EC cert's KeyUsage sets keyAgreement — the marker that its
    key is an ECDH key-agreement key (RFC 5480 §3) rather than an ECDSA signing
    key. Both carry the identical id-ecPublicKey SPKI (OID 1.2.840.10045.2.1) and
    `cryptography` yields an EllipticCurvePublicKey for either, so KeyUsage is the
    only wire signal that distinguishes them."""
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        return bool(ku.key_agreement)
    except Exception:  # noqa: BLE001 — absent/invalid KeyUsage: treat as signing
        return False


def _load_public_key(data: bytes):
    for loader in (serialization.load_pem_public_key,
                   serialization.load_der_public_key,
                   serialization.load_ssh_public_key):
        try:
            return loader(data)
        except Exception:  # noqa: BLE001
            continue
    return None


def _load_private_key(data: bytes):
    for loader in (serialization.load_pem_private_key,
                   serialization.load_der_private_key):
        try:
            return loader(data, password=None)
        except Exception:  # noqa: BLE001 — encrypted/other: skip (no passwords)
            continue
    return None


def _emit_cert(cert: x509.Certificate, locator: str,
               findings: list[Finding], seen: set) -> None:
    pubkey = cert.public_key()
    token, param = _key_token(pubkey)
    # An EC cert marked keyAgreement is an ECDH (key-establishment) artifact, not
    # an ECDSA signing cert — reporting it as ECDSA (a SIGNATURE primitive) would
    # discard the key-establishment role and lose the harvest-now-decrypt-later
    # exposure (a CRITICAL under-reported as HIGH). Remap to the ECDH KEY_AGREE
    # fact, which is curve-aware, so the observed strength/severity stay faithful.
    if token == "ECDSA" and _cert_ec_key_agreement(cert):
        token = "ECDH"
    try:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        subject = issuer = None
    try:
        nvb = cert.not_valid_before_utc.isoformat()
        nva = cert.not_valid_after_utc.isoformat()
    except Exception:  # noqa: BLE001
        nvb = nva = None
    f = classify(token, AssetType.CERTIFICATE, locator,
                 evidence=f"{token}-{param or '?'}",
                 parameter=param,
                 key_establishment=_cert_key_establishment(cert),
                 extra={"subject": subject, "issuer": issuer,
                        "not_before": nvb, "not_after": nva})
    if f and f.fingerprint not in seen:
        seen.add(f.fingerprint)
        findings.append(f)
    # Signature algorithm (chain-of-trust integrity).
    try:
        sig = cert.signature_algorithm_oid._name
    except Exception:  # noqa: BLE001
        sig = None
    if sig:
        s = classify(_sig_token(sig) or sig, AssetType.CERTIFICATE, locator,
                     evidence=sig,
                     extra={"role": "cert-signature", "subject": subject})
        if s and s.fingerprint not in seen:
            seen.add(s.fingerprint)
            findings.append(s)


def scan(root: str | Path) -> list[Finding]:
    """Discover and classify cert/key artifacts under a directory tree."""
    root = Path(root)
    findings: list[Finding] = []
    seen: set = set()
    for path in _iter_pki_files(root):
        rel = (path.relative_to(root) if path.is_relative_to(root)
               else path).as_posix()
        try:
            data = path.read_bytes()
        except OSError:
            continue
        certs = _load_certs(data)
        if certs:
            for cert in certs:
                _emit_cert(cert, rel, findings, seen)
            continue
        pub = _load_public_key(data)
        is_private = False
        if pub is None:
            priv = _load_private_key(data)
            if priv is not None:
                pub = priv.public_key() if hasattr(priv, "public_key") else priv
                is_private = True
        if pub is not None:
            token, param = _key_token(pub)
            f = classify(token, AssetType.CERTIFICATE, rel,
                         evidence=f"key:{token}-{param or '?'}",
                         parameter=param,
                         # A *private* RSA key file is a decryption capability —
                         # HNDL-exposed if it ever wrapped a session key. (DH/
                         # X25519/X448 keys are KEY_AGREE and already key-est.)
                         key_establishment=(is_private and token == "RSA"),
                         extra={"role": "key-file"})
            if f and f.fingerprint not in seen:
                seen.add(f.fingerprint)
                findings.append(f)
    return findings
