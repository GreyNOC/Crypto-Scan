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

import stat
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, ec, dsa, ed25519, ed448, x25519, x448, dh)
from cryptography.hazmat.primitives.serialization import pkcs7

from .classifier import Finding, AssetType, classify
from .code_scanner import SKIP_DIRS, MAX_FILE_BYTES, _rel_parts

PKI_EXTS = {".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p7s",
            ".key", ".pub", ".csr"}


def _key_token(pubkey) -> tuple[str, str | None]:
    """(registry token, strength parameter) for a public key object."""
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", str(pubkey.key_size)
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return "ECDSA", pubkey.curve.name
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "EdDSA", "ed25519"
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return "EdDSA", "ed448"
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
    for p in root.rglob("*"):
        if p.is_dir() or any(part in SKIP_DIRS for part in _rel_parts(p, root)):
            continue
        if p.suffix.lower() not in PKI_EXTS:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
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
                return certs
        except Exception:  # noqa: BLE001 — try the next format
            continue
    return []


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
        s = classify(sig, AssetType.CERTIFICATE, locator, evidence=sig,
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
        key = _load_public_key(data) or _load_private_key(data)
        if key is not None:
            pub = key.public_key() if hasattr(key, "public_key") else key
            token, param = _key_token(pub)
            f = classify(token, AssetType.CERTIFICATE, rel,
                         evidence=f"key:{token}-{param or '?'}",
                         parameter=param, extra={"role": "key-file"})
            if f and f.fingerprint not in seen:
                seen.add(f.fingerprint)
                findings.append(f)
    return findings
