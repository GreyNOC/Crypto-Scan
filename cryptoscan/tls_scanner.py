"""
GreyNOC CryptoScan — TLS / certificate discovery surface.

Performs an authorized handshake against a target host:port, then extracts
the cryptography actually in use: negotiated protocol version, cipher suite
(broken into KEX / cipher / MAC where derivable), and the leaf certificate's
public-key algorithm, key size, and signature algorithm.

AUTHORIZED TESTING ONLY. This module performs a standard TLS handshake — the
same traffic any client sends — and reads the server-presented certificate.
It does not attempt exploitation. Operators are responsible for ensuring they
have authorization to scan the target.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

from .classifier import Finding, AssetType, classify
from . import tls13_probe


@dataclass
class TLSObservation:
    host: str
    port: int
    protocol: str | None = None
    cipher_name: str | None = None
    cipher_bits: int | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_sig_algo: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    key_algo: str | None = None
    key_size: int | None = None
    key_curve: str | None = None
    error: str | None = None


# Map negotiated cipher-suite name fragments to primitive tokens.
def _cipher_tokens(cipher_name: str) -> list[tuple[str, str]]:
    """Return (token, evidence-role) pairs from an OpenSSL cipher name."""
    name = cipher_name.upper()
    tokens: list[tuple[str, str]] = []

    # Key exchange
    if "ECDHE" in name or "ECDH" in name:
        tokens.append(("ECDHE", "key-exchange"))
    elif "DHE" in name or "EDH" in name:
        tokens.append(("DHE", "key-exchange"))
    elif name.startswith("TLS_") and "GCM" in name:
        # TLS 1.3 suites (TLS_AES_256_GCM_SHA384 etc.) use the negotiated
        # group separately; KEX is reported via the group, not the suite.
        pass

    # Authentication (cert-based, surfaced from the cert itself too)
    if "RSA" in name:
        tokens.append(("RSA", "authentication"))
    if "ECDSA" in name:
        tokens.append(("ECDSA", "authentication"))

    # Bulk cipher
    if "AES_256" in name or "AES256" in name:
        tokens.append(("AES-256", "bulk-cipher"))
    elif "AES_128" in name or "AES128" in name:
        tokens.append(("AES-128", "bulk-cipher"))
    elif "CHACHA20" in name:
        tokens.append(("CHACHA20", "bulk-cipher"))
    elif "3DES" in name or "DES_EDE3" in name:
        tokens.append(("3DES", "bulk-cipher"))
    elif "RC4" in name:
        tokens.append(("RC4", "bulk-cipher"))

    # MAC / PRF hash
    if "SHA384" in name:
        tokens.append(("SHA-384", "mac"))
    elif "SHA256" in name:
        tokens.append(("SHA-256", "mac"))
    elif name.endswith("SHA") or "_SHA" in name:
        tokens.append(("SHA-1", "mac"))

    return tokens


def _cert_validity(cert: x509.Certificate) -> tuple[str | None, str | None]:
    """ISO-8601 notBefore/notAfter. Prefers the tz-aware accessors added in
    cryptography 42; falls back to the deprecated naive ones on older libs."""
    def _iso(aware_attr: str, naive_attr: str) -> str | None:
        try:
            dt = getattr(cert, aware_attr)
        except AttributeError:
            try:
                dt = getattr(cert, naive_attr)
            except Exception:
                return None
        try:
            return dt.isoformat()
        except Exception:
            return None
    return (_iso("not_valid_before_utc", "not_valid_before"),
            _iso("not_valid_after_utc", "not_valid_after"))


def _key_details(cert: x509.Certificate) -> tuple[str, int | None, str | None]:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size, None
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "ECDSA", pk.curve.key_size, pk.curve.name
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA", pk.key_size, None
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "EdDSA", 256, "ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "EdDSA", 448, "ed448"
    return type(pk).__name__, None, None


def probe(host: str, port: int = 443, timeout: float = 8.0) -> TLSObservation:
    """Perform one authorized TLS handshake and read the leaf certificate."""
    obs = TLSObservation(host=host, port=port)
    ctx = ssl.create_default_context()
    # We inspect what the server offers; do not fail the probe on trust issues.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                obs.protocol = tls.version()
                cipher = tls.cipher()
                if cipher:
                    obs.cipher_name, _, obs.cipher_bits = cipher
                der = tls.getpeercert(binary_form=True)
                if der:
                    cert = x509.load_der_x509_certificate(der)
                    try:
                        obs.cert_subject = cert.subject.rfc4514_string()
                        obs.cert_issuer = cert.issuer.rfc4514_string()
                    except Exception:
                        pass
                    try:
                        obs.cert_sig_algo = cert.signature_algorithm_oid._name
                    except Exception:
                        obs.cert_sig_algo = None
                    obs.cert_not_before, obs.cert_not_after = _cert_validity(cert)
                    obs.key_algo, obs.key_size, obs.key_curve = _key_details(cert)
    except Exception as exc:  # noqa: BLE001 — report, don't crash the scan
        obs.error = f"{type(exc).__name__}: {exc}"
    return obs


def _enumerate_tls12_suites(host: str, port: int, timeout: float) -> list[str]:
    """Enumerate the TLS<=1.2 cipher suites the server accepts, via repeated
    handshakes that each exclude the suites already found (OpenSSL '!NAME'
    syntax). Best-effort: degrades gracefully on restrictive OpenSSL builds, and
    returns [] for a TLS-1.3-only server (handled by the raw probe instead)."""
    accepted: list[str] = []
    excluded = ""
    for _ in range(32):  # safety cap; real servers run out of suites well before
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            pass
        # Prefer SECLEVEL=0 so legacy suites (3DES/CBC) can be offered and thus
        # detected; fall back if the build rejects it.
        if not any(_try_set_ciphers(ctx, s) for s in (
                f"ALL:COMPLEMENTOFALL:@SECLEVEL=0{excluded}",
                f"ALL:COMPLEMENTOFALL{excluded}")):
            break
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    c = tls.cipher()
                    name = c[0] if c else None
        except (ssl.SSLError, OSError):
            break
        if not name or name in accepted:
            break
        accepted.append(name)
        excluded += ":!" + name
    return accepted


def _try_set_ciphers(ctx: ssl.SSLContext, cipher_str: str) -> bool:
    try:
        ctx.set_ciphers(cipher_str)
        return True
    except ssl.SSLError:
        return False


def scan(host: str, port: int = 443, timeout: float = 8.0) -> list[Finding]:
    """Probe a TLS endpoint and emit classified Findings."""
    obs = probe(host, port, timeout)
    findings: list[Finding] = []
    locator = f"{host}:{port}"
    if obs.error:
        return findings

    # TLS 1.3 group + PQC-hybrid readiness + accepted cipher-suite enumeration.
    try:
        g = tls13_probe.probe(host, port, timeout)
    except Exception:  # noqa: BLE001 — probe is advisory
        g = None

    # Cipher-suite-derived primitives, from the negotiated suite AND the server's
    # full accepted set (TLS 1.3 raw enumeration + the TLS 1.2 set_ciphers loop) —
    # one finding per unique primitive. Closes the single-handshake limitation.
    suite_names: list[str] = []
    if obs.cipher_name:
        suite_names.append(obs.cipher_name)
    if g is not None:
        suite_names.extend(g.accepted_cipher_suites)
    suite_names.extend(_enumerate_tls12_suites(host, port, timeout))
    all_suites = sorted(set(suite_names))
    seen_tokens: set[str] = set()
    for suite in suite_names:
        for token, role in _cipher_tokens(suite):
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            f = classify(
                token, AssetType.TLS_ENDPOINT, locator,
                evidence=suite,
                key_establishment=(role == "key-exchange"),
                # Transport key exchange is treated as long-lived-data exposed:
                # captured ciphertext is decryptable once the KEX is broken.
                long_lived_data=(role == "key-exchange"),
                extra={"protocol": obs.protocol, "role": role,
                       "cipher_bits": obs.cipher_bits},
            )
            if f:
                findings.append(f)

    # Certificate public key (authentication / identity). Pass the curve name
    # as the strength parameter for EC keys (so a sub-112-bit curve escalates),
    # and the modulus size for RSA/DSA.
    if obs.key_algo:
        f = classify(
            obs.key_algo, AssetType.CERTIFICATE, locator,
            evidence=f"{obs.key_algo}-{obs.key_size or '?'}"
                     f"{'/' + obs.key_curve if obs.key_curve else ''}",
            parameter=obs.key_curve or (str(obs.key_size) if obs.key_size else None),
            extra={"subject": obs.cert_subject, "issuer": obs.cert_issuer,
                   "curve": obs.key_curve, "key_size": obs.key_size,
                   "not_before": obs.cert_not_before,
                   "not_after": obs.cert_not_after},
        )
        if f:
            findings.append(f)

    # Certificate signature algorithm (chain-of-trust integrity).
    if obs.cert_sig_algo:
        f = classify(
            obs.cert_sig_algo, AssetType.CERTIFICATE, locator,
            evidence=obs.cert_sig_algo,
            extra={"role": "cert-signature", "subject": obs.cert_subject},
        )
        if f:
            findings.append(f)

    # TLS 1.3 negotiated key-exchange group — the live HNDL signal v0.1.0 could
    # not see, plus PQC-hybrid readiness. Carries the full accepted cipher-suite
    # set so the CBOM protocol asset can enumerate it.
    if g is not None and g.negotiated_group is not None:
        ng = g.negotiated_group
        f = classify(
            ng.classifier_token, AssetType.TLS_ENDPOINT, locator,
            evidence=ng.name,
            key_establishment=True,
            parameter=ng.curve_parameter,
            extra={"protocol": "TLSv1.3", "role": "kex-group",
                   "group_code": f"0x{int(ng):04X}",
                   "pqc_hybrid": ng.is_hybrid_pqc,
                   "supports_pqc_hybrid": g.supports_pqc_hybrid,
                   "accepted_cipher_suites": all_suites},
        )
        if f:
            findings.append(f)

    return findings
