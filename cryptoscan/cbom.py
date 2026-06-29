"""
GreyNOC CryptoScan — CycloneDX 1.6 CBOM emitter.

Serializes a finding set into a CycloneDX 1.6 Bill of Materials with
cryptographic-asset components (cryptoProperties), so the output drops into
existing SBOM/supply-chain tooling (Dependency-Track, etc.).

Reference: CycloneDX 1.6 cryptography model — components[].cryptoProperties
with assetType of algorithm | certificate | protocol | related-crypto-material.
We emit `algorithm` assets (source/dep/cipher primitives), `certificate` assets
(TLS leaf certs, with certificateProperties), and `protocol` assets (TLS
endpoints, with version + cipherSuites), annotating each with
nistQuantumSecurityLevel and our own GreyNOC risk properties.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .classifier import Finding, AssetType
from .primitives import Primitive, QuantumRisk, PQC_PARAM_SETS

from ._version import __version__

CDX_SPEC = "1.6"
TOOL_NAME = "GreyNOC CryptoScan"
TOOL_VENDOR = "GreyNOC"
TOOL_VERSION = __version__

# CycloneDX nistQuantumSecurityLevel: NIST PQC security strength categories.
# 0 = offers no quantum security for its hard problem; 1..5 = NIST categories
# (1≈AES-128 brute force, 3≈AES-192, 5≈AES-256). We only assert a category
# where NIST actually pins one — Shor/Legacy primitives and bare hashes get 0.
def _nist_level(f: Finding) -> int:
    risk = f.fact.risk
    if risk in (QuantumRisk.SHOR, QuantumRisk.LEGACY):
        return 0
    prim = f.fact.primitive
    cb = f.fact.classical_bits
    if prim in (Primitive.BLOCK_CIPHER, Primitive.STREAM_CIPHER):
        if cb is None:
            return 0
        if cb >= 256:
            return 5
        if cb >= 192:
            return 3
        if cb >= 128:
            return 1
        return 0
    if prim in (Primitive.HASH, Primitive.MAC):
        return 0  # NIST does not pin bare hashes/MACs to a PQC category
    if risk is QuantumRisk.SAFE and prim in (
            Primitive.PKE, Primitive.SIGNATURE, Primitive.KEY_AGREE):
        return _pqc_level(f)
    return 0


def _pqc_level(f: Finding) -> int:
    """Standardized-PQC NIST category, param-set-aware where the set is known.

    The canonical PQC facts have a generic name ('ML-KEM') and usually no
    `parameter`, so we look for a known parameter-set token in the parameter and
    the observed evidence (e.g. a dependency named 'ml-kem-512'). Default to the
    recommended category-3 sets (ML-KEM-768 / ML-DSA-65) when none is observed.
    """
    for src in (f.parameter, f.evidence, f.fact.name):
        if not src:
            continue
        low = str(src).lower()
        for param_set, category in PQC_PARAM_SETS.items():
            if param_set in low:
                return category
    # Hybrid groups (e.g. SecP384r1MLKEM1024) carry their strength via the
    # fact's quantum_bits rather than a parameter-set token; map that to a
    # category so the highest-security hybrid isn't under-reported as cat-3.
    qb = f.fact.quantum_bits
    if qb is not None:
        if qb >= 192:
            return 5
        if qb >= 128:
            return 3
        return 1
    return 3


def _primitive_to_cdx(p: Primitive) -> str:
    # CycloneDX uses these exact primitive tokens.
    return p.value


# OpenSSL/ssl protocol version string -> CycloneDX protocolProperties.version.
def _tls_version(protocol: str) -> str:
    return {
        "TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1.1": "1.1",
        "TLSv1": "1.0", "SSLv3": "3.0", "SSLv2": "2.0",
    }.get(protocol, protocol)


# CycloneDX cryptoFunctions vocabulary roles by suite token role.
_SUITE_ROLES = {"key-exchange", "authentication", "bulk-cipher", "mac"}


def _algorithm_component(f: Finding) -> dict:
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{f.fingerprint}",
        "name": f.fact.name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": _primitive_to_cdx(f.fact.primitive),
                "executionEnvironment": "software-plain-ram",
                "cryptoFunctions": _crypto_functions(f),
                "nistQuantumSecurityLevel": _nist_level(f),
            },
        },
        "evidence": {
            "occurrences": [
                {"location": f.locator}
            ]
        },
        "properties": _greynoc_properties(f),
    }
    if f.parameter:
        comp["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = str(f.parameter)
    return comp


def _certificate_component(f: Finding) -> dict:
    """A TLS leaf certificate, modeled as a CycloneDX `certificate` asset.

    Carries certificateProperties (subject/issuer/validity/format) when we
    observed them, and the GreyNOC risk annotations for the cert's key/signature
    algorithm. We do not emit dangling signatureAlgorithmRef/subjectPublicKeyRef
    bom-refs — the algorithm identity lives in the component name + properties,
    so there is nothing to dangle.
    """
    ex = f.extra or {}
    certprops: dict = {"certificateFormat": "X.509"}
    for src, dst, cap in (
        ("subject", "subjectName", 300),
        ("issuer", "issuerName", 300),
        ("not_before", "notValidBefore", 64),
        ("not_after", "notValidAfter", 64),
    ):
        v = ex.get(src)
        if v:
            certprops[dst] = str(v)[:cap]
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{f.fingerprint}",
        "name": f.fact.name,
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": certprops,
        },
        "evidence": {"occurrences": [{"location": f.locator}]},
        "properties": _greynoc_properties(f) + [
            {"name": "greynoc:assetRole", "value": "certificate"},
        ],
    }


def _protocol_component(locator: str, protocol: str | None,
                        cipher_suites: list[str]) -> dict:
    """A TLS endpoint, modeled as a CycloneDX `protocol` asset."""
    pp: dict = {"type": "tls"}
    if protocol:
        pp["version"] = _tls_version(protocol)
    if cipher_suites:
        pp["cipherSuites"] = [{"name": cs} for cs in cipher_suites]
    name = f"TLS {_tls_version(protocol)}".strip() if protocol else "TLS"
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/protocol/{locator}",
        "name": name,
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": pp,
        },
        "evidence": {"occurrences": [{"location": locator}]},
        "properties": [
            {"name": "greynoc:assetType", "value": "tls-endpoint"},
            {"name": "greynoc:locator", "value": locator},
        ],
    }


def _crypto_functions(f: Finding) -> list[str]:
    # Values MUST come from the CycloneDX cryptoFunctions enum. Note 'keyderive'
    # (no hyphen) is the schema token; 'key-agreement' is NOT valid.
    p = f.fact.primitive
    return {
        Primitive.PKE: ["encapsulate", "decapsulate"],
        Primitive.KEY_AGREE: ["keygen", "keyderive"],
        Primitive.SIGNATURE: ["sign", "verify"],
        Primitive.BLOCK_CIPHER: ["encrypt", "decrypt"],
        Primitive.STREAM_CIPHER: ["encrypt", "decrypt"],
        Primitive.HASH: ["digest"],
        Primitive.MAC: ["tag", "verify"],
    }.get(p, ["other"])


def _greynoc_properties(f: Finding) -> list[dict]:
    props = [
        {"name": "greynoc:quantumRisk", "value": f.fact.risk.value},
        {"name": "greynoc:severity", "value": f.severity().value},
        {"name": "greynoc:hndlExposed", "value": str(f.hndl_exposed()).lower()},
        {"name": "greynoc:classicallyWeak",
         "value": str(f.classical_weakness()).lower()},
        {"name": "greynoc:assetType", "value": f.asset_type.value},
        {"name": "greynoc:evidence", "value": f.evidence[:200]},
    ]
    cbits = f.effective_classical_bits()
    if cbits is not None:
        props.append({"name": "greynoc:classicalBits", "value": str(cbits)})
    if f.fact.quantum_bits is not None:
        props.append({"name": "greynoc:quantumBits",
                      "value": str(f.fact.quantum_bits)})
    if f.fact.migrate_to:
        props.append({"name": "greynoc:migrateTo",
                      "value": "; ".join(f.fact.migrate_to)})
    if f.fact.standard:
        props.append({"name": "greynoc:standard", "value": f.fact.standard})
    return props


def build_cbom(findings: list[Finding], target: str) -> dict:
    components = []
    seen: set[str] = set()
    # Collect TLS endpoints that carry real protocol data, so we can emit one
    # `protocol` asset per endpoint. Gated on observed protocol -> a synthetic
    # TLS finding with no protocol context produces no protocol component.
    endpoints: dict[str, dict] = {}
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        if f.asset_type is AssetType.CERTIFICATE and f.fact.primitive in (
                Primitive.SIGNATURE, Primitive.PKE):
            components.append(_certificate_component(f))
        else:
            components.append(_algorithm_component(f))
        if f.asset_type is AssetType.TLS_ENDPOINT:
            ex = f.extra or {}
            proto = ex.get("protocol")
            if proto:
                ep = endpoints.setdefault(
                    f.locator, {"protocol": proto, "suites": set()})
                if ex.get("role") in _SUITE_ROLES and f.evidence:
                    ep["suites"].add(f.evidence)
                # Full enumerated accepted set, when the probe captured it.
                for suite in ex.get("accepted_cipher_suites") or ():
                    ep["suites"].add(suite)

    for locator, info in endpoints.items():
        components.append(_protocol_component(
            locator, info["protocol"], sorted(info["suites"])))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "author": TOOL_VENDOR,
                     "name": TOOL_NAME, "version": TOOL_VERSION}
                ]
            },
            "component": {
                "type": "application",
                "name": target,
                "bom-ref": "target",
            },
            "properties": [
                {"name": "greynoc:scanProfile", "value": "pqc-posture-mvp"},
                {"name": "greynoc:discipline",
                 "value": "authorized-testing-only;reproducible;no-fabrication"},
            ],
        },
        "components": components,
    }
