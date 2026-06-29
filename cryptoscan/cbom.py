"""
GreyNOC CryptoScan — CycloneDX 1.6 CBOM emitter.

Serializes a finding set into a CycloneDX 1.6 Bill of Materials with
cryptographic-asset components (cryptoProperties), so the output drops into
existing SBOM/supply-chain tooling (Dependency-Track, etc.).

Reference: CycloneDX 1.6 cryptography model — components[].cryptoProperties
with assetType of algorithm | certificate | protocol | related-crypto-material.
We emit `algorithm` and `certificate` assets, the two surfaces this MVP
discovers, and annotate each with nistQuantumSecurityLevel and our own
GreyNOC risk properties under the `properties` array.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .classifier import Finding, AssetType
from .primitives import Primitive, QuantumRisk

CDX_SPEC = "1.6"
TOOL_NAME = "GreyNOC CryptoScan"
TOOL_VENDOR = "GreyNOC"
TOOL_VERSION = "0.1.0"

# NIST PQC security categories 1-5; map our facts to a coarse level.
def _nist_level(f: Finding) -> int:
    if f.fact.risk is QuantumRisk.SAFE:
        return 3  # ML-KEM-768 / ML-DSA-65 / AES-256 class
    return 0      # offers no quantum security for its hard problem


def _primitive_to_cdx(p: Primitive) -> str:
    # CycloneDX uses these exact primitive tokens.
    return p.value


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
    """A cert-borne key/signature algorithm.

    Modeled as an `algorithm` asset (the thing we actually inventory), with the
    certificate subject/issuer carried in evidence + properties. This keeps the
    component schema-valid under CycloneDX 1.6 while preserving cert context.
    """
    comp = _algorithm_component(f)
    subject = (f.extra or {}).get("subject")
    issuer = (f.extra or {}).get("issuer")
    if subject:
        comp["properties"].append(
            {"name": "greynoc:certSubject", "value": str(subject)[:200]})
    if issuer:
        comp["properties"].append(
            {"name": "greynoc:certIssuer", "value": str(issuer)[:200]})
    comp["properties"].append(
        {"name": "greynoc:assetRole", "value": "certificate"})
    return comp


def _crypto_functions(f: Finding) -> list[str]:
    p = f.fact.primitive
    return {
        Primitive.PKE: ["encapsulate", "decapsulate"],
        Primitive.KEY_AGREE: ["keygen", "key-agreement"],
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
        {"name": "greynoc:assetType", "value": f.asset_type.value},
        {"name": "greynoc:evidence", "value": f.evidence[:200]},
    ]
    if f.fact.classical_bits is not None:
        props.append({"name": "greynoc:classicalBits",
                      "value": str(f.fact.classical_bits)})
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
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        if f.asset_type is AssetType.CERTIFICATE and f.fact.primitive in (
                Primitive.SIGNATURE, Primitive.PKE):
            components.append(_certificate_component(f))
        else:
            components.append(_algorithm_component(f))

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
