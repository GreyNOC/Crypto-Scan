"""
GreyNOC CryptoScan — findings model + context-aware risk classifier.

A Finding is one observed use of a cryptographic primitive, tied to where it
was found (an asset). The classifier takes the base CryptoFact and escalates
or annotates severity using deployment context — e.g. a Shor-broken key
agreement protecting long-lived data is the textbook HNDL crown jewel and is
flagged accordingly.

Discipline: every Finding carries provenance (source + locator) so results are
reproducible and auditable. Nothing is asserted that isn't tied to an observation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum

from .primitives import CryptoFact, Primitive, QuantumRisk, Severity, lookup


class AssetType(str, Enum):
    TLS_ENDPOINT = "tls-endpoint"
    CERTIFICATE = "certificate"
    SOURCE = "source"
    DEPENDENCY = "dependency"
    CONFIG = "config"


@dataclass
class Finding:
    fact: CryptoFact
    asset_type: AssetType
    locator: str                 # host:port, file:line, package@version
    evidence: str                # the literal observed token / context
    # Deployment context flags that modulate severity:
    long_lived_data: bool = False     # protects data with multi-year secrecy need
    key_establishment: bool = False   # used to derive/transport session keys
    parameter: str | None = None      # key size, curve, mode, etc.
    extra: dict = field(default_factory=dict)

    def severity(self) -> Severity:
        # Role-aware severity for Shor-broken primitives:
        #   key establishment  -> CRITICAL (HNDL: harvestable today)
        #   signature / auth    -> HIGH     (forgery / identity risk, not HNDL)
        if self.fact.risk is QuantumRisk.SHOR:
            return Severity.CRITICAL if self._is_key_establishment() else Severity.HIGH
        return self.fact.severity()

    def _is_key_establishment(self) -> bool:
        # Key-agreement primitives are always key establishment. Public-key
        # encryption (RSA) only when the observed role says so — an RSA *cert*
        # used purely for authentication (e.g. TLS 1.3) is NOT HNDL-exposed.
        if self.fact.primitive is Primitive.KEY_AGREE:
            return True
        if self.fact.primitive is Primitive.PKE:
            return self.key_establishment
        return False

    def hndl_exposed(self) -> bool:
        """True if this finding is 'harvest now, decrypt later' exposed."""
        return (self.fact.risk is QuantumRisk.SHOR
                and self._is_key_establishment())

    @property
    def fingerprint(self) -> str:
        raw = f"{self.asset_type.value}|{self.locator}|{self.fact.name}|{self.evidence}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "algorithm": self.fact.name,
            "primitive": self.fact.primitive.value,
            "quantum_risk": self.fact.risk.value,
            "severity": self.severity().value,
            "hndl_exposed": self.hndl_exposed(),
            "asset_type": self.asset_type.value,
            "locator": self.locator,
            "evidence": self.evidence,
            "parameter": self.parameter,
            "classical_bits": self.fact.classical_bits,
            "quantum_bits": self.fact.quantum_bits,
            "standard": self.fact.standard,
            "migrate_to": list(self.fact.migrate_to),
            "note": self.fact.note,
            **({"context": self.extra} if self.extra else {}),
        }


def classify(token: str,
             asset_type: AssetType,
             locator: str,
             evidence: str | None = None,
             *,
             long_lived_data: bool = False,
             key_establishment: bool = False,
             parameter: str | None = None,
             extra: dict | None = None) -> Finding | None:
    """Resolve a token to a Finding, or None if unknown."""
    fact = lookup(token)
    if fact is None:
        return None
    return Finding(
        fact=fact,
        asset_type=asset_type,
        locator=locator,
        evidence=evidence or token,
        long_lived_data=long_lived_data,
        key_establishment=key_establishment,
        parameter=parameter,
        extra=extra or {},
    )


def summarize(findings: list[Finding]) -> dict:
    """Roll up a finding set into posture metrics."""
    by_sev: dict[str, int] = {s.value: 0 for s in Severity}
    by_risk: dict[str, int] = {r.value: 0 for r in QuantumRisk}
    hndl = 0
    for f in findings:
        by_sev[f.severity().value] += 1
        by_risk[f.fact.risk.value] += 1
        if f.hndl_exposed():
            hndl += 1

    total = len(findings)
    vulnerable = by_risk[QuantumRisk.SHOR.value] + by_risk[QuantumRisk.GROVER.value]
    safe = by_risk[QuantumRisk.SAFE.value]
    # Simple 0-100 posture score: fraction PQ-ready, penalized by HNDL exposure.
    if total:
        readiness = round(100 * safe / total)
        readiness = max(0, readiness - min(40, hndl * 5))
    else:
        readiness = 100

    return {
        "total_findings": total,
        "hndl_exposed": hndl,
        "quantum_vulnerable": vulnerable,
        "pq_safe": safe,
        "by_severity": by_sev,
        "by_quantum_risk": by_risk,
        "pq_readiness_score": readiness,
    }
