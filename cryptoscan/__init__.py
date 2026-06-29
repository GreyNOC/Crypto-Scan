"""
GreyNOC CryptoScan — Cryptographic Posture Management / PQC migration scanner.

Discovers cryptography in use across TLS endpoints and source/dependency trees,
classifies each primitive's quantum risk, and emits a CycloneDX 1.6 CBOM plus a
migration roadmap.

Authorized testing only. Reproducible findings. No fabrication.
"""

from ._version import __version__
from .classifier import Finding, classify, summarize, AssetType
from .primitives import QuantumRisk, Severity, Primitive, lookup
from . import tls_scanner, code_scanner, cbom, report

__all__ = [
    "Finding", "classify", "summarize", "AssetType",
    "QuantumRisk", "Severity", "Primitive", "lookup",
    "tls_scanner", "code_scanner", "cbom", "report",
    "__version__",
]
