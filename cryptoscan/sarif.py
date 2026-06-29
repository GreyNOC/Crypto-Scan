"""
GreyNOC CryptoScan — SARIF 2.1.0 output.

Serializes source- and dependency-discovery findings into a SARIF 2.1.0 log so
they surface natively in GitHub code scanning (the Security tab) and any other
SARIF-aware tooling. Each cryptographic primitive becomes a rule; each observed
use becomes a result with file:line provenance parsed from the finding locator.

Only SOURCE and DEPENDENCY findings carry a code location, so only those are
emitted here — TLS/endpoint posture belongs in the CBOM and the Markdown report,
not in a code-scanning log. No fabrication: a result is emitted only where we
have a real artifact location.
"""

from __future__ import annotations

from ._version import __version__
from .classifier import Finding, AssetType
from .primitives import Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "GreyNOC CryptoScan"
INFORMATION_URI = "https://github.com/GreyNOC/Crypto-Scan"

# Asset types that have a code/file location worth reporting to a SARIF consumer.
_CODE_ASSETS = (AssetType.SOURCE, AssetType.DEPENDENCY)


def _severity_to_level(sev: Severity) -> str:
    """SARIF result.level. GitHub renders error/warning/note distinctly."""
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if sev is Severity.MEDIUM:
        return "warning"
    return "note"


# GitHub code scanning sorts by the numeric security-severity (0.0–10.0).
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule_id(f: Finding) -> str:
    return f"greynoc/{f.fact.risk.value}/{f.fact.name}"


def _parse_locator(asset_type: AssetType, locator: str) -> dict | None:
    """Build a SARIF physicalLocation from a finding locator.

    SOURCE locators are 'path:line' (line optional); DEPENDENCY locators are
    'manifest -> package' (no line). Returns None if no usable artifact path.
    """
    if asset_type is AssetType.SOURCE:
        path, sep, tail = locator.rpartition(":")
        # SARIF region.startLine has a schema minimum of 1.
        if sep and tail.isdigit() and int(tail) >= 1:
            return {
                "artifactLocation": {"uri": path},
                "region": {"startLine": int(tail)},
            }
        # No parseable (>=1) line — report the whole file.
        return {"artifactLocation": {"uri": locator}}
    if asset_type is AssetType.DEPENDENCY:
        manifest = locator.split(" -> ", 1)[0].strip()
        if manifest:
            return {"artifactLocation": {"uri": manifest}}
    return None


def _rule(f: Finding) -> dict:
    rule = {
        "id": _rule_id(f),
        "name": f"{f.fact.name.replace('-', '')}Usage",
        "shortDescription": {
            "text": f"{f.fact.name} — {f.fact.risk.value}",
        },
        "fullDescription": {
            "text": f.fact.note or f"{f.fact.name} cryptographic primitive.",
        },
        "defaultConfiguration": {"level": _severity_to_level(f.severity())},
        "properties": {
            "tags": ["cryptography", "post-quantum", f.fact.risk.value],
            "security-severity": _SECURITY_SEVERITY[f.severity()],
        },
    }
    if f.fact.migrate_to:
        rule["help"] = {
            "text": "Migrate to: " + "; ".join(f.fact.migrate_to),
        }
    return rule


def _message(f: Finding) -> str:
    bits = [f"{f.fact.name} ({f.fact.risk.value})"]
    if f.hndl_exposed():
        bits.append("harvest-now-decrypt-later exposed")
    if f.fact.migrate_to:
        bits.append("migrate to " + "; ".join(f.fact.migrate_to))
    return " — ".join(bits) + f". Evidence: {f.evidence[:160]}"


def build_sarif(findings: list[Finding], target: str) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    seen: set[str] = set()

    for f in findings:
        if f.asset_type not in _CODE_ASSETS:
            continue
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        loc = _parse_locator(f.asset_type, f.locator)
        if loc is None:
            continue
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = _rule(f)
        results.append({
            "ruleId": rid,
            "level": _severity_to_level(f.severity()),
            "message": {"text": _message(f)},
            "locations": [{"physicalLocation": loc}],
            "partialFingerprints": {"greynocFingerprint": f.fingerprint},
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"target": target},
            }
        ],
    }
