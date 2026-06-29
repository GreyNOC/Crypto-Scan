"""
GreyNOC CryptoScan — posture diffing (the assurance layer).

Compares two findings-JSON outputs (the `--json` envelope: {target, summary,
findings[]}) and answers the question a migration program actually cares about:
*did the fix land, and did anything regress?*

Findings are matched on the stable per-finding `fingerprint`. A source finding
whose code simply moved lines keeps its algorithm/file but changes its locator
(and thus its fingerprint); we re-pair those as MOVED rather than reporting a
spurious add+remove. The verdict (MIGRATION_LANDED / REGRESSION / PARTIAL /
NO_CHANGE) is derived from the true introduced/resolved sets; the numeric deltas
are read from the two summary blocks — these are different lenses and can
legitimately disagree, which the report states explicitly.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .primitives import Severity

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")

DISCIPLINE = "authorized-testing-only · reproducible · no-fabrication"

# Verdict labels.
MIGRATION_LANDED = "MIGRATION_LANDED"
REGRESSION = "REGRESSION"
PARTIAL = "PARTIAL"
NO_CHANGE = "NO_CHANGE"


def load_findings_json(path: str) -> dict:
    """Load and validate a findings-JSON envelope. Raises ValueError on a
    malformed file or a finding without a 16-hex fingerprint."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError(f"{path}: not a CryptoScan findings JSON")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{path}: 'findings' is not a list")
    for f in findings:
        fp = f.get("fingerprint") if isinstance(f, dict) else None
        if not isinstance(fp, str) or not _FINGERPRINT_RE.match(fp):
            raise ValueError(f"{path}: finding missing a 16-hex fingerprint")
    data.setdefault("summary", {})
    return data


def index_by_fingerprint(findings: list[dict]) -> dict[str, dict]:
    return {f["fingerprint"]: f for f in findings}


def strip_line(locator: str) -> str:
    """Drop a trailing ':<int>' line number (source locators only)."""
    base, sep, tail = locator.rpartition(":")
    return base if sep and tail.isdigit() else locator


def secondary_key(finding: dict) -> tuple:
    """Locator-stable identity for a SOURCE finding, used to detect moves."""
    return (finding.get("algorithm"), finding.get("asset_type"),
            strip_line(finding.get("locator", "")))


def diff_findings(old: list[dict], new: list[dict]) -> dict:
    old_ix = index_by_fingerprint(old)
    new_ix = index_by_fingerprint(new)

    persisting = [new_ix[fp] for fp in new_ix if fp in old_ix]
    intro_fps = [fp for fp in new_ix if fp not in old_ix]
    resolved_fps = [fp for fp in old_ix if fp not in new_ix]

    # Re-pair MOVED source findings by their locator-stable secondary key.
    old_sec: dict[tuple, list[str]] = {}
    for fp in resolved_fps:
        f = old_ix[fp]
        if f.get("asset_type") == "source":
            old_sec.setdefault(secondary_key(f), []).append(fp)

    moved: list[dict] = []
    consumed_old: set[str] = set()
    introduced: list[dict] = []
    for fp in intro_fps:
        f = new_ix[fp]
        if f.get("asset_type") == "source":
            bucket = old_sec.get(secondary_key(f))
            if bucket:
                ofp = bucket.pop(0)
                consumed_old.add(ofp)
                moved.append({"algorithm": f.get("algorithm"),
                              "from": old_ix[ofp].get("locator"),
                              "to": f.get("locator")})
                continue
        introduced.append(f)
    resolved = [old_ix[fp] for fp in resolved_fps if fp not in consumed_old]

    return {
        "introduced": introduced,
        "resolved": resolved,
        "moved": moved,
        "persisting": persisting,
    }


def verdict(diff: dict) -> str:
    introduced = diff["introduced"]
    resolved = diff["resolved"]
    new_bad = [f for f in introduced
               if f.get("hndl_exposed") or f.get("severity") == "CRITICAL"]
    resolved_hndl = [f for f in resolved if f.get("hndl_exposed")]
    if new_bad:
        return REGRESSION                       # regression wins over landing
    if not introduced and not resolved:
        return NO_CHANGE                         # moves don't change posture
    if resolved_hndl:
        return MIGRATION_LANDED
    return PARTIAL


def _summary_deltas(old_s: dict, new_s: dict) -> dict:
    def d(key):
        return (new_s.get(key, 0) or 0) - (old_s.get(key, 0) or 0)
    sev_old = old_s.get("by_severity", {})
    sev_new = new_s.get("by_severity", {})
    return {
        "pq_readiness_score": d("pq_readiness_score"),
        "hndl_exposed": d("hndl_exposed"),
        "quantum_vulnerable": d("quantum_vulnerable"),
        "total_findings": d("total_findings"),
        "by_severity": {s.value: (sev_new.get(s.value, 0) - sev_old.get(s.value, 0))
                        for s in Severity},
    }


def diff_exit_code(v: str, fail_on_regression: bool = True) -> int:
    return 2 if (v == REGRESSION and fail_on_regression) else 0


def build_diff(old_doc: dict, new_doc: dict) -> dict:
    """Full machine-readable diff: verdict, finding sets, summary deltas."""
    d = diff_findings(old_doc.get("findings", []), new_doc.get("findings", []))
    v = verdict(d)
    return {
        "verdict": v,
        "old_target": old_doc.get("target"),
        "new_target": new_doc.get("target"),
        "counts": {
            "introduced": len(d["introduced"]),
            "resolved": len(d["resolved"]),
            "moved": len(d["moved"]),
            "persisting": len(d["persisting"]),
        },
        "deltas": _summary_deltas(old_doc.get("summary", {}),
                                  new_doc.get("summary", {})),
        "introduced": d["introduced"],
        "resolved": d["resolved"],
        "moved": d["moved"],
    }


_VERDICT_BLURB = {
    MIGRATION_LANDED: "HNDL-exposed assets were resolved and nothing critical "
                      "was introduced — the migration landed.",
    REGRESSION: "A new HNDL-exposed or CRITICAL asset appeared — posture "
                "regressed. Investigate before shipping.",
    PARTIAL: "Some findings changed without resolving HNDL exposure or "
             "regressing — partial progress.",
    NO_CHANGE: "No findings were introduced or resolved (moves aside).",
}


def render_markdown(diff: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    v = diff["verdict"]
    de = diff["deltas"]
    lines = [
        "# GreyNOC Cryptographic Posture Diff",
        "",
        f"**Old:** `{diff['old_target']}`  ",
        f"**New:** `{diff['new_target']}`  ",
        f"**Generated:** {now}  ",
        f"**Discipline:** {DISCIPLINE}",
        "",
        "---",
        "",
        f"## Verdict: {v}",
        "",
        _VERDICT_BLURB.get(v, ""),
        "",
        f"- Introduced: **{diff['counts']['introduced']}** · "
        f"Resolved: **{diff['counts']['resolved']}** · "
        f"Moved: {diff['counts']['moved']} · "
        f"Persisting: {diff['counts']['persisting']}",
        f"- PQ-readiness delta: **{de['pq_readiness_score']:+d}** · "
        f"HNDL delta: **{de['hndl_exposed']:+d}** · "
        f"CRITICAL delta: {de['by_severity']['CRITICAL']:+d}",
        "",
        "> Note: the verdict is derived from the matched finding sets; the "
        "deltas above are read from each scan's summary block. These are "
        "different lenses (e.g. a re-located finding counts as MOVED, not as "
        "an add+remove) and can legitimately disagree.",
        "",
    ]
    if diff["introduced"]:
        lines += ["## Introduced", "",
                  "| Severity | Algorithm | Risk | Where |",
                  "|---|---|---|---|"]
        for f in _sorted(diff["introduced"]):
            lines.append(f"| {f.get('severity')} | {f.get('algorithm')} | "
                         f"{f.get('quantum_risk')} | `{f.get('locator')}` |")
        lines.append("")
    if diff["resolved"]:
        lines += ["## Resolved", "",
                  "| Severity | Algorithm | Risk | Where |",
                  "|---|---|---|---|"]
        for f in _sorted(diff["resolved"]):
            lines.append(f"| {f.get('severity')} | {f.get('algorithm')} | "
                         f"{f.get('quantum_risk')} | `{f.get('locator')}` |")
        lines.append("")
    if diff["moved"]:
        lines += ["## Moved (same logical asset, new location)", "",
                  "| Algorithm | From | To |", "|---|---|---|"]
        for m in diff["moved"]:
            lines.append(f"| {m['algorithm']} | `{m['from']}` | `{m['to']}` |")
        lines.append("")
    return "\n".join(lines)


def _sorted(findings: list[dict]) -> list[dict]:
    def rank(f):
        try:
            return Severity[f.get("severity", "INFO")].rank
        except KeyError:
            return 0
    return sorted(findings, key=lambda f: (-rank(f), f.get("algorithm", "")))
