"""
GreyNOC CryptoScan — Mosca Risk Engine.

Turns an inventory finding into a *decision*. Mosca's inequality (Michele Mosca,
IACR ePrint 2015/1075; IEEE S&P 16(5), 2018) states the harvest-now-decrypt-later
exposure condition:

        X + Y > Z

  X = years the data must remain secret (its shelf life),
  Y = years to migrate the estate to post-quantum cryptography,
  Z = years until a cryptographically-relevant quantum computer (CRQC) exists.

If X + Y > Z, then data you transmit today — protected by a Shor-breakable key
exchange — is decryptable before you can finish migrating the data that still
needs to be secret. You are already exposed.

Discipline note (no fabrication): X, Y and Z are *assumptions*, not measurements.
Every default below is labeled with its basis and is overridable; `.basis()`
returns the citations so a CISO can see — and challenge — exactly what the
verdict rests on. The engine asserts the arithmetic, not the future.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .classifier import Finding


class DataTier(str, Enum):
    """Data-classification tier -> secrecy shelf life (X)."""
    TOP_SECRET = "top-secret"
    SECRET = "secret"
    CONFIDENTIAL = "confidential"
    PII_REGULATED = "pii-regulated"
    COMMERCIAL = "commercial"
    TRANSIENT = "transient"


class ZScenario(str, Enum):
    """CRQC-arrival planning scenario (Z)."""
    LOW = "low"          # aggressive / pessimistic-for-defender
    EXPECTED = "expected"
    HIGH = "high"        # conservative / optimistic-for-defender


class Urgency(str, Enum):
    ACT_NOW = "ACT-NOW"        # inequality already violated
    PLAN = "PLAN"              # slack within the planning horizon
    MONITOR = "MONITOR"        # comfortable slack
    NOT_EXPOSED = "NOT-EXPOSED"  # not harvest-now-decrypt-later exposed


# --- Defaults (all overridable; see MoscaParameters.basis() for the basis) ---

# X: secrecy shelf life by tier, in years. Heuristics — see basis().
DEFAULT_SECRECY_YEARS: dict[DataTier, int] = {
    DataTier.TOP_SECRET: 25,
    DataTier.SECRET: 15,
    DataTier.CONFIDENTIAL: 10,
    DataTier.PII_REGULATED: 7,
    DataTier.COMMERCIAL: 5,
    DataTier.TRANSIENT: 1,
}

# Y: years to migrate the estate. Engineering planning assumption, not a standard.
DEFAULT_MIGRATION_YEARS = 7

# Z: years until a CRQC, by scenario. Expert-opinion planning figures, NOT facts.
DEFAULT_CRQC_YEARS: dict[ZScenario, int] = {
    ZScenario.LOW: 5,
    ZScenario.EXPECTED: 12,
    ZScenario.HIGH: 20,
}

# Slack (Z - (X+Y)) at or below this many years counts as PLAN rather than MONITOR.
DEFAULT_PLAN_HORIZON = 3

# Tier assumed when a finding carries no data classification.
DEFAULT_TIER = DataTier.CONFIDENTIAL


@dataclass(frozen=True)
class MoscaParameters:
    secrecy_years: dict = field(
        default_factory=lambda: dict(DEFAULT_SECRECY_YEARS))
    migration_years: int = DEFAULT_MIGRATION_YEARS
    crqc_years: dict = field(default_factory=lambda: dict(DEFAULT_CRQC_YEARS))
    plan_horizon: int = DEFAULT_PLAN_HORIZON
    default_tier: DataTier = DEFAULT_TIER

    @classmethod
    def from_overrides(cls, *, migration_years: int | None = None,
                       plan_horizon: int | None = None,
                       default_tier: DataTier | None = None,
                       crqc_low: int | None = None,
                       crqc_expected: int | None = None,
                       crqc_high: int | None = None,
                       secrecy_overrides: dict | None = None
                       ) -> "MoscaParameters":
        sy = dict(DEFAULT_SECRECY_YEARS)
        if secrecy_overrides:
            sy.update(secrecy_overrides)
        cz = dict(DEFAULT_CRQC_YEARS)
        if crqc_low is not None:
            cz[ZScenario.LOW] = crqc_low
        if crqc_expected is not None:
            cz[ZScenario.EXPECTED] = crqc_expected
        if crqc_high is not None:
            cz[ZScenario.HIGH] = crqc_high
        return cls(
            secrecy_years=sy,
            migration_years=(migration_years if migration_years is not None
                             else DEFAULT_MIGRATION_YEARS),
            crqc_years=cz,
            plan_horizon=(plan_horizon if plan_horizon is not None
                          else DEFAULT_PLAN_HORIZON),
            default_tier=default_tier or DEFAULT_TIER,
        )

    def basis(self) -> dict[str, str]:
        """Citations / rationale for each assumption. Transparency is the point:
        a verdict is only as defensible as the assumptions it rests on."""
        return {
            "model": ("Mosca's inequality X+Y>Z — M. Mosca, IACR ePrint "
                      "2015/1075 (2015); IEEE Security & Privacy 16(5), 2018."),
            "migration_years": (
                "Y default 7yr is an engineering planning assumption (no single "
                "authoritative source); override per estate. Regulatory clocks: "
                "NIST IR 8547 (ipd, Nov 2024) deprecates RSA-2048/ECDSA P-256 by "
                "2030 and disallows by 2035; CNSA 2.0 mandates PQC for "
                "software/firmware signing exclusively by 2030 and broadly for "
                "browsers/servers/OS by 2033 (NSM-10 horizon 2035)."),
            "crqc_years": (
                "Z is uncertain: LOW 5 / EXPECTED 12 / HIGH 20 years are planning "
                "scenarios from expert-opinion surveys (e.g. Global Risk "
                "Institute Quantum Threat Timeline), NOT facts — override to your "
                "risk appetite."),
            "secrecy_years": (
                "X by tier are heuristics. TOP_SECRET=25 is a proxy/upper bound "
                "from E.O. 13526 automatic declassification at 25 years (not a "
                "statutory secrecy duration; exemptions can exceed it). "
                "SECRET 15 / CONFIDENTIAL 10 / PII 7 / COMMERCIAL 5 / TRANSIENT 1 "
                "are configurable heuristics."),
        }

    def to_dict(self) -> dict:
        return {
            "secrecy_years": {t.value: y for t, y in self.secrecy_years.items()},
            "migration_years": self.migration_years,
            "crqc_years": {s.value: y for s, y in self.crqc_years.items()},
            "plan_horizon": self.plan_horizon,
            "default_tier": self.default_tier.value,
        }


@dataclass(frozen=True)
class MoscaVerdict:
    algorithm: str
    locator: str
    tier: DataTier
    scenario: ZScenario
    x_secrecy_years: int
    y_migration_years: int
    z_crqc_years: int
    slack_years: int          # Z - (X + Y); negative => already exposed
    exposure_years: int       # max(0, (X+Y) - Z)
    collapse_year: int        # now_year + Z (when the CRQC is assumed to arrive)
    inequality_violated: bool
    urgency: Urgency

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "locator": self.locator,
            "data_tier": self.tier.value,
            "scenario": self.scenario.value,
            "x_secrecy_years": self.x_secrecy_years,
            "y_migration_years": self.y_migration_years,
            "z_crqc_years": self.z_crqc_years,
            "slack_years": self.slack_years,
            "exposure_years": self.exposure_years,
            "collapse_year": self.collapse_year,
            "inequality_violated": self.inequality_violated,
            "urgency": self.urgency.value,
        }


def _this_year() -> int:
    return datetime.now(timezone.utc).year


def _resolve_tier(finding: Finding, params: MoscaParameters) -> DataTier:
    """Tier precedence: finding.extra['data_tier'] (read-only) > default."""
    raw = (finding.extra or {}).get("data_tier")
    if isinstance(raw, DataTier):
        return raw
    if raw:
        try:
            return DataTier(str(raw).lower())
        except ValueError:
            try:
                return DataTier[str(raw).upper().replace("-", "_")]
            except KeyError:
                pass
    return params.default_tier


def assess(finding: Finding, params: MoscaParameters | None = None, *,
           now_year: int | None = None,
           scenario: ZScenario = ZScenario.EXPECTED,
           tier: DataTier | None = None) -> MoscaVerdict:
    """Apply Mosca's inequality to one finding. Only harvest-now-decrypt-later
    findings carry exposure; everything else is NOT_EXPOSED."""
    params = params or MoscaParameters()
    if now_year is None:
        now_year = _this_year()
    tier = tier or _resolve_tier(finding, params)
    # Tolerate a partial secrecy_years dict (library callers) by falling back to
    # the built-in default for any tier the caller didn't override.
    x = params.secrecy_years.get(tier, DEFAULT_SECRECY_YEARS[tier])
    y = params.migration_years
    z = params.crqc_years[scenario]
    slack = z - (x + y)
    collapse_year = now_year + z

    if not finding.hndl_exposed():
        return MoscaVerdict(
            algorithm=finding.fact.name, locator=finding.locator, tier=tier,
            scenario=scenario, x_secrecy_years=x, y_migration_years=y,
            z_crqc_years=z, slack_years=slack, exposure_years=0,
            collapse_year=collapse_year, inequality_violated=False,
            urgency=Urgency.NOT_EXPOSED)

    violated = slack < 0
    if violated:
        urgency = Urgency.ACT_NOW
    elif slack <= params.plan_horizon:
        urgency = Urgency.PLAN
    else:
        urgency = Urgency.MONITOR

    return MoscaVerdict(
        algorithm=finding.fact.name, locator=finding.locator, tier=tier,
        scenario=scenario, x_secrecy_years=x, y_migration_years=y,
        z_crqc_years=z, slack_years=slack, exposure_years=max(0, -slack),
        collapse_year=collapse_year, inequality_violated=violated,
        urgency=urgency)


def assess_posture(findings: list[Finding], params: MoscaParameters | None = None,
                   *, now_year: int | None = None,
                   scenario: ZScenario = ZScenario.EXPECTED) -> dict:
    """Roll a finding set up into a Mosca posture for one scenario."""
    params = params or MoscaParameters()
    if now_year is None:
        now_year = _this_year()
    verdicts = [assess(f, params, now_year=now_year, scenario=scenario)
                for f in findings if f.hndl_exposed()]
    counts = {u.value: 0 for u in Urgency if u is not Urgency.NOT_EXPOSED}
    worst_rank = -1
    rank = {Urgency.ACT_NOW: 3, Urgency.PLAN: 2, Urgency.MONITOR: 1}
    worst = None
    for v in verdicts:
        counts[v.urgency.value] += 1
        if rank.get(v.urgency, 0) > worst_rank:
            worst_rank = rank.get(v.urgency, 0)
            worst = v.urgency
    return {
        "scenario": scenario.value,
        "now_year": now_year,
        "hndl_findings": len(verdicts),
        "violated": sum(1 for v in verdicts if v.inequality_violated),
        "by_urgency": counts,
        "worst_urgency": (worst or Urgency.NOT_EXPOSED).value,
        "collapse_year": now_year + params.crqc_years[scenario],
        "max_exposure_years": max((v.exposure_years for v in verdicts),
                                  default=0),
        "verdicts": [v.to_dict() for v in verdicts],
    }


def mosca_summary(findings: list[Finding], params: MoscaParameters | None = None,
                  *, now_year: int | None = None,
                  scenario: ZScenario = ZScenario.EXPECTED) -> dict:
    """Full Mosca summary for the report/JSON: the chosen-scenario posture, the
    assumptions + their basis, and a scenario-sensitivity sweep."""
    params = params or MoscaParameters()
    if now_year is None:
        now_year = _this_year()
    posture = assess_posture(findings, params, now_year=now_year,
                             scenario=scenario)
    sensitivity = {
        s.value: assess_posture(findings, params, now_year=now_year,
                                scenario=s)["violated"]
        for s in ZScenario
    }
    return {
        "model": "X + Y > Z",
        "scenario": scenario.value,
        "now_year": now_year,
        "parameters": params.to_dict(),
        "basis": params.basis(),
        "posture": posture,
        "scenario_sensitivity_violated": sensitivity,
    }
