"""
GreyNOC CryptoScan — command-line interface.

  cryptoscan tls   <host[:port]> [host2 ...] [--cbom out.json] [--report out.md]
  cryptoscan code  <path>                    [--cbom out.json] [--report out.md]
  cryptoscan scan  <path> --tls host[:port]  [--cbom out.json] [--report out.md]

Exit code is 2 when findings at or above the --fail-on severity are present
(default: critical), so it can gate CI; pass --fail-on none to never fail.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .classifier import Finding, summarize
from .primitives import Severity
from . import (tls_scanner, ssh_scanner, code_scanner, pki_scanner,
               cbom as cbom_mod, report as report_mod, sarif as sarif_mod,
               mosca as mosca_mod, diff as diff_mod)
from .mosca import MoscaParameters, DataTier, ZScenario


# Severity threshold the scan fails CI on. "none" never fails.
_GATE_CHOICES = ["critical", "high", "medium", "low", "none"]


def _force_utf8() -> None:
    """Emit UTF-8 regardless of the platform console codepage.

    The report uses '·', '—' and '…'; on a legacy Windows console (cp1252)
    an unconfigured stream raises UnicodeEncodeError or prints mojibake.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass  # already-wrapped / non-reconfigurable stream — leave as is


def _write_text(path: str, text: str) -> None:
    """Write UTF-8 with a trailing newline, independent of the OS locale."""
    if not text.endswith("\n"):
        text += "\n"
    Path(path).write_text(text, encoding="utf-8")


def _mosca_from_args(args) -> "tuple[MoscaParameters, ZScenario]":
    """Build Mosca parameters + scenario from the CLI overrides."""
    scenario = ZScenario(args.z_scenario)
    secrecy: dict = {}
    for item in (args.secrecy_years or []):
        tier_s, _, val = item.partition("=")
        try:
            secrecy[DataTier(tier_s.strip().lower())] = int(val)
        except (ValueError, KeyError):
            print(f"[!] ignoring bad --secrecy-years '{item}'", file=sys.stderr)
    default_tier = None
    if args.default_tier:
        try:
            default_tier = DataTier(args.default_tier.strip().lower())
        except ValueError:
            print(f"[!] ignoring bad --default-tier '{args.default_tier}'",
                  file=sys.stderr)
    crqc = {"low": None, "expected": None, "high": None}
    if args.crqc_years is not None:
        crqc[scenario.value] = args.crqc_years
    params = MoscaParameters.from_overrides(
        migration_years=args.migration_years,
        default_tier=default_tier,
        crqc_low=crqc["low"], crqc_expected=crqc["expected"],
        crqc_high=crqc["high"],
        secrecy_overrides=secrecy or None,
    )
    return params, scenario


def _gate(summary: dict, fail_on: str) -> int:
    """Exit 2 if any finding meets/exceeds the fail-on severity, else 0."""
    if fail_on == "none":
        return 0
    threshold = Severity[fail_on.upper()].rank
    by_sev = summary["by_severity"]
    triggered = sum(
        n for sev, n in by_sev.items() if Severity[sev].rank >= threshold
    )
    return 2 if triggered else 0


def _run_diff(args) -> int:
    """Diff two findings-JSON files (the assurance layer)."""
    try:
        old_doc = diff_mod.load_findings_json(args.old)
        new_doc = diff_mod.load_findings_json(args.new)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    d = diff_mod.build_diff(old_doc, new_doc)
    if args.report:
        _write_text(args.report, diff_mod.render_markdown(d))
        print(f"[+] Diff report written: {args.report}", file=sys.stderr)
    if args.json:
        _write_text(args.json, json.dumps(d, indent=2))
        print(f"[+] Diff JSON written: {args.json}", file=sys.stderr)
    c = d["counts"]
    de = d["deltas"]
    print(f"\n=== Posture diff: {d['old_target']} -> {d['new_target']} ===")
    print(f"Verdict: {d['verdict']}")
    print(f"introduced {c['introduced']} · resolved {c['resolved']} · "
          f"moved {c['moved']} · persisting {c['persisting']}")
    print(f"PQ-readiness {de['pq_readiness_score']:+d} · "
          f"HNDL {de['hndl_exposed']:+d} · "
          f"CRITICAL {de['by_severity']['CRITICAL']:+d}")
    code = diff_mod.diff_exit_code(d["verdict"], args.fail_on_regression)
    if code:
        print("[gate] failing: posture regressed", file=sys.stderr)
    return code


def _parse_target(t: str, default_port: int = 443) -> tuple[str, int]:
    if ":" in t and not t.startswith("["):
        host, _, port = t.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            raise ValueError(f"bad target '{t}': port must be numeric")
    return t, default_port


def _run_tls(targets: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for t in targets:
        try:
            host, port = _parse_target(t)
        except ValueError as exc:
            print(f"    ! skipping {exc}", file=sys.stderr)
            continue
        print(f"[*] TLS handshake: {host}:{port}", file=sys.stderr)
        obs = tls_scanner.probe(host, port)
        if obs.error:
            print(f"    ! {obs.error}", file=sys.stderr)
            continue
        print(f"    {obs.protocol} / {obs.cipher_name} / "
              f"key={obs.key_algo}-{obs.key_size or '?'} "
              f"sig={obs.cert_sig_algo}", file=sys.stderr)
        findings.extend(tls_scanner.scan(host, port))
    return findings


def _run_ssh(targets: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for t in targets:
        try:
            host, port = _parse_target(t, default_port=22)
        except ValueError as exc:
            print(f"    ! skipping {exc}", file=sys.stderr)
            continue
        print(f"[*] SSH KEXINIT probe: {host}:{port}", file=sys.stderr)
        obs = ssh_scanner.probe(host, port)
        if obs.error and not obs.kex_algorithms:
            print(f"    ! {obs.error}", file=sys.stderr)
            continue
        print(f"    {obs.banner} / kex={len(obs.kex_algorithms)} "
              f"hostkey={len(obs.host_key_algorithms)} "
              f"enc={len(obs.encryption_algorithms)}", file=sys.stderr)
        findings.extend(ssh_scanner.scan(host, port))
    return findings


def _run_code(path: str) -> list[Finding]:
    print(f"[*] Static crypto discovery: {path}", file=sys.stderr)
    findings = code_scanner.scan(path)
    pki = pki_scanner.scan(path)
    if pki:
        print(f"    {len(pki)} certificate/key artifact(s) found",
              file=sys.stderr)
    print(f"    {len(findings) + len(pki)} crypto usage(s) found",
          file=sys.stderr)
    return findings + pki


def _emit(findings: list[Finding], target: str, args) -> int:
    s = summarize(findings)
    mosca_doc = None
    if getattr(args, "mosca", False):
        params, scenario = _mosca_from_args(args)
        mosca_doc = mosca_mod.mosca_summary(findings, params, scenario=scenario)
    if args.cbom:
        doc = cbom_mod.build_cbom(findings, target)
        _write_text(args.cbom, json.dumps(doc, indent=2))
        print(f"[+] CBOM written: {args.cbom}  "
              f"({len(doc['components'])} components)", file=sys.stderr)
    if args.report:
        md = report_mod.render(findings, target, mosca=mosca_doc)
        _write_text(args.report, md)
        print(f"[+] Report written: {args.report}", file=sys.stderr)
    if args.json:
        out = {"target": target, "summary": s,
               "findings": [f.to_dict() for f in findings]}
        if mosca_doc:
            out["mosca"] = mosca_doc
        _write_text(args.json, json.dumps(out, indent=2))
        print(f"[+] JSON written: {args.json}", file=sys.stderr)
    if getattr(args, "sarif", None):
        doc = sarif_mod.build_sarif(findings, target)
        _write_text(args.sarif, json.dumps(doc, indent=2))
        n = len(doc["runs"][0]["results"])
        print(f"[+] SARIF written: {args.sarif}  ({n} results)", file=sys.stderr)

    # Console summary
    print(f"\n=== Posture: {target} ===")
    print(f"PQ-readiness: {s['pq_readiness_score']}/100 | "
          f"assets: {s['total_findings']} | "
          f"HNDL-exposed: {s['hndl_exposed']} | "
          f"vulnerable: {s['quantum_vulnerable']} | safe: {s['pq_safe']}")
    sev = s["by_severity"]
    print(f"CRITICAL {sev['CRITICAL']} · HIGH {sev['HIGH']} · "
          f"MEDIUM {sev['MEDIUM']} · LOW {sev['LOW']} · INFO {sev['INFO']}")
    if mosca_doc:
        p = mosca_doc["posture"]
        print(f"Mosca [{mosca_doc['scenario']}]: {p['worst_urgency']} · "
              f"HNDL {p['hndl_findings']} · already-exposed {p['violated']} · "
              f"CRQC≈{p['collapse_year']} (X+Y>Z)")

    code = _gate(s, args.fail_on)
    if code:
        print(f"[gate] failing: findings at or above "
              f"'{args.fail_on}' severity present", file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="cryptoscan",
        description="GreyNOC CryptoScan — PQC posture & CBOM generator")
    p.add_argument("--version", action="version",
                   version=f"GreyNOC CryptoScan {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def _add_outputs(sp):
        sp.add_argument("--cbom", metavar="FILE", help="write CycloneDX 1.6 CBOM")
        sp.add_argument("--report", metavar="FILE", help="write Markdown report")
        sp.add_argument("--json", metavar="FILE", help="write raw findings JSON")
        sp.add_argument("--sarif", metavar="FILE",
                        help="write SARIF 2.1.0 (GitHub code scanning)")
        sp.add_argument("--fail-on", choices=_GATE_CHOICES, default="critical",
                        metavar="{critical,high,medium,low,none}",
                        help="severity that makes the scan exit 2 to gate CI "
                             "(default: critical)")
        # Mosca risk-horizon analysis (off by default -> v0.1.0-identical output).
        sp.add_argument("--mosca", action="store_true",
                        help="add Mosca X+Y>Z risk-horizon analysis")
        sp.add_argument("--z-scenario", choices=["low", "expected", "high"],
                        default="expected",
                        help="CRQC arrival scenario for Mosca (default: expected)")
        sp.add_argument("--crqc-years", type=int, metavar="N",
                        help="override CRQC years (Z) for the chosen scenario")
        sp.add_argument("--migration-years", type=int, metavar="N",
                        help="override estate migration time (Y)")
        sp.add_argument("--secrecy-years", action="append", metavar="TIER=N",
                        help="override data secrecy lifetime (X) for a tier "
                             "(repeatable), e.g. --secrecy-years secret=15")
        sp.add_argument("--default-tier", metavar="TIER",
                        help="data tier assumed when unknown (default: "
                             "confidential)")

    sp_tls = sub.add_parser("tls", help="scan TLS endpoint(s)")
    sp_tls.add_argument("targets", nargs="+", metavar="HOST[:PORT]")
    _add_outputs(sp_tls)

    sp_ssh = sub.add_parser("ssh", help="scan SSH endpoint(s) via KEXINIT")
    sp_ssh.add_argument("targets", nargs="+", metavar="HOST[:PORT]")
    _add_outputs(sp_ssh)

    sp_code = sub.add_parser("code", help="scan a source/dependency tree")
    sp_code.add_argument("path")
    _add_outputs(sp_code)

    sp_scan = sub.add_parser("scan", help="combined code + TLS + SSH scan")
    sp_scan.add_argument("path")
    sp_scan.add_argument("--tls", nargs="+", default=[], metavar="HOST[:PORT]")
    sp_scan.add_argument("--ssh", nargs="+", default=[], metavar="HOST[:PORT]")
    _add_outputs(sp_scan)

    sp_diff = sub.add_parser(
        "diff", help="diff two findings JSON files (did the migration land?)")
    sp_diff.add_argument("old", metavar="OLD.json")
    sp_diff.add_argument("new", metavar="NEW.json")
    sp_diff.add_argument("--report", metavar="FILE", help="write Markdown diff")
    sp_diff.add_argument("--json", metavar="FILE", help="write machine diff JSON")
    sp_diff.add_argument("--fail-on-regression", action=argparse.BooleanOptionalAction,
                         default=True,
                         help="exit 2 if posture regressed (default: on)")

    args = p.parse_args(argv)
    _force_utf8()

    if args.cmd == "diff":
        return _run_diff(args)

    if args.cmd == "tls":
        findings = _run_tls(args.targets)
        target = ", ".join(args.targets)
    elif args.cmd == "ssh":
        findings = _run_ssh(args.targets)
        target = ", ".join(args.targets)
    elif args.cmd == "code":
        findings = _run_code(args.path)
        target = args.path
    else:  # scan
        findings = _run_code(args.path) + _run_tls(args.tls) + _run_ssh(args.ssh)
        extras = (([f", {', '.join(args.tls)}"] if args.tls else [])
                  + ([f", {', '.join(args.ssh)}"] if args.ssh else []))
        target = f"{args.path}" + "".join(extras)

    return _emit(findings, target, args)


if __name__ == "__main__":
    raise SystemExit(main())
