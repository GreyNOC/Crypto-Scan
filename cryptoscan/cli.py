"""
GreyNOC CryptoScan — command-line interface (also installed as `gs` / `gscan`).

Subcommands (see `--help` on each for flags):
  tls     <host ...>            scan TLS endpoint(s)
  ssh     <host ...>            scan SSH endpoint(s) via KEXINIT
  ike     <host ...>            scan IPsec/IKEv2 endpoint(s)
  assess  <host ...>            one host across TLS + SSH + IKEv2
  code    <path>               scan a source / dependency / cert-file tree
  scan    <path> [--tls/--ssh/--ike ...]   combined code + endpoints
  diff    <old.json> <new.json>            posture diff (did the migration land?)

Common outputs: --cbom / --report / --json / --sarif; Mosca risk via --mosca.

Exit codes:
  0  success / posture within the gate
  1  diff could not load an input file
  2  findings at or above --fail-on (default: critical), or a diff regression
  3  scan could not complete — a code path that does not exist, or an endpoint
     scan where no target was reachable (a "measured nothing" is NOT a clean
     posture; distinct so CI never reads an all-errored scan as green)
--fail-on none suppresses the findings gate AND the endpoint-incomplete exit 3;
a nonexistent code/scan path still exits 3 (it is a usage error, not a posture).
Note argparse also uses exit 2 for usage errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .classifier import Finding, summarize
from .primitives import Severity
from . import (tls_scanner, ssh_scanner, ike_scanner, code_scanner, pki_scanner,
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
    t = t.strip()
    # Bracketed IPv6: '[host]' or '[host]:port' — parse the port after the ']'
    # rather than treating the whole thing as an opaque host (which silently
    # dropped an explicit port).
    if t.startswith("["):
        end = t.find("]")
        if end == -1:
            raise ValueError(f"bad target '{t}': unclosed '['")
        host, rest = t[1:end], t[end + 1:]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            # e.g. '[::1]8443' — a dropped ':' must not silently scan the default
            # port; surface it rather than probe the wrong port.
            raise ValueError(f"bad target '{t}': unexpected text after ']'")
        try:
            return host, int(rest[1:])
        except ValueError:
            raise ValueError(f"bad target '{t}': port must be numeric")
    # Bare IPv6 (two or more colons, unbracketed): a literal host, default port —
    # never split on a colon inside the address.
    if t.count(":") >= 2:
        return t, default_port
    if ":" in t:
        host, _, port = t.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            raise ValueError(f"bad target '{t}': port must be numeric")
    return t, default_port


def _run_tls(targets: list[str]) -> tuple[list[Finding], int]:
    """Returns (findings, reached) — reached counts targets that answered, so a
    scan is 'incomplete' only when nothing responded, not when a reachable host
    simply yielded no findings."""
    findings: list[Finding] = []
    reached = 0
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
        reached += 1
        print(f"    {obs.protocol} / {obs.cipher_name} / "
              f"key={obs.key_algo}-{obs.key_size or '?'} "
              f"sig={obs.cert_sig_algo}", file=sys.stderr)
        findings.extend(tls_scanner.scan(host, port, obs=obs))
    return findings, reached


def _run_ssh(targets: list[str]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    reached = 0
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
        reached += 1
        print(f"    {obs.banner} / kex={len(obs.kex_algorithms)} "
              f"hostkey={len(obs.host_key_algorithms)} "
              f"enc={len(obs.encryption_algorithms)}", file=sys.stderr)
        findings.extend(ssh_scanner.scan(host, port, obs=obs))
    return findings, reached


def _run_ike(targets: list[str]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    reached = 0
    for t in targets:
        try:
            host, port = _parse_target(t, default_port=500)
        except ValueError as exc:
            print(f"    ! skipping {exc}", file=sys.stderr)
            continue
        print(f"[*] IKEv2 IKE_SA_INIT probe: {host}:{port}", file=sys.stderr)
        obs = ike_scanner.probe(host, port)
        # A responder that answered (even NO_PROPOSAL_CHOSEN / an unmapped
        # transform) was reached, even if it produced no classified finding.
        if obs.error and not obs.is_response and obs.dh_group is None \
                and obs.preferred_group is None:
            print(f"    ! {obs.error}", file=sys.stderr)
            continue
        reached += 1
        print(f"    response={obs.is_response} dh_group={obs.dh_group} "
              f"enc={obs.encryption}", file=sys.stderr)
        findings.extend(ike_scanner.scan(host, port, obs=obs))
    return findings, reached


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


def _emit(findings: list[Finding], target: str, args,
          incomplete: bool = False) -> int:
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
        # Versioned like the CBOM/SARIF envelopes; no timestamp so identical
        # scans stay byte-identical (checksummable, golden-file friendly).
        # scan_status flags an unmeasured run so a downstream diff/dashboard does
        # not read its empty 0/100 summary as a clean posture.
        out = {"schema_version": "1", "scanner_version": __version__,
               "target": target,
               "scan_status": "incomplete" if incomplete else "complete",
               "summary": s,
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
    if incomplete:
        # A scan that reached nothing has an UNKNOWN posture, not a 100/100 one —
        # never let an all-errored run read as clean.
        print("PQ-readiness: n/a — scan incomplete (no target was reachable); "
              "posture is unknown, not clean")
    else:
        print(f"PQ-readiness: {s['pq_readiness_score']}/100 | "
              f"assets: {s['total_findings']} | "
              f"HNDL-exposed: {s['hndl_exposed']} | "
              f"vulnerable: {s['quantum_vulnerable']} | safe: {s['pq_safe']}")
    sev = s["by_severity"]
    print(f"CRITICAL {sev['CRITICAL']} · HIGH {sev['HIGH']} · "
          f"MEDIUM {sev['MEDIUM']} · LOW {sev['LOW']} · INFO {sev['INFO']}")
    kex_eps, pq_observed, pq_offered = report_mod.pq_hybrid_status(findings)
    if kex_eps:
        extra = f" · offering-only {len(pq_offered)}" if pq_offered else ""
        print(f"PQ key-exchange: {len(pq_observed)}/{len(kex_eps)} endpoint(s) "
              f"with a PQ hybrid observed{extra}")
    if mosca_doc:
        p = mosca_doc["posture"]
        print(f"Mosca [{mosca_doc['scenario']}]: {p['worst_urgency']} · "
              f"HNDL {p['hndl_findings']} · already-exposed {p['violated']} · "
              f"CRQC≈{p['collapse_year']} (X+Y>Z)")

    code = _gate(s, args.fail_on)
    if code:
        print(f"[gate] failing: findings at or above "
              f"'{args.fail_on}' severity present", file=sys.stderr)
    elif incomplete and args.fail_on != "none":
        # Distinct from a findings gate: the scan could not measure the target.
        print("[gate] failing: scan incomplete — no target reachable (exit 3)",
              file=sys.stderr)
        code = 3
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

    sp_ike = sub.add_parser("ike", help="scan IPsec/IKEv2 endpoint(s)")
    sp_ike.add_argument("targets", nargs="+", metavar="HOST[:PORT]")
    _add_outputs(sp_ike)

    sp_assess = sub.add_parser(
        "assess", help="scan a host across TLS + SSH + IKEv2 (default ports)")
    sp_assess.add_argument("targets", nargs="+", metavar="HOST")
    _add_outputs(sp_assess)

    sp_code = sub.add_parser("code", help="scan a source/dependency tree")
    sp_code.add_argument("path")
    _add_outputs(sp_code)

    sp_scan = sub.add_parser("scan", help="combined code + TLS + SSH + IKE scan")
    sp_scan.add_argument("path")
    sp_scan.add_argument("--tls", nargs="+", default=[], metavar="HOST[:PORT]")
    sp_scan.add_argument("--ssh", nargs="+", default=[], metavar="HOST[:PORT]")
    sp_scan.add_argument("--ike", nargs="+", default=[], metavar="HOST[:PORT]")
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

    # A code/scan path that does not exist is a scan that cannot run — reject it
    # up front rather than silently "finding nothing" and exiting clean (a common
    # CI footgun: a typo'd path reads as a passing posture).
    if args.cmd in ("code", "scan") and not Path(args.path).exists():
        print(f"[!] path does not exist: {args.path} (exit 3)", file=sys.stderr)
        return 3

    # 'incomplete' means the scan could not MEASURE its target(s) — every probe
    # errored/timed out — not that it measured them and found nothing. A reachable
    # endpoint that negotiates nothing (e.g. IKE NO_PROPOSAL_CHOSEN) is complete.
    incomplete = False
    if args.cmd == "tls":
        findings, reached = _run_tls(args.targets)
        target = ", ".join(args.targets)
        incomplete = bool(args.targets) and reached == 0
    elif args.cmd == "ssh":
        findings, reached = _run_ssh(args.targets)
        target = ", ".join(args.targets)
        incomplete = bool(args.targets) and reached == 0
    elif args.cmd == "ike":
        findings, reached = _run_ike(args.targets)
        target = ", ".join(args.targets)
        incomplete = bool(args.targets) and reached == 0
    elif args.cmd == "assess":
        tf, tr = _run_tls(args.targets)
        sf, sr = _run_ssh(args.targets)
        kf, kr = _run_ike(args.targets)
        findings = tf + sf + kf
        target = ", ".join(args.targets)
        incomplete = bool(args.targets) and (tr + sr + kr) == 0
    elif args.cmd == "code":
        findings = _run_code(args.path)
        target = args.path
    else:  # scan
        code_findings = _run_code(args.path)
        tf, tr = _run_tls(args.tls)
        sf, sr = _run_ssh(args.ssh)
        kf, kr = _run_ike(args.ike)
        findings = code_findings + tf + sf + kf
        extras = (([f", {', '.join(args.tls)}"] if args.tls else [])
                  + ([f", {', '.join(args.ssh)}"] if args.ssh else [])
                  + ([f", {', '.join(args.ike)}"] if args.ike else []))
        target = f"{args.path}" + "".join(extras)
        # Endpoints were requested but none responded -> the endpoint half
        # measured nothing (code findings, if any, are still reported).
        endpoints_requested = len(args.tls) + len(args.ssh) + len(args.ike)
        incomplete = endpoints_requested > 0 and (tr + sr + kr) == 0

    return _emit(findings, target, args, incomplete=incomplete)


if __name__ == "__main__":
    raise SystemExit(main())
