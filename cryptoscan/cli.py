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
from . import (tls_scanner, code_scanner, cbom as cbom_mod,
               report as report_mod, sarif as sarif_mod)


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


def _parse_target(t: str) -> tuple[str, int]:
    if ":" in t and not t.startswith("["):
        host, _, port = t.rpartition(":")
        return host, int(port)
    return t, 443


def _run_tls(targets: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for t in targets:
        host, port = _parse_target(t)
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


def _run_code(path: str) -> list[Finding]:
    print(f"[*] Static crypto discovery: {path}", file=sys.stderr)
    findings = code_scanner.scan(path)
    print(f"    {len(findings)} crypto usage(s) found", file=sys.stderr)
    return findings


def _emit(findings: list[Finding], target: str, args) -> int:
    s = summarize(findings)
    if args.cbom:
        doc = cbom_mod.build_cbom(findings, target)
        _write_text(args.cbom, json.dumps(doc, indent=2))
        print(f"[+] CBOM written: {args.cbom}  "
              f"({len(doc['components'])} components)", file=sys.stderr)
    if args.report:
        md = report_mod.render(findings, target)
        _write_text(args.report, md)
        print(f"[+] Report written: {args.report}", file=sys.stderr)
    if args.json:
        out = {"target": target, "summary": s,
               "findings": [f.to_dict() for f in findings]}
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

    sp_tls = sub.add_parser("tls", help="scan TLS endpoint(s)")
    sp_tls.add_argument("targets", nargs="+", metavar="HOST[:PORT]")
    _add_outputs(sp_tls)

    sp_code = sub.add_parser("code", help="scan a source/dependency tree")
    sp_code.add_argument("path")
    _add_outputs(sp_code)

    sp_scan = sub.add_parser("scan", help="combined code + TLS scan")
    sp_scan.add_argument("path")
    sp_scan.add_argument("--tls", nargs="+", default=[], metavar="HOST[:PORT]")
    _add_outputs(sp_scan)

    args = p.parse_args(argv)
    _force_utf8()

    if args.cmd == "tls":
        findings = _run_tls(args.targets)
        target = ", ".join(args.targets)
    elif args.cmd == "code":
        findings = _run_code(args.path)
        target = args.path
    else:  # scan
        findings = _run_code(args.path) + _run_tls(args.tls)
        target = f"{args.path}" + (f" + {', '.join(args.tls)}" if args.tls else "")

    return _emit(findings, target, args)


if __name__ == "__main__":
    raise SystemExit(main())
