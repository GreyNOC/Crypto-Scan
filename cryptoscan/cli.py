"""
GreyNOC CryptoScan — command-line interface.

  cryptoscan tls   <host[:port]> [host2 ...] [--cbom out.json] [--report out.md]
  cryptoscan code  <path>                    [--cbom out.json] [--report out.md]
  cryptoscan scan  <path> --tls host[:port]  [--cbom out.json] [--report out.md]

Exit code is non-zero when CRITICAL findings are present, so it can gate CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .classifier import Finding, summarize
from .primitives import Severity
from . import tls_scanner, code_scanner, cbom as cbom_mod, report as report_mod


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
        Path(args.cbom).write_text(json.dumps(doc, indent=2))
        print(f"[+] CBOM written: {args.cbom}  "
              f"({len(doc['components'])} components)", file=sys.stderr)
    if args.report:
        md = report_mod.render(findings, target)
        Path(args.report).write_text(md)
        print(f"[+] Report written: {args.report}", file=sys.stderr)
    if args.json:
        out = {"target": target, "summary": s,
               "findings": [f.to_dict() for f in findings]}
        Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"[+] JSON written: {args.json}", file=sys.stderr)

    # Console summary
    print(f"\n=== Posture: {target} ===")
    print(f"PQ-readiness: {s['pq_readiness_score']}/100 | "
          f"assets: {s['total_findings']} | "
          f"HNDL-exposed: {s['hndl_exposed']} | "
          f"vulnerable: {s['quantum_vulnerable']} | safe: {s['pq_safe']}")
    sev = s["by_severity"]
    print(f"CRITICAL {sev['CRITICAL']} · HIGH {sev['HIGH']} · "
          f"MEDIUM {sev['MEDIUM']} · LOW {sev['LOW']} · INFO {sev['INFO']}")

    return 2 if sev["CRITICAL"] else 0


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
