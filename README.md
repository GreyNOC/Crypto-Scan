# GreyNOC CryptoScan

[![CI](https://github.com/GreyNOC/Crypto-Scan/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyNOC/Crypto-Scan/actions/workflows/ci.yml)

**Cryptographic Posture Management & PQC migration scanner.**
Discovers the cryptography actually in use across TLS endpoints and
source/dependency trees, classifies each primitive's quantum risk, and emits a
**CycloneDX 1.6 CBOM** (Cryptographic Bill of Materials) plus a CISO-readable
migration roadmap.

> Authorized testing only · reproducible findings · no fabrication.

GreyNOC · `GN-TOOL-CRYPTOSCAN-001` · v0.2.0

---

## Why this exists

NIST finalized the first post-quantum standards in 2024 — **ML-KEM (FIPS 203)**,
**ML-DSA (FIPS 204)**, **SLH-DSA (FIPS 205)** — and CNSA 2.0 / federal mandates
put migration on a clock. The hard part isn't choosing the new algorithms; it's
that almost no organization knows *where their current cryptography lives*. RSA,
ECC, and finite-field Diffie-Hellman are "harvest now, decrypt later" (HNDL)
liabilities: traffic captured today is decryptable the day a
cryptographically-relevant quantum computer exists.

CryptoScan answers the discovery-and-inventory question first, then prioritizes
remediation by HNDL exposure.

## What it does

- **Live TLS 1.3 key-exchange capture + PQC-hybrid detection** — a from-scratch
  ClientHello/ServerHello probe reads the *actually negotiated* group (X25519,
  P-256, …) and detects post-quantum hybrids like **X25519MLKEM768**. This is the
  live harvest-now-decrypt-later signal, not an inference from the certificate.
- **TLS / certificate discovery** — authorized handshake; negotiated protocol +
  cipher suite + the leaf certificate's key algorithm, size, curve, validity, and
  signature algorithm.
- **Source + dependency discovery** — static, read-only scan of source for direct
  crypto API usage and JOSE/JWT/JCA/WebCrypto patterns (file:line provenance), and
  of manifests across **seven ecosystems** — `requirements.txt`, `package.json`,
  `Cargo.toml`, `go.mod`/`go.sum`, Maven `pom.xml`, Gradle, `Gemfile`(`.lock`),
  `composer.json` — for crypto-bearing packages.
- **Quantum-risk classification** — every primitive maps to a defensible public
  position (NIST FIPS 203/204/205, SP 800-57, SP 800-131A, CNSA 2.0), and severity
  is **parameter-aware**: a sub-112-bit key/curve (RSA-1024, secp192r1) is flagged
  `classically-weak` on top of its quantum risk.
  - `shor-broken` — RSA / ECC / DH, broken outright by Shor.
  - `grover-weakened` — symmetric strength ~halved; only a problem below floor.
  - `pq-safe` — standardized PQC (incl. hybrid KEX), or AES-256 / SHA-384+ class.
  - `classically-weak` — already broken pre-quantum (MD5, SHA-1, 3DES, RC4, weak keys).
- **Mosca Risk Engine** — applies Mosca's inequality **X + Y > Z** (data secrecy
  lifetime + migration time vs years-to-quantum) to turn *"you have RSA"* into
  *"this traffic is already harvestable; you are past the safe migration date."*
  Every assumption is labeled, cited, and overridable.
- **CBOM emission** — **CycloneDX 1.6** with `algorithm`, `certificate`, and
  `protocol` crypto-assets; validated against the official CycloneDX 1.6 strict
  schema in CI.
- **SARIF 2.1.0** — source/dependency findings flow into the GitHub Security tab.
- **Posture diffing** — `cryptoscan diff old.json new.json` proves a migration
  landed (and didn't regress); the assurance layer.
- **Migration roadmap** — vulnerable primitives grouped, severity-ranked, and
  mapped to their NIST PQC target with locations.

## Risk model

| Class | Severity floor | HNDL? | Examples |
|---|---|---|---|
| Shor-broken, key establishment | CRITICAL | yes | ECDHE, X25519, RSA key transport |
| Shor-broken, signature / auth | HIGH | no | ECDSA cert, RSA auth cert, EdDSA |
| classically-weak (legacy or < 112-bit key) | HIGH | no | MD5, SHA-1, 3DES, RC4, RSA-1024, secp192r1 |
| Grover-weakened (< 112-bit eff.) | MEDIUM | no | AES-128, AES-192 |
| pq-safe | INFO | no | ML-KEM, ML-DSA, **X25519MLKEM768 hybrid**, AES-256, SHA-384 |

HNDL flagging is **role-accurate**: an RSA certificate used purely for
authentication (e.g. TLS 1.3) is HIGH, not a HNDL CRITICAL — only key-establishment
uses are harvestable. A hybrid like X25519MLKEM768 is `pq-safe` (its ML-KEM half
protects the shared secret) even though the classical half is Shor-broken.

## Install

```bash
pip install -e .                         # installs the package + cryptography
pip install -e ".[validation]"           # optional: CBOM strict-schema self-validation
```

## Usage

```bash
# TLS endpoint(s)
python -m cryptoscan.cli tls example.com:443 api.example.com:443 \
    --cbom cbom.json --report report.md

# Source / dependency tree
python -m cryptoscan.cli code ./my-repo --report report.md --json findings.json

# Combined, with the Mosca risk engine and all outputs
python -m cryptoscan.cli scan ./my-repo --tls example.com:443 \
    --cbom cbom.json --report report.md --json findings.json --sarif out.sarif \
    --mosca --z-scenario expected

# Tune the Mosca assumptions (all overridable & printed in the report)
python -m cryptoscan.cli code ./my-repo --mosca \
    --crqc-years 8 --migration-years 5 \
    --default-tier secret --secrecy-years pii-regulated=10

# Prove a migration landed (assurance layer); exit 2 on regression
python -m cryptoscan.cli diff before.json after.json --report diff.md

# Gate CI on a chosen severity (default: critical)
python -m cryptoscan.cli code ./my-repo --fail-on high      # fail on HIGH or worse
python -m cryptoscan.cli code ./my-repo --fail-on none      # never fail (inventory only)
```

Exit code is **2** when findings at or above `--fail-on` (default **critical**)
are present, so it gates CI; pass `--fail-on none` to only inventory. `diff` exits
2 on a posture **regression** (`--no-fail-on-regression` to disable).

## Outputs

- `--cbom`   CycloneDX 1.6 CBOM with `algorithm`/`certificate`/`protocol` assets
  (drops into Dependency-Track / SBOM tooling; strict-schema validated in CI)
- `--report` Markdown posture report + Mosca risk horizon + migration roadmap
- `--json`   raw findings with fingerprints + provenance (and the Mosca block)
- `--sarif`  SARIF 2.1.0 for GitHub code scanning (source/dependency findings)

Each finding carries a stable `fingerprint` (sha256 of asset+locator+algo+evidence)
and a `locator` normalized to POSIX separators, so results are reproducible and
diffable across scans and operating systems.

## Scope & limitations

Stated plainly, because the no-fabrication standard cuts both ways. These are
current as of v0.2.1 (unchanged by it), split into gaps we intend to close and
properties that are deliberate.

**Roadmap gaps (open, will be addressed):**

- **Cipher-suite enumeration is single-handshake.** The TLS probe reports the
  *negotiated* suite, not the server's full accepted set. (The key-exchange
  *group* probe already enumerates hybrid support across multiple offers; the
  same multi-offer approach for cipher suites is the next step.)
- **Surface coverage is TLS + code/deps.** HSM, firmware, IPsec/SSH, S/MIME, and
  traffic-capture surfaces are out of scope today (see Roadmap).

**By design (intentional, not defects):**

- **Source scan is pattern-based** — it favors recall over precision, so treat
  source findings as leads to confirm, not proof of exploitable config. (A
  semantic/AST pass could raise precision but is a different tool.)
- **Mosca X/Y/Z are assumptions, not measurements.** The defaults are labeled,
  cited (`mosca.MoscaParameters.basis()`), and overridable — the engine asserts
  the arithmetic, not the future. This is honesty, not a bug to fix.

## Roadmap

1. ~~TLS 1.3 `supported_groups` probe~~ ✓ · full cipher-suite enumeration.
2. SSH / IPsec / S-MIME surfaces.
3. ~~Continuous re-scan + posture diffing~~ ✓ (`cryptoscan diff`).
4. ~~Hybrid-readiness checks (X25519MLKEM768)~~ ✓.

## Layout

```
cryptoscan/
  primitives.py   crypto knowledge base (risk truth, strength tables, JOSE/COSE)
  classifier.py   Finding model + context- and parameter-aware severity
  tls_scanner.py  TLS / cert discovery
  tls13_probe.py  live TLS 1.3 ClientHello/ServerHello group + PQC-hybrid probe
  code_scanner.py source + 7-ecosystem dependency discovery
  mosca.py        Mosca X+Y>Z risk engine
  cbom.py         CycloneDX 1.6 CBOM emitter (algorithm/certificate/protocol)
  sarif.py        SARIF 2.1.0 emitter (GitHub code scanning)
  diff.py         posture diffing (assurance layer)
  report.py       Markdown posture report + Mosca horizon + roadmap
  cli.py          command-line entrypoint
tests/            test_core.py (v0.1.0 regression) + test_v2.py (v0.2.0)
sample-target/    deliberately mixed-crypto, multi-ecosystem fixture
```

## Development

```bash
pip install -e .          # installs the package + `cryptography`
pip install pytest
pytest -q tests/          # or: python tests/test_core.py
```

CI (GitHub Actions) runs the suite on Linux and Windows across Python 3.10 and
3.13, smoke-tests the CLI against `sample-target/`, and asserts that finding
locators stay OS-independent so fingerprints remain reproducible.

See [CHANGELOG.md](CHANGELOG.md) for notable changes.
