"""
GreyNOC CryptoScan — source code + dependency discovery surface.

Two complementary passes over a target directory:

  1. Source pass: regex over source files for direct cryptographic API usage
     and primitive literals (RSA.generate, ec.SECP256R1, AES.new, MD5(), etc).
     Each hit carries file:line provenance.

  2. Dependency pass: parse manifests (requirements.txt, package.json,
     Cargo.toml, go.mod) and flag packages known to ship quantum-vulnerable
     primitives by default, so the inventory reaches into the supply chain.

This is static and read-only. No code is executed.
"""

from __future__ import annotations

import json
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

from .classifier import Finding, AssetType, classify

# File extensions worth grepping for inline crypto usage.
SOURCE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift",
}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
             "dist", "build", "target", "vendor", ".tox", ".mypy_cache"}

# (compiled pattern, token, human-readable description)
SOURCE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bRSA\.generate|RSAPrivateKey|generate_private_key\s*\(\s*public_exponent|new RSAKey|crypto\.generateKeyPair\w*\(\s*['\"]rsa", re.I),
     "RSA", "RSA key generation/use"),
    (re.compile(r"\bec\.(SECP|generate_private_key)|EllipticCurve|crypto/ecdsa|ECDSA|elliptic\.(P256|P384)|new ec\.", re.I),
     "ECDSA", "Elliptic-curve (ECDSA) use"),
    (re.compile(r"\bECDH|key_agreement|exchange\s*\(\s*ec\.ECDH|crypto/ecdh", re.I),
     "ECDH", "Elliptic-curve Diffie-Hellman"),
    (re.compile(r"\bEd25519|Ed448|ed25519\.|nacl\.sign", re.I),
     "Ed25519", "Edwards-curve signature"),
    (re.compile(r"\bDiffieHellman|\bDH\.generate|crypto/dh\b|dhparam", re.I),
     "DH", "Finite-field Diffie-Hellman"),
    (re.compile(r"\bDSA\.generate|crypto/dsa\b|new DSA", re.I),
     "DSA", "DSA signature"),
    (re.compile(r"\bAES\.new\([^)]*MODE_|aes-128|AES_128|createCipheriv\(\s*['\"]aes-128", re.I),
     "AES-128", "AES-128 usage"),
    (re.compile(r"\baes-256|AES_256|createCipheriv\(\s*['\"]aes-256|AESGCM\b", re.I),
     "AES-256", "AES-256 usage"),
    (re.compile(r"\b3DES|DES3\.new|TripleDES|des-ede3", re.I),
     "3DES", "Triple-DES usage"),
    (re.compile(r"\bDES\.new|\bdes-cbc\b", re.I),
     "DES", "Single-DES usage"),
    (re.compile(r"\bRC4\b|ARC4\.new|arcfour", re.I),
     "RC4", "RC4 stream cipher"),
    (re.compile(r"\bMD5\b|hashlib\.md5|createHash\(\s*['\"]md5", re.I),
     "MD5", "MD5 hash"),
    (re.compile(r"\bSHA1\b|sha-1|hashlib\.sha1|createHash\(\s*['\"]sha1", re.I),
     "SHA-1", "SHA-1 hash"),
    (re.compile(r"\bML-?KEM|Kyber|ml_kem|mlkem", re.I),
     "ML-KEM", "ML-KEM (PQC) usage"),
    (re.compile(r"\bML-?DSA|Dilithium|ml_dsa|mldsa", re.I),
     "ML-DSA", "ML-DSA (PQC) usage"),
    (re.compile(r"\bSPHINCS|SLH-?DSA", re.I),
     "SLH-DSA", "SLH-DSA (PQC) usage"),
    # JOSE/JWT algorithm identifiers (gated near alg/sign/jwt to cut FPs). RS/PS
    # -> RSA, ES -> ECDSA, EdDSA -> Ed25519, HS -> HMAC. 'none' is intentionally
    # NOT matched (no faithful fact to attach).
    (re.compile(r"['\"](?:RS|PS)(?:256|384|512)['\"]", re.I),
     "RSA", "JOSE RSA signature (RS/PS)"),
    (re.compile(r"['\"]ES(?:256|384|512)K?['\"]", re.I),
     "ECDSA", "JOSE ECDSA signature (ES)"),
    (re.compile(r"['\"]EdDSA['\"]", re.I),
     "Ed25519", "JOSE EdDSA signature"),
    (re.compile(r"['\"]HS(?:256|384|512)['\"]", re.I),
     "HMAC", "JOSE HMAC (HS)"),
    # Java JCA / JCE.
    (re.compile(r"KeyPairGenerator\.getInstance\(\s*['\"]RSA|Cipher\.getInstance\(\s*['\"]RSA|with(?:RSA|RSAandMGF1)\b", re.I),
     "RSA", "Java JCA RSA"),
    (re.compile(r"KeyPairGenerator\.getInstance\(\s*['\"]EC['\"]|Signature\.getInstance\(\s*['\"][\w]*withECDSA", re.I),
     "ECDSA", "Java JCA EC/ECDSA"),
    (re.compile(r"MessageDigest\.getInstance\(\s*['\"]MD5", re.I),
     "MD5", "Java JCA MD5"),
    # WebCrypto SubtleCrypto.
    (re.compile(r"name:\s*['\"]RSA-(?:PSS|OAEP)['\"]|name:\s*['\"]RSASSA-PKCS1", re.I),
     "RSA", "WebCrypto RSA"),
    (re.compile(r"name:\s*['\"]ECDSA['\"]", re.I),
     "ECDSA", "WebCrypto ECDSA"),
    (re.compile(r"name:\s*['\"]ECDH['\"]", re.I),
     "ECDH", "WebCrypto ECDH"),
    # Go standard library crypto imports.
    (re.compile(r"crypto/rsa", re.I), "RSA", "Go crypto/rsa"),
    (re.compile(r"crypto/ed25519", re.I), "Ed25519", "Go crypto/ed25519"),
    (re.compile(r"crypto/md5", re.I), "MD5", "Go crypto/md5"),
    # libsodium / NaCl: crypto_box is X25519 key agreement (HNDL-exposed);
    # crypto_sign is Ed25519 (covered above).
    (re.compile(r"crypto_box\b|sodium_box|nacl\.box", re.I),
     "X25519", "libsodium crypto_box (X25519)"),
    # secp256k1 (blockchain) — ECDSA over a Koblitz curve.
    (re.compile(r"\bsecp256k1\b", re.I), "ECDSA", "secp256k1 ECDSA"),
]

# Dependency name -> token (None = known-irrelevant, skipped). Packages that, by
# default, embody the primitive. Recall over precision: treat as a lead.
DEP_SIGNATURES: dict[str, str | None] = {
    # Python
    "pycryptodome": "RSA", "pycrypto": "RSA", "rsa": "RSA",
    "ecdsa": "ECDSA", "fastecdsa": "ECDSA",
    "ed25519": "Ed25519", "pynacl": "Ed25519",
    "elliptic": "ECDSA", "secp256k1": "ECDSA",
    "node-rsa": "RSA", "jsrsasign": "RSA",
    "node-forge": "RSA",
    "tweetnacl": "Ed25519",
    "ring": "ECDSA",
    "openssl": "RSA",
    "bcrypt": None,  # not quantum-relevant; ignored
    # JS / npm (blockchain ECDSA over secp256k1)
    "ethers": "ECDSA", "web3": "ECDSA",
    "@noble/secp256k1": "ECDSA", "secp256k1-native": "ECDSA",
    # Java / Maven (BouncyCastle, Conscrypt embody RSA/ECDSA)
    "bcprov-jdk18on": "RSA", "bcprov-jdk15on": "RSA", "bcpkix-jdk18on": "RSA",
    "conscrypt-openjdk-uber": "RSA",
    # Ruby
    "rbnacl": "Ed25519",
    # PHP / composer (vendor/package keys)
    "phpseclib/phpseclib": "RSA",
    "paragonie/sodium_compat": "Ed25519",
    # Go (last path segment of the module)
    "btcec": "ECDSA",
    # PQC libs — surfaced as SAFE / inventory positive
    "liboqs": "ML-KEM", "oqs": "ML-KEM", "pqcrypto": "ML-KEM",
    "kyber-py": "ML-KEM", "dilithium-py": "ML-DSA",
}

MAX_FILE_BYTES = 2_000_000  # skip files larger than 2 MB


def _rel_parts(path: Path, root: Path) -> tuple[str, ...]:
    """Path parts relative to the scan root. SKIP_DIRS must be tested against
    these, NOT path.parts — otherwise scanning a project that simply lives under
    a directory named e.g. 'build' or 'vendor' would skip every file."""
    rel = path.relative_to(root) if path.is_relative_to(root) else path
    return rel.parts


def _iter_source_files(root: Path):
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in _rel_parts(p, root)):
            continue
        if p.suffix.lower() in SOURCE_EXTS:
            try:
                st = p.stat()
            except OSError:
                continue
            # Skip non-regular files (FIFO/device/socket) so reading can't hang.
            if stat.S_ISREG(st.st_mode) and st.st_size <= MAX_FILE_BYTES:
                yield p


def scan_source(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # as_posix() so locators (and thus fingerprints) are identical
        # whether the scan runs on Windows or POSIX — reproducibility depends
        # on it.
        rel = (path.relative_to(root) if path.is_relative_to(root) else path).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 1000:
                line = line[:1000]
            for pattern, token, desc in SOURCE_PATTERNS:
                if pattern.search(line):
                    f = classify(
                        token, AssetType.SOURCE, f"{rel}:{lineno}",
                        evidence=line.strip()[:160],
                        key_establishment=token in ("ECDH", "DH", "RSA"),
                        extra={"pattern": desc},
                    )
                    if f:
                        findings.append(f)
    return findings


def _parse_requirements(path: Path) -> list[str]:
    names = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[ @;]", line, maxsplit=1)[0].strip().lower()
        if name:
            names.append(name)
    return names


def _parse_package_json(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    names = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        names.extend(k.lower() for k in (data.get(key) or {}).keys())
    return names


def _parse_cargo(path: Path) -> list[str]:
    names, in_deps = [], False
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("["):
            in_deps = "dependencies" in s
            continue
        if in_deps and "=" in s:
            names.append(s.split("=", 1)[0].strip().strip('"').lower())
    return names


def _parse_gomod(path: Path) -> list[str]:
    names = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = re.search(r"^\s*([\w./-]+)\s+v\d", line)
        if m:
            names.append(m.group(1).split("/")[-1].lower())
    return names


def _parse_pom(path: Path) -> list[str]:
    """Maven pom.xml. Namespace-agnostic: any <artifactId> text.

    Rejects XML that declares a DTD or entities — a Maven POM never needs them,
    and parsing them would expose the scanner to entity-expansion (billion-
    laughs) denial-of-service from a hostile manifest in scanned code.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    low = text.lower()
    if "<!doctype" in low or "<!entity" in low:
        return []
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        return []
    names = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]  # strip XML namespace
        if tag == "artifactId" and el.text:
            names.append(el.text.strip().lower())
    return names


def _parse_gradle(path: Path) -> list[str]:
    """Gradle build.gradle / .kts — pull artifact from 'group:artifact:ver'."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    names = []
    for m in re.finditer(r"""['"]([\w.\-]+):([\w.\-]+):[\w.\-+]*['"]""", text):
        names.append(m.group(2).strip().lower())
    return names


def _parse_gemfile(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    names = []
    for line in lines:
        m = re.match(r"\s*gem\s+['\"]([\w\-]+)['\"]", line)
        if m:
            names.append(m.group(1).lower())
    return names


def _parse_gemfile_lock(path: Path) -> list[str]:
    """Gemfile.lock: top-level gems are the 4-space-indented specs entries."""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    names = []
    for line in lines:
        m = re.match(r"^    ([\w\-]+) \(", line)  # exactly 4 spaces
        if m:
            names.append(m.group(1).lower())
    return names


def _parse_composer_json(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    names = []
    for key in ("require", "require-dev"):
        names.extend(k.lower() for k in (data.get(key) or {}).keys())
    return names


def _parse_gosum(path: Path) -> list[str]:
    """go.sum: module path per line; reduce to the last meaningful segment
    (dropping trailing version-suffix segments like /v2)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    names: set[str] = set()
    for line in lines:
        m = re.match(r"^([\w./\-]+)\s+v", line)
        if not m:
            continue
        seg = m.group(1).rstrip("/").split("/")
        while seg and re.fullmatch(r"v\d+", seg[-1]):
            seg.pop()
        if seg:
            names.add(seg[-1].lower())
    return list(names)


MANIFESTS = {
    "requirements.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "cargo.toml": _parse_cargo,
    "go.mod": _parse_gomod,
    "go.sum": _parse_gosum,
    "pom.xml": _parse_pom,
    "build.gradle": _parse_gradle,
    "build.gradle.kts": _parse_gradle,
    "gemfile": _parse_gemfile,
    "gemfile.lock": _parse_gemfile_lock,
    "composer.json": _parse_composer_json,
}


def scan_dependencies(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if path.is_dir() or any(part in SKIP_DIRS
                                for part in _rel_parts(path, root)):
            continue
        parser = MANIFESTS.get(path.name.lower())
        if not parser:
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        # Skip special files (FIFO/device) and pathologically large manifests.
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
            continue
        rel = (path.relative_to(root) if path.is_relative_to(root) else path).as_posix()
        try:
            names = parser(path)
        except Exception:  # noqa: BLE001 — one bad manifest must not kill the scan
            continue
        for name in names:
            token = DEP_SIGNATURES.get(name)
            if not token:
                continue
            f = classify(
                token, AssetType.DEPENDENCY, f"{rel} -> {name}",
                evidence=name,
                key_establishment=token in ("RSA", "ECDH", "DH"),
                extra={"manifest": path.name, "package": name},
            )
            if f:
                findings.append(f)
    return findings


def scan(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings = scan_source(root) + scan_dependencies(root)
    # Dedupe by fingerprint: several patterns can match one source line and
    # produce identical (asset|locator|algo|evidence) fingerprints. Without
    # this, summarize() over-counts while every fingerprint-keyed consumer
    # (report/CBOM/SARIF/diff) collapses them — header and body would disagree.
    seen: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        deduped.append(f)
    return deduped
