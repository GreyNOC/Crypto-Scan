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
]

# Dependency name -> token. Packages that, by default, embody the primitive.
DEP_SIGNATURES: dict[str, str] = {
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
    # PQC libs — surfaced as SAFE / inventory positive
    "liboqs": "ML-KEM", "oqs": "ML-KEM", "pqcrypto": "ML-KEM",
    "kyber-py": "ML-KEM", "dilithium-py": "ML-DSA",
}

MAX_FILE_BYTES = 2_000_000  # skip files larger than 2 MB


def _iter_source_files(root: Path):
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SOURCE_EXTS:
            try:
                if p.stat().st_size <= MAX_FILE_BYTES:
                    yield p
            except OSError:
                continue


def scan_source(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_source_files(root):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        rel = path.relative_to(root) if path.is_relative_to(root) else path
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
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[ ]", line, 1)[0].strip().lower()
        if name:
            names.append(name)
    return names


def _parse_package_json(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return []
    names = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        names.extend(k.lower() for k in (data.get(key) or {}).keys())
    return names


def _parse_cargo(path: Path) -> list[str]:
    names, in_deps = [], False
    for line in path.read_text(errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("["):
            in_deps = "dependencies" in s
            continue
        if in_deps and "=" in s:
            names.append(s.split("=", 1)[0].strip().strip('"').lower())
    return names


def _parse_gomod(path: Path) -> list[str]:
    names = []
    for line in path.read_text(errors="ignore").splitlines():
        m = re.search(r"^\s*([\w./-]+)\s+v\d", line)
        if m:
            names.append(m.group(1).split("/")[-1].lower())
    return names


MANIFESTS = {
    "requirements.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "cargo.toml": _parse_cargo,
    "go.mod": _parse_gomod,
}


def scan_dependencies(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if path.is_dir() or any(part in SKIP_DIRS for part in path.parts):
            continue
        parser = MANIFESTS.get(path.name.lower())
        if not parser:
            continue
        rel = path.relative_to(root) if path.is_relative_to(root) else path
        try:
            names = parser(path)
        except OSError:
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
    return scan_source(root) + scan_dependencies(root)
