"""
GreyNOC CryptoScan — cryptographic primitive knowledge base.

Single source of truth for how each primitive behaves under a
cryptographically-relevant quantum computer (CRQC). All quantum-risk
classification flows from the facts encoded here. No fabrication: every
entry maps to a defensible public position (NIST FIPS 203/204/205, SP 800-208,
NSA CNSA 2.0, NIST SP 800-131A transition guidance).

Risk model
----------
SHOR    : public-key primitive broken outright by Shor's algorithm
          (RSA, finite-field DH, all elliptic-curve schemes). A CRQC
          recovers the private key from public parameters. These are the
          "harvest now, decrypt later" (HNDL) liabilities.
GROVER  : symmetric primitive whose effective strength is ~halved by
          Grover's algorithm. Only a problem below a strength floor.
SAFE    : NIST PQC-standardized, or symmetric/hash strength that remains
          adequate post-quantum.
LEGACY  : already broken or deprecated by CLASSICAL cryptanalysis,
          independent of quantum. Surfaced because it is genuine risk and
          tends to co-locate with quantum-vulnerable config.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class QuantumRisk(str, Enum):
    SHOR = "shor-broken"          # asymmetric, broken by Shor
    GROVER = "grover-weakened"    # symmetric, halved by Grover
    SAFE = "pq-safe"              # standardized PQC or adequate symmetric
    LEGACY = "classically-weak"   # already broken/deprecated, pre-quantum
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
        }[self.value]


# CycloneDX 1.6 cryptoProperties.algorithmProperties.primitive vocabulary
class Primitive(str, Enum):
    PKE = "pke"                      # public-key encryption / KEM
    SIGNATURE = "signature"
    KEY_AGREE = "key-agree"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    DRBG = "drbg"
    OTHER = "other"


@dataclass(frozen=True)
class CryptoFact:
    """A canonical fact sheet for one cryptographic primitive."""
    name: str
    primitive: Primitive
    risk: QuantumRisk
    # Effective classical bits of security at the named strength.
    classical_bits: int | None = None
    # Effective bits AGAINST a quantum adversary (Grover halves symmetric;
    # Shor collapses asymmetric to ~0 for the hard problem).
    quantum_bits: int | None = None
    # NIST PQC standard reference where applicable.
    standard: str | None = None
    # Suggested PQC migration target(s).
    migrate_to: tuple[str, ...] = field(default_factory=tuple)
    note: str = ""

    def severity(self) -> Severity:
        """Default severity for this primitive in isolation.

        Context (long-lived data, key-exchange role) can escalate this in the
        classifier; this is the floor.
        """
        if self.risk is QuantumRisk.SHOR:
            # Key-establishment Shor breaks are the HNDL crown jewels.
            if self.primitive in (Primitive.PKE, Primitive.KEY_AGREE):
                return Severity.CRITICAL
            return Severity.HIGH  # signatures: forgery risk, but no HNDL
        if self.risk is QuantumRisk.LEGACY:
            return Severity.HIGH
        if self.risk is QuantumRisk.GROVER:
            qb = self.quantum_bits or 0
            if qb < 112:
                return Severity.MEDIUM
            return Severity.LOW
        if self.risk is QuantumRisk.SAFE:
            return Severity.INFO
        return Severity.MEDIUM


# Default PQC migration targets, by role.
PQ_KEM = ("ML-KEM-768 (FIPS 203)",)
PQ_SIG = ("ML-DSA-65 (FIPS 204)", "SLH-DSA (FIPS 205)")

# ---------------------------------------------------------------------------
# Registry. Keys are normalized lowercase tokens; the classifier normalizes
# observed strings before lookup.
# ---------------------------------------------------------------------------
REGISTRY: dict[str, CryptoFact] = {}


def _reg(fact: CryptoFact, *aliases: str) -> None:
    REGISTRY[fact.name.lower()] = fact
    for a in aliases:
        REGISTRY[a.lower()] = fact


# --- Asymmetric: Shor-broken -----------------------------------------------
_reg(CryptoFact("RSA", Primitive.PKE, QuantumRisk.SHOR, 112, 0,
                migrate_to=PQ_KEM,
                note="Integer factorization; Shor recovers private key. "
                     "Also used for signatures — same break."),
     "rsaencryption", "rsassa", "rsa-pss", "rsassa-pss", "sha256withrsa",
     "sha256withrsaencryption", "sha1withrsa", "sha384withrsaencryption",
     "sha512withrsaencryption")

_reg(CryptoFact("ECDSA", Primitive.SIGNATURE, QuantumRisk.SHOR, 128, 0,
                migrate_to=PQ_SIG,
                note="ECDLP; Shor forges signatures."),
     "ecdsa-with-sha256", "ecdsa-with-sha384", "sha256withecdsa",
     "ecdsawithsha256", "prime256v1-ecdsa")

_reg(CryptoFact("ECDH", Primitive.KEY_AGREE, QuantumRisk.SHOR, 128, 0,
                migrate_to=PQ_KEM,
                note="ECDLP key agreement; HNDL-exposed."),
     "ecdhe", "x25519-ecdh")

_reg(CryptoFact("EdDSA", Primitive.SIGNATURE, QuantumRisk.SHOR, 128, 0,
                migrate_to=PQ_SIG,
                note="Edwards-curve signatures (Ed25519/Ed448); ECDLP."),
     "ed25519", "ed448")

_reg(CryptoFact("DH", Primitive.KEY_AGREE, QuantumRisk.SHOR, 112, 0,
                migrate_to=PQ_KEM,
                note="Finite-field Diffie-Hellman; discrete log."),
     "dhe", "diffie-hellman", "ffdhe", "ffdhe2048", "ffdhe3072")

_reg(CryptoFact("DSA", Primitive.SIGNATURE, QuantumRisk.SHOR, 112, 0,
                migrate_to=PQ_SIG,
                note="Finite-field DSA; discrete log. Also deprecated by NIST."))

_reg(CryptoFact("X25519", Primitive.KEY_AGREE, QuantumRisk.SHOR, 128, 0,
                migrate_to=("X25519MLKEM768 hybrid (RFC 9370 style)",) + PQ_KEM,
                note="Montgomery-curve ECDH; ECDLP. Common TLS 1.3 default."),
     "x25519kyber768", "curve25519")

# --- Symmetric / hash: Grover-weakened or safe -----------------------------
_reg(CryptoFact("AES-128", Primitive.BLOCK_CIPHER, QuantumRisk.GROVER, 128, 64,
                migrate_to=("AES-256",),
                note="Grover -> ~64-bit effective. Below CNSA 2.0 floor."),
     "aes128", "aes-128-gcm", "aes_128_gcm", "aes-128-cbc", "aes128-gcm")

_reg(CryptoFact("AES-192", Primitive.BLOCK_CIPHER, QuantumRisk.GROVER, 192, 96,
                migrate_to=("AES-256",),
                note="Grover -> ~96-bit effective."),
     "aes192", "aes-192-gcm")

_reg(CryptoFact("AES-256", Primitive.BLOCK_CIPHER, QuantumRisk.SAFE, 256, 128,
                note="Grover -> ~128-bit effective; CNSA 2.0 approved."),
     "aes256", "aes-256-gcm", "aes_256_gcm", "aes-256-cbc", "aes256-gcm")

# ChaCha20 is its own stream cipher — report it by name, never as AES-256.
_reg(CryptoFact("ChaCha20", Primitive.STREAM_CIPHER, QuantumRisk.SAFE, 256, 128,
                note="256-bit stream cipher; Grover -> ~128-bit. Not "
                     "quantum-broken. ChaCha20-Poly1305 is a TLS 1.3 AEAD."),
     "chacha20", "chacha20-poly1305", "chacha20poly1305")

_reg(CryptoFact("3DES", Primitive.BLOCK_CIPHER, QuantumRisk.LEGACY, 112, 56,
                migrate_to=("AES-256",),
                note="Sweet32; deprecated by NIST SP 800-131A (disallowed 2024)."),
     "des-ede3", "triple-des", "tdea", "3des-ede-cbc")

_reg(CryptoFact("DES", Primitive.BLOCK_CIPHER, QuantumRisk.LEGACY, 56, 28,
                migrate_to=("AES-256",), note="Broken classically."),
     "des-cbc")

_reg(CryptoFact("RC4", Primitive.STREAM_CIPHER, QuantumRisk.LEGACY, 0, 0,
                migrate_to=("AES-256-GCM",), note="Broken classically (RFC 7465)."),
     "arcfour", "rc4-128")

_reg(CryptoFact("MD5", Primitive.HASH, QuantumRisk.LEGACY, 0, 0,
                migrate_to=("SHA-256", "SHA-384"),
                note="Collisions trivial; never quantum-relevant."),
     "md5withrsaencryption")

_reg(CryptoFact("SHA-1", Primitive.HASH, QuantumRisk.LEGACY, 0, 0,
                migrate_to=("SHA-256", "SHA-384"),
                note="SHAttered; disallowed by NIST after 2030 / already for sigs."),
     "sha1", "sha-1", "sha1withrsaencryption")

_reg(CryptoFact("SHA-256", Primitive.HASH, QuantumRisk.SAFE, 256, 128,
                note="Grover preimage -> ~128-bit; adequate."),
     "sha256", "sha-256", "sha2-256")

_reg(CryptoFact("SHA-384", Primitive.HASH, QuantumRisk.SAFE, 384, 192,
                note="CNSA 2.0 approved."),
     "sha384", "sha-384")

_reg(CryptoFact("SHA-512", Primitive.HASH, QuantumRisk.SAFE, 512, 256,
                note="Adequate post-quantum."),
     "sha512", "sha-512")

# SHA-3 family — distinct primitive from SHA-2; don't fold into SHA-512.
_reg(CryptoFact("SHA3-256", Primitive.HASH, QuantumRisk.SAFE, 256, 128,
                note="Keccak; Grover preimage -> ~128-bit; adequate."),
     "sha3-256", "sha3_256")

_reg(CryptoFact("SHA3-512", Primitive.HASH, QuantumRisk.SAFE, 512, 256,
                note="Keccak; adequate post-quantum."),
     "sha3-512", "sha3_512")

# --- PQC standardized: safe ------------------------------------------------
_reg(CryptoFact("ML-KEM", Primitive.PKE, QuantumRisk.SAFE,
                standard="FIPS 203",
                note="Module-Lattice KEM (Kyber). Target for key establishment."),
     "ml-kem-512", "ml-kem-768", "ml-kem-1024", "kyber", "kyber768", "mlkem")

_reg(CryptoFact("ML-DSA", Primitive.SIGNATURE, QuantumRisk.SAFE,
                standard="FIPS 204",
                note="Module-Lattice signature (Dilithium)."),
     "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "dilithium", "mldsa")

_reg(CryptoFact("SLH-DSA", Primitive.SIGNATURE, QuantumRisk.SAFE,
                standard="FIPS 205",
                note="Stateless hash-based signature (SPHINCS+)."),
     "slh-dsa", "sphincs", "sphincs+")

_reg(CryptoFact("FN-DSA", Primitive.SIGNATURE, QuantumRisk.SAFE,
                standard="FIPS 206 (draft)",
                note="FFT-lattice signature (Falcon)."),
     "falcon", "fn-dsa")


def lookup(token: str) -> CryptoFact | None:
    """Resolve an observed algorithm token to a CryptoFact, or None."""
    if not token:
        return None
    return REGISTRY.get(token.strip().lower())


def all_facts() -> list[CryptoFact]:
    seen: set[int] = set()
    out: list[CryptoFact] = []
    for f in REGISTRY.values():
        if id(f) not in seen:
            seen.add(id(f))
            out.append(f)
    return out
