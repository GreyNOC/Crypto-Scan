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
                migrate_to=("X25519MLKEM768 hybrid (draft-ietf-tls-ecdhe-mlkem)",)
                + PQ_KEM,
                note="Montgomery-curve ECDH; ECDLP. Common TLS 1.3 default."),
     "curve25519")

_reg(CryptoFact("X448", Primitive.KEY_AGREE, QuantumRisk.SHOR, 224, 0,
                migrate_to=PQ_KEM,
                note="Curve448 ECDH (RFC 7748); ECDLP. ~224-bit classical."),
     "x448", "curve448")

# --- Hybrid PQC key exchange (classical ECDHE + ML-KEM): PQ-safe -----------
# Reported by name per group — a SecP256r1MLKEM768 handshake must not be
# mislabeled X25519MLKEM768. The shared secret resists harvest-now-decrypt-later
# because the ML-KEM half holds even though the classical half is Shor-broken.
_HYBRID_NOTE = ("Hybrid TLS 1.3 key exchange (classical ECDHE + ML-KEM). The "
                "ML-KEM half defeats harvest-now-decrypt-later; the classical "
                "half alone is Shor-broken.")
_HYBRID_STD = "FIPS 203 + draft-ietf-tls-ecdhe-mlkem"

_reg(CryptoFact("X25519MLKEM768", Primitive.KEY_AGREE, QuantumRisk.SAFE, 128, 128,
                standard=_HYBRID_STD, note=_HYBRID_NOTE),
     "x25519mlkem768")
_reg(CryptoFact("SecP256r1MLKEM768", Primitive.KEY_AGREE, QuantumRisk.SAFE, 128, 128,
                standard=_HYBRID_STD, note=_HYBRID_NOTE),
     "secp256r1mlkem768")
_reg(CryptoFact("SecP384r1MLKEM1024", Primitive.KEY_AGREE, QuantumRisk.SAFE, 192, 192,
                standard=_HYBRID_STD, note=_HYBRID_NOTE),
     "secp384r1mlkem1024")
_reg(CryptoFact("X25519Kyber768Draft00", Primitive.KEY_AGREE, QuantumRisk.SAFE, 128, 128,
                standard="draft-tls-westerbaan-xyber768d00 (obsolete)",
                note=_HYBRID_NOTE + " OBSOLETE draft group; superseded by "
                     "X25519MLKEM768."),
     "x25519kyber768draft00", "x25519kyber768")
# mlkem768x25519-sha256 (SSH) is the same ML-KEM-768 + X25519 primitive pair as
# the TLS group; same risk class, distinct protocol artifact.
REGISTRY["mlkem768x25519"] = REGISTRY["x25519mlkem768"]

# SSH-specific PQ hybrid key exchange (distinct from the TLS groups above).
_reg(CryptoFact("SNTRUP761X25519", Primitive.KEY_AGREE, QuantumRisk.SAFE, 128, 128,
                standard="RFC 9941",
                note="SSH hybrid KEX: Streamlined NTRU Prime (sntrup761) + "
                     "X25519. PQ half is NTRU Prime, NOT ML-KEM/NIST. OpenSSH "
                     "default since 9.0; resists harvest-now-decrypt-later."),
     "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
     "sntrup761x25519")
_reg(CryptoFact("MLKEM768NISTP256", Primitive.KEY_AGREE, QuantumRisk.SAFE, 128, 128,
                standard=_HYBRID_STD,
                note="SSH hybrid KEX: ML-KEM-768 + ECDH P-256. "),
     "mlkem768nistp256-sha256", "mlkem768nistp256")
_reg(CryptoFact("MLKEM1024NISTP384", Primitive.KEY_AGREE, QuantumRisk.SAFE, 192, 192,
                standard=_HYBRID_STD,
                note="SSH hybrid KEX: ML-KEM-1024 + ECDH P-384. "),
     "mlkem1024nistp384-sha384", "mlkem1024nistp384")

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

# --- MAC -------------------------------------------------------------------
_reg(CryptoFact("HMAC", Primitive.MAC, QuantumRisk.SAFE, 256, 128,
                note="Keyed-hash MAC (RFC 2104). Quantum-adequate at >=256-bit "
                     "key; security is bounded by the key, not the digest."),
     "hmac", "hmac-sha256", "hmacsha256", "hmac-sha384", "hmac-sha512",
     "hs256", "hs384", "hs512")

_reg(CryptoFact("Poly1305", Primitive.MAC, QuantumRisk.SAFE, 128, 128,
                note="One-time authenticator (RFC 8439); the MAC half of "
                     "ChaCha20-Poly1305. 128-bit tag; not quantum-broken."),
     "poly1305")

_reg(CryptoFact("UMAC", Primitive.MAC, QuantumRisk.SAFE, 128, 128,
                note="Universal-hash MAC (RFC 4418), not HMAC. umac-128 is "
                     "adequate; umac-64's 64-bit tag is below the modern "
                     "integrity floor."),
     "umac", "umac-128", "umac-128@openssh.com", "umac-64", "umac-64@openssh.com")

_reg(CryptoFact("AES-XCBC", Primitive.MAC, QuantumRisk.SAFE, 128, 64,
                note="AES-128-based MAC (XCBC RFC 3566 / CMAC RFC 4493). "
                     "Strength bounded by the 128-bit AES key."),
     "aes-xcbc", "aes128-xcbc", "aes-cmac", "aes128-cmac")

# Absence of confidentiality is itself a finding (IPsec ENCR_NULL, RFC 2410).
_reg(CryptoFact("NULL-ENCRYPTION", Primitive.OTHER, QuantumRisk.LEGACY, 0, 0,
                note="No confidentiality — ENCR_NULL (RFC 2410); traffic is "
                     "plaintext. Not a weakness of an algorithm, the absence "
                     "of one."),
     "null", "null-encryption", "encr_null")

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


# ---------------------------------------------------------------------------
# Parameter strength tables. Used by the classifier to make severity
# key-size / curve aware: a Shor-broken primitive at a sub-112-bit parameter is
# *also* classically broken and must not be under-counted.
# ---------------------------------------------------------------------------

# RSA / finite-field DH / DSA modulus size (bits) -> comparable classical
# security strength (bits). NIST SP 800-57 Part 1 Rev 5, Table 2.
STRENGTH_BY_MODULUS: dict[int, int] = {
    1024: 80, 2048: 112, 3072: 128, 7680: 192, 15360: 256,
}
# Tokens whose `parameter` is a numeric modulus size.
MODULUS_TOKENS = frozenset({"RSA", "DH", "DSA"})

# The classical-strength floor NIST treats as the minimum acceptable (112-bit,
# e.g. RSA-2048 / P-224). At or above this is the "legacy floor"; below it is
# classically weak.
STRENGTH_FLOOR = 112

# Elliptic curve -> (approx. classical security bits, field size note). Strength
# is the Pollard-rho estimate ~ n/2 (NIST SP 800-186), consistent with the bits
# already recorded on the ECDSA/ECDH/EdDSA facts above.
CURVE_FACTS: dict[str, int] = {
    "secp192r1": 96, "prime192v1": 96, "p-192": 96,
    "secp224r1": 112, "p-224": 112,
    "secp256r1": 128, "prime256v1": 128, "p-256": 128,
    "secp384r1": 192, "p-384": 192,
    "secp521r1": 256, "p-521": 256,
    "secp256k1": 128,
    "x25519": 128, "curve25519": 128,
    "x448": 224,
    "ed25519": 128, "ed448": 224,
    "brainpoolp256r1": 128, "brainpoolp384r1": 192, "brainpoolp512r1": 256,
}

# PQC parameter set -> NIST security CATEGORY (1..5). FIPS 203/204/205, FIPS 206
# (draft). ML-DSA-44 is category 2; the rest follow 1/3/5.
PQC_PARAM_SETS: dict[str, int] = {
    "ml-kem-512": 1, "ml-kem-768": 3, "ml-kem-1024": 5,
    "ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 5,
    "slh-dsa-128s": 1, "slh-dsa-128f": 1,
    "slh-dsa-192s": 3, "slh-dsa-192f": 3,
    "slh-dsa-256s": 5, "slh-dsa-256f": 5,
    "falcon-512": 1, "falcon-1024": 5,
    "fn-dsa-512": 1, "fn-dsa-1024": 5,
}

# JOSE/COSE algorithm identifier -> registry token. RFC 7518 / 8037 / 8812.
JOSE_COSE_ALGS: dict[str, str] = {
    "rs256": "RSA", "rs384": "RSA", "rs512": "RSA",
    "ps256": "RSA", "ps384": "RSA", "ps512": "RSA",
    "rsa-oaep": "RSA", "rsa-oaep-256": "RSA", "rsa1_5": "RSA",
    "es256": "ECDSA", "es384": "ECDSA", "es512": "ECDSA", "es256k": "ECDSA",
    "eddsa": "EdDSA",
    "ecdh-es": "ECDH",
    "hs256": "HMAC", "hs384": "HMAC", "hs512": "HMAC",
    "a128gcm": "AES-128", "a192gcm": "AES-192", "a256gcm": "AES-256",
    "a128kw": "AES-128", "a256kw": "AES-256",
    "a128cbc-hs256": "AES-128", "a256cbc-hs512": "AES-256",
}


def _modulus_strength(n: int) -> int:
    """Comparable classical strength (bits) for an RSA/DH/DSA modulus of n bits.

    Floors to the highest SP 800-57 row at or below n. A 4096-bit modulus lands
    on the 3072 row (128); NIST does not publish a distinct row for it.
    """
    if n < 1024:
        return 56  # well below any acceptable floor
    bits = 80
    for size, strength in sorted(STRENGTH_BY_MODULUS.items()):
        if n >= size:
            bits = strength
        else:
            break
    return bits


def strength_for(token: str, parameter: str | int | None) -> tuple[int | None, str]:
    """Resolve a (token, parameter) to (classical_bits, label).

    Dispatch is on parameter SHAPE, not token name:
      numeric + modulus token -> SP 800-57 modulus table,
      curve name              -> CURVE_FACTS.
    label: 'weak' (< 112-bit), 'floor' (== 112-bit), '' otherwise/unknown.
    """
    if parameter is None:
        return None, ""
    p = str(parameter).strip()
    if not p:
        return None, ""
    bits: int | None = None
    if p.isdigit():
        if token and token.upper() in MODULUS_TOKENS:
            bits = _modulus_strength(int(p))
    else:
        bits = CURVE_FACTS.get(p.lower())
    if bits is None:
        return None, ""
    if bits < STRENGTH_FLOOR:
        return bits, "weak"
    if bits == STRENGTH_FLOOR:
        return bits, "floor"
    return bits, ""


def curve_fact(name: str) -> int | None:
    """Classical security bits for a named curve, or None if unknown."""
    if not name:
        return None
    return CURVE_FACTS.get(name.strip().lower())


def pqc_category(param_set: str) -> int | None:
    """NIST security category (1..5) for a PQC parameter set, or None."""
    if not param_set:
        return None
    return PQC_PARAM_SETS.get(param_set.strip().lower())


def jose_alg(alg_id: str) -> CryptoFact | None:
    """Resolve a JOSE/COSE algorithm id (e.g. 'ES256', 'A128GCM') to a fact."""
    if not alg_id:
        return None
    token = JOSE_COSE_ALGS.get(alg_id.strip().lower())
    return lookup(token) if token else None


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
