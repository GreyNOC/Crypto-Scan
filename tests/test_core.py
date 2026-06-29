"""Unit tests for GreyNOC CryptoScan core logic."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoscan.classifier import classify, summarize, AssetType
from cryptoscan.primitives import QuantumRisk, Severity, Primitive, lookup, all_facts
from cryptoscan import cbom as cbom_mod
from cryptoscan import code_scanner
from cryptoscan.cli import _gate


def test_shor_kem_is_critical_and_hndl():
    f = classify("ECDH", AssetType.TLS_ENDPOINT, "h:443",
                 key_establishment=True)
    assert f is not None
    assert f.fact.risk is QuantumRisk.SHOR
    assert f.severity() is Severity.CRITICAL
    assert f.hndl_exposed() is True


def test_rsa_signature_role_still_critical_when_key_establishment():
    # RSA used for key transport -> HNDL critical
    f = classify("RSA", AssetType.CERTIFICATE, "h:443", key_establishment=True)
    assert f.severity() is Severity.CRITICAL


def test_aes128_is_grover_medium():
    f = classify("AES-128", AssetType.TLS_ENDPOINT, "h:443")
    assert f.fact.risk is QuantumRisk.GROVER
    assert f.severity() is Severity.MEDIUM
    assert f.hndl_exposed() is False


def test_aes256_is_safe():
    f = classify("aes-256-gcm", AssetType.TLS_ENDPOINT, "h:443")
    assert f.fact.risk is QuantumRisk.SAFE
    assert f.severity() is Severity.INFO


def test_md5_is_legacy_high():
    f = classify("MD5", AssetType.SOURCE, "x.py:1")
    assert f.fact.risk is QuantumRisk.LEGACY
    assert f.severity() is Severity.HIGH


def test_mlkem_is_safe_with_standard():
    f = classify("kyber768", AssetType.DEPENDENCY, "req.txt")
    assert f.fact.risk is QuantumRisk.SAFE
    assert f.fact.standard == "FIPS 203"


def test_unknown_token_returns_none():
    assert classify("blowfish-xyz", AssetType.SOURCE, "x:1") is None


def test_summary_readiness_penalizes_hndl():
    findings = [
        classify("ECDH", AssetType.TLS_ENDPOINT, "h:443", key_establishment=True),
        classify("aes-256-gcm", AssetType.TLS_ENDPOINT, "h:443"),
    ]
    s = summarize(findings)
    assert s["hndl_exposed"] == 1
    assert s["quantum_vulnerable"] == 1
    assert s["pq_safe"] == 1
    # 50% safe baseline, minus HNDL penalty -> below 50
    assert s["pq_readiness_score"] < 50


def test_cbom_is_valid_cyclonedx_shape():
    findings = [
        classify("RSA", AssetType.CERTIFICATE, "h:443", key_establishment=True),
        classify("AES-128", AssetType.TLS_ENDPOINT, "h:443"),
    ]
    doc = cbom_mod.build_cbom(findings, "test-target")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert len(doc["components"]) == 2
    for c in doc["components"]:
        assert c["type"] == "cryptographic-asset"
        assert "cryptoProperties" in c
        assert c["cryptoProperties"]["assetType"] in (
            "algorithm", "certificate", "protocol", "related-crypto-material")
        # GreyNOC risk annotations present
        names = {p["name"] for p in c["properties"]}
        assert "greynoc:quantumRisk" in names
        assert "greynoc:severity" in names


def test_code_scanner_finds_mixed_crypto():
    sample = Path(__file__).resolve().parents[1] / "sample-target"
    findings = code_scanner.scan(sample)
    names = {f.fact.name for f in findings}
    # Should catch RSA, ECDSA, MD5, AES-128, 3DES, SHA-1, ML-KEM at minimum
    for expected in {"RSA", "ECDSA", "MD5", "AES-128", "3DES", "SHA-1", "ML-KEM"}:
        assert expected in names, f"missing {expected} in {names}"
    # dependency pass picks up node-rsa / ecdsa / pynacl
    dep_locs = {f.locator for f in findings if f.asset_type is AssetType.DEPENDENCY}
    assert any("node-rsa" in loc for loc in dep_locs)


def test_registry_has_no_orphan_aliases():
    # every fact resolvable by its own canonical name
    for fact in all_facts():
        assert lookup(fact.name) is fact


def test_chacha20_classified_by_name_not_aes():
    # No-fabrication: a ChaCha20 suite must report as ChaCha20, not AES-256.
    for token in ("chacha20", "chacha20-poly1305", "CHACHA20"):
        fact = lookup(token)
        assert fact is not None, token
        assert fact.name == "ChaCha20"
        assert fact.primitive is Primitive.STREAM_CIPHER
        assert fact.risk is QuantumRisk.SAFE


def test_sha3_is_distinct_from_sha512():
    # SHA-3 must not be folded into the SHA-512 fact.
    assert lookup("sha3-256").name == "SHA3-256"
    assert lookup("sha3-512").name == "SHA3-512"
    assert lookup("sha-512").name == "SHA-512"


def test_locators_use_posix_separators_for_reproducibility():
    # Fingerprints are sha256(locator|...); a backslash on Windows would make
    # them differ from a POSIX scan of the same tree. Locators must be posix.
    sample = Path(__file__).resolve().parents[1] / "sample-target"
    findings = code_scanner.scan(sample)
    assert findings
    for f in findings:
        assert "\\" not in f.locator, f.locator


def test_fail_on_gate_thresholds():
    # MEDIUM-only finding set.
    s = summarize([classify("AES-128", AssetType.SOURCE, "x.py:1")])
    assert _gate(s, "critical") == 0   # nothing at/above critical
    assert _gate(s, "medium") == 2     # the AES-128 is MEDIUM
    assert _gate(s, "none") == 0       # gate disabled
    # CRITICAL finding trips every threshold except 'none'.
    s2 = summarize([classify("ECDH", AssetType.TLS_ENDPOINT, "h:443",
                             key_establishment=True)])
    assert _gate(s2, "critical") == 2
    assert _gate(s2, "none") == 0


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
    raise SystemExit(0 if passed == len(fns) else 1)
