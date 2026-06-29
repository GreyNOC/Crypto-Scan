"""Tests for GreyNOC CryptoScan v0.2.0 subsystems.

Kept separate from test_core.py (the v0.1.0 regression suite). pytest discovers
both; nothing here may change the behavior the 15 core tests pin.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoscan.classifier import classify, AssetType
from cryptoscan.primitives import Severity
from cryptoscan import cbom as cbom_mod
from cryptoscan import sarif as sarif_mod

# CycloneDX 1.6 cryptoFunctions vocabulary.
_CDX_CRYPTO_FUNCTIONS = {
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
}
_CDX_ASSET_TYPES = {"algorithm", "certificate", "protocol",
                    "related-crypto-material"}


# --- CBOM enrichment -------------------------------------------------------

def test_cbom_uses_only_valid_cryptofunctions():
    fs = [
        classify("ECDHE", AssetType.TLS_ENDPOINT, "h:443",
                 key_establishment=True),
        classify("RSA", AssetType.CERTIFICATE, "h:443", key_establishment=True),
        classify("AES-256", AssetType.TLS_ENDPOINT, "h:443"),
        classify("SHA-256", AssetType.TLS_ENDPOINT, "h:443"),
    ]
    doc = cbom_mod.build_cbom(fs, "t")
    for c in doc["components"]:
        ap = c["cryptoProperties"].get("algorithmProperties")
        if ap:
            for fn in ap["cryptoFunctions"]:
                assert fn in _CDX_CRYPTO_FUNCTIONS, fn
        assert c["cryptoProperties"]["assetType"] in _CDX_ASSET_TYPES


def test_cbom_nist_level_only_where_nist_pins_one():
    def level(token, **kw):
        f = classify(token, AssetType.TLS_ENDPOINT, "h:443", **kw)
        comp = cbom_mod._algorithm_component(f)
        return comp["cryptoProperties"]["algorithmProperties"][
            "nistQuantumSecurityLevel"]

    assert level("ECDHE", key_establishment=True) == 0   # Shor -> none
    assert level("3DES") == 0                             # legacy -> none
    assert level("AES-128") == 1                          # NIST cat 1
    assert level("AES-256") == 5                          # NIST cat 5
    assert level("SHA-256") == 0                          # hash: not pinned
    assert level("ML-KEM") == 3                           # ML-KEM-768 class


def test_cbom_emits_protocol_asset_with_version_and_suites():
    fs = [
        classify("ECDHE", AssetType.TLS_ENDPOINT, "api:443",
                 evidence="ECDHE-RSA-AES256-GCM-SHA384", key_establishment=True,
                 extra={"protocol": "TLSv1.2", "role": "key-exchange"}),
        classify("AES-256", AssetType.TLS_ENDPOINT, "api:443",
                 evidence="ECDHE-RSA-AES256-GCM-SHA384",
                 extra={"protocol": "TLSv1.2", "role": "bulk-cipher"}),
    ]
    doc = cbom_mod.build_cbom(fs, "t")
    protos = [c for c in doc["components"]
              if c["cryptoProperties"]["assetType"] == "protocol"]
    assert len(protos) == 1
    pp = protos[0]["cryptoProperties"]["protocolProperties"]
    assert pp["type"] == "tls"
    assert pp["version"] == "1.2"
    assert {s["name"] for s in pp["cipherSuites"]} == {
        "ECDHE-RSA-AES256-GCM-SHA384"}


def test_cbom_certificate_asset_modeled_as_certificate():
    f = classify("ECDSA", AssetType.CERTIFICATE, "h:443",
                 extra={"subject": "CN=example.com", "issuer": "CN=CA",
                        "not_before": "2025-01-01T00:00:00+00:00"})
    doc = cbom_mod.build_cbom([f], "t")
    cert = doc["components"][0]
    cp = cert["cryptoProperties"]
    assert cp["assetType"] == "certificate"
    assert cp["certificateProperties"]["certificateFormat"] == "X.509"
    assert cp["certificateProperties"]["subjectName"] == "CN=example.com"
    assert cp["certificateProperties"]["notValidBefore"].startswith("2025")


def test_cbom_no_protocol_component_without_protocol_data():
    # The v0.1.0 fixture: a TLS finding with no protocol context must NOT
    # spawn a protocol component (keeps the count-2 core test honest).
    fs = [classify("RSA", AssetType.CERTIFICATE, "h:443", key_establishment=True),
          classify("AES-128", AssetType.TLS_ENDPOINT, "h:443")]
    doc = cbom_mod.build_cbom(fs, "t")
    assert len(doc["components"]) == 2
    assert not [c for c in doc["components"]
                if c["cryptoProperties"]["assetType"] == "protocol"]


# --- SARIF -----------------------------------------------------------------

def test_sarif_minimal_valid_shape():
    f = classify("MD5", AssetType.SOURCE, "src/a.py:10")
    doc = sarif_mod.build_sarif([f], "t")
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "GreyNOC CryptoScan"
    assert driver["rules"]
    res = doc["runs"][0]["results"][0]
    assert res["message"]["text"]
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 10


def test_sarif_excludes_tls_and_certificate_findings():
    fs = [
        classify("ECDHE", AssetType.TLS_ENDPOINT, "h:443", key_establishment=True),
        classify("RSA", AssetType.CERTIFICATE, "h:443", key_establishment=True),
        classify("MD5", AssetType.SOURCE, "src/a.py:1"),
    ]
    doc = sarif_mod.build_sarif(fs, "t")
    assert len(doc["runs"][0]["results"]) == 1  # only the SOURCE finding


def test_sarif_severity_to_level():
    assert sarif_mod._severity_to_level(Severity.CRITICAL) == "error"
    assert sarif_mod._severity_to_level(Severity.HIGH) == "error"
    assert sarif_mod._severity_to_level(Severity.MEDIUM) == "warning"
    assert sarif_mod._severity_to_level(Severity.LOW) == "note"
    assert sarif_mod._severity_to_level(Severity.INFO) == "note"


def test_sarif_dependency_has_no_region():
    f = classify("RSA", AssetType.DEPENDENCY, "requirements.txt -> node-rsa",
                 key_establishment=True)
    doc = sarif_mod.build_sarif([f], "t")
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "requirements.txt"
    assert "region" not in loc


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
