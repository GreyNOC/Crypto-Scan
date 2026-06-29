"""Tests for GreyNOC CryptoScan v0.2.0 subsystems.

Kept separate from test_core.py (the v0.1.0 regression suite). pytest discovers
both; nothing here may change the behavior the 15 core tests pin.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoscan.classifier import classify, AssetType
from cryptoscan.primitives import (Severity, QuantumRisk, Primitive,
                                    strength_for, curve_fact, pqc_category,
                                    jose_alg, lookup)
from cryptoscan import cbom as cbom_mod
from cryptoscan import sarif as sarif_mod


# --- Knowledge base + parameter-aware severity -----------------------------

def test_rsa_1024_is_classically_weak_but_severity_unchanged():
    weak = classify("RSA", AssetType.CERTIFICATE, "h:443", parameter="1024")
    assert weak.classical_weakness() is True
    assert weak.severity() is Severity.HIGH            # RSA sig role
    keyest = classify("RSA", AssetType.CERTIFICATE, "h:443", parameter="1024",
                      key_establishment=True)
    assert keyest.severity() is Severity.CRITICAL


def test_rsa_2048_is_the_floor_not_weak():
    f = classify("RSA", AssetType.CERTIFICATE, "h:443", parameter="2048")
    assert f.classical_weakness() is False
    # parameter=None path must behave identically to the 2048 floor.
    g = classify("RSA", AssetType.CERTIFICATE, "h:443")
    assert g.classical_weakness() is False
    assert f.severity() is g.severity()


def test_secp192r1_is_shor_and_classically_weak():
    f = classify("ECDSA", AssetType.CERTIFICATE, "h:443", parameter="secp192r1")
    assert f.fact.risk is QuantumRisk.SHOR
    assert f.classical_weakness() is True
    assert f.severity() is Severity.HIGH


def test_aes128_never_escalated_by_strength():
    f = classify("AES-128", AssetType.TLS_ENDPOINT, "h:443", parameter="128")
    assert f.fact.risk is QuantumRisk.GROVER
    assert f.severity() is Severity.MEDIUM
    assert f.classical_weakness() is False


def test_strength_for_dispatches_on_parameter_shape():
    assert strength_for("RSA", "1024") == (80, "weak")
    assert strength_for("RSA", "2048") == (112, "floor")
    assert strength_for("RSA", "3072") == (128, "")
    assert strength_for("RSA", "4096") == (128, "")   # floors to 3072 row
    assert strength_for("ECDSA", "secp192r1") == (96, "weak")
    assert strength_for("ECDSA", "secp256r1") == (128, "")
    assert strength_for("AES-128", "128") == (None, "")  # not a modulus token
    assert curve_fact("P-256") == 128


def test_pqc_param_categories():
    assert pqc_category("ML-KEM-768") == 3
    assert pqc_category("ml-kem-1024") == 5
    assert pqc_category("ML-DSA-44") == 2
    assert pqc_category("ml-dsa-87") == 5
    assert pqc_category("unknown-set") is None


def test_jose_cose_algorithm_mapping():
    assert jose_alg("ES256K").name == "ECDSA"
    assert jose_alg("RS256").name == "RSA"
    assert jose_alg("EdDSA").name == "EdDSA"
    a = jose_alg("A128GCM")
    assert a.name == "AES-128" and a.risk is QuantumRisk.GROVER
    h = jose_alg("HS256")
    assert h.name == "HMAC" and h.primitive is Primitive.MAC
    assert jose_alg("none") is None        # no faithful fact -> skipped


def test_hmac_fact_registered_and_safe():
    f = lookup("HMAC")
    assert f is not None and f.primitive is Primitive.MAC
    assert f.risk is QuantumRisk.SAFE
    assert lookup("HS256") is f            # JOSE alias resolves to it


def test_classically_weak_surfaced_in_finding_dict():
    d = classify("RSA", AssetType.CERTIFICATE, "h:443",
                 parameter="1024").to_dict()
    assert d["classically_weak"] is True

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


# --- TLS 1.3 live probe (offline parse + classifier integration) -----------

import struct
from cryptoscan import tls13_probe
from cryptoscan.tls13_probe import NamedGroup


def _server_hello(group, hrr=False):
    rnd = tls13_probe._HRR_RANDOM if hrr else b"\x01" * 32
    sv = struct.pack(">HH", tls13_probe._EXT_SUPPORTED_VERSIONS, 2) + \
        struct.pack(">H", tls13_probe._TLS13_VERSION)
    if hrr:
        ksd = struct.pack(">H", int(group))
    else:
        ksd = struct.pack(">H", int(group)) + struct.pack(">H", 32) + b"\x2a" * 32
    ks = struct.pack(">HH", tls13_probe._EXT_KEY_SHARE, len(ksd)) + ksd
    exts = sv + ks
    return (struct.pack(">H", 0x0303) + rnd + b"\x00" +
            struct.pack(">H", 0x1301) + b"\x00" +
            struct.pack(">H", len(exts)) + exts)


def test_named_group_codepoints_match_iana():
    assert int(NamedGroup.x25519) == 0x001D
    assert int(NamedGroup.secp256r1) == 0x0017
    assert int(NamedGroup.X25519MLKEM768) == 0x11EC
    assert int(NamedGroup.SecP256r1MLKEM768) == 0x11EB
    assert int(NamedGroup.SecP384r1MLKEM1024) == 0x11ED
    assert int(NamedGroup.X25519Kyber768Draft00) == 0x6399


def test_every_group_token_resolves_to_a_fact():
    for g in NamedGroup:
        assert lookup(g.classifier_token) is not None, g.name


def test_parse_normal_server_hello():
    r = tls13_probe.parse_server_hello(_server_hello(NamedGroup.x25519))
    assert r.is_hrr is False
    assert r.negotiated_version == 0x0304
    assert NamedGroup.from_code(r.selected_group) is NamedGroup.x25519


def test_parse_hello_retry_request_selects_hybrid():
    r = tls13_probe.parse_server_hello(
        _server_hello(NamedGroup.X25519MLKEM768, hrr=True))
    assert r.is_hrr is True
    g = NamedGroup.from_code(r.selected_group)
    assert g is NamedGroup.X25519MLKEM768 and g.is_hybrid_pqc


def test_client_hello_is_well_formed():
    ch = tls13_probe.build_client_hello("example.com")
    assert ch[0] == 0x16                         # handshake record
    assert ch[5] == 0x01                         # ClientHello
    assert struct.unpack_from(">H", ch, 3)[0] == len(ch) - 5


def test_hybrid_kex_is_pq_safe_not_hndl():
    for token in ("x25519mlkem768", "secp256r1mlkem768", "x25519kyber768"):
        f = classify(token, AssetType.TLS_ENDPOINT, "h:443",
                     key_establishment=True)
        assert f.fact.risk is QuantumRisk.SAFE, token
        assert f.severity() is Severity.INFO
        assert f.hndl_exposed() is False


def test_classical_x25519_still_critical_and_hndl():
    f = classify("x25519", AssetType.TLS_ENDPOINT, "h:443",
                 key_establishment=True)
    assert f.fact.risk is QuantumRisk.SHOR
    assert f.severity() is Severity.CRITICAL
    assert f.hndl_exposed() is True


# --- Ecosystem discovery ---------------------------------------------------

from cryptoscan import code_scanner as _cs


def test_every_scanner_token_resolves_to_a_fact():
    # Import-time correctness: no typo'd token in patterns/signatures.
    for _pat, token, _desc in _cs.SOURCE_PATTERNS:
        assert lookup(token) is not None, token
    for name, token in _cs.DEP_SIGNATURES.items():
        if token is not None:
            assert lookup(token) is not None, (name, token)


def test_multi_ecosystem_manifests_discovered():
    sample = Path(__file__).resolve().parents[1] / "sample-target"
    fs = _cs.scan(sample)
    by_loc = {f.locator: f.fact.name for f in fs
              if f.asset_type is AssetType.DEPENDENCY}
    # Maven, composer, Gemfile, go.sum each surfaced at least one package.
    assert any("pom.xml -> bcprov" in loc for loc in by_loc)
    assert any("composer.json -> phpseclib/phpseclib" in loc for loc in by_loc)
    assert any("Gemfile -> rbnacl" in loc for loc in by_loc)
    assert any("go.sum -> btcec" in loc for loc in by_loc)


def test_jose_and_java_source_patterns():
    sample = Path(__file__).resolve().parents[1] / "sample-target"
    fs = _cs.scan(sample)
    names = {(f.locator.split(":")[0], f.fact.name) for f in fs
             if f.asset_type is AssetType.SOURCE}
    assert ("src/tokens.js", "HMAC") in names      # HS256
    assert ("src/tokens.js", "RSA") in names        # RS256
    assert ("src/tokens.js", "ECDSA") in names      # ES256
    assert ("src/Signer.java", "RSA") in names      # KeyPairGenerator RSA
    assert ("src/Signer.java", "ECDSA") in names    # withECDSA
    assert ("src/Signer.java", "MD5") in names      # MD5


def test_malformed_manifest_does_not_crash_scan(tmp_path):
    (tmp_path / "pom.xml").write_text("<project><dependency>", encoding="utf-8")
    (tmp_path / "composer.json").write_text("{ not json", encoding="utf-8")
    # Must not raise; just yields no findings from the broken files.
    fs = _cs.scan(tmp_path)
    assert isinstance(fs, list)


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
