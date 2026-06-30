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


def test_cbom_validates_against_cyclonedx_1_6_strict_schema():
    # Gated on the optional [validation] extra; a no-op when it isn't installed.
    try:
        from cyclonedx.validation.json import JsonStrictValidator
        from cyclonedx.schema import SchemaVersion
    except ImportError:
        return
    import json
    fs = [
        classify("ECDHE", AssetType.TLS_ENDPOINT, "h:443",
                 evidence="ECDHE-RSA-AES256-GCM-SHA384", key_establishment=True,
                 extra={"protocol": "TLSv1.2", "role": "key-exchange"}),
        classify("AES-256", AssetType.TLS_ENDPOINT, "h:443",
                 evidence="ECDHE-RSA-AES256-GCM-SHA384",
                 extra={"protocol": "TLSv1.2", "role": "bulk-cipher"}),
        classify("RSA", AssetType.CERTIFICATE, "h:443", key_establishment=True,
                 parameter="2048",
                 extra={"subject": "CN=example.com", "issuer": "CN=CA",
                        "not_before": "2025-01-01T00:00:00+00:00"}),
        classify("x25519mlkem768", AssetType.TLS_ENDPOINT, "h:443",
                 key_establishment=True),
        classify("MD5", AssetType.SOURCE, "src/a.py:3"),
    ]
    doc = cbom_mod.build_cbom(fs, "validation-target")
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(
        json.dumps(doc))
    assert errors is None, errors


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


def test_tls13_cipher_suite_codepoints():
    cs = tls13_probe.TLS13_CIPHER_SUITES
    assert cs[0x1301] == "TLS_AES_128_GCM_SHA256"
    assert cs[0x1302] == "TLS_AES_256_GCM_SHA384"
    assert cs[0x1303] == "TLS_CHACHA20_POLY1305_SHA256"
    assert cs[0x1304] == "TLS_AES_128_CCM_SHA256"
    assert cs[0x1305] == "TLS_AES_128_CCM_8_SHA256"


def test_build_client_hello_carries_requested_cipher_suites():
    ch = tls13_probe.build_client_hello("example.com", cipher_suites=(0x1304,))
    assert struct.pack(">H", 0x1304) in ch
    # default offer still includes the three AEAD suites
    default = tls13_probe.build_client_hello("example.com")
    assert struct.pack(">H", 0x1303) in default
    # round-trips a parseable record (handshake / ClientHello)
    assert ch[0] == 0x16 and ch[5] == 0x01


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


# --- Mosca risk engine -----------------------------------------------------

from cryptoscan.mosca import (MoscaParameters, DataTier, ZScenario, Urgency,
                              assess, assess_posture, mosca_summary)


def _ecdh(extra=None):
    return classify("ECDH", AssetType.TLS_ENDPOINT, "h:443",
                    key_establishment=True, extra=extra or {})


def test_mosca_inequality_violated_act_now():
    # X(confidential)=10, Y=7, Z(expected)=12 -> 17 > 12 -> violated, exposure 5.
    v = assess(_ecdh(), now_year=2026)
    assert v.inequality_violated is True
    assert v.urgency is Urgency.ACT_NOW
    assert v.exposure_years == 5
    assert v.collapse_year == 2038       # 2026 + Z(12)


def test_mosca_plan_vs_monitor_boundary():
    plan = MoscaParameters.from_overrides(crqc_expected=20)   # slack 3
    assert assess(_ecdh(), params=plan, now_year=2026).urgency is Urgency.PLAN
    mon = MoscaParameters.from_overrides(crqc_expected=21)    # slack 4
    assert assess(_ecdh(), params=mon, now_year=2026).urgency is Urgency.MONITOR


def test_mosca_not_exposed_for_non_hndl():
    sig = classify("RSA", AssetType.CERTIFICATE, "h:443")     # auth, not HNDL
    aes = classify("AES-128", AssetType.TLS_ENDPOINT, "h:443")
    assert assess(sig, now_year=2026).urgency is Urgency.NOT_EXPOSED
    assert assess(aes, now_year=2026).urgency is Urgency.NOT_EXPOSED


def test_mosca_tier_override_via_extra():
    v = assess(_ecdh(extra={"data_tier": "transient"}), now_year=2026)
    assert v.tier is DataTier.TRANSIENT
    assert v.x_secrecy_years == 1
    assert v.inequality_violated is False     # 1+7=8 < 12
    assert v.urgency is Urgency.MONITOR


def test_mosca_from_overrides_flips_verdict_and_keeps_basis():
    finding = _ecdh(extra={"data_tier": "transient"})
    assert assess(finding, now_year=2026).urgency is Urgency.MONITOR
    aggressive = MoscaParameters.from_overrides(crqc_expected=5)  # Z=5
    assert assess(finding, params=aggressive,
                  now_year=2026).urgency is Urgency.ACT_NOW
    assert "model" in aggressive.basis()


def test_mosca_now_year_is_deterministic_at_both_layers():
    v1 = assess(_ecdh(), now_year=2030)
    v2 = assess(_ecdh(), now_year=2030)
    assert v1.collapse_year == v2.collapse_year == 2042
    p = assess_posture([_ecdh()], now_year=2030)
    assert p["collapse_year"] == 2042


def test_mosca_scenario_sensitivity_is_monotonic():
    s = mosca_summary([_ecdh()], now_year=2026)
    sens = s["scenario_sensitivity_violated"]
    assert sens["low"] >= sens["expected"] >= sens["high"]
    assert sens["high"] == 0          # 17 < 20
    assert s["posture"]["worst_urgency"] == "ACT-NOW"


def test_report_mosca_section_is_opt_in():
    from cryptoscan import report as report_mod
    findings = [_ecdh()]
    plain = report_mod.render(findings, "t")
    assert "Mosca" not in plain                    # default: v0.1.0-shaped
    m = mosca_summary(findings, now_year=2026)
    withm = report_mod.render(findings, "t", mosca=m)
    assert "Quantum risk horizon" in withm
    assert "X + Y > Z" in withm


# --- Posture diffing -------------------------------------------------------

import json as _json
from cryptoscan.classifier import summarize as _summarize
from cryptoscan import diff as diff_mod
from cryptoscan import cli as cli_mod


def _envelope(findings, target="t"):
    return {"target": target, "summary": _summarize(findings),
            "findings": [f.to_dict() for f in findings]}


def test_diff_pure_resolution_is_migration_landed():
    old = _envelope([classify("ECDH", AssetType.TLS_ENDPOINT, "h:443",
                              key_establishment=True),
                     classify("ML-KEM", AssetType.DEPENDENCY, "r.txt -> kyber")])
    new = _envelope([classify("ML-KEM", AssetType.DEPENDENCY, "r.txt -> kyber")])
    d = diff_mod.build_diff(old, new)
    assert d["verdict"] == diff_mod.MIGRATION_LANDED
    assert d["counts"]["resolved"] == 1
    assert diff_mod.diff_exit_code(d["verdict"]) == 0


def test_diff_new_critical_is_regression_exit_2():
    old = _envelope([classify("ML-KEM", AssetType.DEPENDENCY, "r.txt -> kyber")])
    new = _envelope([classify("ML-KEM", AssetType.DEPENDENCY, "r.txt -> kyber"),
                     classify("ECDH", AssetType.TLS_ENDPOINT, "h:443",
                              key_establishment=True)])
    d = diff_mod.build_diff(old, new)
    assert d["verdict"] == diff_mod.REGRESSION
    assert diff_mod.diff_exit_code(d["verdict"]) == 2


def test_diff_regression_wins_over_landing():
    # Resolve an HNDL ECDH but introduce a new HNDL RSA-key-transport.
    old = _envelope([classify("ECDH", AssetType.TLS_ENDPOINT, "h:443",
                              key_establishment=True)])
    new = _envelope([classify("RSA", AssetType.DEPENDENCY, "r.txt -> node-rsa",
                              key_establishment=True)])
    d = diff_mod.build_diff(old, new)
    assert d["verdict"] == diff_mod.REGRESSION


def test_diff_identical_is_no_change_exit_0():
    fs = [classify("AES-256", AssetType.TLS_ENDPOINT, "h:443")]
    d = diff_mod.build_diff(_envelope(fs), _envelope(fs))
    assert d["verdict"] == diff_mod.NO_CHANGE
    assert diff_mod.diff_exit_code(d["verdict"]) == 0


def test_diff_line_move_is_moved_not_add_remove():
    old = _envelope([classify("RSA", AssetType.SOURCE, "src/a.py:5")])
    new = _envelope([classify("RSA", AssetType.SOURCE, "src/a.py:8")])
    d = diff_mod.build_diff(old, new)
    assert d["counts"]["moved"] == 1
    assert d["counts"]["introduced"] == 0
    assert d["counts"]["resolved"] == 0
    assert d["verdict"] == diff_mod.NO_CHANGE


def test_diff_strip_line_only_removes_trailing_int():
    assert diff_mod.strip_line("src/a.py:5") == "src/a.py"
    assert diff_mod.strip_line("src/a.py") == "src/a.py"


def test_diff_moved_pairing_is_source_only():
    # Two different certs on the same endpoint must not be paired as "moved".
    old = _envelope([classify("RSA", AssetType.CERTIFICATE, "h:443",
                              evidence="RSA-2048")])
    new = _envelope([classify("ECDSA", AssetType.CERTIFICATE, "h:443",
                              evidence="ECDSA-256")])
    d = diff_mod.build_diff(old, new)
    assert d["counts"]["moved"] == 0
    assert d["counts"]["introduced"] == 1
    assert d["counts"]["resolved"] == 1


def test_diff_rejects_malformed_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"findings": [{"algorithm": "RSA"}]}', encoding="utf-8")
    try:
        diff_mod.load_findings_json(str(bad))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_diff_cli_end_to_end(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(_json.dumps(_envelope(
        [classify("ECDH", AssetType.TLS_ENDPOINT, "h:443",
                  key_establishment=True)])), encoding="utf-8")
    new.write_text(_json.dumps(_envelope([])), encoding="utf-8")
    report = tmp_path / "diff.md"
    rc = cli_mod.main(["diff", str(old), str(new), "--report", str(report)])
    assert rc == 0
    text = report.read_text(encoding="utf-8")
    assert "MIGRATION_LANDED" in text
    assert "no-fabrication" in text


# --- Review fixes ----------------------------------------------------------

def test_scan_root_under_skipdir_still_finds_things(tmp_path):
    # Fix #1: a project living under a dir named like a SKIP_DIRS entry must
    # still be scanned (SKIP_DIRS is relative to the scan root, not absolute).
    proj = tmp_path / "build" / "myproject" / "src"
    proj.mkdir(parents=True)
    (proj / "a.py").write_text("rsa_key = RSA.generate(2048)\n",
                               encoding="utf-8")
    fs = _cs.scan(tmp_path / "build" / "myproject")
    assert any(f.fact.name == "RSA" for f in fs)
    # But a real vendored dir *inside* the project is still skipped.
    vend = proj / "vendor"
    vend.mkdir()
    (vend / "b.py").write_text("h = hashlib.md5(b'')\n", encoding="utf-8")
    fs2 = _cs.scan(tmp_path / "build" / "myproject")
    assert not any("vendor" in f.locator for f in fs2)


def test_cbom_pqc_level_is_param_set_aware():
    def level(token):
        f = classify(token, AssetType.DEPENDENCY, "r.txt -> " + token,
                     evidence=token)
        return cbom_mod._algorithm_component(f)["cryptoProperties"][
            "algorithmProperties"]["nistQuantumSecurityLevel"]
    assert level("ml-kem-512") == 1
    assert level("ml-dsa-44") == 2
    assert level("ml-kem-768") == 3
    assert level("ml-kem-1024") == 5
    assert level("ml-dsa-87") == 5
    assert level("ML-KEM") == 3            # generic, no set -> recommended cat 3


def test_source_scan_has_no_duplicate_fingerprints():
    # Fix #5: the same line matching multiple patterns must not double-count.
    sample = Path(__file__).resolve().parents[1] / "sample-target"
    fs = _cs.scan(sample)
    fps = [f.fingerprint for f in fs]
    assert len(fps) == len(set(fps))       # summarize() now agrees with consumers


def test_effective_classical_bits_follows_the_curve():
    # Fix #6: an EC key on a stronger curve reports its real strength.
    ec384 = classify("ECDSA", AssetType.CERTIFICATE, "h:443",
                     parameter="secp384r1")
    assert ec384.effective_classical_bits() == 192
    rsa4096 = classify("RSA", AssetType.CERTIFICATE, "h:443", parameter="4096")
    assert rsa4096.effective_classical_bits() == 128


def test_sarif_never_emits_startline_zero():
    # Fix #7: a :0 locator must fall back to a whole-file location.
    loc = sarif_mod._parse_locator(AssetType.SOURCE, "app/x.py:0")
    assert "region" not in loc
    assert loc["artifactLocation"]["uri"] == "app/x.py:0"


def test_cli_skips_bad_tls_target_without_crashing():
    # Fix #8: a non-numeric port is skipped, not a fatal traceback.
    from cryptoscan import cli as _cli
    try:
        _cli._parse_target("example.com:https")
        assert False, "expected ValueError"
    except ValueError:
        pass
    # The full code path must not raise.
    assert _cli._run_tls(["example.com:https"]) == []


def test_parse_server_hello_rejects_truncated_extension():
    # Fix #2: an extension length past the buffer must not surface a group.
    import struct as _s
    from cryptoscan import tls13_probe as _t
    # key_share ext claims 100 bytes but only 2 follow.
    ksd = _s.pack(">H", 0x1234)
    ks = _s.pack(">HH", _t._EXT_KEY_SHARE, 100) + ksd
    body = (_s.pack(">H", 0x0303) + b"\x01" * 32 + b"\x00" +
            _s.pack(">H", 0x1301) + b"\x00" + _s.pack(">H", len(ks)) + ks)
    r = _t.parse_server_hello(body)
    assert r.error is not None
    assert r.selected_group is None
    assert r.negotiated_version is None


def test_parse_server_hello_never_raises_on_random_bytes():
    from cryptoscan import tls13_probe as _t
    for b in (b"", b"\x00", b"\xff" * 7, bytes(range(40)), b"\x03\x03" + b"\x00" * 5):
        r = _t.parse_server_hello(b)        # must not raise
        assert r is not None


def test_pom_parser_rejects_entity_expansion(tmp_path):
    # billion-laughs: a hostile pom.xml must not expand entities (DoS).
    (tmp_path / "pom.xml").write_text(
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE lolz [\n'
        ' <!ENTITY lol "lol">\n'
        ' <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
        ']>\n'
        '<project><dependencies><dependency>'
        '<artifactId>&lol2;</artifactId></dependency></dependencies></project>',
        encoding="utf-8")
    names = _cs._parse_pom(tmp_path / "pom.xml")
    assert names == []                      # DTD/entity -> refused, no expansion
    # A normal pom still parses.
    (tmp_path / "pom2.xml").write_text(
        '<project><dependencies><dependency>'
        '<artifactId>bcprov-jdk18on</artifactId>'
        '</dependency></dependencies></project>', encoding="utf-8")
    assert _cs._parse_pom(tmp_path / "pom2.xml") == ["bcprov-jdk18on"]


# --- QAQC regression tests -------------------------------------------------

from cryptoscan import report as report_mod
from cryptoscan.mosca import MoscaParameters as _MP


def test_cbom_hybrid_nist_level_by_strength():
    def lvl(token):
        f = classify(token, AssetType.TLS_ENDPOINT, "h:443",
                     key_establishment=True)
        return cbom_mod._algorithm_component(f)["cryptoProperties"][
            "algorithmProperties"]["nistQuantumSecurityLevel"]
    assert lvl("secp384r1mlkem1024") == 5   # ML-KEM-1024 strength
    assert lvl("x25519mlkem768") == 3       # ML-KEM-768 strength
    assert lvl("secp256r1mlkem768") == 3
    assert lvl("ML-KEM") == 3               # generic -> recommended cat 3


def test_diff_escalating_move_is_regression():
    old = _envelope([classify("RSA", AssetType.SOURCE, "app.py:10")])  # HIGH
    nf = classify("RSA", AssetType.SOURCE, "app.py:55", key_establishment=True)
    new = _envelope([nf])                                              # CRITICAL+HNDL
    d = diff_mod.build_diff(old, new)
    assert d["verdict"] == diff_mod.REGRESSION
    assert d["counts"]["moved"] == 0
    assert diff_mod.diff_exit_code(d["verdict"]) == 2


def test_diff_plain_move_still_neutral():
    old = _envelope([classify("RSA", AssetType.SOURCE, "app.py:10")])
    new = _envelope([classify("RSA", AssetType.SOURCE, "app.py:55")])
    d = diff_mod.build_diff(old, new)
    assert d["counts"]["moved"] == 1
    assert d["verdict"] == diff_mod.NO_CHANGE


def test_diff_partial_verdict():
    old = _envelope([classify("MD5", AssetType.SOURCE, "x.py:1")])
    new = _envelope([classify("SHA-1", AssetType.SOURCE, "x.py:1")])
    d = diff_mod.build_diff(old, new)
    assert d["verdict"] == diff_mod.PARTIAL
    assert d["counts"]["introduced"] == 1 and d["counts"]["resolved"] == 1


def test_report_hndl_and_roadmap_sections():
    findings = [
        classify("ECDH", AssetType.TLS_ENDPOINT, "h:443", key_establishment=True),
        classify("MD5", AssetType.SOURCE, "a.py:1"),
        classify("AES-256", AssetType.TLS_ENDPOINT, "h:443"),
    ]
    md = report_mod.render(findings, "t")
    assert "Priority 0 — Harvest-now-decrypt-later" in md
    assert "Migration roadmap" in md
    # Worst severity first: ECDH (CRITICAL) roadmap entry precedes MD5 (HIGH).
    assert md.index("Replace ECDH") < md.index("Replace MD5")
    assert "Findings (severity-ranked)" in md


def test_report_empty_findings_says_no_migration():
    md = report_mod.render([], "t")
    assert "No quantum-vulnerable primitives requiring migration" in md
    assert "100/100" in md


def test_cli_code_scan_writes_all_artifacts(tmp_path):
    sample = Path(__file__).resolve().parents[1] / "sample-target"
    out = {k: str(tmp_path / f"o.{k}") for k in ("cbom", "report", "json", "sarif")}
    rc = cli_mod.main([
        "code", str(sample),
        "--cbom", out["cbom"], "--report", out["report"],
        "--json", out["json"], "--sarif", out["sarif"],
        "--mosca", "--fail-on", "none",
    ])
    assert rc == 0
    for p in out.values():
        assert Path(p).exists() and Path(p).stat().st_size > 0
    import json as _j
    assert "mosca" in _j.loads(Path(out["json"]).read_text(encoding="utf-8"))
    # Default gate trips on CRITICAL findings.
    assert cli_mod.main(["code", str(sample)]) == 2


def test_mosca_from_args_parses_overrides():
    import argparse
    ns = argparse.Namespace(z_scenario="low", secrecy_years=["secret=20"],
                            default_tier="top-secret", crqc_years=7,
                            migration_years=4)
    params, scenario = cli_mod._mosca_from_args(ns)
    assert scenario is ZScenario.LOW
    assert params.migration_years == 4
    assert params.default_tier is DataTier.TOP_SECRET
    assert params.secrecy_years[DataTier.SECRET] == 20
    assert params.crqc_years[ZScenario.LOW] == 7


def test_mosca_from_args_ignores_malformed_input():
    import argparse
    ns = argparse.Namespace(z_scenario="expected", secrecy_years=["bogus=x", "nope"],
                            default_tier="not-a-tier", crqc_years=None,
                            migration_years=None)
    params, scenario = cli_mod._mosca_from_args(ns)   # must not raise
    assert scenario is ZScenario.EXPECTED
    assert params.default_tier is DataTier.CONFIDENTIAL  # default preserved


def test_mosca_tolerates_partial_secrecy_dict():
    p = _MP(secrecy_years={DataTier.CONFIDENTIAL: 99})   # missing other tiers
    v = assess(_ecdh(extra={"data_tier": "transient"}), p, now_year=2026)
    assert v.x_secrecy_years == 1                        # falls back to default


def test_parse_target_variants():
    from cryptoscan.cli import _parse_target
    assert _parse_target("example.com") == ("example.com", 443)
    assert _parse_target("example.com:8443") == ("example.com", 8443)
    # Bracketed IPv6 keeps the default port (documented limitation).
    assert _parse_target("[::1]:443") == ("[::1]:443", 443)


def test_dependency_scan_skips_oversized_manifest(tmp_path):
    big = tmp_path / "requirements.txt"
    big.write_text("rsa\n" + ("# " + "a" * 2_000_010) + "\n", encoding="utf-8")
    fs = _cs.scan_dependencies(tmp_path)
    assert fs == []                                      # too big -> skipped


def test_sarif_conforms_to_sarif_2_1_0_schema():
    try:
        import json
        import urllib.request
        import jsonschema
    except ImportError:
        return
    try:
        schema = json.load(urllib.request.urlopen(
            "https://json.schemastore.org/sarif-2.1.0.json", timeout=20))
    except Exception:
        return  # offline — skip rather than fail the suite
    doc = sarif_mod.build_sarif(
        [classify("MD5", AssetType.SOURCE, "src/a.py:3"),
         classify("RSA", AssetType.DEPENDENCY, "requirements.txt -> node-rsa",
                  key_establishment=True)], "t")
    jsonschema.validate(doc, schema)


# --- SSH endpoint scanning -------------------------------------------------

from cryptoscan import ssh_scanner as _ssh


def _kexinit(kex, hostkey, enc, mac):
    def nl(items):
        s = ",".join(items).encode()
        return struct.pack(">I", len(s)) + s
    body = b"\x14" + b"\x00" * 16
    for lst in (kex, hostkey, enc, enc, mac, mac, ["none"], ["none"], [], []):
        body += nl(lst)
    return body + b"\x00" + struct.pack(">I", 0)


def test_every_ssh_algo_token_resolves():
    for algo, (token, _role, _ke) in _ssh.SSH_ALGO_MAP.items():
        assert lookup(token) is not None, (algo, token)


def test_ssh_kexinit_name_list_parse():
    p = _kexinit(["curve25519-sha256", "sntrup761x25519-sha512"],
                 ["ssh-ed25519"], ["aes256-ctr"], ["hmac-sha2-256"])
    lists = _ssh._name_lists(p)
    assert lists[0] == ["curve25519-sha256", "sntrup761x25519-sha512"]
    assert lists[1] == ["ssh-ed25519"] and lists[4] == ["hmac-sha2-256"]
    assert _ssh._name_lists(b"\x01nope") is None      # not a KEXINIT


def test_ssh_scan_classifies_offered_set(monkeypatch):
    obs = _ssh.SSHObservation(
        host="h", port=22, banner="SSH-2.0-OpenSSH_9.6",
        kex_algorithms=["sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
                        "diffie-hellman-group1-sha1", "ext-info-s",
                        "kex-strict-s-v00@openssh.com"],
        host_key_algorithms=["ssh-ed25519", "ssh-rsa"],
        encryption_algorithms=["chacha20-poly1305@openssh.com", "3des-cbc"],
        mac_algorithms=["hmac-sha2-256", "hmac-md5", "umac-128@openssh.com"])
    monkeypatch.setattr(_ssh, "probe", lambda *a, **k: obs)
    fs = _ssh.scan("h", 22)
    by = {(f.fact.name, f.extra.get("role")): f for f in fs}
    assert by[("SNTRUP761X25519", "kex")].severity() is Severity.INFO
    x = by[("X25519", "kex")]
    assert x.hndl_exposed() and x.severity() is Severity.CRITICAL
    assert by[("DH", "kex")].classical_weakness() is True        # group1 = 1024-bit
    assert ("RSA", "hostkey") in by and ("SHA-1", "hostkey-hash") in by
    assert ("3DES", "cipher") in by
    assert ("HMAC", "mac") in by and ("MD5", "mac") in by and ("UMAC", "mac") in by
    # Non-crypto KEXINIT markers are never scored.
    assert not any("ext-info" in f.evidence or "kex-strict" in f.evidence
                   for f in fs)


def test_ssh_pq_hybrids_are_safe():
    for token in ("SNTRUP761X25519", "MLKEM768NISTP256", "MLKEM1024NISTP384"):
        f = classify(token, AssetType.SSH_ENDPOINT, "h:22", key_establishment=True)
        assert f.fact.risk is QuantumRisk.SAFE and f.hndl_exposed() is False
    assert lookup("mlkem768x25519") is lookup("x25519mlkem768")


# --- PKI / certificate-file scanning ---------------------------------------

def test_pki_surfaces_key_agreement_key_files_as_hndl(tmp_path):
    # Crown-jewel HNDL: an X25519/X448/DH key file must NOT be silently dropped.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519, x448
    from cryptoscan import pki_scanner
    xk = x25519.X25519PrivateKey.generate()
    (tmp_path / "x.key").write_bytes(xk.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    fs = pki_scanner.scan(tmp_path)
    x = next((f for f in fs if f.fact.name == "X25519"), None)
    assert x is not None and x.hndl_exposed() is True
    # X448 key type is also recognized (no silent fall-through).
    assert pki_scanner._key_token(
        x448.X448PrivateKey.generate().public_key())[0] == "X448"


def test_ssh_rsa_cert_variant_flags_sha1(monkeypatch):
    obs = _ssh.SSHObservation(
        host="h", port=22,
        host_key_algorithms=["ssh-rsa-cert-v01@openssh.com"])
    monkeypatch.setattr(_ssh, "probe", lambda *a, **k: obs)
    pairs = {(f.fact.name, f.extra.get("role")) for f in _ssh.scan("h", 22)}
    assert ("RSA", "hostkey") in pairs
    assert ("SHA-1", "hostkey-hash") in pairs


def test_pki_scan_classifies_certs_and_keys(tmp_path):
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptoscan import pki_scanner

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak.example")])
    cert = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2026, 1, 1))
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    eck = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "s.key").write_bytes(eck.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    fs = pki_scanner.scan(tmp_path)
    pairs = {(f.fact.name, f.classical_weakness()) for f in fs}
    assert ("RSA", True) in pairs                  # RSA-1024 cert -> weak
    assert any(f.fact.name == "ECDSA" for f in fs)  # EC key file


# --- IPsec / IKEv2 endpoint scanning ---------------------------------------

from cryptoscan import ike_scanner as _ike


def _ike_response(transforms, *, flags=0x20):
    """Build an IKE_SA_INIT response with one chosen proposal (for parse tests).
    transforms: list of (ttype, tid, keybits|None)."""
    trs = b""
    for i, (tt, tid, kb) in enumerate(transforms):
        last = (i == len(transforms) - 1)
        attrs = struct.pack(">HH", 0x800E, kb) if kb else b""
        trs += struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs),
                           tt, 0, tid) + attrs
    prop = struct.pack(">BBHBBBB", 0, 0, 8 + len(trs), 1, 1, 0,
                       len(transforms)) + trs
    sa = struct.pack(">BBH", 0, 0, 4 + len(prop)) + prop
    hdr = struct.pack(">8s8sBBBBII", _ike._INIT_SPI, b"B" * 8, 33, 0x20, 34,
                      flags, 0, 28 + len(sa))
    return hdr + sa


def test_ike_tokens_resolve():
    toks = {t for t, _ in _ike.DH_GROUPS.values()}
    toks |= {v for v in _ike._ENCR.values() if v != "AES"}
    toks |= set(_ike._PRF.values()) | set(_ike._INTEG.values())
    for t in toks:
        assert lookup(t) is not None, t


def test_ike_build_request_is_valid():
    req = _ike.build_ike_sa_init()
    nxt, ver, exch, flags = struct.unpack_from(">xxxxxxxxxxxxxxxxBBBB", req, 0)
    assert nxt == 33 and ver == 0x20 and exch == 34 and flags == 0x08
    assert struct.unpack_from(">I", req, 24)[0] == len(req)   # length backfilled


def test_ike_parse_and_classify_negotiated_set(monkeypatch):
    # Responder chose: AES-256-GCM, HMAC-SHA2-256 PRF, HMAC-SHA2-256-128, Curve25519
    resp = _ike_response([(1, 20, 256), (2, 5, None), (3, 12, None), (4, 31, None)])
    o = _ike.parse_response(resp)
    assert o.is_response and o.encryption == ("AES", 256) and o.dh_group == 31
    monkeypatch.setattr(_ike, "probe", lambda *a, **k: _replace_host(o))
    by = {f.fact.name: f for f in _ike.scan("h", 500)}
    assert by["X25519"].hndl_exposed() and by["X25519"].severity() is Severity.CRITICAL
    assert by["AES-256"].fact.risk is QuantumRisk.SAFE
    assert "HMAC" in by


def _replace_host(o):
    o.host, o.port = "h", 500
    return o


def test_ike_weak_modp_group_is_classically_weak(monkeypatch):
    o = _ike.IKEObservation(host="h", port=500, is_response=True, dh_group=2)
    monkeypatch.setattr(_ike, "probe", lambda *a, **k: o)
    dh = next(f for f in _ike.scan("h", 500) if f.fact.name == "DH")
    assert dh.classical_weakness() is True       # MODP-1024 = 80-bit
    assert dh.severity() is Severity.CRITICAL


def test_ike_mlkem_group_is_pq_safe(monkeypatch):
    o = _ike.IKEObservation(host="h", port=500, is_response=True, dh_group=36)
    monkeypatch.setattr(_ike, "probe", lambda *a, **k: o)
    f = next(f for f in _ike.scan("h", 500) if f.fact.name == "ML-KEM")
    assert f.fact.risk is QuantumRisk.SAFE and f.hndl_exposed() is False


def test_ike_invalid_ke_payload_yields_preferred_group():
    # Notify(INVALID_KE_PAYLOAD=17) carrying preferred group 19 (ECP-256).
    nd = struct.pack(">H", 19)
    notify = struct.pack(">BBH", 0, 0, 17) + nd
    body = struct.pack(">BBH", 0, 0, 4 + len(notify)) + notify
    hdr = struct.pack(">8s8sBBBBII", _ike._INIT_SPI, b"B" * 8, 41, 0x20, 34,
                      0x20, 0, 28 + len(body))
    o = _ike.parse_response(hdr + body)
    assert o.notify == 17 and o.preferred_group == 19


def test_ike_rejects_non_response_and_unknown_cipher():
    # Rank 2: a request (INITIATOR flag, not RESPONSE) must be rejected.
    req = _ike.build_ike_sa_init()
    assert _ike.parse_response(req) is None
    # A response that doesn't echo our initiator SPI is rejected.
    bad_spi = _ike_response([(4, 31, None)])
    bad_spi = b"\x00" * 8 + bad_spi[8:]
    assert _ike.parse_response(bad_spi) is None
    # Rank 1: an unrecognized cipher (Camellia-CBC tid 23) must NOT become AES.
    resp = _ike_response([(1, 23, 256), (4, 31, None)])
    o = _ike.parse_response(resp)
    assert o.encryption == (None, 256)              # not mislabeled "AES"
    o.host, o.port = "h", 500
    import cryptoscan.ike_scanner as m
    saved = m.probe
    m.probe = lambda *a, **k: o
    try:
        names = {f.fact.name for f in _ike.scan("h", 500)}
    finally:
        m.probe = saved
    assert not any("AES" in n for n in names)       # no fabricated AES finding
    assert "X25519" in names                        # the real Curve25519 KEX is kept


def test_ike_parse_never_raises_on_garbage():
    for b in (b"", b"\x00" * 28, bytes(range(60)), b"\xff" * 40):
        _ike.parse_response(b)   # must not raise (returns None or an obs)


def test_ike_null_encryption_is_flagged(monkeypatch):
    o = _ike.IKEObservation(host="h", port=500, is_response=True,
                            encryption=("null", None))
    monkeypatch.setattr(_ike, "probe", lambda *a, **k: o)
    f = next(f for f in _ike.scan("h", 500) if "NULL" in f.fact.name)
    assert f.severity() is Severity.HIGH        # plaintext IPsec


if __name__ == "__main__":
    import inspect
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = skipped = 0
    for fn in fns:
        if inspect.signature(fn).parameters:
            print(f"SKIP {fn.__name__} (needs a pytest fixture; run under pytest)")
            skipped += 1
            continue
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    runnable = len(fns) - skipped
    print(f"\n{passed}/{runnable} passed ({skipped} skipped — run under pytest)")
    raise SystemExit(0 if passed == runnable else 1)
