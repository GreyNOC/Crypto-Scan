"""Tests for the release-helper scripts under packaging/.

Loaded by file path via importlib because the directory name `packaging`
collides with the installed pip `packaging` library.
"""

import importlib.util
import sys
import tarfile
import zipfile
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1] / "packaging"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"_pkg_{name}", _PKG / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


changelog_section = _load("changelog_section")
make_archive = _load("make_archive")

_SAMPLE = """# Changelog

## [0.2.1] — patch
patch body line.

## [0.2.10] — later
ten body.

## [0.2.0] — first
first body.
"""


def test_changelog_section_extracts_exact_version():
    assert changelog_section.section("0.2.1", _SAMPLE).strip() == "patch body line."
    assert changelog_section.section("0.2.0", _SAMPLE).strip() == "first body."


def test_changelog_section_no_substring_collision():
    # '0.2.1' must NOT return the '[0.2.10]' body.
    assert "ten body" not in changelog_section.section("0.2.1", _SAMPLE)


def test_changelog_section_missing_version_returns_none():
    assert changelog_section.section("9.9.9", _SAMPLE) is None


def test_make_archive_round_trips(tmp_path):
    src = tmp_path / "payload"
    src.mkdir()
    (src / "gs").write_text("binary", encoding="utf-8")
    (src / "README.txt").write_text("notes", encoding="utf-8")

    zip_path = make_archive.shutil.make_archive(
        str(tmp_path / "out"), "zip", root_dir=str(src))
    assert set(zipfile.ZipFile(zip_path).namelist()) >= {"gs", "README.txt"}

    tar_path = make_archive.shutil.make_archive(
        str(tmp_path / "out2"), "gztar", root_dir=str(src))
    with tarfile.open(tar_path) as tf:
        assert {"./gs", "./README.txt"} <= set(tf.getnames()) or \
               {"gs", "README.txt"} <= set(tf.getnames())


def test_make_archive_main_bad_args_returns_2(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["make_archive.py", "only-one-arg"])
    assert make_archive.main() == 2
