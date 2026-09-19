from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_project_declares_custom_proprietary_license_and_documents() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata["project"]

    assert project["license"] == "LicenseRef-JARVIS-Proprietary"
    assert project["license-files"] == ["LICENSE.txt", "EULA.txt", "PRIVACY_POLICY.txt"]
    assert (ROOT / "LICENSE.txt").is_file()
    assert (ROOT / "EULA.txt").is_file()
    assert (ROOT / "PRIVACY_POLICY.txt").is_file()
    assert "JARVIS PROPRIETARY SOFTWARE LICENSE" in (ROOT / "LICENSE.txt").read_text(
        encoding="utf-8"
    )
    assert "JARVIS END USER LICENSE AGREEMENT" in (ROOT / "EULA.txt").read_text(encoding="utf-8")
    assert "JARVIS PRIVACY POLICY" in (ROOT / "PRIVACY_POLICY.txt").read_text(encoding="utf-8")


def test_legal_documents_have_no_unresolved_owner_placeholders() -> None:
    license_text = (ROOT / "LICENSE.txt").read_text(encoding="utf-8")
    eula_text = (ROOT / "EULA.txt").read_text(encoding="utf-8")
    privacy_text = (ROOT / "PRIVACY_POLICY.txt").read_text(encoding="utf-8")
    all_text = license_text + eula_text + privacy_text

    assert "[LICENSOR LEGAL NAME]" not in all_text
    assert "[COPYRIGHT YEAR]" not in license_text + eula_text
    assert "[CONTACT EMAIL]" not in eula_text
    assert "[GOVERNING LAW]" not in eula_text
    assert "[COURTS / JURISDICTION]" not in eula_text
    assert "[LIABILITY CAP / COMMERCIAL POLICY TO BE CONFIRMED]" not in eula_text
    assert "intentionally not published" in (eula_text + privacy_text).lower()


def test_first_party_metadata_does_not_claim_an_open_source_license() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    classifiers = metadata["project"].get("classifiers", [])
    assert not any("License :: OSI Approved" in classifier for classifier in classifiers)
