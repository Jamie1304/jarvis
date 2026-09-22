"""Build and smoke-test JARVIS from distribution artifacts only."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path
from textwrap import dedent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LEGAL_FILES = ("LICENSE.txt", "EULA.txt", "PRIVACY_POLICY.txt")


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, env=env, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def _ensure_build_tool(tool_dir: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tool_dir)
    # Keep the frontend deterministic and separate from the caller's
    # site-packages.  The project build backend is intentionally resolved by
    # normal PEP 517 isolation from pyproject.toml below.
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--quiet",
            "--target",
            str(tool_dir),
            "build==1.2.2",
        ],
        cwd=PROJECT_ROOT,
    )
    return environment


def _python(venv_root: Path) -> Path:
    executable = venv_root / "Scripts" / "python.exe"
    if not executable.is_file():
        raise RuntimeError("fresh virtual environment did not contain Python")
    return executable


def _audit_legal_metadata(wheel: Path, sdist: Path) -> None:
    """Require the built artifacts to carry the first-party legal metadata."""
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        dist_info = next(
            name.removesuffix("METADATA") for name in names if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(f"{dist_info}METADATA").decode("utf-8")
        for filename in _LEGAL_FILES:
            if f"{dist_info}licenses/{filename}" not in names:
                raise RuntimeError(f"wheel omitted legal file: {filename}")
            if f"License-File: {filename}" not in metadata:
                raise RuntimeError(f"wheel metadata omitted License-File: {filename}")
        if "License-Expression: LicenseRef-JARVIS-Proprietary" not in metadata:
            raise RuntimeError("wheel metadata omitted the proprietary license expression")
        if "License: MIT" in metadata or "License: Apache" in metadata:
            raise RuntimeError("wheel metadata contains a contradictory first-party license")

    with tarfile.open(sdist) as archive:
        names = set(archive.getnames())
        root = sdist.stem.removesuffix(".tar")
        for filename in _LEGAL_FILES:
            if f"{root}/{filename}" not in names:
                raise RuntimeError(f"sdist omitted legal file: {filename}")


def _installed_record_integrity_smoke() -> str:
    """Return an installed-only negative smoke for the full RECORD validator."""

    return dedent(
        """
        from importlib import metadata
        from pathlib import Path

        from jarvis.security.startup import (
            InstalledDistributionIntegrityEvidenceProvider,
            IntegrityEvidenceError,
        )

        provider = InstalledDistributionIntegrityEvidenceProvider()
        provider.validate()
        distribution = metadata.distribution("jarvis")
        root = Path(distribution.locate_file(""))
        dist_info = next(
            child for child in root.iterdir()
            if child.is_dir()
            and child.name.casefold().endswith(".dist-info")
            and (child / "METADATA").is_file()
            and "Name: jarvis" in (child / "METADATA").read_text(encoding="utf-8")
        )
        record = dist_info / "RECORD"

        def must_reject(label, mutate, restore):
            provider.validate()
            mutate()
            try:
                provider.validate()
            except IntegrityEvidenceError:
                pass
            else:
                raise AssertionError(f"installed RECORD regression accepted: {label}")
            finally:
                restore()
            provider.validate()

        noncritical = root / "jarvis" / "adoption.py"
        original_noncritical = noncritical.read_bytes()
        must_reject(
            "noncritical member mutation",
            lambda: noncritical.write_bytes(original_noncritical + b"\\n# record-smoke\\n"),
            lambda: noncritical.write_bytes(original_noncritical),
        )

        must_reject(
            "noncritical member deletion",
            noncritical.unlink,
            lambda: noncritical.write_bytes(original_noncritical),
        )

        trusted_core = root / "jarvis" / "security" / "integrity.py"
        original_trusted_core = trusted_core.read_bytes()
        must_reject(
            "trusted-core member deletion",
            trusted_core.unlink,
            lambda: trusted_core.write_bytes(original_trusted_core),
        )

        installer = dist_info / "INSTALLER"
        original_installer = installer.read_bytes()
        must_reject(
            "INSTALLER content mutation",
            lambda: installer.write_bytes(original_installer + b"record-smoke\\n"),
            lambda: installer.write_bytes(original_installer),
        )

        metadata_file = dist_info / "METADATA"
        original_metadata = metadata_file.read_bytes()
        must_reject(
            "METADATA content mutation",
            lambda: metadata_file.write_bytes(original_metadata + b"\\nX-Record-Smoke: 1\\n"),
            lambda: metadata_file.write_bytes(original_metadata),
        )

        legal_file = dist_info / "licenses" / "LICENSE.txt"
        original_legal = legal_file.read_bytes()
        must_reject(
            "legal metadata mutation",
            lambda: legal_file.write_bytes(original_legal + b"\\nrecord-smoke\\n"),
            lambda: legal_file.write_bytes(original_legal),
        )

        original_record = record.read_bytes()
        def tamper_installer_record():
            rows = record.read_text(encoding="utf-8").splitlines()
            replacement = []
            changed = False
            for row in rows:
                if row.startswith(f"{dist_info.name}/INSTALLER,sha256="):
                    replacement.append(f"{dist_info.name}/INSTALLER,sha256={'A' * 43},4")
                    changed = True
                else:
                    replacement.append(row)
            if not changed:
                raise AssertionError("installed wheel did not record INSTALLER")
            record.write_text("\\n".join(replacement) + "\\n", encoding="utf-8")
        must_reject(
            "INSTALLER RECORD hash only",
            tamper_installer_record,
            lambda: record.write_bytes(original_record),
        )

        def tamper_installer_size():
            rows = record.read_text(encoding="utf-8").splitlines()
            replacement = []
            changed = False
            for row in rows:
                if row.startswith(f"{dist_info.name}/INSTALLER,sha256="):
                    replacement.append(row.rsplit(",", 1)[0] + ",999999")
                    changed = True
                else:
                    replacement.append(row)
            if not changed:
                raise AssertionError("installed wheel did not record INSTALLER")
            record.write_text("\\n".join(replacement) + "\\n", encoding="utf-8")
        must_reject(
            "INSTALLER RECORD size only",
            tamper_installer_size,
            lambda: record.write_bytes(original_record),
        )

        def remove_noncritical_record_row():
            record.write_text(
                "\\n".join(
                    row for row in record.read_text(encoding="utf-8").splitlines()
                    if not row.startswith("jarvis/adoption.py,")
                ) + "\\n",
                encoding="utf-8",
            )
        must_reject(
            "RECORD row removal",
            remove_noncritical_record_row,
            lambda: record.write_bytes(original_record),
        )

        must_reject(
            "fake RECORD row",
            lambda: record.write_text(
                record.read_text(encoding="utf-8")
                + "jarvis/_record_smoke_fake.py,sha256=" + "A" * 43 + ",1\\n",
                encoding="utf-8",
            ),
            lambda: record.write_bytes(original_record),
        )

        must_reject(
            "malformed RECORD",
            lambda: record.write_text("not,a,valid,record\\n", encoding="utf-8"),
            lambda: record.write_bytes(original_record),
        )

        extra = root / "jarvis" / "_record_smoke_extra.py"
        must_reject(
            "unrecorded package member",
            lambda: extra.write_text("extra = True\\n", encoding="utf-8"),
            lambda: extra.unlink(missing_ok=True),
        )

        cache = root / "jarvis" / "__pycache__"
        cache.mkdir(exist_ok=True)
        allowed_pyc = cache / "adoption.cpython-312.pyc"
        original_allowed_pyc = allowed_pyc.read_bytes() if allowed_pyc.exists() else None
        allowed_pyc.write_bytes(b"synthetic-bytecode")
        provider.validate()
        if original_allowed_pyc is None:
            allowed_pyc.unlink()
        else:
            allowed_pyc.write_bytes(original_allowed_pyc)
        disallowed_pyc = cache / "unknown.cpython-312.pyc"
        must_reject(
            "unrelated bytecode cache",
            lambda: disallowed_pyc.write_bytes(b"synthetic-bytecode"),
            lambda: disallowed_pyc.unlink(missing_ok=True),
        )

        class VersionMismatchDistribution:
            version = "0.0.0"

            def locate_file(self, path):
                return distribution.locate_file(path)

        try:
            InstalledDistributionIntegrityEvidenceProvider(
                lambda _name: VersionMismatchDistribution()
            ).validate()
        except IntegrityEvidenceError:
            pass
        else:
            raise AssertionError("installed version mismatch was accepted")
        print("installed wheel full RECORD integrity tamper matrix: PASS")
        """
    )


def _artifact_smoke(wheel: Path, root: Path, label: str) -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"
    venv_root = root / f"venv-{label}"
    state_root = root / f"state-{label}"
    working_root = root / f"cwd-{label}"
    state_root.mkdir()
    working_root.mkdir()
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_root)
    python = _python(venv_root)
    _run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--quiet",
            str(wheel),
        ],
        cwd=working_root,
        env=environment,
    )
    smoke = (
        "import asyncio; import os; from pathlib import Path; import jarvis; "
        "from jarvis.credentials import TestOnlyInMemorySecretBackend; "
        "from jarvis.runtime import ApplicationRuntime, RuntimeStatus; "
        "assert jarvis.__version__ == '1.0.0'; "
        f"assert Path(jarvis.__file__).resolve().is_relative_to(Path(r'{PROJECT_ROOT}')) is False; "
        f"os.environ.update(JARVIS_ENVIRONMENT='production', JARVIS_APP_DATA_DIR=r'{state_root}', "
        "JARVIS_AI_PROVIDER='ollama'); "
        "runtime = ApplicationRuntime.create_from_environment("
        "recovery_key_backend=TestOnlyInMemorySecretBackend(), "
        "); "
        "assert runtime.status is RuntimeStatus.READY, runtime.error; "
        "assert runtime.container is not None; "
        "asyncio.run(runtime.aclose()); asyncio.run(runtime.aclose())"
    )
    _run([str(python), "-c", smoke], cwd=working_root, env=environment)
    _run(
        [str(python), "-c", _installed_record_integrity_smoke()],
        cwd=working_root,
        env=environment,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jarvis-package-smoke-") as temporary:
        root = Path(temporary)
        artifacts = root / "artifacts"
        tools = root / "build-tools"
        source_for_sdist = root / "sdist-source"
        artifacts.mkdir()
        tools.mkdir()
        source_for_sdist.mkdir()
        environment = _ensure_build_tool(tools)
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--sdist",
                "--outdir",
                str(artifacts),
                str(PROJECT_ROOT),
            ],
            cwd=PROJECT_ROOT,
            env=environment,
        )
        wheel = artifacts / "jarvis-1.0.0-py3-none-any.whl"
        sdist = artifacts / "jarvis-1.0.0.tar.gz"
        if not wheel.is_file() or not sdist.is_file():
            raise RuntimeError("wheel or sdist was not produced")
        _audit_legal_metadata(wheel, sdist)
        with zipfile.ZipFile(wheel) as archive:
            wheel_entry_count = len(archive.infolist())
        print(
            f"wheel: {wheel.name} size={wheel.stat().st_size} "
            f"sha256={hashlib.sha256(wheel.read_bytes()).hexdigest().upper()} "
            f"entries={wheel_entry_count}"
        )
        print(
            f"sdist: {sdist.name} size={sdist.stat().st_size} "
            f"sha256={hashlib.sha256(sdist.read_bytes()).hexdigest().upper()}"
        )
        _artifact_smoke(wheel, root, "wheel")
        print("wheel artifact-only production composition: PASS")

        with tarfile.open(sdist) as archive:
            archive.extractall(source_for_sdist, filter="data")
        extracted = source_for_sdist / "jarvis-1.0.0"
        sdist_artifacts = root / "sdist-artifacts"
        sdist_artifacts.mkdir()
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--outdir",
                str(sdist_artifacts),
                str(extracted),
            ],
            cwd=source_for_sdist,
            env=environment,
        )
        sdist_wheel = sdist_artifacts / "jarvis-1.0.0-py3-none-any.whl"
        if not sdist_wheel.is_file():
            raise RuntimeError("sdist wheel was not produced")
        _audit_legal_metadata(sdist_wheel, sdist)
        print(
            f"sdist-roundtrip wheel: {sdist_wheel.name} size={sdist_wheel.stat().st_size} "
            f"sha256={hashlib.sha256(sdist_wheel.read_bytes()).hexdigest().upper()}"
        )
        _artifact_smoke(sdist_wheel, root, "sdist")
        print("sdist round-trip artifact-only production composition: PASS")
        print("package artifact smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
