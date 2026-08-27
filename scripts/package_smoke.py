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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LEGAL_FILES = ("LICENSE.txt", "EULA.txt", "PRIVACY_POLICY.txt")


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, env=env, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def _ensure_build_tool(tool_dir: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tool_dir)
    try:
        __import__("build")
    except ImportError:
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
                "--no-isolation",
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
                "--no-isolation",
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
