"""Controlled non-shell command execution for explicitly cataloged executables."""

import asyncio
import os
from abc import ABC, abstractmethod
from collections.abc import Mapping
from pathlib import Path

from jarvis.computer.models import CommandDefinition, CommandExecution

_MAX_OUTPUT_CHARACTERS = 16_384


class CommandAdapter(ABC):
    @abstractmethod
    async def execute(
        self,
        command: CommandDefinition,
        arguments: tuple[str, ...],
        working_directory: str,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> CommandExecution:
        """Execute one already-cataloged command without a shell."""


class SubprocessCommandAdapter(CommandAdapter):
    """Windows-compatible process adapter using create_subprocess_exec only."""

    async def execute(
        self,
        command: CommandDefinition,
        arguments: tuple[str, ...],
        working_directory: str,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> CommandExecution:
        try:
            executable = Path(command.executable)
            working_root = Path(working_directory).resolve(strict=True)
            trusted_executable = executable.resolve(strict=True)
        except (OSError, RuntimeError):
            return CommandExecution(
                None, "", "Trusted command identity is unavailable", rejected=True
            )
        if (
            not executable.is_absolute()
            or not trusted_executable.is_file()
            or not working_root.is_dir()
        ):
            return CommandExecution(None, "", "Trusted command identity is invalid", rejected=True)
        process = await asyncio.create_subprocess_exec(
            os.fspath(trusted_executable),
            *arguments,
            cwd=os.fspath(working_root),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_trusted_subprocess_environment(),
        )
        communication = asyncio.create_task(process.communicate())
        cancellation_wait = asyncio.create_task(cancellation.wait())
        try:
            done, _ = await asyncio.wait(
                {communication, cancellation_wait},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if communication in done:
                stdout, stderr = await communication
                return CommandExecution(
                    exit_code=process.returncode,
                    stdout=self._decode(stdout),
                    stderr=self._decode(stderr),
                )
            if cancellation_wait in done:
                stdout, stderr = await self._terminate(process, communication)
                return CommandExecution(
                    exit_code=process.returncode,
                    stdout=self._decode(stdout),
                    stderr=self._decode(stderr),
                    cancelled=True,
                )
            stdout, stderr = await self._terminate(process, communication)
            return CommandExecution(
                exit_code=process.returncode,
                stdout=self._decode(stdout),
                stderr=self._decode(stderr),
                timed_out=True,
            )
        except asyncio.CancelledError:
            await self._terminate(process, communication)
            raise
        finally:
            if not cancellation_wait.done():
                cancellation_wait.cancel()
            await asyncio.gather(cancellation_wait, return_exceptions=True)

    @staticmethod
    async def _terminate(
        process: asyncio.subprocess.Process,
        communication: asyncio.Task[tuple[bytes, bytes]],
    ) -> tuple[bytes, bytes]:
        if process.returncode is None:
            process.kill()
        return await communication

    @staticmethod
    def _decode(value: bytes) -> str:
        return value.decode("utf-8", errors="replace")[:_MAX_OUTPUT_CHARACTERS]


class ControlledCommandService:
    """Resolves a trusted command ID before delegating to the no-shell adapter."""

    def __init__(
        self,
        commands: Mapping[str, CommandDefinition],
        adapter: CommandAdapter | None = None,
    ) -> None:
        self._commands = dict(commands)
        self._adapter = adapter or SubprocessCommandAdapter()

    def describe(self, command_id: str) -> CommandDefinition | None:
        return self._commands.get(command_id)

    async def execute(
        self,
        command_id: str,
        arguments: tuple[str, ...],
        working_directory: str,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> CommandExecution:
        command = self.describe(command_id)
        if command is None:
            return CommandExecution(
                exit_code=None,
                stdout="",
                stderr="Command ID is not in the trusted catalog",
                rejected=True,
            )
        if arguments not in command.allowed_argument_sequences:
            return CommandExecution(
                exit_code=None,
                stdout="",
                stderr="Arguments are not permitted for the trusted command",
                rejected=True,
            )
        return await self._adapter.execute(
            command,
            arguments,
            working_directory,
            timeout_seconds,
            cancellation,
        )


def _trusted_subprocess_environment() -> dict[str, str]:
    """Pass only OS process essentials; never ambient credentials or Python hooks."""

    allowed = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    return environment
