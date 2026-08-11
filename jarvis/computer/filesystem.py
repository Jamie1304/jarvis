"""Limited, adapter-backed filesystem integration for brokered tools."""

import asyncio
from abc import ABC, abstractmethod
from pathlib import Path


class FilesystemAdapter(ABC):
    @abstractmethod
    async def read_text(self, normalized_path: str, max_characters: int) -> str:
        """Read bounded text from a path already normalized by the permission broker."""


class LocalFilesystemAdapter(FilesystemAdapter):
    """Local text reader; callers must pass a broker-authorized canonical path."""

    async def read_text(self, normalized_path: str, max_characters: int) -> str:
        return await asyncio.to_thread(self._read_text, normalized_path, max_characters)

    @staticmethod
    def _read_text(normalized_path: str, max_characters: int) -> str:
        with Path(normalized_path).open("r", encoding="utf-8") as source:
            return source.read(max_characters)
