from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str) -> Iterator[BinaryIO]:
    with absolute_path(name).open("rb") as fh:
        yield fh


def open_file_gz(name: str) -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), "rb") as fh:
        yield fh
