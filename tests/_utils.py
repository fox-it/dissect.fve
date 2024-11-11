import gzip
from pathlib import Path
from typing import BinaryIO, Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str) -> Iterator[BinaryIO]:
    with absolute_path(name).open("rb") as f:
        yield f


def open_file_gz(name: str) -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), "rb") as f:
        yield f
