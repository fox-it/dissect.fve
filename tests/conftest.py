from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import pytest

from tests._utils import open_file_gz

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def bde_aes_128() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bde/aes_128.bin.gz")


@pytest.fixture
def bde_decrypted() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bde/decrypted.bin.gz")


@pytest.fixture
def bde_suspended() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bde/suspended.bin.gz")


@pytest.fixture
def bde_vista() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bde/vista.bin.gz")


@pytest.fixture
def bde_win7_partial() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bde/win7_partial.bin.gz")


@pytest.fixture
def bde_eow_partial() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bde/eow_partial.bin.gz")
