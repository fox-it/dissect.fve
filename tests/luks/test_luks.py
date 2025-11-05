from __future__ import annotations

import contextlib
from typing import BinaryIO

import pytest

from dissect.fve.crypto import argon2
from dissect.fve.luks.luks import LUKS, derive_passphrase_key
from dissect.fve.luks.metadata import Keyslot
from tests._util import open_file_gz


def _verify_crypto_stream(luks_obj: LUKS) -> None:
    stream = luks_obj.open()
    for i in range(4):
        assert stream.read(512) == bytes([i] * 512)


def _verify_passphrase_crypto(test_file: BinaryIO, passphrase: str, cipher_type: str) -> None:
    luks_obj = LUKS(test_file)

    assert not luks_obj.unlocked
    assert luks_obj.keyslots

    try:
        luks_obj.unlock_with_passphrase(passphrase)
    except ValueError as e:
        if "Hashing failed: out of memory" in str(e):
            pytest.skip("Argon2 failed due to insufficient memory, skipping")
        raise

    assert luks_obj.find_segment(luks_obj._active_keyslot_id).encryption == cipher_type
    _verify_crypto_stream(luks_obj)


@pytest.mark.parametrize(
    ("test_file", "password", "cipher"),
    [
        pytest.param("_data/luks1/aes-ecb.bin.gz", "password", "aes-ecb", id="luks1-aes-ecb"),
        pytest.param("_data/luks1/sha1.bin.gz", "password", "aes-ecb", id="luks1-aes-ecb-sha1"),
        pytest.param("_data/luks2/aes-cbc-plain.bin.gz", "password", "aes-cbc-plain", id="luks2-aes-cbc-plain"),
        pytest.param("_data/luks2/aes-cbc-essiv.bin.gz", "password", "aes-cbc-essiv:sha256", id="luks2-aes-cbc-essiv"),
        pytest.param("_data/luks2/aes-ecb-pbkdf2.bin.gz", "password", "aes-ecb", id="luks2-aes-ecb-pbkdf2"),
        pytest.param("_data/luks2/aes-xts-plain64.bin.gz", "password", "aes-xts-plain64", id="luks2-aes-xts-plain64"),
        pytest.param("_data/luks2/multiple-slots.bin.gz", "password", "aes-cbc-plain", id="luks2-multiple-slots-1"),
        pytest.param("_data/luks2/multiple-slots.bin.gz", "another", "aes-cbc-plain", id="luks2-multiple-slots-2"),
    ],
)
def test_luks(test_file: str, password: str, cipher: str, request: pytest.FixtureRequest) -> None:
    if (
        request.node.callspec.id
        in (
            "luks2-aes-cbc-plain",
            "luks2-aes-cbc-essiv",
            "luks2-aes-xts-plain64",
            "luks2-multiple-slots-1",
            "luks2-multiple-slots-2",
        )
        and not argon2.HAS_ARGON2
    ):
        pytest.skip("Argon2 is not available, skipping")

    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_passphrase_crypto(fh, password, cipher)


def test_luks_kdf_pbkdf2() -> None:
    keyslot = Keyslot.from_dict(
        {
            "type": "luks2",
            "key_size": 32,
            "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            "area": {"type": "raw", "offset": "32768", "size": "131072", "encryption": "aes-ecb", "key_size": 32},
            "kdf": {
                "type": "pbkdf2",
                "hash": "sha256",
                "iterations": 3426718,
                "salt": "fmh2v7DaJ2D/tFkvvGB+mogBu3s+tUpDuKaf0vQyqIA=",
            },
        }
    )

    assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
        "05cff19a3cbc2d5612bdbcaee94db532b95b2cd33a997d1f2b30ffb166f302a6"
    )


@pytest.mark.skipif(not argon2.HAS_ARGON2, reason="Argon2 is not available, skipping")
def test_luks_kdf_argon2i() -> None:
    keyslot = Keyslot.from_dict(
        {
            "type": "luks2",
            "key_size": 32,
            "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            "area": {"type": "raw", "offset": "32768", "size": "131072", "encryption": "aes-ecb", "key_size": 32},
            "kdf": {
                "type": "argon2i",
                "time": 5,
                "memory": 1048576,
                "cpus": 4,
                "salt": "fsv0tZWR6Q/WkidkWY6p0jiP1A+am8CH8h3D8gYEoYE=",
            },
        }
    )

    try:
        assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
            "37f6085467d330749f59ea348491908a4faddabcb67523efc649419ecb52bd94"
        )
    except ValueError as e:
        if "Hashing failed: out of memory" in str(e):
            pytest.skip("Argon2 failed due to insufficient memory, skipping")
        raise


@pytest.mark.skipif(not argon2.HAS_ARGON2, reason="Argon2 is not available, skipping")
def test_luks_kdf_argon2id() -> None:
    keyslot = Keyslot.from_dict(
        {
            "type": "luks2",
            "key_size": 32,
            "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            "area": {"type": "raw", "offset": "32768", "size": "131072", "encryption": "aes-ecb", "key_size": 32},
            "kdf": {
                "type": "argon2id",
                "time": 5,
                "memory": 1048576,
                "cpus": 4,
                "salt": "yssVZKHcjdSON4vM096WRyzZBWfz5Pf+a08cRzPdcZg=",
            },
        }
    )

    try:
        assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
            "15b7b31551e6df90e6dbc58bb5dbc5f82efa8f36fdab9422f8a9bdfa72a8af85"
        )
    except ValueError as e:
        if "Hashing failed: out of memory" in str(e):
            pytest.skip("Argon2 failed due to insufficient memory, skipping")
        raise
