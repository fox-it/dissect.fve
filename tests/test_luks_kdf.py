from __future__ import annotations

from dissect.fve.luks.luks import derive_passphrase_key
from dissect.fve.luks.metadata import Keyslot


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

    assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
        "37f6085467d330749f59ea348491908a4faddabcb67523efc649419ecb52bd94"
    )


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

    assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
        "15b7b31551e6df90e6dbc58bb5dbc5f82efa8f36fdab9422f8a9bdfa72a8af85"
    )
