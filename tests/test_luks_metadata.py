from __future__ import annotations

from dissect.fve.luks.metadata import Metadata


def test_luks_metadata() -> None:
    obj = {
        "keyslots": {
            "0": {
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
        },
        "tokens": {},
        "segments": {
            "0": {
                "type": "crypt",
                "offset": "16777216",
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": "aes-ecb",
                "sector_size": 512,
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": ["0"],
                "segments": ["0"],
                "hash": "sha256",
                "iterations": 217366,
                "salt": "uvTVgMNRd82F6+o5onDIqPtlqNb7N2Ah8ygqPUiK7k0=",
                "digest": "DChjy4pamOC06wmGlIJFzZk2hZgocGQ+BXumiMRTlRU=",
            }
        },
        "config": {"json_size": "12288", "keyslots_size": "16744448"},
    }

    assert Metadata.from_dict(obj)
