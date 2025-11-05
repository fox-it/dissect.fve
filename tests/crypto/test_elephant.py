from __future__ import annotations

import hashlib

from dissect.fve.crypto import elephant


def test_crypto_elephant_diffuser_a() -> None:
    buffer = bytearray(b"a" * 512)
    view = memoryview(buffer)

    elephant.diffuser_a_encrypt(view, 512)

    assert hashlib.sha256(buffer).hexdigest() == "f58aa15c1219f893c4ed355d363d8f831bcc0c4a82c6bbffcca321aada9e86ec"

    elephant.diffuser_a_decrypt(view, 512)

    assert buffer == b"a" * 512


def test_crypto_elephant_diffuser_b() -> None:
    buffer = bytearray(b"a" * 512)
    view = memoryview(buffer)

    elephant.diffuser_b_encrypt(view, 512)

    assert hashlib.sha256(buffer).hexdigest() == "1d5a51ae0d0b6309f1f8661376af9ebd880b1274601f6841f5aaeb5273580133"

    elephant.diffuser_b_decrypt(view, 512)

    assert buffer == b"a" * 512
