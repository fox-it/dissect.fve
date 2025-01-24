from __future__ import annotations

import hashlib

from dissect.fve.crypto.utils import xor

DIGEST_SIZE = {
    "sha1": 20,
    "sha256": 32,
}


def _hash(buf: bytes, hash: str, iv: int) -> bytes:
    ctx = hashlib.new(hash)
    ctx.update((iv & 0xFFFFFFFF).to_bytes(4, "big"))
    ctx.update(buf)
    return ctx.digest()


def diffuse(buf: bytes, hash: str) -> bytes:
    buf_size = len(buf)
    digest_size = DIGEST_SIZE[hash]

    view = memoryview(buf)
    result = bytearray(buf_size)

    passes, remainder = divmod(buf_size, digest_size)

    for i in range(passes):
        result[i * digest_size : (i + 1) * digest_size] = _hash(view[i * digest_size : (i + 1) * digest_size], hash, i)

    if remainder:
        result[passes * digest_size : buf_size] = _hash(view[buf_size - remainder : buf_size], hash, passes)[:remainder]

    return bytes(result)


def merge(buf: bytes, block_size: int, block_num: int, hash: str) -> bytes:
    if block_size * block_num > len(buf):
        raise ValueError(f"Unexpected input buffer size ({block_size} * {block_num} != {len(buf)})")

    tmp = bytearray(block_size)
    view = memoryview(buf)

    for i in range(block_num - 1):
        block = view[i * block_size : (i + 1) * block_size]
        xor(block, tmp, output=tmp)
        tmp[:] = diffuse(tmp, hash)

    xor(view[(block_num - 1) * block_size : block_num * block_size], tmp, output=tmp)
    return bytes(tmp)
