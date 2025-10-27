from __future__ import annotations

import io
from typing import BinaryIO

from dissect.util.stream import AlignedStream

from dissect.fve.crypto import create_cipher


class CryptStream(AlignedStream):
    """Transparently decrypting stream.

    Args:
        fh: The original file-like object, usually the encrypted disk.
        cipher: The cipher name/specification.
        key: The encryption key.
        key_size: Optional key size hint.
        offset: Optional base offset to the encrypted region. Segment offset in LUKS.
        size: Optional size hint. If ``None`` or ``"dynamic"``, determine the size by seeking to the end of ``fh``.
        iv_tweak: Optional IV tweak, or offset.
        sector_size: Optional sector size. Defaults to 512.
    """

    def __init__(
        self,
        fh: BinaryIO,
        cipher: str,
        key: bytes,
        key_size: int | None = None,
        offset: int = 0,
        size: int | str | None = None,
        iv_tweak: int = 0,
        sector_size: int = 512,
    ):
        self.fh = fh
        self.cipher = create_cipher(cipher, key, key_size or len(key) * 8, sector_size, 512)
        self.offset = offset
        self.iv_tweak = iv_tweak
        self.sector_size = sector_size

        if size in (None, "dynamic"):
            size = fh.seek(0, io.SEEK_END) - offset

        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buf = bytearray(self.fh.read(length))
        self.cipher.decrypt(buf, (offset // 512) + self.iv_tweak, buf)
        return bytes(buf)
