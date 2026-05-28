from __future__ import annotations

from typing import BinaryIO

from dissect.util.stream import RangeStream

from dissect.fve.crypto.dmcrypt import CryptStream


class CryptoImplementation:
    __type__: str

    def __init__(self, key: bytes, fh: BinaryIO, offset: int, size: int | None) -> None:
        self.key = key
        self.fh = fh
        self.offset = offset
        self.size = size

    def open(self) -> CryptStream:
        raise NotImplementedError


class AesXts256Plain64(CryptoImplementation):
    """VeraCrypt AES256 XTS with plain64 iv tweak mode implementation."""

    __type__ = "aes-xts-256-plain64"

    def open(self) -> CryptStream:
        return CryptStream(
            RangeStream(self.fh, self.offset, self.size),
            self.__type__,
            self.key,
            offset=0,
            iv_tweak=self.offset // 512,
            size=self.size,
        )


CIPHERS: tuple[type[CryptoImplementation]] = (AesXts256Plain64,)
