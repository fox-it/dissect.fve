from __future__ import annotations

import math
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.veracrypt.c_veracrypt import (
    TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET,
    c_veracrypt,
)
from dissect.fve.veracrypt.crypto import CIPHERS
from dissect.fve.veracrypt.keys import KEY_DERIVATIONS

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.fve.luks.luks import CryptStream


class VeraCrypt:
    """VeraCrypt full volume encryption implementation.

    Supports encrypted file containers and system partitions using key derivation
    algorithm PKCS5 (SHA512 or SHA256) and AES XTS cipher (SHA512 or SHA256).

    Non-system partitions and hidden volumes are not implemented as well as other key
    derivation algorithms or ciphers. Key files are also not implemented.

    References:
        - https://veracrypt.jp/en/System%20Encryption.html
        - https://github.com/veracrypt/VeraCrypt
    """

    def __init__(self, fh: BinaryIO, *, is_system: bool = False) -> None:
        self._fh = fh
        self.is_system = is_system
        self.header = None
        self.unlocked = False

        if is_system:
            if not hasattr(fh, "disk"):
                raise ValueError("Expecting BinaryIO 'disk' attribute on provided 'fh' when is_system is True")
            self.fh: BinaryIO = fh.disk  # type: ignore
        else:
            self.fh = fh

    def __repr__(self) -> str:
        return f"<VeraCrypt fh={self.fh} is_system={self.is_system!r} unlocked={self.unlocked!r}>"

    def unlock_with_passphrase(self, passphrase: str, pim: int | None = None) -> None:
        """Unlock the volume with a passphrase.

        Supports the following PKCS5 header key derivation functions::
            - HMAC SHA512 (default)
            - HMAC SHA256

        Supports the following encryption modes::
            - AES XTS (default)

        KDF HMAC BLAKE2s-256, WHIRLPOOL and STREEBOG are not implemented.
        Ciphers (XTS mode) Serpent, Twofish and Camellia are not implemented.
        """
        if self.is_system:
            self.fh.seek(TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET)

        self.header_salt = self.fh.read(64)
        header_ciphertext = self.fh.read(512)

        for Kdf in KEY_DERIVATIONS:
            kdf = Kdf(passphrase, self.header_salt)
            keys = kdf.derive(pim)

            for Cipher in CIPHERS:
                cipher = Cipher(keys, BytesIO(header_ciphertext), 0, 512)
                plaintext = cipher.open().read()
                header = c_veracrypt.VolumeHeader(plaintext)

                if header.magic == b"VERA":
                    self.header_keys = keys
                    self.header = header
                    self.cipher = cipher.__type__
                    # NOTE: Could contain more keys if other cipher(s) are used.
                    self.key = self.header.master_keys[0:64]
                    self.unlocked = True
                    break

            if self.unlocked:
                break

        if not self.unlocked:
            raise ValueError("Unable to decrypt using provided passphrase")

    def unlock_with_header_key(self, keys: bytes) -> None:
        """Unlock the volume with a raw encryption key. Supports AES XTS encryption mode only."""
        if len(keys) not in (32, 64):
            raise ValueError(f"Header key is of invalid length ({len(keys)})")

        if self.is_system:
            self.fh.seek(TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET)

        self.header_salt = self.fh.read(64)
        header_ciphertext = self.fh.read(512)

        for Cipher in CIPHERS:
            cipher = Cipher(keys, BytesIO(header_ciphertext), 0, 512)
            plaintext = cipher.open().read()
            header = c_veracrypt.VolumeHeader(plaintext)

            if header.magic == b"VERA":
                self.header_keys = keys
                self.header = header
                self.cipher = cipher.__type__
                # NOTE: Could contain more keys if other cipher(s) are used.
                self.key = self.header.master_keys[0:64]
                self.unlocked = True
                break

        if not self.unlocked:
            raise ValueError("Unable to decrypt using provided header keys")

    def unlock_with_keyfile(self, path: Path) -> None:
        """Unlock the volume with a key file."""
        raise NotImplementedError

    def open(self) -> CryptStream:
        """Open this volume and return a readable (decrypted) stream."""
        if not self.unlocked:
            raise ValueError("Volume is locked")

        if self.header:
            offset = self.header.mk_scope_offset
            size = self.header.mk_scope_size
        else:
            offset = 0x20000  # 256 * 512
            size = None  # TODO: if is_system, we could use the size of the volume

        if not (Cipher := next((c for c in CIPHERS if c.__type__ == self.cipher), None)):
            raise NotImplementedError(f"Unsupported Cipher {self.cipher}")

        cipher = Cipher(self.key, self.fh, offset, size)
        return cipher.open()


def entropy(data: bytes) -> float:
    """Simple Shannon entropy implementation.

    References:
        - https://en.wikipedia.org/wiki/Entropy_(information_theory)
    """
    len_data = len(data)
    prob = [float(data.count(c)) / len_data for c in dict.fromkeys(list(data))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


def is_veracrypt_volume(fh: BinaryIO) -> bool:
    """This function implements a smell test to see if the provided file handle or Volume could possibly be a VeraCrypt volume."""  # noqa: E501
    if not hasattr(fh, "size"):
        offset = fh.tell()
        fh.read()  # this is very resource intensive on large file handles
        size = fh.tell()
        fh.seek(offset)
    else:
        size: int = fh.size  # type: ignore

    # Division test
    if size % 512 != 0:
        return False

    # Entropy test
    offset = fh.tell()
    chunk = fh.read(4096)
    fh.seek(offset)
    return entropy(chunk) > 7.9

    # TODO: Make sure the volume does not contain any filesystem(s) or magic headers from regular files.
