from __future__ import annotations

import io
import math
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.veracrypt.c_veracrypt import (
    TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET,
    c_veracrypt,
)
from dissect.fve.veracrypt.crypto import CIPHERS
from dissect.fve.veracrypt.key import KEY_DERIVATIONS

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
        self.fh = fh
        self.is_system = is_system
        self.unlocked = False
        self.header = None

        self.cipher = None
        self.size = None
        self.version = None
        self.client_version = None

        if is_system:
            self.fh.seek(TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET)

        self.header_salt = self.fh.read(64)
        self.header_ciphertext = self.fh.read(512)

    def __repr__(self) -> str:
        return (
            f"<VeraCrypt fh={self.fh} is_system={self.is_system} unlocked={self.unlocked} size={self.size} "
            f"cipher={self.cipher} version={self.version} client_version={self.client_version}>"
        )

    def unlock_with_passphrase(self, passphrase: str, pim: int | None = None) -> None:
        """Unlock the volume with a passphrase.

        Supports the following PKCS5 header key derivation functions:
            - HMAC SHA512 (default)
            - HMAC SHA256

        Supports the following encryption modes:
            - AES XTS (default)

        KDF HMAC BLAKE2s-256, WHIRLPOOL and STREEBOG are not implemented.
        Ciphers (XTS mode) Serpent, Twofish and Camellia are not implemented.
        """
        for Kdf in KEY_DERIVATIONS:
            kdf = Kdf(passphrase, self.header_salt)
            keys = kdf.derive(pim)
            if self._decrypt_header(keys):
                break

        if not self.unlocked:
            raise ValueError("Unable to decrypt using provided passphrase")

    def unlock_with_header_key(self, keys: bytes) -> None:
        """Unlock the volume with a raw encryption key. Supports AES XTS encryption mode only."""
        if len(keys) not in (32, 64):
            raise ValueError(f"Header key is of invalid length ({len(keys)}), expected 32 or 64 bytes")

        if not self._decrypt_header(keys):
            raise ValueError("Unable to decrypt using provided header keys")

    def unlock_with_key_file(self, path: Path) -> None:
        """Unlock the volume with a key file."""
        raise NotImplementedError

    def unlock_with_key_fh(self, fh: BinaryIO) -> None:
        """Unlock the volume with a key file handle."""
        raise NotImplementedError

    def _decrypt_header(self, keys: bytes) -> bool:
        """Decrypt the VeraCrypt header using any of the available :class:`Cipher` implementations."""
        for Cipher in CIPHERS:
            cipher = Cipher(BytesIO(self.header_ciphertext), keys, 0, 512)
            plaintext = cipher.open().read()
            header = c_veracrypt.VolumeHeader(plaintext)

            if header.magic == b"VERA":
                self.header_keys = keys
                self.header = header
                self.cipher = cipher.__type__
                self.key = self.header.master_keys[0:64]  # NOTE: Could contain more keys if other cipher(s) are used.
                self.size = header.volume_size
                self.version = header.version
                self.client_version = header.client_version
                self.unlocked = True
                break

        return self.unlocked

    def open(self) -> CryptStream:
        """Open this volume and return a readable (decrypted) stream."""
        if not self.unlocked:
            raise ValueError("Volume is locked")

        if not (Cipher := next((c for c in CIPHERS if c.__type__ == self.cipher), None)):
            raise NotImplementedError(f"Unsupported Cipher {self.cipher}")

        offset = self.header.mk_scope_offset
        size = self.header.mk_scope_size
        cipher = Cipher(self.fh, self.key, offset, size)
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
    """Perform a smell test to see if the provided file-like object could be a VeraCrypt volume."""
    offset = fh.tell()

    if not hasattr(fh, "size"):
        size = fh.seek(0, io.SEEK_END)
        fh.seek(offset)
    else:
        size: int = fh.size  # type: ignore

    # Division test
    if size % 512 != 0:
        return False

    # Entropy test
    chunk = fh.read(4096)
    fh.seek(offset)
    return entropy(chunk) > 7.9

    # TODO: Make sure the volume does not contain any filesystem(s) or magic headers from regular files.
