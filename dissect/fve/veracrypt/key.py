from __future__ import annotations

import hashlib
from typing import Literal


class KeyDerivation:
    """VeraCrypt PKCS5 header key derivation implementation.

    References:
        - https://veracrypt.jp/en/Header%20Key%20Derivation.html
        - https://github.com/veracrypt/VeraCrypt/blob/master/src/Volume/Pkcs5Kdf.h
        - ``pkcs5->DeriveKey(headerKey, password, pim, salt);``
    """

    __hash__: Literal["sha256", "sha512"]

    passphrase: bytes
    salt: bytes

    def __init__(self, passphrase: str, salt: bytes) -> None:
        self.passphrase: bytes = passphrase.encode("latin-1")
        self.salt = salt

        # If the passphrase is longer than the hash block size, create a digest.
        if len(self.passphrase) > (hash := hashlib.new(self.__hash__)).block_size:
            hash.update(self.passphrase)
            self.passphrase = hash.digest()

    def pim(self, pim: int | None = None) -> int:
        """Implements Personal Iterations Multiplier (PIM).

        Takes a user supplied ``pim`` integer and translates to PBKDF2 iterations count.

        References:
            - https://veracrypt.jp/en/Personal%20Iterations%20Multiplier%20%28PIM%29.html
        """
        raise NotImplementedError

    def derive(self, pim: int | None = None) -> bytes:
        """Implements PBKDF2-HMAC header key derivation based on the provided passphrase.

        Does not implement Argon2id key derivation.

        References:
            - https://veracrypt.jp/en/Header%20Key%20Derivation.html
        """
        return hashlib.pbkdf2_hmac(
            hash_name=self.__hash__,
            password=self.passphrase,
            salt=self.salt,
            iterations=self.pim(pim),
            dklen=64,
        )


class Pkcs5HmacSha512(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA512 header key derivation."""

    __hash__ = "sha512"

    def pim(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else 500_000


class Pkcs5HmacSha256(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 header key derivation."""

    __hash__ = "sha256"

    def pim(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else 500_000


class Pkcs5HmacSha256_Boot(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 boot header key derivation."""

    __hash__ = "sha256"

    def pim(self, pim: int | None = None) -> int:
        return pim * 2048 if pim else 200_000


KEY_DERIVATIONS = (
    Pkcs5HmacSha512,
    Pkcs5HmacSha256,
    Pkcs5HmacSha256_Boot,
)
