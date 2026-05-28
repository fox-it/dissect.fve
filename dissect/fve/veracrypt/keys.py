from __future__ import annotations

from Crypto.Hash import SHA256, SHA512
from Crypto.Protocol.KDF import PBKDF2


class KeyDerivation:
    """VeraCrypt PKCS5 header key derivation implementation.

    References:
        - https://veracrypt.jp/en/Header%20Key%20Derivation.html
        - https://github.com/veracrypt/VeraCrypt/blob/master/src/Volume/Pkcs5Kdf.h
        - ``pkcs5->DeriveKey(headerKey, password, pim, salt);``
    """

    __hash__: SHA512 | SHA256

    passphrase: bytes
    salt: bytes

    def __init__(self, passphrase: str, salt: bytes) -> None:
        self.passphrase: bytes = passphrase.encode("latin-1")
        self.salt = salt

        # If the passphrase is longer than the hash block size, create a digest.
        if len(self.passphrase) > self.__hash__.block_size:
            self.passphrase = self.__hash__.new(self.passphrase).digest()

    def pim(self, pim: int | None = None) -> int:
        raise NotImplementedError

    def derive(self, pim: int | None = None) -> bytes:
        return PBKDF2(
            self.passphrase.decode("latin-1"),
            self.salt,
            dkLen=64,
            count=self.pim(pim),
            hmac_hash_module=self.__hash__,
        )


class Pkcs5HmacSha512(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA512 header key derivation."""

    __hash__ = SHA512

    def pim(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else 500_000


class Pkcs5HmacSha256(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 header key derivation."""

    __hash__ = SHA256

    def pim(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else 500_000


class Pkcs5HmacSha256_Boot(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 boot header key derivation."""

    __hash__ = SHA256

    def pim(self, pim: int | None = None) -> int:
        return pim * 2048 if pim else 200_000


KEY_DERIVATIONS = (
    Pkcs5HmacSha512,
    Pkcs5HmacSha256,
    Pkcs5HmacSha256_Boot,
)
