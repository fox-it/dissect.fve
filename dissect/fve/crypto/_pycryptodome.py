from __future__ import annotations

import hashlib
import platform
import sys
from typing import Any, Callable

from Crypto.Cipher import AES
from Crypto.Util import _raw_api

from dissect.fve.crypto import elephant
from dissect.fve.crypto.base import DECRYPT, ENCRYPT, IV, Cipher

if platform.python_implementation() == "CPython":
    # On CPython, our own "pure Python" XOR is somehow faster than the one from pycryptodome
    from dissect.fve.crypto.utils import xor
else:
    # On PyPy the opposite is true, and also just use this as the default fallback
    from Crypto.Util.strxor import strxor as xor

POINTER_SIZE = 8 if sys.maxsize > 2**32 else 4


if _raw_api.backend == "cffi":

    def get_iv_view(cipher: AES.CbcMode | AES.EcbMode, size: int) -> memoryview:
        return _raw_api.ffi.cast(_raw_api.uint8_t_type, cipher._state.get() + POINTER_SIZE)[0:size]

elif _raw_api.backend == "ctypes":
    import ctypes

    def get_iv_view(cipher: AES.CbcMode | AES.EcbMode, size: int) -> memoryview:
        return ctypes.cast(cipher._state.get().value + POINTER_SIZE, ctypes.POINTER(ctypes.c_char * size))[0]

else:

    def get_iv_view(cipher: AES.CbcMode | AES.EcbMode, size: int) -> memoryview:
        raise NotImplementedError("Unsupported pycryptodome backend")


# Sanity check if fast IV is available
def _fast_iv_works() -> bool:
    try:
        magic = b"\x69" * 16
        cipher = AES.new(b"\x00" * 16, AES.MODE_CBC, iv=magic)
        return _raw_api.get_raw_buffer(get_iv_view(cipher, 16)) == magic
    except Exception:
        return False


FAST_IV = _fast_iv_works()


class EcbMode(Cipher):
    """ECB mode implementation for FVE crypto."""

    def __init__(
        self,
        factory: Any,
        key: bytes,
        key_size: int,
        iv_mode: type[IV],
        iv_options: str,
        sector_size: int = 512,
        iv_sector_size: int = 512,
    ):
        if key_size not in (128, 256):
            raise ValueError(f"Incorrect key size for ECB mode ({key_size} bits)")
        super().__init__(key, key_size, factory.block_size, iv_mode, iv_options, sector_size, iv_sector_size)

        self._cipher = AES.new(key[: self.key_size_bytes], AES.MODE_ECB)

    def _crypt_sector(self, mode: int, buffer: bytearray, iv: bytes) -> None:
        (self._cipher.encrypt if mode == ENCRYPT else self._cipher.decrypt)(buffer, output=buffer)


class CbcMode(Cipher):
    """CBC mode implementation for FVE crypto."""

    def __init__(
        self,
        factory: Any,
        key: bytes,
        key_size: int,
        iv_mode: type[IV],
        iv_options: str,
        sector_size: int = 512,
        iv_sector_size: int = 512,
    ):
        if key_size not in (128, 256):
            raise ValueError(f"Incorrect key size for CBC mode ({key_size} bits)")
        super().__init__(key, key_size, factory.block_size, iv_mode, iv_options, sector_size, iv_sector_size)

        if FAST_IV:
            self._cipher = AES.new(key[: self.key_size_bytes], AES.MODE_CBC, iv=b"\x00" * self.block_size)
            self._iv_view = get_iv_view(self._cipher, self.block_size)
        else:
            self._key = key[: self.key_size_bytes]

    def _crypt_sector(self, mode: int, buffer: bytearray, iv: bytes) -> None:
        if FAST_IV:
            self._iv_view[0 : self.block_size] = iv
            cipher = self._cipher
        else:
            cipher = AES.new(self._key, AES.MODE_CBC, iv=iv)

        (cipher.encrypt if mode == ENCRYPT else cipher.decrypt)(buffer, output=buffer)


class XtsMode(Cipher):
    """XTS mode implementation for FVE crypto."""

    def __init__(
        self,
        factory: AES,
        key: bytes,
        key_size: int,
        iv_mode: type[IV],
        iv_options: str,
        sector_size: int = 512,
        iv_sector_size: int = 512,
    ):
        if (len(key), key_size) not in ((32, 128), (64, 256)):
            raise ValueError(f"Incorrect key size for XTS mode ({len(key)} bytes, {key_size} bits)")
        super().__init__(key, key_size, key_size // 8, iv_mode, iv_options, sector_size, iv_sector_size)

        self._aes_cipher = factory.new(key[: self.block_size], factory.MODE_ECB)
        self._tweak_cipher = factory.new(key[self.block_size :], factory.MODE_ECB)

    def _crypt_sector(self, mode: int, buffer: bytearray, iv: bytes) -> None:
        tweak = self._tweak_cipher.encrypt(iv)
        _t = int.from_bytes(tweak, "little")

        crypt = self._aes_cipher.encrypt if mode == ENCRYPT else self._aes_cipher.decrypt

        view = buffer
        block_size = self.block_size

        for _ in range(self.sector_size // 16):
            block_slice = view[:16]
            xor(block_slice, tweak[:16], output=block_slice)
            crypt(block_slice, output=block_slice)
            xor(tweak[:16], block_slice, output=block_slice)

            _t <<= 1
            if _t & (1 << 128):
                _t ^= (1 << 128) | (0x87)
            tweak = (_t & ((1 << (block_size * 8)) - 1)).to_bytes(block_size, "little")

            view = view[16:]


class EBOIV(IV):
    """Encrypted byte-offset IV.

    Specific to Bitlocker.
    """

    def __init__(self, cipher: Cipher, key: bytes, iv_options: str | None = None):
        super().__init__(cipher, key)
        self._ecb_cipher = AES.new(key, AES.MODE_ECB)

    def generate(self, mode: int, iv: bytearray, data: bytearray, sector: int = 0) -> None:
        iv[:] = self._ecb_cipher.encrypt((sector * self.cipher.sector_size).to_bytes(16, "little"))


class ESSIV(IV):
    """Encrypted sector|salt IV.

    The sector number is encrypted with the bulk cipher using a salt as key. The salt should be
    derived from the bulk cipher's key via hashing.
    """

    def __init__(self, cipher: Cipher, key: bytes, iv_options: str | None = "sha256"):
        super().__init__(cipher, key)
        # Only support one cipher mode for now
        self._cipher = AES.new(hashlib.new(iv_options, key).digest(), AES.MODE_ECB)

    def generate(self, mode: int, iv: bytearray, data: bytearray, sector: int = 0) -> None:
        self._cipher.encrypt(sector.to_bytes(self.cipher.block_size, "little"), output=iv)


class Elephant(IV):
    """Extended eboiv with Elephant diffuser.

    Specific to Bitlocker. The key is always 64 bytes, but you need to take only the
    amount of bytes for the key size that you're working with.
    """

    def __init__(self, cipher: Cipher, key: bytes, iv_options: str | None = None):
        super().__init__(cipher, key)
        self._ecb_cipher = AES.new(key[32 : 32 + cipher.key_size_bytes], AES.MODE_ECB)
        self._eboiv = EBOIV(cipher, key[: cipher.key_size_bytes])

        self._sector_key = bytearray(32)
        self._sector_key_view = memoryview(self._sector_key)

    def _elephant(self, mode: int, data: bytearray, sector: int) -> None:
        sector_size = self.cipher.sector_size
        sector_key_view = self._sector_key_view

        # Generate the IV and sector key
        iv = bytearray((sector * sector_size).to_bytes(16, "little"))
        self._ecb_cipher.encrypt(iv, output=sector_key_view[:16])
        iv[15] = 0x80
        self._ecb_cipher.encrypt(iv, output=sector_key_view[16:])

        if mode == DECRYPT:
            # Apply diffuser B
            elephant.diffuser_b_decrypt(data, sector_size)

            # Apply diffuser A
            elephant.diffuser_a_decrypt(data, sector_size)

        # Apply sector key
        xor(data, self._sector_key * (sector_size // 32), output=data)

        if mode == ENCRYPT:
            # Apply diffuser A
            elephant.diffuser_a_encrypt(data, sector_size)

            # Apply diffuser B
            elephant.diffuser_b_encrypt(data, sector_size)

    def generate(self, mode: int, iv: bytearray, data: bytearray, sector: int = 0) -> None:
        if mode == ENCRYPT:
            self._elephant(mode, data, sector)
        self._eboiv.generate(mode, iv, data, sector)

    def post(self, mode: int, data: bytearray, sector: int = 0) -> None:
        if mode == DECRYPT:
            self._elephant(mode, data, sector)


def _create_cipher_factory(mode: type[Cipher]) -> Callable[..., Cipher]:
    def cipher_factory(factory: AES, **kwargs) -> Cipher:
        try:
            key = kwargs.pop("key")
            key_size = kwargs.pop("key_size")
            iv_mode = kwargs.pop("iv_mode")
        except KeyError as e:
            raise TypeError("Missing parameter:" + str(e))

        sector_size = kwargs.pop("sector_size", 512)
        iv_sector_size = kwargs.pop("iv_sector_size", 512)
        iv_options = kwargs.pop("iv_options", None)

        return mode(factory, key, key_size, iv_mode, iv_options, sector_size, iv_sector_size)

    return cipher_factory


_create_fve_ecb_cipher = _create_cipher_factory(EcbMode)
_create_fve_cbc_cipher = _create_cipher_factory(CbcMode)
_create_fve_xts_cipher = _create_cipher_factory(XtsMode)


def new(key: bytes, mode: int, *args, **kwargs) -> Cipher:
    """Create a new cipher object."""
    if mode not in ("ecb", "cbc", "xts"):
        return AES.new(key, mode, *args, **kwargs)

    if mode == "ecb":
        return _create_fve_ecb_cipher(AES, key=key, mode=mode, **kwargs)
    if mode == "cbc":
        return _create_fve_cbc_cipher(AES, key=key, mode=mode, **kwargs)
    if mode == "xts":
        return _create_fve_xts_cipher(AES, key=key, mode=mode, **kwargs)

    raise ValueError(f"Unsupported mode: {mode} (key: {key!r}, args: {args}, kwargs: {kwargs})")
