from __future__ import annotations

ENCRYPT = 0
DECRYPT = 1


class Cipher:
    def __init__(
        self,
        key: bytes,
        key_size: int,
        block_size: int,
        iv_mode: type[IV],
        iv_options: str,
        sector_size: int = 512,
        iv_sector_size: int = 512,
    ):
        self.key = key
        self.key_size = key_size
        self.key_size_bytes = key_size // 8
        self.block_size = block_size
        self.sector_size = sector_size
        self.iv_sector_size = iv_sector_size

        self.iv_mode = iv_mode(self, key, iv_options)

    def _crypt_sector(self, mode: int, buffer: bytearray, iv: bytes) -> None:
        raise NotImplementedError

    def _crypt(self, mode: int, ciphertext: bytes, sector: int = 0, output: bytearray | None = None) -> bytes | None:
        length = len(ciphertext)

        if length % self.block_size:
            raise ValueError("Ciphertext is not aligned to block size")

        out = output or bytearray(length)
        out[:] = ciphertext
        out_view = memoryview(out)

        iv = bytearray(self.iv_mode.iv_size)
        iv_view = memoryview(iv)

        iv_mode = self.iv_mode
        sector_size = self.sector_size
        sector_increment = sector_size // self.iv_sector_size

        for _ in range(length // sector_size):
            out_slice = out_view[:sector_size]

            # Generate the IV
            iv_mode.generate(mode, iv_view, out_slice, sector)

            # Do the crypting
            self._crypt_sector(mode, out_slice, iv)

            # Perform possible post operations for the IV
            iv_mode.post(mode, out_slice, sector)

            out_view = out_view[sector_size:]
            sector += sector_increment

        return None if output is not None else bytes(out)

    def encrypt(self, ciphertext: bytes, sector: int = 0, output: bytearray | None = None) -> bytes | None:
        return self._crypt(ENCRYPT, ciphertext, sector, output)

    def decrypt(self, ciphertext: bytes, sector: int = 0, output: bytearray | None = None) -> bytes | None:
        return self._crypt(DECRYPT, ciphertext, sector, output)


class IV:
    def __init__(self, cipher: Cipher, key: bytes, iv_options: str | None = None):
        self.cipher = cipher
        self.iv_size = cipher.block_size

    def generate(self, mode: int, iv: bytearray, data: bytearray, sector: int = 0) -> None:
        pass

    def post(self, mode: int, data: bytearray, sector: int = 0) -> None:
        pass


class Plain(IV):
    def generate(self, mode: int, iv: bytearray, data: bytearray, sector: int = 0) -> None:
        iv[:] = b"\x00" * self.iv_size
        iv[:4] = (sector & 0xFFFFFFFF).to_bytes(4, "little")


class Plain64(IV):
    def generate(self, mode: int, iv: bytearray, data: bytearray, sector: int = 0) -> None:
        iv[:] = b"\x00" * self.iv_size
        iv[:8] = sector.to_bytes(8, "little")


class Plain64BE(IV):
    def generate(self, mode: int, iv: bytearray, data: bytearray, sector: int = 0) -> None:
        iv[:] = b"\x00" * self.iv_size
        iv[:8] = sector.to_bytes(8, "big")


class EBOIV(IV):
    def __init__(self, cipher: Cipher, key: bytes, iv_options: str | None = None):
        # Implementation specific
        raise NotImplementedError


class ESSIV(IV):
    def __init__(self, cipher: Cipher, key: bytes, iv_options: str | None = None):
        # Implementation specific
        raise NotImplementedError


class Elephant(IV):
    def __init__(self, cipher: Cipher, key: bytes, iv_options: str | None = None):
        # Implementation specific
        raise NotImplementedError
