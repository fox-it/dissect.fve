from __future__ import annotations

import hashlib
import struct


def stretch(password: bytes, salt: bytes, rounds: int = 0x100000) -> bytes:
    """Stretch a password with a specified salt.

    Bitlocker uses this as the key derivation algorithm.
    """
    # Stretch data looks like the following:
    # chained hash | user hash | salt | counter
    # SHA256 digest length is 32 bytes
    # Salt length is 16 bytes
    # Counter is a uint64
    if len(password) != 32:
        raise ValueError("Invalid password length")

    if len(salt) != 16:
        raise ValueError("Invalid salt length")

    data = bytearray(32 + 32 + 16 + 8)
    view = memoryview(data)

    view[32:64] = password
    view[64:80] = salt

    for i in range(rounds):
        view[80:] = i.to_bytes(8, "little")
        view[:32] = hashlib.sha256(view).digest()

    return bytes(view[:32])


def derive_user_key(user_password: str) -> bytes:
    """Derive an AES key from a given user passphrase."""
    return hashlib.sha256(hashlib.sha256(user_password.encode("utf-16-le")).digest()).digest()


def derive_recovery_key(recovery_password: str) -> bytes:
    """Derive an AES key from a given recovery password."""
    check_recovery_password(recovery_password)

    blocks = recovery_password.split("-")
    key = b"".join(struct.pack("<H", int(block) // 11) for block in blocks)
    return hashlib.sha256(bytes(key)).digest()


def check_recovery_password(recovery_password: str) -> bool:
    """Check if a given recovery password is valid."""
    blocks = recovery_password.split("-")
    if len(blocks) != 8:
        raise ValueError("Invalid recovery password: invalid length")

    for block in blocks:
        if not block.isdigit():
            raise ValueError("Invalid recovery password: contains non-numeric value")

        value = int(block)
        if value % 11:
            raise ValueError("Invalid recovery password: block not divisible by 11")

        if value >= 2**16 * 11:
            raise ValueError("Invalid recovery password: larger than 2 ** 16 * 11 (720896)")

        digits = list(map(int, block))
        checksum = (digits[0] - digits[1] + digits[2] - digits[3] + digits[4]) % 11
        if checksum != digits[5]:
            raise ValueError("Invalid recovery password: invalid block checksum")

    return True
