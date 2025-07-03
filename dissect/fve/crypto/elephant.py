from __future__ import annotations

from dissect.util.xmemoryview import xmemoryview


def diffuser_a_decrypt(buffer: memoryview, sector_size: int) -> None:
    a_cycles = 5
    r_a = [9, 0, 13, 0]
    int_size = sector_size >> 2

    buffer_i = xmemoryview(buffer, "<I")

    for _ in range(a_cycles):
        for i in range(int_size):
            buffer_i[i] = (buffer_i[i] + (buffer_i[i - 2] ^ _rotate_left(buffer_i[i - 5], r_a[i % 4]))) & 0xFFFFFFFF


def diffuser_a_encrypt(buffer: memoryview, sector_size: int) -> None:
    a_cycles = 5
    r_a = [9, 0, 13, 0]
    int_size = sector_size >> 2

    buffer_i = xmemoryview(buffer, "<I")

    for _ in range(a_cycles):
        for i in range(int_size - 1, -1, -1):
            buffer_i[i] = (buffer_i[i] - (buffer_i[i - 2] ^ _rotate_left(buffer_i[i - 5], r_a[i % 4]))) & 0xFFFFFFFF


def diffuser_b_decrypt(buffer: memoryview, sector_size: int) -> None:
    b_cycles = 3
    r_b = [0, 10, 0, 25]
    int_size = sector_size >> 2

    buffer_i = xmemoryview(buffer, "<I")

    for _ in range(b_cycles):
        for i in range(int_size):
            buffer_i[i] = (
                buffer_i[i] + (buffer_i[(i + 2) % int_size] ^ _rotate_left(buffer_i[(i + 5) % int_size], r_b[i % 4]))
            ) & 0xFFFFFFFF


def diffuser_b_encrypt(buffer: memoryview, sector_size: int) -> None:
    b_cycles = 3
    r_b = [0, 10, 0, 25]
    int_size = sector_size >> 2

    buffer_i = xmemoryview(buffer, "<I")

    for _ in range(b_cycles):
        for i in range(int_size - 1, -1, -1):
            buffer_i[i] = (
                buffer_i[i] - (buffer_i[(i + 2) % int_size] ^ _rotate_left(buffer_i[(i + 5) % int_size], r_b[i % 4]))
            ) & 0xFFFFFFFF


def _rotate_left(num: int, count: int) -> int:
    return ((num << count) | (num >> (32 - count))) & ((0b1 << 32) - 1)
