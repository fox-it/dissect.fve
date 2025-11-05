from __future__ import annotations

import platform


# Reference: https://www.da.vidbuchanan.co.uk/blog/python-swar.html
# Sorry David
def xor_pseudo_simd(a: bytes, b: bytes, output: bytearray) -> None:
    output[:] = int.to_bytes(int.from_bytes(a, "little") ^ int.from_bytes(b, "little"), len(output), "little")


# On PyPy the naive loop is actually faster
# Also just use this as the default fallback, seems safer
def xor_naive(a: bytes, b: bytes, output: bytearray) -> None:
    for i in range(len(output)):
        output[i] = a[i] ^ b[i]


xor = xor_pseudo_simd if platform.python_implementation() == "CPython" else xor_naive
