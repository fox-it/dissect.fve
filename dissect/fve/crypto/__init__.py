from __future__ import annotations

# Only pycryptodome is supported right now
from dissect.fve.crypto import _pycryptodome
from dissect.fve.crypto.base import Cipher, Plain, Plain64, Plain64BE

IV_MODE_MAP = {
    "plain": Plain,
    "plain64": Plain64,
    "plain64be": Plain64BE,
    "eboiv": _pycryptodome.EBOIV,
    "essiv": _pycryptodome.ESSIV,
    "elephant": _pycryptodome.Elephant,
}


def create_cipher(
    spec: str, key: bytes, key_size: int | None = None, sector_size: int = 512, iv_sector_size: int = 512
) -> Cipher:
    """Create a cipher object according to a given cipher specification and key.

    For more information on the cipher specification, read the documentation on :func:`parse_cipher_spec`.

    Args:
        spec: The cipher specification to parse.
        key: The key to initialize the cipher with.
        key_size: Optional key size that overrides the specification key size.
        sector_size: Optional sector size.
    """
    cipher_name, cipher_mode, key_size, iv_name, iv_options = parse_cipher_spec(
        spec, key_size=key_size, key_size_hint=len(key) * 8
    )

    if cipher_name != "aes":
        raise ValueError("Only AES support is implemented")

    if cipher_mode not in ("ecb", "cbc", "xts"):
        raise ValueError(f"Invalid cipher mode: {cipher_name}-{cipher_mode} (from {spec})")

    if (iv := IV_MODE_MAP.get(iv_name)) is None:
        raise ValueError(f"Invalid iv mode: {iv_name}:{iv_options} (from {spec})")

    return _pycryptodome.new(
        key,
        cipher_mode,
        key_size=key_size,
        iv_mode=iv,
        iv_options=iv_options,
        sector_size=sector_size,
        iv_sector_size=iv_sector_size,
    )


def parse_cipher_spec(
    spec: str, key_size: int | None = None, key_size_hint: int | None = None
) -> tuple[str, str, int, str, str | None]:
    """Parse a cipher specification into a tuple of (cipher, mode, key size, iv mode, iv options).

    Inspired by and accepts LUKS/dm-crypt-like cipher specifications in the form of::

        cipher-mode-keysize-iv:ivopts

    The ``mode``, ``keysize``, ``iv`` and ``ivopts`` are optional and will default to ``cbc``,
    the ``key_size`` argument and ``plain`` respectively.

    Args:
        spec: The cipher specification to parse.
        key_size: Optional key size that overrides the specification key size.
        key_size_hint: Optional key size hint for the amount of bits that the key actually has.
    """
    cipher_name, _, tmp = spec.partition("-")
    cipher_mode, _, tmp = tmp.partition("-")

    result_key_size = key_size_hint
    specified_key_size, _, tmp = tmp.partition("-")
    if specified_key_size.isdigit():
        result_key_size = int(specified_key_size)
    else:
        if tmp:
            raise ValueError("Unexpected cipher spec format")
        tmp = specified_key_size

    if key_size:
        result_key_size = key_size

    if not result_key_size:
        raise ValueError("Missing key size")

    iv_name = None
    iv_options = None
    iv_name, _, iv_options = tmp.partition(":")

    if not cipher_mode:
        cipher_mode = "cbc"

    if not iv_name:
        iv_name = "plain"
        iv_options = None

    if cipher_mode == "xts" and key_size_hint == result_key_size:
        result_key_size //= 2

    return cipher_name, cipher_mode, result_key_size, iv_name, iv_options or None
