try:
    from dissect.fve import _native

    HAS_ARGON2 = True

    hash_secret_raw = _native.crypto.argon2.hash_secret_raw

except (ImportError, AttributeError):
    try:
        import argon2

        HAS_ARGON2 = True

        def hash_secret_raw(
            secret: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int, hash_len: int, type: str
        ) -> bytes:
            return argon2.low_level.hash_secret_raw(
                secret,
                salt,
                time_cost,
                memory_cost,
                parallelism,
                hash_len,
                {"argon2i": argon2.low_level.Type.I, "argon2id": argon2.low_level.Type.ID}[type],
            )
    except ImportError:
        HAS_ARGON2 = False

        def hash_secret_raw(
            secret: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int, hash_len: int, type: str
        ) -> bytes:
            raise RuntimeError(
                "A native Argon2 implementation is not available. "
                "Please ensure that the dissect.fve._native module is built and accessible, "
                "or install `argon2-cffi` from PyPI."
            )
