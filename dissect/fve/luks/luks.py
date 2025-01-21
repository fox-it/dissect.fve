# References:
# - https://gitlab.com/cryptsetup/cryptsetup
# - https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf

from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

import argon2
from dissect.util.stream import AlignedStream

from dissect.fve.crypto import create_cipher
from dissect.fve.luks import af
from dissect.fve.luks.c_luks import (
    LUKS2_MAGIC_1ST,
    LUKS2_MAGIC_2ND,
    SECONDARY_HEADER_OFFSETS,
    c_luks,
)
from dissect.fve.luks.metadata import Digest, Keyslot, Metadata, Segment

if TYPE_CHECKING:
    from pathlib import Path


class LUKS:
    """LUKS disk encryption."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = None
        self.header1 = None
        self.header2 = None

        first_offset, second_offset, version = find_luks_headers(fh)
        if version is None:
            raise ValueError("Not a LUKS volume")

        if version == 1:
            header_struct = c_luks.luks_phdr
        elif version == 2:
            header_struct = c_luks.luks2_hdr_disk
        else:
            raise ValueError(f"Unsupported LUKS version: {version}")

        if first_offset is not None:
            fh.seek(first_offset)
            self.header1 = header_struct(fh)
            self.header = self.header1

        if second_offset is not None:
            fh.seek(second_offset)
            self.header2 = header_struct(fh)

        self.header = self.header2 or self.header1

        # LUKS1
        self.cipher_name = None
        self.cipher_mode = None
        self.hash_spec = None

        # LUKS2
        self.label = None
        self.checksum_algorithm = None
        self.metadata, self.metadata1, self.metadata2 = None, None, None

        self.uuid = UUID(self.header.uuid.strip(b"\x00").decode())

        if self.header.version == 1:
            # LUKS1
            self.metadata = Metadata.from_luks1_header(self.header)
        else:
            # LUKS2
            self.label = self.header.label.strip(b"\x00").decode()
            self.checksum_algorithm = self.header.checksum_alg.strip(b"\x00").decode()

            self.metadata1 = None
            if self.header is self.header1:
                json_area1 = fh.read(self.header1.hdr_size - 4096).rstrip(b"\x00").decode()
                self.metadata1 = Metadata.from_json(json_area1)
                self.header2 = c_luks.luks2_hdr_disk(fh)

            json_area2 = fh.read(self.header2.hdr_size - 4096).rstrip(b"\x00").decode()
            self.metadata2 = Metadata.from_json(json_area2)

            self.metadata = self.metadata1 or self.metadata2

        self._active_volume_key = None
        self._active_keyslot_id = None

    @property
    def unlocked(self) -> bool:
        return self._active_volume_key is not None

    @property
    def keyslots(self) -> dict[int, Keyslot]:
        return self.metadata.keyslots

    def unlock(self, key: bytes, keyslot: int) -> None:
        """Unlock the volume with the volume encryption key."""
        if not self._verify_volume_key(key, keyslot):
            raise ValueError(f"Invalid volume key for keyslot {keyslot}")
        self._active_volume_key = key
        self._active_keyslot_id = keyslot

    def unlock_with_key_file(self, path: Path, offset: int = 0, size: int = -1, keyslot: int | None = None) -> None:
        with path.open("rb") as fh:
            self.unlock_with_key_fh(fh, offset, size, keyslot)

    def unlock_with_key_fh(self, fh: BinaryIO, offset: int = 0, size: int = -1, keyslot: int | None = None) -> None:
        fh.seek(offset)
        self._unlock_passphrase(fh.read(size), keyslot)

    def unlock_with_passphrase(self, passphrase: str, keyslot: int | None = None) -> None:
        """Unlock this volume with a passphrase and optional keyslot hint."""
        self._unlock_passphrase(passphrase.encode(), keyslot)

    def _unlock_passphrase(self, passphrase: bytes, keyslot: int | None = None) -> None:
        """Unlock this volume with a passphrase and optional keyslot hint."""
        keyslots = (
            [(keyslot, self.metadata.keyslots[keyslot])] if keyslot is not None else self.metadata.keyslots.items()
        )

        idx = None
        vk = None
        errors = []
        for idx, keyslot in keyslots:
            try:
                key = derive_passphrase_key(passphrase, keyslot)
            except Exception as exc:
                errors.append((idx, exc))
                continue

            try:
                vk = self._unlock_volume_key(key, idx)
            except Exception as exc:
                errors.append((idx, exc))
                continue

            try:
                self.unlock(vk, idx)
                break
            except ValueError:
                continue
        else:
            if errors:
                msg = "\n".join(f"{idx}: {exc}" for idx, exc in errors)
                raise ValueError(f"No valid keyslot found, but there were errors for the following keyslots:\n{msg}")
            raise ValueError("No valid keyslot found")

    def _unlock_volume_key(self, key: bytes, keyslot: int) -> None:
        """Unlock the volume key using the given encryption key and keyslot."""
        keyslot_obj = self.metadata.keyslots[keyslot]

        self.fh.seek(keyslot_obj.area.offset)
        area = self.fh.read(keyslot_obj.key_size * keyslot_obj.af.stripes)

        cipher = create_cipher(keyslot_obj.area.encryption, key, keyslot_obj.area.key_size * 8)
        return af.merge(
            cipher.decrypt(area),
            keyslot_obj.key_size,
            keyslot_obj.af.stripes,
            keyslot_obj.af.hash,
        )

    def _verify_volume_key(self, key: bytes, keyslot: int) -> None:
        """Verify the given key for the given keyslot."""
        digest = self.find_digest(keyslot)
        if digest.type == "pbkdf2":
            result = hashlib.pbkdf2_hmac(digest.hash, key, digest.salt, digest.iterations, len(digest.digest))
        else:
            # Only the pbkdf2 type is supported in LUKS2
            raise NotImplementedError(f"Unsupported digest algorithm: {digest.type}")

        return result == digest.digest

    def find_digest(self, keyslot: int) -> Digest:
        """Find digest metadata corresponding to the given keyslot."""
        digests = [digest for digest in self.metadata.digests.values() if keyslot in digest.keyslots]
        if not digests:
            raise ValueError(f"No digest found for keyslot {keyslot}")

        return digests[0]

    def find_segment(self, keyslot: int) -> Segment:
        """Find segment metadata corresponding to the given keyslot."""
        digest = self.find_digest(keyslot)
        segments = [segment for segment_id, segment in self.metadata.segments.items() if segment_id in digest.segments]
        if not segments:
            raise ValueError(f"No segment found for keyslot {keyslot}")

        if len(segments) > 1:
            raise NotImplementedError(f"Keyslot {keyslot} has more than one segment")

        return segments[0]

    def open(self) -> CryptStream:
        """Open this volume and return a readable (decrypted) stream."""
        if not self.unlocked:
            raise ValueError("Volume is locked")

        # Technically LUKS supports multiple segments, but practically it only ever has one
        # Don't bother with supporting multiple segments for now
        segment = self.find_segment(self._active_keyslot_id)

        return CryptStream(
            self.fh,
            segment.encryption,
            self._active_volume_key,
            self.metadata.keyslots[self._active_keyslot_id].key_size * 8,
            segment.offset,
            segment.size,
            segment.iv_tweak,
            segment.sector_size,
        )


def derive_passphrase_key(passphrase: bytes, keyslot: Keyslot) -> bytes:
    """Derive a key from a passphrase with the given keyslot KDF information.

    Args:
        passphrase: The passphrase to derive a key from.
        keyslot: The keyslot to use for the derivation.
    """
    kdf = keyslot.kdf

    if kdf.type == "pbkdf2":
        return hashlib.pbkdf2_hmac(kdf.hash, passphrase, kdf.salt, kdf.iterations, keyslot.key_size)

    if kdf.type.startswith("argon2"):
        return argon2.low_level.hash_secret_raw(
            passphrase,
            kdf.salt,
            kdf.time,
            kdf.memory,
            kdf.cpus,
            keyslot.key_size,
            {"argon2i": argon2.low_level.Type.I, "argon2id": argon2.low_level.Type.ID}[kdf.type],
        )

    raise NotImplementedError(f"Unsupported kdf algorithm: {kdf.type}")


class CryptStream(AlignedStream):
    """Transparently decrypting stream.

    Technically this is dm-crypt territory, but it's more practical to place it in the LUKS namespace.

    Args:
        fh: The original file-like object, usually the encrypted disk.
        cipher: The cipher name/specification.
        key: The encryption key.
        key_size: Optional key size hint.
        offset: Optional base offset to the encrypted region. Segment offset in LUKS.
        size: Optional size hint. If ``None`` or ``"dynamic"``, determine the size by seeking to the end of ``fh``.
        iv_tweak: Optional IV tweak, or offset.
        sector_size: Optional sector size. Defaults to 512.
    """

    def __init__(
        self,
        fh: BinaryIO,
        cipher: str,
        key: bytes,
        key_size: int | None = None,
        offset: int = 0,
        size: int | str | None = None,
        iv_tweak: int = 0,
        sector_size: int = 512,
    ):
        self.fh = fh
        self.cipher = create_cipher(cipher, key, key_size or len(key) * 8, sector_size, 512)
        self.offset = offset
        self.iv_tweak = iv_tweak
        self.sector_size = sector_size

        if size in (None, "dynamic"):
            size = fh.seek(0, io.SEEK_END) - offset

        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buf = bytearray(self.fh.read(length))
        self.cipher.decrypt(buf, (offset // 512) + self.iv_tweak, buf)
        return bytes(buf)


def find_luks_headers(fh: BinaryIO) -> tuple[int | None, int | None, int | None]:
    stored_position = fh.tell()

    fh.seek(0)
    first_header = None
    second_header = None
    version = None

    if fh.read(c_luks.LUKS2_MAGIC_L) == LUKS2_MAGIC_1ST:
        first_header = 0
        version = int.from_bytes(fh.read(2), "big")

    for offset in SECONDARY_HEADER_OFFSETS:
        fh.seek(offset)
        if fh.read(c_luks.LUKS2_MAGIC_L) == LUKS2_MAGIC_2ND:
            second_header = offset
            version = int.from_bytes(fh.read(2), "big")
            break

    fh.seek(stored_position)
    return first_header, second_header, version


def is_luks_volume(fh: BinaryIO) -> bool:
    """Return whether the file-like object is a LUKS volume."""
    _, _, version = find_luks_headers(fh)
    return version is not None
