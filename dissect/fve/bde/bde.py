# References:
# - https://github.com/libyal/libbde
# - https://github.com/Aorimn/dislocker
# - https://github.com/thewhiteninja/ntfstool
# - https://gitlab.com/cryptsetup/cryptsetup
# - fvevol.sys
# - fveapi.dll

from __future__ import annotations

import io
import logging
import os
import struct
from bisect import bisect_right
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.util.stream import AlignedStream

from dissect.fve.bde.c_bde import (
    BITLOCKER_SIGNATURE,
    CIPHER_MAP,
    EOW_INFORMATION_OFFSET_GUID,
    FVE_DATUM_ROLE,
    FVE_DATUM_TYPE,
    FVE_STATE,
    INFORMATION_OFFSET_GUID,
    c_bde,
)
from dissect.fve.bde.eow import EowInformation
from dissect.fve.bde.information import Dataset, Information, KeyDatum, VmkInfoDatum
from dissect.fve.bde.keys import derive_recovery_key, derive_user_key, stretch
from dissect.fve.crypto import create_cipher
from dissect.fve.exceptions import InvalidHeaderError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from uuid import UUID

Run = tuple[int, int, int]

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_BDE", "CRITICAL"))


class BDE:
    """Bitlocker disk encryption."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.boot_sector = BootSector(fh)

        self._available_information: list[Information] = []
        for offset in self.boot_sector.information_offsets:
            try:
                self._available_information.append(Information(self.fh, offset))
            except InvalidHeaderError as e:  # noqa: PERF203
                log.warning("Failed to parse BDE information at offset 0x%x", offset, exc_info=e)

        self._valid_information = [info for info in self._available_information if info.is_valid()]
        if not self._valid_information:
            raise InvalidHeaderError("No valid BDE information found")
        self.information = self._valid_information[0]

        self.eow_information = None
        self._available_eow_information: list[EowInformation] = []
        for offset in self.boot_sector.eow_offsets:
            try:
                self._available_eow_information.append(EowInformation(self.fh, offset))
            except InvalidHeaderError as e:  # noqa: PERF203
                log.warning("Failed to parse BDE EOW information at offset 0x%x", offset, exc_info=e)

        self._valid_eow_information = [info for info in self._available_eow_information if info.is_valid()]
        if self._available_eow_information and not self._valid_eow_information:
            raise InvalidHeaderError("No valid EOW information found")

        if self._valid_eow_information:
            self.eow_information = self._valid_eow_information[0]

        self._fvek_datum = None
        self._fvek_type = None
        self._fvek = None

    @property
    def identifiers(self) -> list[UUID]:
        datums = self.information.dataset.find_datum(
            role=FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO,
            type_=FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO,
        )
        return [d.identifier for d in datums]

    @property
    def sector_size(self) -> int:
        return self.boot_sector.sector_size

    @property
    def version(self) -> int:
        return self.information.version

    @property
    def paused(self) -> bool:
        return self.information.current_state == FVE_STATE.PAUSED

    @property
    def decrypted(self) -> bool:
        return self.information.current_state == FVE_STATE.DECRYPTED

    @property
    def encrypted(self) -> bool:
        return not self.decrypted

    @property
    def switching(self) -> bool:
        return self.information.current_state not in (FVE_STATE.DECRYPTED, FVE_STATE.ENCRYPTED)

    @property
    def unlocked(self) -> bool:
        return self._fvek is not None or self.information.current_state == FVE_STATE.DECRYPTED

    def description(self) -> str | None:
        """Return the volume description, if present."""
        return self.information.dataset.find_description()

    def has_clear_key(self) -> bool:
        """Return whether this volume has a clear/obfuscated encryption key. Used in paused volumes."""
        return self.information.dataset.find_clear_vmk() is not None

    def has_recovery_password(self) -> bool:
        """Return whether this volume can be unlocked with a recovery password."""
        return len(list(self.information.dataset.find_recovery_vmk())) != 0

    def has_passphrase(self) -> bool:
        """Return whether this volume can be unlocked with a user passphrase."""
        return len(list(self.information.dataset.find_passphrase_vmk())) != 0

    def has_bek(self) -> bool:
        """Return whether this volume can be unlocked with a BEK file."""
        return len(list(self.information.dataset.find_external_vmk())) != 0

    def unlock(self, key: bytes) -> BDE:
        """Unlock this volume with the specified encryption key."""
        self.information.check_integrity(key)

        fvek = self.information.dataset.find_fvek()
        if not fvek:
            raise ValueError("No FVEK found")

        fvek = fvek.unbox(key)
        if not isinstance(fvek, KeyDatum):
            raise TypeError("Invalid unboxed FVEK")

        self._fvek_datum = fvek
        self._fvek_type = fvek.key_type
        self._fvek = fvek.data

        return self

    def unlock_with_clear_key(self) -> BDE:
        """Unlock this volume with the clear/obfuscated key."""
        vmk = self.information.dataset.find_clear_vmk()
        if not vmk:
            raise ValueError("No clear VMK found")

        return self.unlock(vmk.decrypt(vmk.clear_key()))

    def unlock_with_recovery_password(self, recovery_password: str, identifier: UUID | str | None = None) -> BDE:
        """Unlock this volume with the recovery password."""
        recovery_key = derive_recovery_key(recovery_password)
        return self._unlock_with_user_key(self.information.dataset.find_recovery_vmk(), recovery_key, identifier)

    def unlock_with_passphrase(self, passphrase: str, identifier: UUID | str | None = None) -> BDE:
        """Unlock this volume with the user passphrase."""
        user_key = derive_user_key(passphrase)
        return self._unlock_with_user_key(self.information.dataset.find_passphrase_vmk(), user_key, identifier)

    def unlock_with_bek(self, bek_fh: BinaryIO) -> BDE:
        """Unlock this volume with a BEK file."""
        bek_ds = Dataset(bek_fh)
        startup_key = bek_ds.find_startup_key()
        if not startup_key:
            raise ValueError("No startup key found")

        for vmk in self.information.dataset.find_external_vmk():
            if vmk.identifier == startup_key.identifier:
                break
        else:
            raise ValueError("No compatible VMK found")

        decrypted_key = vmk.decrypt(startup_key.external_key())
        return self.unlock(decrypted_key)

    def unlock_with_fvek(self, key: bytes) -> BDE:
        """Unlock this volume with a raw FVEK key."""
        self._fvek_type = self.information.dataset.fvek_type
        self._fvek = key
        return self

    def _unlock_with_user_key(
        self, vmks: list[VmkInfoDatum], user_key: bytes, identifier: UUID | str | None = None
    ) -> BDE:
        decrypted_key = None
        for vmk in vmks:
            if identifier and str(identifier) != str(vmk.identifier):
                continue

            # There should only be one stretch key
            stretch_key = vmk.stretch_key(None)
            if not stretch_key:
                continue  # Shouldn't happen

            aes_key = stretch(user_key, stretch_key.salt)
            try:
                decrypted_key = vmk.decrypt(aes_key)
                break
            except ValueError:
                continue
        else:
            raise ValueError("No compatible VMK found")

        return self.unlock(decrypted_key)

    def open(self) -> BitlockerStream:
        """Open this volume and return a readable (decrypted) stream."""
        if not self.unlocked:
            raise ValueError("Volume is locked")
        return BitlockerStream(self)

    def reserved_regions(self) -> list[tuple[int, int]]:
        """Return a list of reserved regions for this volume.

        Some areas of the volume must "fake" return all null bytes when read.
        This includes things like the information regions.

        Reference:
        - InitializeFilterData
        - FveLibIdentifyCurrentRegionTypeAndEnd
        """
        regions = []

        if self.version == 1:
            information_size = (self.boot_sector.cluster_size + 0x3FFF) & ~(self.boot_sector.cluster_size - 1)
        elif self.version >= 2:
            information_size = ~(self.sector_size - 1) & (self.sector_size + 0xFFFF)

        # All information offsets are reserved regions
        regions.extend(
            [
                (offset // self.sector_size, information_size // self.sector_size)
                for offset in self.information.information_offset
            ]
        )

        if self.version >= 2:
            num_sectors = self.information.virtualized_sectors or 1
            regions.append((self.information.virtualized_block_offset // self.sector_size, num_sectors))

        for eow_info in self._valid_eow_information:
            eow_information_size = ~(self.sector_size - 1) & (eow_info.size + self.sector_size - 1)
            regions.append((eow_info.offset // self.sector_size, eow_information_size // self.sector_size))

            for bitmap in eow_info.bitmaps:
                regions.append((bitmap.offset // self.sector_size, bitmap.size // self.sector_size))
                regions.append((bitmap.conv_log_offset // self.sector_size, eow_info.conv_log_size // self.sector_size))

        # In progress encryption/decryption with dirty state
        if self.information.current_state == FVE_STATE.SWITCHING_DIRTY and self.information.state_size:
            regions.append(
                (
                    self.information.state_offset // self.sector_size,
                    self.information.state_size // self.sector_size,
                )
            )

        return sorted(set(regions), key=itemgetter(0))


class BootSector:
    """Bitlocker boot sector parsing.

    Bitlocker seems to do some funny stuff with the boot sector. Instead of trying to make sense of that,
    just do what Microsoft does in their driver: looking for specific GUIDs to determine the version.

    If no GUIDs can be found, but the Oem string still says -FVE-FS-, we're dealing with a legacy Vista volume.
    """

    def __init__(self, fh: BinaryIO):
        buf = fh.read(512)

        self.boot_sector = c_bde.BOOT_SECTOR(buf)
        self.sector_size = self.boot_sector.Bpb.BytesPerSector
        self.cluster_size = self.sector_size * self.boot_sector.Bpb.SectorsPerCluster

        self.guid = None
        self.information_offsets = []
        self.eow_offsets = []

        info_guid_offset = buf.find(INFORMATION_OFFSET_GUID.bytes_le)
        eow_guid_offset = buf.find(EOW_INFORMATION_OFFSET_GUID.bytes_le)

        if eow_guid_offset != -1:
            info = c_bde.FVE_EOW_GUID_RECOGNITION(buf[eow_guid_offset:])
            self.guid = EOW_INFORMATION_OFFSET_GUID
            self.information_offsets = info.InformationOffset
            self.eow_offsets = info.EowOffset
        elif info_guid_offset != -1:
            info = c_bde.FVE_GUID_RECOGNITION(buf[info_guid_offset:])
            self.guid = INFORMATION_OFFSET_GUID
            self.information_offsets = info.InformationOffset
        elif self.boot_sector.Oem == BITLOCKER_SIGNATURE:
            self.information_offsets = [self.boot_sector.InformationLcn * self.cluster_size]
        else:
            raise ValueError("Not a BDE volume")


class BitlockerStream(AlignedStream):
    """Transparently decrypting Bitlocker stream.

    Provides a transparently decrypted Bitlocker stream for reading. Takes care of the reserved regions, as well
    as the virtualized blocks in Vista and newer Bitlocker versions.

    For Vista, the first 0x2000 bytes aren't actually encrypted. The very first sector is obviously modified to
    contain the Bitlocker information, so when reading that sector we must patch the Oem ID to be the NTFS one,
    as well as replacing the secondary MFT location with one that's located in the Information structure.

    For newer versions, the first N sectors (usually 16) _are_ encrypted, but have been placed elsewhere on the
    volume. The location and amount of so-called virtualized sectors are specified in the Information structure.

    The Microsoft implementation works on a byte level, for the time being it's easier for us to work on sector
    level. I haven't seen a reason why this would break, yet.
    """

    RUN_PLAIN = 0
    RUN_VISTA_HEADER = 1
    RUN_SPARSE = 2
    RUN_ENCRYPTED = 3

    def __init__(self, bde: BDE):
        self.bde = bde
        self._fh = bde.fh

        size = getattr(bde.fh, "size", None)
        try:
            if size is None:
                bde.fh.seek(0, io.SEEK_END)
                size = bde.fh.tell()
        except Exception:
            pass

        self.sector_size = bde.sector_size
        if self.bde.encrypted:
            self.encrypted = True
            self.cipher = create_cipher(
                CIPHER_MAP[bde._fvek_type],
                bde._fvek,
                sector_size=self.sector_size,
                iv_sector_size=self.sector_size,
            )
        else:
            self.encrypted = False
            self.cipher = None

        self._reserved_regions = bde.reserved_regions()
        self._virtualized_block_offset = bde.information.virtualized_block_offset
        self._virtualized_block_sector = self._virtualized_block_offset // self.sector_size
        self._virtualized_sector_count = bde.information.virtualized_sectors

        self._state_offset_sector = bde.information.state_offset // self.sector_size

        self.is_eow = bde.eow_information is not None
        self._eow_bitmaps = []
        self._eow_bitmap_lookup = []
        self._eow_sectors_per_chunk = None

        if self.is_eow:
            self._eow_bitmaps = bde.eow_information.bitmaps
            self._eow_bitmap_lookup = [bm.region_offset // self.sector_size for bm in self._eow_bitmaps]
            self._eow_sectors_per_chunk = self.bde.eow_information.chunk_size // self.sector_size

        super().__init__(size=size)

    def _iter_run_state(self, sector: int, count: int) -> Iterator[Run]:
        while count > 0:
            if self.is_eow:
                bitmap_idx = bisect_right(self._eow_bitmap_lookup, sector)
                bitmap = self._eow_bitmaps[bitmap_idx - 1]

                relative_sector = sector - (bitmap.region_offset // self.sector_size)
                chunk = (relative_sector * self.sector_size) // self.bde.eow_information.chunk_size
                chunk_count = -(-count // self._eow_sectors_per_chunk)

                for bit_set, bit_count in bitmap.runs(chunk, chunk_count):
                    run_type = BitlockerStream.RUN_ENCRYPTED if bit_set else BitlockerStream.RUN_PLAIN
                    run_count = min(count, bit_count * self._eow_sectors_per_chunk)

                    yield (run_type, sector, run_count)

                    sector += run_count
                    count -= run_count
            else:
                # The StateOffset determines how much of the volume is encrypted.
                # In pre-EOW Bitlocker, it's actually used to determine how much of the volume is encrypted
                # for partially encrypted volumes, but since EOW, it seems to just contain the volume size.
                # Pre-EOW volumes are encrypted back to front, so reading beyond the StateOffset means reading
                # plaintext data.
                if self._state_offset_sector and sector < self._state_offset_sector:
                    remaining_sectors = min(self._state_offset_sector - sector, count)
                    yield (BitlockerStream.RUN_ENCRYPTED, sector, remaining_sectors)

                    sector += remaining_sectors
                    count -= remaining_sectors

                if self._state_offset_sector and sector >= self._state_offset_sector:
                    yield (BitlockerStream.RUN_PLAIN, sector, count)
                elif self.encrypted:
                    yield (BitlockerStream.RUN_ENCRYPTED, sector, count)
                else:
                    yield (BitlockerStream.RUN_PLAIN, sector, count)

                sector += count
                count -= count

    def _iter_runs(self, offset: int, length: int) -> Iterator[Run]:
        sector = offset // self.sector_size
        count = -(-length // self.sector_size)

        while count != 0:
            # Vista volume header behaviour
            if self.bde.version == 1 and sector < 0x2000 // self.sector_size:
                if sector == 0:
                    yield (BitlockerStream.RUN_VISTA_HEADER, sector, 1)

                    sector += 1
                    count -= 1

                # Intentionally fall through
                if count:
                    remaining_sectors = min((0x2000 // self.sector_size) - sector, count)

                    yield (BitlockerStream.RUN_PLAIN, sector, remaining_sectors)

                    sector += remaining_sectors
                    count -= remaining_sectors

            # Only on Bitlocker version >= 2
            if sector < self._virtualized_sector_count:
                remaining_sectors = min(self._virtualized_sector_count - sector, count)

                yield from self._iter_run_state(sector + self._virtualized_block_sector, remaining_sectors)

                sector += remaining_sectors
                count -= remaining_sectors

            for region_start, region_size in self._reserved_regions:
                if count == 0:
                    break

                region_end = region_start + region_size

                # Starts outside a region but ends in or after it
                if sector < region_start < sector + count:
                    remaining_sectors = min(region_start - sector, count)

                    yield from self._iter_run_state(sector, remaining_sectors)

                    sector += remaining_sectors
                    count -= remaining_sectors

                # Starts in a region
                if region_start <= sector < region_end:
                    remaining_sectors = min(region_end - sector, count)

                    yield (BitlockerStream.RUN_SPARSE, sector, remaining_sectors)

                    sector += remaining_sectors
                    count -= remaining_sectors
            else:
                yield from self._iter_run_state(sector, count)

                sector += count
                count -= count

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        for run_type, read_sector, sector_count in _consolidate_runs(self._iter_runs(offset, length)):
            if run_type == BitlockerStream.RUN_PLAIN:
                self._fh.seek(read_sector * self.sector_size)
                result.append(self._fh.read(sector_count * self.sector_size))
            elif run_type == BitlockerStream.RUN_VISTA_HEADER:
                self._fh.seek(read_sector * self.sector_size)
                buf = bytearray(self._fh.read(sector_count * self.sector_size))
                buf[0x03:0x0B] = b"NTFS    "
                buf[0x38:0x40] = struct.pack("<Q", self.bde.information.header.Mft2StartLcn)
                result.append(bytes(buf))
            elif run_type == BitlockerStream.RUN_SPARSE:
                result.append(b"\x00" * self.sector_size * sector_count)
            elif run_type == BitlockerStream.RUN_ENCRYPTED:
                self._fh.seek(read_sector * self.sector_size)
                buf = self._fh.read(sector_count * self.sector_size)
                result.append(self.cipher.decrypt(buf, read_sector))

        return b"".join(result)


def _consolidate_runs(it: Iterator[Run]) -> Iterator[Run]:
    current_type = None
    current_sector = None
    current_count = 0

    for run_type, sector, count in it:
        if current_type is None:
            current_type = run_type
            current_sector = sector
            current_count = count
            continue

        if current_type != run_type or current_sector + current_count != sector:
            yield (current_type, current_sector, current_count)

            current_type = run_type
            current_sector = sector
            current_count = count
        else:
            current_count += count

    if current_type is not None:
        yield (current_type, current_sector, current_count)


def is_bde_volume(fh: BinaryIO) -> bool:
    stored_position = fh.tell()
    try:
        fh.seek(0)
        BootSector(fh)
    except ValueError:
        return False
    else:
        return True
    finally:
        fh.seek(stored_position)
