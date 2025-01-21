# References:
# - fvevol.sys

from __future__ import annotations

from binascii import crc32
from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.bde.c_bde import (
    EOW_BM_SIGNATURE,
    EOW_BR_SIGNATURE,
    EOW_SIGNATURE,
    c_bde,
)
from dissect.fve.exceptions import InvalidHeaderError

if TYPE_CHECKING:
    from collections.abc import Iterator


class EowInformation:
    """Bitlocker EOW Information."""

    def __init__(self, fh: BinaryIO, offset: int):
        self.fh = fh
        self.offset = offset
        fh.seek(offset)

        self.header = c_bde.FVE_EOW_INFORMATION(fh)
        if self.header.HeaderSignature != EOW_SIGNATURE:
            raise InvalidHeaderError("Invalid EOW information signature")

        _crc32 = self.header.Crc32
        self.header.Crc32 = 0
        self._valid_checksum = crc32(self.header.dumps()) == _crc32
        self.header.Crc32 = _crc32

    def is_valid(self) -> bool:
        return self._valid_checksum

    @property
    def size(self) -> int:
        return self.header.Size

    @property
    def chunk_size(self) -> int:
        return self.header.ChunkSize

    @property
    def conv_log_size(self) -> int:
        return self.header.ConvLogSize

    @cached_property
    def bitmaps(self) -> list[EowBitmap]:
        return [EowBitmap(self.fh, offset) for offset in self.header.BitmapOffsets]


class EowBitmap:
    """Bitlocker EOW Bitmap.

    A bitmap contains multiple bitmap records, but only one record is active. The active record is
    determined by the Lsn field in the header. The record with the highest Lsn is the active record.

    It looks like the number of bitmap records is hardcoded to 2, but let's keep the implementation
    flexible.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        self.fh = fh
        self.offset = offset
        fh.seek(offset)

        self.header = c_bde.FVE_EOW_BITMAP(fh)
        if self.header.HeaderSignature != EOW_BM_SIGNATURE:
            raise ValueError("Invalid EOW bitmap signature")

        _crc32 = self.header.Crc32
        self.header.Crc32 = 0
        remainder = fh.read(self.header.RecordOffset[0] - self.header.HeaderSize)
        self._valid_checksum = crc32(self.header.dumps() + remainder) == _crc32
        self.header.Crc32 = _crc32

        self._record_data = fh.read(self.header.Size - self.header.RecordOffset[0])

    def __repr__(self) -> str:
        return f"<EowBitmap region_offset=0x{self.region_offset:x} region_size=0x{self.region_size:x}>"

    def is_valid(self) -> bool:
        return self._valid_checksum

    def runs(self, chunk: int, length: int) -> Iterator[tuple[int, int]]:
        yield from self.active_record.runs(chunk, length)

    @property
    def size(self) -> int:
        return self.header.Size

    @property
    def region_offset(self) -> int:
        return self.header.RegionOffset

    @property
    def region_size(self) -> int:
        return self.header.RegionSize

    @property
    def conv_log_offset(self) -> int:
        return self.header.ConvLogOffset

    @cached_property
    def active_record(self) -> EowBitmapRecord:
        latest_record = None

        for record in self.records:
            if latest_record is None:
                latest_record = record
                continue

            if record.sequence_number > latest_record.sequence_number:
                latest_record = record

        return latest_record

    @cached_property
    def records(self) -> list[EowBitmapRecord]:
        result = []

        buf = BytesIO(self._record_data)
        base = self.header.RecordOffset[0]
        for offset in self.header.RecordOffset:
            buf.seek(offset - base)
            result.append(EowBitmapRecord(buf))

        return result


class EowBitmapRecord:
    """Bitlocker EOW Bitmap Record.

    The record holding the actual bitmap. Each bit indicates a chunk with the size defined by
    the EOW information. The Lsn is the sequence number of that record.

    The flags are currently unknown, but seem related to an encrypted/decrypted state.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_bde.FVE_EOW_BITMAP_RECORD(fh)
        if self.header.HeaderSignature != EOW_BR_SIGNATURE:
            raise ValueError("Invalid EOW bitmap record signature")

        _crc32 = self.header.Crc32
        self.header.Crc32 = 0
        self._data = memoryview(fh.read(self.header.Size - self.header.HeaderSize))
        self._valid_checksum = crc32(self.header.dumps() + self._data) == _crc32
        self.header.Crc32 = _crc32

    def __repr__(self) -> str:
        return f"<EowBitmapRecord sequence_number={self.sequence_number} bitmap_size=0x{self.bitmap_size:x}>"

    def is_valid(self) -> bool:
        return self._valid_checksum

    def runs(self, chunk: int, length: int) -> Iterator[tuple[int, int]]:
        yield from _iter_bitmap(self.bitmap, self.bitmap_size, chunk, length)

    @property
    def size(self) -> int:
        return self.header.Size

    @property
    def bitmap(self) -> bytes:
        return self._data

    @property
    def bitmap_size(self) -> int:
        return self.header.BitmapSize

    @property
    def sequence_number(self) -> int:
        return self.header.SequenceNumber


def _iter_bitmap(bitmap: bytes, size: int, start: int, count: int) -> Iterator[tuple[int, int]]:
    byte_idx, bit_idx = divmod(start, 8)
    remaining_bits = size - start
    current_bit = (bitmap[byte_idx] & (1 << bit_idx)) >> bit_idx
    current_count = 0

    for byte in bitmap[byte_idx:]:
        if count == 0 or remaining_bits == 0:
            break

        if (current_bit, byte) == (0, 0) or (current_bit, byte) == (1, 0xFF):
            max_count = min(count, remaining_bits, 8 - bit_idx)
            current_count += max_count
            remaining_bits -= max_count
            count -= max_count
            bit_idx = 0
        else:
            for cur_bit_idx in range(bit_idx, min(count, remaining_bits, 8)):
                bit_set = (byte & (1 << cur_bit_idx)) >> cur_bit_idx

                if bit_set == current_bit:
                    current_count += 1
                else:
                    yield (current_bit, current_count)
                    current_bit = bit_set
                    current_count = 1

                remaining_bits -= 1
                count -= 1

    if current_count:
        yield (current_bit, current_count)
