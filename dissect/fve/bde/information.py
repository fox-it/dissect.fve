from __future__ import annotations

import hashlib
from binascii import crc32
from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from Crypto.Cipher import AES
from dissect.util import ts

from dissect.fve.bde.c_bde import (
    BITLOCKER_SIGNATURE,
    FVE_DATUM_ROLE,
    FVE_DATUM_TYPE,
    FVE_KEY_FLAG,
    FVE_KEY_PROTECTOR,
    FVE_KEY_TYPE,
    FVE_STATE,
    c_bde,
)
from dissect.fve.exceptions import InvalidHeaderError

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator


class Information:
    """Bitlocker Information.

    Parses Bitlocker Information and Dataset at a specified offset.

    Bitlocker Information consists of a small header, a Dataset and at least a CRC32 validation check.
    The CRC32 Validation information is positioned after the Information buffer.

    The ``StateOffset`` field contains the offset to a conversion log, but it also doubles as a "watermark",
    containing the offset up until where the Bitlocker encryption is active.
    The conversion log as pointed to by the ``StateOffset`` seems to only be used by older Bitlocker
    implementations. It looks like more modern implementations (Windows 10+) seem to prefer EOW.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        self.offset = offset
        fh.seek(offset)

        self.header = c_bde.FVE_INFORMATION(fh)
        if self.header.Signature != BITLOCKER_SIGNATURE:
            raise InvalidHeaderError("Invalid BDE information signature")

        # Datums are lazily parsed so we can safely parse the dataset header
        self.dataset = Dataset(fh)

        fh.seek(offset)
        self._buf = fh.read(self.size)

        self.validation = Validation(fh)
        self._valid_checksum = crc32(self._buf) == self.validation.crc32

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"offset=0x{self.offset:x} current_state={self.current_state} next_state={self.next_state}>"
        )

    def is_valid(self) -> bool:
        """Validate the integrity of this Information block."""
        # TODO add sha256 check
        return self._valid_checksum

    def check_integrity(self, key: KeyDatum | bytes) -> bool:
        """Check the integrity of this Information block."""
        if self.validation.integrity_check:
            datum = self.validation.integrity_check.unbox(key)
            return hashlib.sha256(self._buf).digest() == datum.data
        return self.is_valid()

    @property
    def size(self) -> int:
        stored_size = self.header.HeaderSize
        if self.version >= 2:
            stored_size <<= 4
        return stored_size

    @property
    def version(self) -> int:
        return self.header.Version

    @property
    def current_state(self) -> FVE_STATE:
        return FVE_STATE(self.header.CurrentState)

    @property
    def next_state(self) -> FVE_STATE:
        return FVE_STATE(self.header.NextState)

    @property
    def state_offset(self) -> int:
        return self.header.StateOffset

    @property
    def state_size(self) -> int:
        return self.header.StateSize

    @property
    def virtualized_sectors(self) -> int:
        return self.header.VirtualizedSectors

    @property
    def virtualized_block_offset(self) -> int:
        return self.header.VirtualizedBlockOffset

    @property
    def information_offset(self) -> list[int]:
        return self.header.InformationOffset


class Validation:
    """Bitlocker Information Validation.

    The Validation structure is a small piece of data positioned after the Information buffer.
    It contains a CRC32 value of the entire Information buffer. It also contains an integrity check
    datum, which is a AES-CCM encrypted datum, encrypted with the same key that decrypts the FVEK.
    Decrypting the integrity check yields you a SHA256 digest, which must match the entire Information buffer.
    """

    def __init__(self, fh: BinaryIO):
        self.validation = c_bde.FVE_VALIDATION(fh)
        self.integrity_check = None
        if self.version >= 2:  # I think
            self.integrity_check = Datum.from_fh(fh)

    @property
    def version(self) -> int:
        return self.validation.Version

    @property
    def crc32(self) -> int:
        return self.validation.Crc32


class Dataset:
    """Bitlocker Information Dataset.

    The dataset is a simple data structure, consisting of a small header and one or more "datum".
    Each datum has a role and type, and you can query the dataset for datums with a specific role or type.
    Querying the dataset means iterating the datum array until you found the datum you're looking for.
    """

    def __init__(self, fh: BinaryIO):
        offset = fh.tell()
        self.header = c_bde.FVE_DATASET(fh)
        self.identifier = UUID(bytes_le=self.header.Identification)

        fh.seek(offset)
        self._buf = fh.read(self.header.Size)

    def __iter__(self) -> Iterator[Datum]:
        yield from self.data

    @cached_property
    def data(self) -> list[Datum]:
        """Return the list of Datum in this Dataset."""
        result = []

        buf = BytesIO(memoryview(self._buf)[self.header.StartOffset :])
        remaining = self.header.EndOffset - self.header.StartOffset
        while remaining >= Datum.MINIMAL_SIZE:
            datum = Datum.from_fh(buf)
            result.append(datum)

            remaining -= datum.size

        return result

    @property
    def fvek_type(self) -> FVE_KEY_TYPE:
        return FVE_KEY_TYPE(self.header.FvekType)

    def find_datum(self, role: FVE_DATUM_ROLE, type_: FVE_DATUM_TYPE) -> Iterator[Datum]:
        """Find one or more datum specified by role and type."""
        for datum in self:
            if (datum.role == role or role is None) and (datum.type == type_ or type_ is None):
                yield datum

    def find_description(self) -> str | None:
        """Find the description datum."""
        for datum in self.find_datum(FVE_DATUM_ROLE.DESCRIPTION, FVE_DATUM_TYPE.UNICODE):
            return datum.text
        return None

    def find_virtualization_info(self) -> VirtualizationInfoDatum | None:
        """Find the virtualization info datum."""
        for datum in self.find_datum(FVE_DATUM_ROLE.VIRTUALIZATION_INFO, FVE_DATUM_TYPE.VIRTUALIZATION_INFO):
            return datum
        return None

    def find_startup_key(self) -> ExternalInfoDatum | None:
        """Find the external startup/recovery key information."""
        for datum in self.find_datum(FVE_DATUM_ROLE.STARTUP_KEY, FVE_DATUM_TYPE.EXTERNAL_INFO):
            return datum
        return None

    def find_fvek(self) -> AesCcmEncryptedDatum | None:
        """Find the encrypted FVEK."""
        for datum in self.find_datum(FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY, FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY):
            return datum
        return None

    def find_vmk(
        self,
        protector_type: FVE_KEY_PROTECTOR | None = None,
        min_priority: int = 0x0000,
        max_priority: int = 0x7FFF,
        mask: int = 0xFF00,
    ) -> Iterator[VmkInfoDatum]:
        """Find one or more VMK datum specified by key priority."""
        for datum in self.find_datum(FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO, FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO):
            if datum.priority.value < min_priority or datum.priority.value > max_priority:
                continue

            if protector_type is None or datum.priority & mask == protector_type:
                yield datum

    def find_clear_vmk(self) -> VmkInfoDatum | None:
        """Find the clear key VMK (for paused volumes)."""
        for vmk in self.find_vmk(FVE_KEY_PROTECTOR.CLEAR, max_priority=0xFF, mask=0x0000):
            return vmk
        return None

    def find_external_vmk(self) -> Iterator[VmkInfoDatum]:
        """Find the external VMK."""
        yield from self.find_vmk(FVE_KEY_PROTECTOR.EXTERNAL)

    def find_recovery_vmk(self) -> Iterator[VmkInfoDatum]:
        """Find the recovery VMK."""
        yield from self.find_vmk(FVE_KEY_PROTECTOR.RECOVERY_PASSWORD)

    def find_passphrase_vmk(self) -> Iterator[VmkInfoDatum]:
        """Find the passphrase VMK."""
        yield from self.find_vmk(FVE_KEY_PROTECTOR.PASSPHRASE)


class Datum:
    """Bitlocker Dataset Datum.

    A Datum is the main metadata structure in Bitlocker. It's a small data structure, specifying a
    size, role and type, followed by the necessary data to interpret that datum type.

    Datums can be "complex", in which case they can contain nested datums. These nested datums always
    have the PROPERTY role.

    Datums can also have a data segment. A data segment is present if a datum is not complex, but contains
    data beyond the size of that datums' type structure.

    Originally, this information is stored in a table, also containing a type's minimal size. This implementation
    doesn't currently do that, instead relying on the reading from a file handle with cstruct. Whatever is left
    on the file handle is the data segment.
    """

    __struct__ = None
    __complex__ = False

    MINIMAL_SIZE = len(c_bde.FVE_DATUM)

    def __init__(self, fh: BinaryIO):
        self.header = c_bde.FVE_DATUM(fh)
        self._data = fh.read(self.data_size)

        buf = BytesIO(self._data)
        self._datum = self.__struct__(buf) if self.__struct__ else None
        self.data_segment = buf.read() if not self.__complex__ else None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} type={self.type.name}>"

    @property
    def role(self) -> FVE_DATUM_ROLE:
        return FVE_DATUM_ROLE(self.header.Role)

    @property
    def type(self) -> FVE_DATUM_TYPE:
        return FVE_DATUM_TYPE(self.header.Type)

    @property
    def size(self) -> int:
        return self.header.Size

    @property
    def data_size(self) -> int:
        return self.size - self.MINIMAL_SIZE

    @cached_property
    def properties(self) -> list[Datum]:
        """Return a list of property datum if this datum is complex."""
        result = []

        if self.__complex__:
            remaining = self.data_size - len(self.__struct__)
            buf = BytesIO(memoryview(self._data)[len(self.__struct__) :])
            while remaining >= self.MINIMAL_SIZE:
                nested = Datum.from_fh(buf)
                result.append(nested)

                remaining -= nested.size

        return result

    @classmethod
    def from_fh(cls, fh: BinaryIO) -> Datum:
        """Read a datum from a file handle."""
        offset = fh.tell()
        header = c_bde.FVE_DATUM(fh)
        fh.seek(offset)

        return DATUM_TYPE_MAP.get(FVE_DATUM_TYPE(header.Type), Datum)(fh)

    @classmethod
    def from_bytes(cls, buf: bytes) -> Datum:
        """Read a datum from raw bytes."""
        return cls.from_fh(BytesIO(buf))

    def find_property(self, type_: FVE_DATUM_TYPE | None) -> Iterator[Datum]:
        """Find one or more datum with a specified type within the properties."""
        for datum in self.properties:
            if datum.type == type_ or type_ is None:
                yield datum


class SimpleDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_SIMPLE

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} data={self.data}>"

    @property
    def data(self) -> int:
        return self._datum.Data


class SimpleLargeDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_SIMPLE_LARGE

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} data={self.data}>"

    @property
    def data(self) -> int:
        return self._datum.Data


class GuidDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_GUID

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} guid={self.guid}>"

    @property
    def guid(self) -> UUID:
        return UUID(bytes_le=self._datum.Guid)


class KeyDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_KEY

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} key_type={self.key_type} key_flags={self.key_flags}>"

    @property
    def key_type(self) -> FVE_KEY_TYPE:
        return FVE_KEY_TYPE(self._datum.KeyType)

    @property
    def key_flags(self) -> FVE_KEY_FLAG:
        return FVE_KEY_FLAG(self._datum.KeyFlags)

    @property
    def data(self) -> bytes:
        return self._data[len(KeyDatum.__struct__) :]


class UnicodeDatum(Datum):
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} text={self.text}>"

    @property
    def text(self) -> str:
        return self._data.decode("utf-16-le").rstrip("\x00")


class StretchKeyDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_STRETCH_KEY
    __complex__ = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} key_type={self.key_type} key_flags={self.key_flags}>"

    @property
    def key_type(self) -> FVE_KEY_TYPE:
        return FVE_KEY_TYPE(self._datum.KeyType)

    @property
    def key_flags(self) -> FVE_KEY_FLAG:
        return FVE_KEY_FLAG(self._datum.KeyFlags)

    @property
    def salt(self) -> bytes:
        return self._datum.Salt


class UseKeyDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_USE_KEY
    __complex__ = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} key_type={self.key_type} key_flags={self.key_flags}>"

    @property
    def key_type(self) -> FVE_KEY_TYPE:
        return FVE_KEY_TYPE(self._datum.KeyType)

    @property
    def key_flags(self) -> FVE_KEY_FLAG:
        return FVE_KEY_FLAG(self._datum.KeyFlags)


class AesCcmEncryptedDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_AESCCM_ENC

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} role={self.role.name} "
            f"nonce_time={self.nonce_time} nonce_counter={self.nonce_counter}>"
        )

    @property
    def nonce(self) -> bytes:
        return self._data[: len(c_bde.FVE_NONCE)]

    @property
    def nonce_time(self) -> datetime.datetime | int:
        try:
            return ts.wintimestamp(self._datum.Nonce.DateTime)
        except ValueError:
            return self._datum.Nonce.DateTime

    @property
    def nonce_counter(self) -> int:
        return self._datum.Nonce.Counter

    @property
    def mac(self) -> bytes:
        return self._datum.MAC

    @property
    def data(self) -> bytes:
        return self._data[len(self.__struct__) :]

    def unbox(self, key: KeyDatum | bytes) -> Datum:
        key = key.data if isinstance(key, KeyDatum) else key
        cipher = AES.new(key, AES.MODE_CCM, nonce=self.nonce)
        decrypted_data = cipher.decrypt_and_verify(self.data, self.mac)
        return Datum.from_bytes(decrypted_data)


class TpmEncryptedBlobDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_TPM_ENC_BLOB

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} pcr_bitmap={self.pcr_bitmap}>"

    @property
    def pcr_bitmap(self) -> int:
        return self._datum.PcrBitmap

    @property
    def data(self) -> bytes:
        return self._data[len(self.__struct__) :]


class ValidationEntry:
    def __init__(self, fh: BinaryIO):
        self._entry = c_bde.FVE_DATUM_VALIDATION_ENTRY(fh)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} hash={self.hash}>"

    @property
    def hash(self) -> bytes:
        return self._entry.Hash


class ValidationInfoDatum(Datum):
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name} allow_list={self.allow_list}>"

    @property
    def allow_list(self) -> list[ValidationEntry]:
        fh = BytesIO(self._data)
        return [ValidationEntry(fh) for _ in range(len(self._data) // len(c_bde.FVE_DATUM_VALIDATION_ENTRY))]


class VmkInfoDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_VMK_INFO
    __complex__ = True

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} role={self.role.name} identifier={self.identifier} "
            f"datetime={self.datetime} priority={self.priority}>"
        )

    @property
    def identifier(self) -> UUID:
        return UUID(bytes_le=self._datum.Identifier)

    @property
    def datetime(self) -> datetime.datetime:
        return ts.wintimestamp(self._datum.DateTime)

    @property
    def priority(self) -> FVE_KEY_PROTECTOR:
        return FVE_KEY_PROTECTOR(self._datum.Priority)

    def decrypt(self, key: KeyDatum | bytes) -> KeyDatum:
        encrypted_key = self.aes_ccm_encrypted_key()
        return encrypted_key.unbox(key)

    def label(self) -> str | None:
        for datum in self.find_property(FVE_DATUM_TYPE.UNICODE):
            return datum.text
        return None

    def asymmetric_encrypted_key(self) -> AsymmetricEncryptedDatum | None:
        for datum in self.find_property(FVE_DATUM_TYPE.ASYMMETRIC_ENCRYPTED_KEY):
            return datum
        return None

    def exported_key(self) -> ExportedPublicKeyDatum | None:
        for datum in self.find_property(FVE_DATUM_TYPE.EXPORTED_KEY):
            return datum
        return None

    def tpm_encrypted_blob(self) -> TpmEncryptedBlobDatum | None:
        for datum in self.find_property(FVE_DATUM_TYPE.TPM_ENCRYPTED_BLOB):
            return datum
        return None

    def aes_ccm_encrypted_key(self) -> AesCcmEncryptedDatum | None:
        for datum in self.find_property(FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY):
            return datum
        return None

    def public_key_info(self) -> PublicKeyInfoDatum | None:
        for datum in self.find_property(FVE_DATUM_TYPE.PUBLIC_KEY_INFO):
            return datum
        return None

    def use_keys(self) -> list[UseKeyDatum]:
        return list(self.find_property(FVE_DATUM_TYPE.USE_KEY))

    def use_key(self, key_type: FVE_KEY_TYPE) -> UseKeyDatum | None:
        for datum in self.use_keys():
            if key_type is None or datum.key_type == key_type:
                return datum
        return None

    def stretch_keys(self) -> list[StretchKeyDatum]:
        return list(self.find_property(FVE_DATUM_TYPE.STRETCH_KEY))

    def stretch_key(self, key_type: FVE_KEY_TYPE) -> StretchKeyDatum | None:
        for datum in self.stretch_keys():
            if key_type is None or datum.key_type == key_type:
                return datum
        return None

    def clear_key(self) -> KeyDatum | None:
        for datum in self.find_property(FVE_DATUM_TYPE.KEY):
            return datum
        return None

    def is_enhanced_pin(self) -> bool:
        for stretch_key in self.stretch_keys():
            if stretch_key.key_type == FVE_KEY_TYPE.AES_CCM_256_2 and stretch_key.key_flags & FVE_KEY_FLAG.ENHANCED_PIN:
                return True
        return False

    def is_enhanced_crypto(self) -> bool:
        for stretch_key in self.stretch_keys():
            if (
                stretch_key.key_type == FVE_KEY_TYPE.AES_CCM_256_2
                and stretch_key.key_flags & FVE_KEY_FLAG.ENHANCED_CRYPTO
            ):
                return True
        return False

    def uses_pbkdf2(self) -> bool:
        for stretch_key in self.stretch_keys():
            if (
                stretch_key.type in (FVE_KEY_TYPE.STRETCH_KEY, FVE_KEY_TYPE.STRETCH_KEY_1, FVE_KEY_TYPE.AES_CCM_256_2)
                and stretch_key.key_flags & FVE_KEY_FLAG.PBKDF2
            ):
                return True
        return False


class ExternalInfoDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_EXTERNAL_INFO
    __complex__ = True

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} role={self.role.name} identifier={self.identifier} datetime={self.datetime}>"
        )

    @property
    def identifier(self) -> UUID:
        return UUID(bytes_le=self._datum.Identifier)

    @property
    def datetime(self) -> datetime.datetime:
        return ts.wintimestamp(self._datum.DateTime)

    def label(self) -> str | None:
        for datum in self.find_property(FVE_DATUM_TYPE.UNICODE):
            return datum.text
        return None

    def external_key(self) -> KeyDatum | None:
        for datum in self.find_property(FVE_DATUM_TYPE.KEY):
            return datum
        return None


class UpdateDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_UPDATE
    __complex__ = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"


class ErrorLogDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_ERROR_LOG

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"


class AsymmetricEncryptedDatum(Datum):
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"

    @property
    def data(self) -> bytes:
        return self._data


class ExportedPublicKeyDatum(Datum):
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"

    @property
    def data(self) -> bytes:
        return self._data


class PublicKeyInfoDatum(Datum):
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"

    @property
    def data(self) -> bytes:
        return self._data


class VirtualizationInfoDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_VIRTUALIZATION_INFO

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} role={self.role.name} "
            f"virtualized_block_offset=0x{self.virtualized_block_offset:x} "
            f"virtualized_block_size=0x{self.virtualized_block_size:x}>"
        )

    @property
    def virtualized_block_offset(self) -> int:
        return self._datum.VirtualizedBlockOffset

    @property
    def virtualized_block_size(self) -> int:
        return self._datum.VirtualizedBlockSize


class ConcatHashKeyDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_CONCAT_HASH_KEY

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"


class BackupInfoDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_BACKUP_INFO

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"


class AesCbc256HmacSha512EncryptedDatum(Datum):
    __struct__ = c_bde.FVE_DATUM_AESCBC256_HMAC_SHA512_ENC

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} role={self.role.name}>"

    @property
    def iv(self) -> bytes:
        return self._datum.Iv

    @property
    def mac(self) -> bytes:
        return self._datum.Mac

    @property
    def data(self) -> bytes:
        return self._data[len(self.__struct__) :]


DATUM_TYPE_MAP = {
    FVE_DATUM_TYPE.KEY: KeyDatum,
    FVE_DATUM_TYPE.UNICODE: UnicodeDatum,
    FVE_DATUM_TYPE.STRETCH_KEY: StretchKeyDatum,
    FVE_DATUM_TYPE.USE_KEY: UseKeyDatum,
    FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY: AesCcmEncryptedDatum,
    FVE_DATUM_TYPE.TPM_ENCRYPTED_BLOB: TpmEncryptedBlobDatum,
    FVE_DATUM_TYPE.VALIDATION_INFO: ValidationInfoDatum,
    FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO: VmkInfoDatum,
    FVE_DATUM_TYPE.EXTERNAL_INFO: ExternalInfoDatum,
    FVE_DATUM_TYPE.UPDATE: UpdateDatum,
    FVE_DATUM_TYPE.ERROR_LOG: ErrorLogDatum,
    FVE_DATUM_TYPE.ASYMMETRIC_ENCRYPTED_KEY: AsymmetricEncryptedDatum,
    FVE_DATUM_TYPE.EXPORTED_KEY: ExportedPublicKeyDatum,
    FVE_DATUM_TYPE.PUBLIC_KEY_INFO: PublicKeyInfoDatum,
    FVE_DATUM_TYPE.VIRTUALIZATION_INFO: VirtualizationInfoDatum,
    FVE_DATUM_TYPE.SIMPLE_1: SimpleDatum,
    FVE_DATUM_TYPE.SIMPLE_2: SimpleDatum,
    FVE_DATUM_TYPE.CONCAT_HASH_KEY: ConcatHashKeyDatum,
    FVE_DATUM_TYPE.SIMPLE_3: SimpleDatum,
    FVE_DATUM_TYPE.SIMPLE_LARGE: SimpleLargeDatum,
    FVE_DATUM_TYPE.BACKUP_INFO: BackupInfoDatum,
}
