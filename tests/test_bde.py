from __future__ import annotations

import contextlib
import struct
from typing import BinaryIO

import pytest

from dissect.fve.bde import bde, c_bde, is_bde_volume
from tests._utils import open_file, open_file_gz


def _verify_crypto_stream(bde_obj: bde.BDE) -> None:
    stream = bde_obj.open()
    assert stream.read(512)[3:11] == b"NTFS    "

    # 0x2000 is outside the Vista plain text and the default Bitlocker 2 virtualized region
    stream.seek(0x2000)
    assert stream.read(512)[:8] == b"FILE0\x00\x03\x00"


def _verify_passphrase_crypto(test_file: BinaryIO, passphrase: str, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_passphrase()
    bde_obj.unlock_with_passphrase(passphrase)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_recovery_password_crypto(
    test_file: BinaryIO, recovery_password: str, fvek_type: c_bde.FVE_KEY_TYPE
) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password(recovery_password)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_bek_crypto(test_file: BinaryIO, bek_file: BinaryIO, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_bek()
    bde_obj.unlock_with_bek(bek_file)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def test_bde_basic(bde_aes_128: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_aes_128)

    assert bde_obj.sector_size == 512
    assert bde_obj.version == 2

    assert len(bde_obj._available_information) == len(bde_obj._valid_information) == 3

    dataset = bde_obj.information.dataset
    assert len(dataset.data) == 4
    assert bde_obj.description() == "DESKTOP-QNI1MMF TestVolume 10/8/2021"

    assert bde_obj.reserved_regions() == [(69504, 128), (69632, 16), (84528, 128), (99544, 128)]


def test_bde_decrypted(bde_decrypted: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_decrypted)

    assert bde_obj.decrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.DECRYPTED
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert not stream.encrypted
    assert stream.read(512)[3:11] == b"NTFS    "


def test_bde_suspended(bde_suspended: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_suspended)

    assert bde_obj.has_clear_key()
    bde_obj.unlock_with_clear_key()

    stream = bde_obj.open()
    assert stream.encrypted
    assert stream.read(512)[3:11] == b"NTFS    "


@pytest.mark.parametrize(
    ("test_file", "passphrase", "key_type"),
    [
        ("_data/bde/aes_128.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_128),
        ("_data/bde/aes_256.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_256),
        ("_data/bde/aes_128_diffuser.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER),
        ("_data/bde/aes_256_diffuser.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER),
        ("_data/bde/aes-xts_128.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_XTS_128),
        ("_data/bde/aes-xts_256.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_XTS_256),
    ],
)
def test_bde_passphrase(test_file: str, passphrase: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_passphrase_crypto(fh, passphrase, key_type)


@pytest.mark.parametrize(
    ("test_file", "recovery", "key_type"),
    [
        (
            "_data/bde/recovery_password.bin.gz",
            "284867-596541-514998-422114-660297-261613-215424-199408",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_recovery(test_file: str, recovery: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_recovery_password_crypto(fh, recovery, key_type)


@pytest.mark.parametrize(
    ("test_file", "bek_file", "key_type"),
    [
        (
            "_data/bde/recovery_key.bin.gz",
            "_data/bde/recovery_key.bek",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
        (
            "_data/bde/startup_key.bin.gz",
            "_data/bde/startup_key.bek",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_bek(test_file: str, bek_file: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with (
        contextlib.contextmanager(open_file_gz)(test_file) as fh,
        contextlib.contextmanager(open_file)(bek_file) as bek_fh,
    ):
        _verify_bek_crypto(fh, bek_fh, key_type)


def test_bde_vista(bde_vista: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_vista)

    assert bde_obj.version == 1

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password("517506-503998-044583-576191-587004-635965-501270-087802")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    bde_obj.fh.seek(0)

    patched_sector = bytearray(bde_obj.fh.read(512))
    bde_sector = stream.read(512)

    patched_sector[0x03:0x0B] = b"NTFS    "
    patched_sector[0x38:0x40] = struct.pack("<Q", bde_obj.information.header.Mft2StartLcn)

    assert bde_sector == patched_sector


def test_bde_win7_partial(bde_win7_partial: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_win7_partial)

    assert bde_obj.version == 2

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password("131450-120197-153989-250338-511368-495572-680944-381546")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert list(stream._iter_runs(bde_obj.information.state_offset - 512, 1024)) == [
        (stream.RUN_ENCRYPTED, 2234023, 1),
        (stream.RUN_PLAIN, 2234024, 1),
    ]


def test_bde_eow_partial(bde_eow_partial: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_eow_partial)

    assert bde_obj.version == 2
    assert bde_obj.eow_information

    assert bde_obj.has_passphrase()
    bde_obj.unlock_with_passphrase("password12!@")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert list(stream._iter_runs(0x2202000, 0x800000 * 33)) == [
        (0, 69648, 233328),
        (2, 302976, 128),
        (0, 303104, 98304),
        (3, 401408, 135040),
        (2, 536448, 128),
        (3, 536576, 73744),
    ]


def test_is_bde_volume(bde_aes_128: BinaryIO) -> None:
    assert is_bde_volume(bde_aes_128)
