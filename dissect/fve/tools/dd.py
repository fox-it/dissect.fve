from __future__ import annotations

import argparse
import io
import sys
import traceback
from pathlib import Path
from typing import BinaryIO

from dissect.target import container, volume

from dissect.fve.bde import BDE, is_bde_volume
from dissect.fve.luks import LUKS, is_luks_volume
from dissect.fve.luks.luks import CryptStream

try:
    from rich.progress import (
        BarColumn,
        DownloadColumn,
        Progress,
        TextColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )

    progress = Progress(
        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
        transient=True,
    )

    log = progress.console.log
except ImportError:

    class Progress:
        def __init__(self):
            self.filename = None
            self.total = None

            self.position = 0

        def __enter__(self) -> None:
            pass

        def __exit__(self, *args, **kwargs) -> None:
            sys.stderr.write("\n")
            sys.stderr.flush()

        def add_task(self, name: str, filename: str, total: int, **kwargs) -> None:
            self.filename = filename
            self.total = total

        def update(self, task_id: int, advance: int) -> None:
            self.position += advance

            sys.stderr.write(f"\r{self.filename} {(self.position / self.total) * 100:0.2f}%")
            sys.stderr.flush()

    import logging

    progress = Progress()

    logger = logging.getLogger(__name__)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    stream_handler.setLevel(logging.INFO)
    logger.addHandler(stream_handler)
    logger.setLevel(logging.INFO)

    log = logger.info


def stream(
    fhin: BinaryIO,
    fhout: BinaryIO,
    offset: int,
    length: int,
    chunk_size: int = io.DEFAULT_BUFFER_SIZE,
    task_id: int | None = None,
) -> None:
    fhin.seek(offset)
    while length != 0:
        read_size = min(length, chunk_size)
        fhout.write(fhin.read(read_size))

        progress.update(task_id, advance=read_size)

        length -= read_size


def open_fve(vol: BinaryIO, args: argparse.Namespace) -> BinaryIO:
    # Currently only BDE and LUKS
    if is_bde_volume(vol):
        return _open_bde(vol, args)

    if is_luks_volume(vol):
        return _open_luks(vol, args)

    # Plain volume, return itself
    return vol


def _open_bde(vol: BinaryIO, args: argparse.Namespace) -> BinaryIO | None:
    bde = BDE(vol)

    if bde.has_clear_key():
        bde.unlock_with_clear_key()
    else:
        if args.passphrase and bde.has_passphrase():
            try:
                bde.unlock_with_passphrase(args.passphrase)
                log("Unlocked BDE volume with passphrase")
            except Exception as e:
                log(f"Failed to unlock BDE volume with passphrase: {e}")

        elif args.recovery and bde.has_recovery_password():
            try:
                bde.unlock_with_recovery_password(args.recovery)
                log("Unlocked BDE volume with recovery password")
            except Exception as e:
                log(f"Failed to unlock BDE volume with recovery password: {e}")

        elif args.unlock_file:
            try:
                with args.unlock_file.open("rb") as fh:
                    bde.unlock_with_bek(fh)
                log("Unlocked BDE volume with BEK")
            except Exception as e:
                log(f"Failed to unlock BDE volume with BEK: {e}")

    if not bde.unlocked:
        log("Failed to unlock BDE volume")
        return None

    return bde.open()


def _open_luks(vol: BinaryIO, args: argparse.Namespace) -> BinaryIO | None:
    luks = LUKS(vol)

    if args.passphrase:
        try:
            luks.unlock_with_passphrase(args.passphrase, args.key_slot)
            log("Unlocked LUKS volume with passphrase")
        except Exception as e:
            log(f"Failed to unlock LUKS volume with passphrase: {e}")
    elif args.unlock_file:
        try:
            luks.unlock_with_key_file(args.unlock_file, args.keyfile_offset, args.keyfile_size, args.key_slot)
            log("Unlocked LUKS volume with key file")
        except Exception as e:
            log(f"Failed to unlock LUKS volume with key file: {e}")

    if not luks.unlocked:
        log("Failed to unlock LUKS volume")
        return None

    return luks.open()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="path to container with encrypted volume")
    parser.add_argument("-p", "--passphrase", type=str, help="user passphrase")
    parser.add_argument("-r", "--recovery", type=str, help="recovery passphrase")
    parser.add_argument("-f", "--unlock-file", type=Path, help="unlock file")
    parser.add_argument("--key-slot", type=int, help="LUKS keyslot")
    parser.add_argument("--keyfile-offset", type=int, help="LUKS keyfile offset")
    parser.add_argument("--keyfile-size", type=int, help="LUKS keyfile size")
    parser.add_argument("-o", "--output", type=Path, required=True, help="path to output file")
    parser.add_argument("-v", "--verbose", action="count", default=3, help="increase output verbosity")
    args = parser.parse_args()

    in_path = args.input.resolve()

    if not in_path.exists():
        parser.exit(f"Input file doesn't exist: {in_path}")

    disk = container.open(in_path)
    try:
        vs = volume.open(disk)
        disk_volumes = vs.volumes
    except Exception:
        log("Container has no volume system, treating as raw instead")
        disk_volumes = [volume.Volume(disk, 1, 0, disk.size, None, None, disk=disk)]

    volumes = []
    for vol in disk_volumes:
        fve_vol = None

        try:
            fve_vol = open_fve(vol, args)
        except Exception:
            log(traceback.format_exc())
            log("Exception opening FVE volume")

        if fve_vol is None:
            parser.exit(f"Failed to open FVE volume: {vol}")
        else:
            volumes.append((vol, fve_vol))

    task_id = progress.add_task("decrypt", start=True, visible=True, filename=in_path.name, total=disk.size)

    offset = 0
    with progress, args.output.open("wb") as fh:
        for vol, fve_vol in volumes:
            if offset != vol.offset:
                # We're not to the beginning of the volume yet, fill in
                stream(disk, fh, offset, vol.offset - offset, task_id=task_id)
                offset = vol.offset

            # Stream the decrypted volume
            src_vol = fve_vol or vol
            stream(src_vol, fh, 0, src_vol.size, task_id=task_id)
            offset += src_vol.size

            if isinstance(fve_vol, CryptStream):
                # LUKS volumes don't actually start at the beginning like Bitlocker
                offset += fve_vol.offset

        # There's data after the volumes until the end of the disk
        if offset != disk.size:
            stream(disk, fh, offset, disk.size - offset, task_id=task_id)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
