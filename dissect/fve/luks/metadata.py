from __future__ import annotations

import base64
import json
import sys
from dataclasses import dataclass, field, fields

if sys.version_info >= (3, 10):
    from types import UnionType  # novermin
else:
    # Python 3.9
    from typing import Union as UnionType

from typing import Any, Optional, get_args, get_origin, get_type_hints

from dissect.fve.luks.c_luks import c_luks


@dataclass
class JsonItem:
    _raw: dict | None = field(init=False, repr=False)

    @classmethod
    def from_json(cls, obj: str) -> JsonItem:  # Self, but that's >=3.11
        return cls.from_dict(json.loads(obj))

    @classmethod
    def from_dict(cls, obj: dict[str, str | int | dict | list]) -> JsonItem:  # Self, but that's >=3.11
        kwargs = {}
        raw = None
        type_info = get_type_hints(cls)
        for fld in fields(cls):
            if fld.name == "_raw":
                raw = obj
                continue

            value = obj.get(fld.name, None)
            kwargs[fld.name] = JsonItem._parse_type(type_info[fld.name], value)

        result = cls(**kwargs)
        result._raw = raw
        return result

    @staticmethod
    def _parse_type(type_: Any, value: str | int | dict | list) -> str | int | dict | list | bytes:
        result = None

        if type_ == Optional[type_]:
            result = JsonItem._parse_type(get_args(type_)[0], value) if value is not None else None
        elif get_origin(type_) is UnionType:
            for atype in get_args(type_):
                try:
                    result = JsonItem._parse_type(atype, value)
                    break
                except Exception:
                    continue
        elif get_origin(type_) is list:
            vtype = get_args(type_)[0]
            result = [JsonItem._parse_type(vtype, v) for v in value]
        elif get_origin(type_) is dict:
            ktype, vtype = get_args(type_)
            result = {JsonItem._parse_type(ktype, k): JsonItem._parse_type(vtype, v) for k, v in value.items()}
        elif type_ is bytes:
            result = base64.b64decode(value)
        elif issubclass(type_, JsonItem):
            result = type_.from_dict(value)
        else:
            result = type_(value)

        return result


@dataclass
class Config(JsonItem):
    json_size: int
    keyslots_size: int | None
    flags: list[str] | None
    requirements: list[str] | None


@dataclass
class KeyslotArea(JsonItem):
    type: str
    offset: int
    size: int
    # if type == "raw"
    encryption: str | None
    key_size: int | None
    # type == "datashift-checksum" has all the fields of "checksum" and "datashift"
    # if type == "checksum"
    hash: str | None
    sector_size: int | None
    # if type in ("datashift", "datashift-journal")
    shift_size: int | None


@dataclass
class KeyslotKdf(JsonItem):
    type: str
    salt: bytes
    # if type == "pbkdf2"
    hash: str | None
    iterations: int | None
    # if type in ("argon2i", "argin2id")
    time: int | None
    memory: int | None
    cpus: int | None


@dataclass
class KeyslotAf(JsonItem):
    type: str
    # if type == "luks1"
    stripes: int | None
    hash: str | None


@dataclass
class Keyslot(JsonItem):
    type: str
    key_size: int
    area: KeyslotArea
    priority: int | None
    # if type == "luks2"
    kdf: KeyslotKdf | None
    af: KeyslotAf | None
    # if type == "reencrypt"
    mode: str | None
    direction: str | None


@dataclass
class Digest(JsonItem):
    type: str
    keyslots: list[int]
    segments: list[int]
    salt: bytes
    digest: bytes
    # if type == "pbkdf2"
    hash: str | None
    iterations: int | None


@dataclass
class SegmentIntegrity(JsonItem):
    type: str
    journal_encryption: str
    journal_integrity: str


@dataclass
class Segment(JsonItem):
    type: str
    offset: int
    size: int | str
    flags: list[str] | None
    # if type == "crypt"
    iv_tweak: int | None
    encryption: str | None
    sector_size: int | None
    integrity: SegmentIntegrity | None


@dataclass
class Token(JsonItem):
    type: str
    keyslots: list[int]


@dataclass
class Metadata(JsonItem):
    config: Config
    keyslots: dict[int, Keyslot]
    digests: dict[int, Digest]
    segments: dict[int, Segment]
    tokens: dict[int, Token]

    @classmethod
    def from_luks1_header(self, header: c_luks.luks_phdr) -> Metadata:
        """Map LUKS1 header information into a :class:`Metadata` dataclass."""
        config = Config(0, None, None, None)
        keyslots = {}
        digests = {}
        segments = {}
        tokens = {}

        cipher_spec = "-".join(v.rstrip(b"\x00").decode() for v in [header.cipherName, header.cipherMode])
        hash_spec = header.hashSpec.rstrip(b"\x00").decode()

        for idx, block in enumerate(header.keyblock):
            if block.active == c_luks.LUKS_KEY_DISABLED:
                continue

            keyslots[idx] = Keyslot(
                type="luks1",
                key_size=header.keyBytes,
                area=KeyslotArea(
                    type="raw",
                    offset=block.keyMaterialOffset * 512,
                    size=header.keyBytes * block.stripes,
                    encryption=cipher_spec,
                    key_size=header.keyBytes,
                    hash=None,
                    sector_size=None,
                    shift_size=None,
                ),
                priority=None,
                kdf=KeyslotKdf(
                    type="pbkdf2",
                    salt=block.passwordSalt,
                    hash=hash_spec,
                    iterations=block.passwordIterations,
                    time=None,
                    memory=None,
                    cpus=None,
                ),
                af=KeyslotAf(type="luks1", stripes=block.stripes, hash=hash_spec),
                mode=None,
                direction=None,
            )

        digests[0] = Digest(
            type="pbkdf2",
            keyslots=list(keyslots.keys()),
            segments=[0],
            salt=header.mkDigestSalt,
            digest=header.mkDigest,
            hash=hash_spec,
            iterations=header.mkDigestIterations,
        )

        segments[0] = Segment(
            type="crypt",
            offset=header.payloadOffset * 512,
            size="dynamic",
            flags=None,
            iv_tweak=0,
            encryption=cipher_spec,
            sector_size=512,
            integrity=None,
        )

        return Metadata(config, keyslots, digests, segments, tokens)


# Backward compatibility with Python 3.9
if sys.version_info < (3, 10):
    items = list(globals().values())
    for obj in items:
        if isinstance(obj, type) and issubclass(obj, JsonItem):
            for k, v in obj.__annotations__.items():
                if isinstance(v, str) and "|" in v:
                    # Because we import Union as UnionType
                    obj.__annotations__[k] = f"UnionType[{v.replace(' | ', ', ')}]"
