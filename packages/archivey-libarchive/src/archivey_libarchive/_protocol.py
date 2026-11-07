"""The messages between archivey's process and the libarchive child.

Standard library only. Each message is one tag byte, a 4-byte little-endian length and
the payload. Nothing is unpickled: a child that libarchive's bugs let a crafted archive
take over can send only bytes and JSON, which the parent checks.

Parent to child: ``O`` open (JSON ``{"format": ...}``), ``I`` input bytes (empty at the
end of the archive), ``H`` next header, ``R`` read (4-byte size), ``S`` skip the rest of
the entry's data, ``Q`` quit.

Child to parent: ``N`` need input (4-byte size), ``K`` done, ``H`` header (JSON), ``E``
end of the archive, ``D`` data (empty at the end of the entry), ``X`` error (JSON
``{"code", "errno", "message"}``).
"""

from __future__ import annotations

import base64
import json
import struct
from typing import IO

_HEAD = struct.Struct("<cI")
_SIZE = struct.Struct("<I")

# Larger messages are refused: a read asks for at most 1 MiB, and a header is small.
MAX_PAYLOAD = (1 << 20) + 4096

_BYTES_FIELDS = ("path", "symlink", "hardlink", "uname", "gname")


class ProtocolError(Exception):
    """The other side sent something this protocol does not allow, or went away."""


def send(out: IO[bytes], tag: bytes, payload: bytes = b"") -> None:
    out.write(_HEAD.pack(tag, len(payload)) + payload)
    out.flush()


def receive(inp: IO[bytes]) -> tuple[bytes, bytes]:
    head = inp.read(_HEAD.size)
    if len(head) < _HEAD.size:
        raise ProtocolError("the other process closed the channel")
    tag, length = _HEAD.unpack(head)
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"a message of {length} bytes is over the limit")
    payload = inp.read(length)
    if len(payload) < length:
        raise ProtocolError("the other process closed the channel mid-message")
    return tag, payload


def pack_size(n: int) -> bytes:
    return _SIZE.pack(n)


def unpack_size(payload: bytes) -> int:
    if len(payload) != _SIZE.size:
        raise ProtocolError("a size message is not 4 bytes")
    return _SIZE.unpack(payload)[0]


def pack_json(value: dict[str, object]) -> bytes:
    out = dict(value)
    for key in _BYTES_FIELDS:
        raw = out.get(key)
        if isinstance(raw, bytes):
            out[key] = base64.b64encode(raw).decode("ascii")
    return json.dumps(out).encode("utf-8")


def unpack_json(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except ValueError as exc:
        raise ProtocolError(f"a message is not JSON: {exc}") from None
    if not isinstance(value, dict):
        raise ProtocolError("a message is not a JSON object")
    for key in _BYTES_FIELDS:
        raw = value.get(key)
        if raw is not None:
            if not isinstance(raw, str):
                raise ProtocolError(f"{key} is not a string")
            value[key] = base64.b64decode(raw.encode("ascii"), validate=True)
    return value
