"""The makeself reader: a ``.run`` installer's shell header, then the TAR in each of its
payloads, read in one forward pass.

On-disk layout (makeself 2.2.0 and later, ``makeself-header.sh``)::

    #!/bin/sh
    # This script was generated using Makeself 2.4.5
    ...                   variable assignments: CRCsum, MD5, SHA, label, filesizes, ...
    ...                   the rest of the script, ``skip`` lines in all
    [ payload 1 ][ payload 2 ]...

The header is ``skip`` lines long, and the first payload starts after its last
newline. makeself 2.4.2 and later state it as ``skip="N"`` among the variables at the
top; 2.2.0 to 2.4.0 write the number into each ``offset=`head -n N "$0" | wc -c ...```
line of the script instead. ``filesizes`` lists the payloads' sizes in bytes, one per
payload: 2.2.0 to 2.4.0 add a payload for each ``--append``, and 2.4.2 and later
rewrite the one payload instead. ``CRCsum``, ``MD5`` and ``SHA`` list one value per
payload, all zeros where none was computed: the POSIX ``cksum`` CRC (decimal), MD5 and
SHA-256 (hexadecimal) of the payload's bytes as stored.

A payload is a TAR, compressed by the command the script pipes it through
(``eval "gzip -cd"``). makeself 2.4.2 and later may encrypt or encode the compressed
bytes too, and say how in ``decrypt_cmd``; 2.2.0 to 2.4.0 had base64, gpg and openssl
as compressors instead. archivey reads every compressor it has a codec for, and base64.
An encrypted payload is refused.

The header is parsed, never run. Only the variable block at the top is read as shell
(double-quoted values, which may span lines, with their backslash escapes), up to the
first function definition: a value such as the license text cannot fake a variable
after it. The payload command and the old offset lines are matched as whole lines of
the script after that block.

Every listed digest is checked over its payload's bytes when the walk reaches the
payload's end. It covers every file of that payload, so a match raises them to
``Verification.CHECKSUM`` and a mismatch makes them failures of ``verify_all()``, as
makeself refuses to run then. Handbook page: ``dev-docs/formats/makeself.md``.
"""

from __future__ import annotations

import binascii
import hashlib
import io
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from archivey.diagnostics import ArchiveEofContext, DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.overrides import override
from archivey.types import (
    ArchiveFormat,
    ArchiveInfoExtra,
    ContainerFormat,
    StreamFormat,
)

MAGIC = b"#!/bin/sh\n# This script was generated using Makeself "
# The longest header read. makeself sets none; the license text is the one part that
# can be long, and a header past this is refused rather than buffered.
HEADER_MAX = 2 * 1024 * 1024
_CHUNK = 16 * 1024
# How far past the last payload the check for trailing bytes reads: makeself writes
# nothing there, so this only bounds a report.
TRAILING_SCAN = 1024 * 1024
_READ_SIZE = 64 * 1024

# A function definition at the start of a line ends the variable block.
_FUNCTION = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*\(\)[ \t]*")
_ASSIGNMENT = re.compile(rb'([A-Za-z_][A-Za-z0-9_]*)="')
# makeself 2.2.0 to 2.4.0: the header's line count, written into the script.
_OLD_OFFSET = re.compile(
    rb'^[ \t]*offset=`head -n ([0-9]+) "\$[01]" \| wc -c \| tr -d " "`[ \t]*$',
    re.MULTILINE,
)
# The command a payload is piped through, quoted for ``eval``: after a ``|``, or alone
# on its line (``MS_Decompress`` with no ``decrypt_cmd``).
_PAYLOAD_EVAL = re.compile(rb'(?:\| |^[ \t]+)eval "((?:[^"\\\n]|\\.)*)"', re.MULTILINE)
# ``eval`` of the script's own variables (``"$script" $scriptargs``), not a command.
_VARIABLE_EVAL = (b"$", b"\\$", b'\\"')

_COMPRESSORS: dict[bytes, StreamFormat] = {
    b"gzip -cd": StreamFormat.GZIP,
    b"bzip2 -d": StreamFormat.BZIP2,
    b"xz -d": StreamFormat.XZ,
    b"zstd -cd": StreamFormat.ZSTD,
    b"lz4 -d": StreamFormat.LZ4,
    b"lzop -d": StreamFormat.LZOP,
    b"cat": StreamFormat.UNCOMPRESSED,
    # --compress: Unix compress where the system has it, else gzip, which reads .Z.
    b"exec 2>&-; uncompress -c || test $? -eq 2 || gzip -cd": (
        StreamFormat.UNIX_COMPRESS
    ),
    b"(type compress >/dev/null 2>&1 && compress -fcd || gzip -cd)": (
        StreamFormat.UNIX_COMPRESS
    ),
}
_BZIP3 = re.compile(rb"bzip3 -dj[0-9]*")
# makeself 2.2.0 to 2.4.0: encodings and ciphers in place of a compressor, over the
# plain TAR.
_OLD_BASE64 = frozenset({b"base64 -d -i", b"base64 --decode -i -"})
_OLD_GPG = frozenset({b"gpg -d", b"gpg --yes -d"})
_OLD_OPENSSL = re.compile(rb"openssl aes-256-cbc -d -a( -md sha256)?")
# makeself 2.4.2 and later: ``decrypt_cmd``, run before the compressor.
_OPENSSL = re.compile(rb"openssl enc -aes-256-cbc -d( -salt)?( -pbkdf2)?( -md sha256)?")
_BASE64 = b"base64 --decode"

_NO_CRC = 0
_ZERO_MD5 = b"0" * 32
_ZERO_SHA = b"0" * 64

_COMPRESSION_NAMES = {
    StreamFormat.GZIP: "gzip",
    StreamFormat.BZIP2: "bzip2",
    StreamFormat.XZ: "xz",
    StreamFormat.ZSTD: "zstd",
    StreamFormat.LZ4: "lz4",
    StreamFormat.LZOP: "lzop",
    StreamFormat.BZIP3: "bzip3",
    StreamFormat.UNIX_COMPRESS: "compress",
    StreamFormat.UNCOMPRESSED: "none",
}


@dataclass
class _Header:
    version: str
    sizes: list[int]
    crcs: list[int]
    md5s: list[bytes]
    shas: list[bytes]
    compressor: StreamFormat
    encoding: str | None
    label: bytes | None
    script: bytes | None
    target_dir: bytes | None
    signed: bool


@dataclass
class _Pending:
    """Bytes read past the header while looking for its end: the start of the
    payloads, which the payloads read first."""

    data: bytes = b""


@dataclass
class _Digests:
    crc: _Cksum | None = None
    md5: Any = None
    sha: Any = None
    hashers: list[Any] = field(default_factory=list)


class MakeselfReader(SequentialReader):
    """Walks a makeself archive: its header, then the TAR in each payload."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._extra = ArchiveInfoExtra({})
        self._version: str | None = None

    @override
    def archive_info(self) -> ReaderArchiveInfo:
        # Every payload is one TAR read through its decoder: members share a decode.
        return ReaderArchiveInfo(
            is_solid=True, format_version=self._version, extra=self._extra
        )

    @override
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        pending = _Pending()
        header = self._read_header(stream, pending)
        inner = ArchiveFormat(ContainerFormat.TAR, header.compressor)
        spanning = self._context._spanning_check
        for index, size in enumerate(header.sizes):
            digests = _digests_for(header, index)
            payload = _Payload(pending, stream, size, digests.hashers, index)
            data: BinaryIO = io.BufferedReader(payload, _READ_SIZE)
            if header.encoding == "base64":
                data = io.BufferedReader(_Base64Reader(data, index), _READ_SIZE)
            check = (
                spanning(("makeself payload", index))
                if digests.hashers and spanning is not None
                else None
            )
            for span in self._context.open_nested(data, inner):
                if check is not None:
                    check.cover(span.member)
                yield span
            payload.drain()
            if check is not None:
                failure = _mismatch(header, index, digests)
                if failure is None:
                    check.passed()
                else:
                    raise check.failed(failure)
        self._check_end(pending, stream)

    # The header ---------------------------------------------------------------------

    def _read_header(self, stream: ForwardStream, pending: _Pending) -> _Header:
        budget = self._context.config.listing_limits.max_metadata_bytes
        limit = HEADER_MAX if budget is None else min(HEADER_MAX, budget)
        buffer = bytearray()
        variables: dict[bytes, bytes] | None = None
        block_end = 0
        skip: int | None = None
        end: int | None = None
        scanned = 0
        while end is None:
            if variables is None:
                parsed = _parse_variables(buffer)
                if parsed is not None:
                    variables, block_end = parsed
                    scanned = block_end
                    stated = variables.get(b"skip")
                    if stated is not None:
                        skip = _number(stated, "skip")
            if variables is not None and skip is None:
                # makeself 2.2.0 to 2.4.0: the count is in the script's offset lines.
                found = _OLD_OFFSET.search(buffer, scanned)
                if found is not None:
                    skip = int(found.group(1))
                else:
                    # A line can straddle the end of what is read; look again from
                    # its start.
                    scanned = max(block_end, buffer.rfind(b"\n") + 1)
            if skip is not None:
                end = _after_lines(buffer, skip)
                if end is not None:
                    break
            if len(buffer) >= limit:
                if budget is not None and budget < HEADER_MAX:
                    raise ResourceLimitError(
                        f"makeself header longer than max_metadata_bytes={budget}"
                    )
                raise UnsupportedFeatureError(
                    f"makeself header longer than {HEADER_MAX} bytes"
                )
            chunk = stream.read(min(_CHUNK, limit - len(buffer)))
            if not chunk:
                raise TruncatedError(
                    "makeself header: the file ends "
                    + (
                        "before its variables end"
                        if variables is None
                        else f"inside the {skip} header lines it states"
                        if skip is not None
                        else "before the script states the header's length"
                    )
                )
            buffer += chunk
        assert variables is not None and skip is not None
        pending.data = bytes(buffer[end:])
        return self._describe(bytes(buffer[:end]), variables, block_end, skip)

    def _describe(
        self, text: bytes, variables: dict[bytes, bytes], block_end: int, skip: int
    ) -> _Header:
        first_line_end = text.index(b"\n", len(MAGIC))
        version = text[len(MAGIC) : first_line_end].decode("ascii", "replace").strip()
        self._version = version
        body = text[block_end:]
        if b"skip" not in variables:
            # Every offset line of the script must state the same count.
            counts = {int(m.group(1)) for m in _OLD_OFFSET.finditer(body)}
            if counts != {skip}:
                raise CorruptionError(
                    "makeself header: its offset lines state different lengths "
                    f"({', '.join(str(c) for c in sorted(counts))} lines)"
                )
        commands = {
            _unescape(m.group(1))
            for m in _PAYLOAD_EVAL.finditer(body)
            if not m.group(1).startswith(_VARIABLE_EVAL)
        }
        if len(commands) != 1:
            raise CorruptionError(
                "makeself header: "
                + (
                    "no command to decompress the payload"
                    if not commands
                    else "the script decompresses its payload in more than one way"
                )
            )
        (command,) = commands
        compressor, encoding = _decoders(command, variables.get(b"decrypt_cmd", b""))
        sizes = [_number(t, "filesizes") for t in _required(variables, b"filesizes")]
        if not sizes:
            raise CorruptionError("makeself header: filesizes lists no payload")
        total = variables.get(b"totalsize")
        if (
            total is not None
            and total.strip()
            and _number(total, "totalsize") != sum(sizes)
        ):
            raise CorruptionError(
                f"makeself header: totalsize {_shown(total)} is not the sum of "
                f"filesizes {' '.join(str(s) for s in sizes)}"
            )
        crcs = [_number(t, "CRCsum") for t in _required(variables, b"CRCsum")]
        md5s = [_hex(t, "MD5", 32) for t in _required(variables, b"MD5")]
        shas = [_hex(t, "SHA", 64) for t in variables.get(b"SHA", b"").split()]
        header = _Header(
            version=version,
            sizes=sizes,
            crcs=crcs,
            md5s=md5s,
            shas=shas,
            compressor=compressor,
            encoding=encoding,
            label=variables.get(b"label"),
            script=variables.get(b"script"),
            target_dir=variables.get(b"targetdir"),
            signed=bool(variables.get(b"SIGNATURE", b"").strip()),
        )
        self._extra = self._info(header)
        if encoding in ("openssl", "gpg"):
            raise UnsupportedFeatureError(
                f"makeself payload encrypted with {encoding}: archivey does not "
                "decrypt it"
            )
        return header

    def _info(self, header: _Header) -> ArchiveInfoExtra:
        decode = self._context.decode_name
        extra = ArchiveInfoExtra(
            {
                "makeself.compression": _COMPRESSION_NAMES[header.compressor],
                "makeself.payloads": len(header.sizes),
                "makeself.signed": header.signed,
            }
        )
        if header.encoding is not None:
            extra["makeself.encryption"] = header.encoding
        if header.label:
            extra["makeself.label"] = decode(header.label)
        if header.script:
            extra["makeself.script"] = decode(header.script)
        if header.target_dir:
            extra["makeself.target_dir"] = decode(header.target_dir)
        return extra

    def _check_end(self, pending: _Pending, stream: ForwardStream) -> None:
        """After the last payload: nothing, or zeros. makeself writes nothing there
        and reads no further."""
        scanned = 0
        chunk = pending.data
        pending.data = b""
        while scanned < TRAILING_SCAN:
            if not chunk:
                chunk = stream.read(min(_READ_SIZE, TRAILING_SCAN - scanned))
                if not chunk:
                    return
            stripped = chunk.lstrip(b"\0")
            if stripped:
                at = scanned + len(chunk) - len(stripped)
                self._context.report(
                    DiagnosticCode.ARCHIVE_TRAILING_DATA,
                    f"makeself archive has data {at} bytes after its last payload",
                    ArchiveEofContext(
                        format="makeself",
                        expected_marker="zeros_to_eof",
                        observed_bytes=at,
                        observed_kind="nonzero",
                    ),
                )
                return
            scanned += len(chunk)
            chunk = b""


# Parsing ------------------------------------------------------------------------------


def _parse_variables(buffer: bytearray) -> tuple[dict[bytes, bytes], int] | None:
    """The variable block's double-quoted assignments, and where the block ends (the
    start of the first function definition); ``None`` while ``buffer`` does not
    reach that far.

    A value is read as the shell reads a double-quoted word, with ``\\$``, ``\\```,
    ``\\"`` and ``\\\\`` unescaped and a backslash-newline dropped, so it may span
    lines and nothing inside it is taken for a variable. Other lines (``umask 077``,
    ``if ...``) are skipped. A variable assigned twice is damage: the shell would take
    the last, and a reader should not have to guess which one makeself wrote.
    """
    pos = buffer.find(b"\n", len(MAGIC)) + 1
    if pos == 0:
        return None
    variables: dict[bytes, bytes] = {}
    size = len(buffer)
    while True:
        eol = buffer.find(b"\n", pos)
        if eol < 0:
            return None
        if _FUNCTION.fullmatch(buffer, pos, eol):
            return variables, pos
        match = _ASSIGNMENT.match(buffer, pos, eol)
        if match is None:
            pos = eol + 1
            continue
        value = bytearray()
        at = match.end()
        while True:
            if at >= size:
                return None
            byte = buffer[at]
            if byte == 0x5C:  # backslash
                if at + 1 >= size:
                    return None
                following = buffer[at + 1]
                if following in b'$`"\\':
                    value.append(following)
                elif following != 0x0A:
                    value += b"\\"
                    value.append(following)
                at += 2
                continue
            if byte == 0x22:  # the closing quote
                break
            value.append(byte)
            at += 1
        eol = buffer.find(b"\n", at)
        if eol < 0:
            return None
        # makeself writes ``; export USER_PWD`` after one value; a quote there would
        # open a word this parse does not follow.
        if any(quote in buffer[at + 1 : eol] for quote in (b'"', b"'", b"`")):
            raise CorruptionError(
                f"makeself header: a quote after the value of {_shown(match.group(1))}"
            )
        name = bytes(match.group(1))
        if name in variables:
            raise CorruptionError(f"makeself header assigns {_shown(name)} twice")
        variables[name] = bytes(value)
        pos = eol + 1


def _after_lines(buffer: bytearray, lines: int) -> int | None:
    """The offset after the ``lines``-th newline, or ``None`` before it is read."""
    pos = 0
    for _ in range(lines):
        found = buffer.find(b"\n", pos)
        if found < 0:
            return None
        pos = found + 1
    return pos


def _unescape(raw: bytes) -> bytes:
    """A double-quoted word's text: ``\\X`` is ``X`` for the four escapable bytes."""
    return re.sub(rb'\\([$`"\\])', rb"\1", raw)


def _decoders(command: bytes, decrypt: bytes) -> tuple[StreamFormat, str | None]:
    """The payload's compressor and its encoding or cipher, from the command the
    script pipes it through and ``decrypt_cmd``."""
    command = b" ".join(command.split())
    decrypt = b" ".join(decrypt.split())
    if command in _OLD_BASE64:
        return StreamFormat.UNCOMPRESSED, "base64"
    if command in _OLD_GPG:
        return StreamFormat.UNCOMPRESSED, "gpg"
    if _OLD_OPENSSL.fullmatch(command):
        return StreamFormat.UNCOMPRESSED, "openssl"
    compressor = _COMPRESSORS.get(command)
    if compressor is None and _BZIP3.fullmatch(command):
        compressor = StreamFormat.BZIP3
    if compressor is None:
        raise UnsupportedFeatureError(
            f"makeself payload decompressed with {_shown(command)}, which archivey "
            "does not read"
        )
    if not decrypt:
        return compressor, None
    if decrypt == _BASE64:
        return compressor, "base64"
    if _OPENSSL.fullmatch(decrypt):
        return compressor, "openssl"
    if decrypt.startswith(b"gpg "):
        return compressor, "gpg"
    raise UnsupportedFeatureError(
        f"makeself payload decrypted with {_shown(decrypt)}, which archivey does not "
        "read"
    )


def _required(variables: dict[bytes, bytes], name: bytes) -> list[bytes]:
    value = variables.get(name)
    if value is None:
        raise CorruptionError(f"makeself header has no {name.decode()} variable")
    return value.split()


def _number(raw: bytes, what: str) -> int:
    text = raw.strip()
    if not text.isdigit():
        raise CorruptionError(f"makeself header: {what} {_shown(raw)} is not a number")
    return int(text)


def _hex(raw: bytes, what: str, length: int) -> bytes:
    if len(raw) != length or not all(c in b"0123456789abcdefABCDEF" for c in raw):
        raise CorruptionError(
            f"makeself header: {what} {_shown(raw)} is not {length} hexadecimal digits"
        )
    return raw.lower()


def _shown(raw: bytes) -> str:
    """Header text, quoted for a message that escapes itself (no ``!r``: the
    exception escapes control characters already)."""
    return "'" + raw.decode("utf-8", "backslashreplace") + "'"


# Payloads ----------------------------------------------------------------------------


def _digests_for(header: _Header, index: int) -> _Digests:
    """The hashers for the digests the header states for payload ``index``."""
    digests = _Digests()
    if index < len(header.crcs) and header.crcs[index] != _NO_CRC:
        digests.crc = _Cksum()
        digests.hashers.append(digests.crc)
    if index < len(header.md5s) and header.md5s[index] != _ZERO_MD5:
        digests.md5 = hashlib.md5(usedforsecurity=False)
        digests.hashers.append(digests.md5)
    if index < len(header.shas) and header.shas[index] != _ZERO_SHA:
        digests.sha = hashlib.sha256()
        digests.hashers.append(digests.sha)
    return digests


def _mismatch(header: _Header, index: int, digests: _Digests) -> str | None:
    """What does not match among payload ``index``'s digests, or ``None``."""
    wrong = []
    if digests.crc is not None and digests.crc.value() != header.crcs[index]:
        wrong.append("CRC")
    if (
        digests.md5 is not None
        and digests.md5.hexdigest() != header.md5s[index].decode()
    ):
        wrong.append("MD5")
    if (
        digests.sha is not None
        and digests.sha.hexdigest() != header.shas[index].decode()
    ):
        wrong.append("SHA-256")
    if not wrong:
        return None
    verb = "does" if len(wrong) == 1 else "do"
    return (
        f"makeself payload {index + 1}: its {' and '.join(wrong)} {verb} not match "
        "the header's"
    )


# The bit order of each byte reversed: POSIX cksum is CRC-32 with the bits taken
# most significant first, which binascii.crc32 (least significant first) computes
# over the reversed bytes.
_REVERSED = bytes(int(f"{i:08b}"[::-1], 2) for i in range(256))


def _reverse32(value: int) -> int:
    return int(f"{value:032b}"[::-1], 2)


class _Cksum:
    """The POSIX ``cksum`` CRC: CRC-32 (polynomial 0x04C11DB7) MSB first, from 0,
    over the data and then its length (least significant byte first, as few bytes as
    it takes), inverted."""

    def __init__(self) -> None:
        # binascii.crc32's running value for a register that starts at 0.
        self._state = 0xFFFFFFFF
        self._length = 0

    def update(self, data: bytes) -> None:
        self._state = binascii.crc32(data.translate(_REVERSED), self._state)
        self._length += len(data)

    def value(self) -> int:
        length = self._length
        tail = bytearray()
        while length:
            tail.append(length & 0xFF)
            length >>= 8
        state = binascii.crc32(bytes(tail).translate(_REVERSED), self._state)
        return _reverse32(state ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


class _Payload(io.RawIOBase):
    """One payload's bytes as stored, fed to its digests as they are read: first what
    the header read left over, then the archive's next bytes."""

    def __init__(
        self,
        pending: _Pending,
        stream: ForwardStream,
        size: int,
        hashers: list[Any],
        index: int,
    ) -> None:
        self._pending = pending
        self._stream = stream
        self._left = size
        self._hashers = hashers
        self._index = index
        self._taken: BinaryIO | None = None

    @override
    def readable(self) -> bool:
        return True

    @override
    def readinto(self, buffer: Any) -> int:
        want = min(len(buffer), self._left)
        if want == 0:
            return 0
        pending = self._pending.data
        if pending:
            data = pending[:want]
            self._pending.data = pending[want:]
        else:
            if self._taken is None:
                self._taken = self._stream.take(self._left)
            data = self._taken.read(want)
            if not data:
                raise TruncatedError(
                    f"makeself payload {self._index + 1} ends {self._left} bytes "
                    "short of the size the header states"
                )
        for hasher in self._hashers:
            hasher.update(data)
        self._left -= len(data)
        buffer[: len(data)] = data
        return len(data)

    def drain(self) -> None:
        """Read what the TAR reader left of the payload, for its digests."""
        buffer = bytearray(_READ_SIZE)
        while self.readinto(buffer):
            pass


_BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_NOT_BASE64 = bytes(sorted(set(range(256)) - set(_BASE64_ALPHABET)))


class _Base64Reader(io.RawIOBase):
    """A base64 payload decoded, ignoring line breaks and other bytes outside the
    alphabet as ``base64 -d -i`` does."""

    def __init__(self, raw: BinaryIO, index: int) -> None:
        self._raw = raw
        self._index = index
        self._carry = b""
        self._out = b""
        self._ended = False

    @override
    def readable(self) -> bool:
        return True

    @override
    def readinto(self, buffer: Any) -> int:
        while not self._out and not self._ended:
            chunk = self._raw.read(_READ_SIZE)
            if not chunk:
                self._ended = True
                if self._carry:
                    raise CorruptionError(
                        f"makeself payload {self._index + 1}: its base64 text ends "
                        "part-way through a group of four characters"
                    )
                break
            text = self._carry + chunk.translate(None, _NOT_BASE64)
            whole = len(text) - len(text) % 4
            self._carry = text[whole:]
            try:
                self._out = binascii.a2b_base64(text[:whole], strict_mode=False)
            except binascii.Error as e:
                raise CorruptionError(
                    f"makeself payload {self._index + 1} is not valid base64"
                ) from e
        data = self._out[: len(buffer)]
        self._out = self._out[len(data) :]
        buffer[: len(data)] = data
        return len(data)


class MakeselfHandler(SequentialFormatHandler):
    """makeself self-extracting archives (``.run`` installers)."""

    format = ArchiveFormat.MAKESELF
    magic = (Magic(0, MAGIC),)
    uses_encoding = True

    @override
    def open_sequential(self, context: ReaderContext) -> MakeselfReader:
        return MakeselfReader(context)


MakeselfReadBackend = register_builtin_format(MakeselfHandler)
