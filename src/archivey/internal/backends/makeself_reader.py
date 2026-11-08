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
_CHUNK = 16 * 1024
# How far past the last payload the check for trailing bytes reads: makeself writes
# nothing there, so this only bounds a report.
TRAILING_SCAN = 1024 * 1024
_READ_SIZE = 64 * 1024

# A function definition at the start of a line ends the variable block.
_FUNCTION = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*\(\)[ \t]*")
_ASSIGNMENT = re.compile(rb'([A-Za-z_][A-Za-z0-9_]*)="')
# A double-quoted value's text up to its closing quote, or up to the end of what is
# read; it never stops between a backslash and the byte it escapes.
_VALUE = re.compile(rb'(?:[^"\\]|\\.)*', re.DOTALL)
# An assignment whose value closes on its line, the common case, matched at once.
_LINE_ASSIGNMENT = re.compile(
    rb'([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\\n]|\\.)*)"([^\n]*)\n'
)
# The variables the reader uses; the others (licensetxt, the long one) are passed
# over, not kept.
_USED = frozenset(
    {
        b"CRCsum",
        b"MD5",
        b"SHA",
        b"label",
        b"script",
        b"targetdir",
        b"filesizes",
        b"totalsize",
        b"decrypt_cmd",
        b"skip",
        b"SIGNATURE",
    }
)
# The escapes the shell undoes inside double quotes, and a backslash-newline.
_ESCAPE = re.compile(rb'\\([$`"\\\n])')
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
        # The header is metadata, buffered whole: max_metadata_bytes bounds it. Each
        # step below goes on from where the last chunk left it, so the work is linear
        # in the header's length.
        limit = self._context.config.listing_limits.max_metadata_bytes
        buffer = bytearray()
        parser = _VariableParser()
        lines = _LineCounter()
        variables: dict[bytes, bytes] | None = None
        block_end = 0
        skip: int | None = None
        end: int | None = None
        scanned = 0
        # Where the search for the buffer's last newline ended, and the end of the
        # whole lines before it.
        searched = whole_end = 0
        while True:
            if variables is None and parser.feed(buffer):
                variables, block_end = parser.variables, parser.block_end
                scanned = searched = whole_end = block_end
                stated = variables.get(b"skip")
                if stated is not None:
                    skip = _number(stated, "skip")
            if variables is not None and skip is None:
                # makeself 2.2.0 to 2.4.0: the count is in the script's offset lines.
                # Whole lines only, each searched once: the last line may still
                # be arriving.
                whole_end = _rfind_newline(buffer, searched) + 1 or whole_end
                searched = len(buffer)
                found = _OLD_OFFSET.search(buffer, scanned, whole_end)
                if found is not None:
                    skip = int(found.group(1))
                else:
                    scanned = max(scanned, whole_end)
            if skip is not None:
                end = lines.after(buffer, skip)
                if end is not None:
                    break
            if limit is not None and len(buffer) >= limit:
                raise ResourceLimitError(
                    f"makeself header longer than max_metadata_bytes={limit}"
                )
            want = _CHUNK if limit is None else min(_CHUNK, limit - len(buffer))
            chunk = stream.read(want)
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
        # makeself writes one CRC and one MD5 per payload, zeros where it computed
        # none. 2.4.0's --append leaves SHA at one entry; an entry there that is not
        # zeros could be any payload's, so only a list of zeros may be short.
        for name, listed in ((b"CRCsum", crcs), (b"MD5", md5s)):
            if len(listed) != len(sizes):
                raise CorruptionError(_count_mismatch(name, len(listed), len(sizes)))
        if len(shas) not in (0, len(sizes)) and any(v != _ZERO_SHA for v in shas):
            raise CorruptionError(_count_mismatch(b"SHA", len(shas), len(sizes)))
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


class _VariableParser:
    """The variable block's double-quoted assignments, and where the block ends (the
    start of the first function definition), read from a buffer that grows.

    A value is read as the shell reads a double-quoted word, with ``\\$``, ``\\```,
    ``\\"`` and ``\\\\`` unescaped and a backslash-newline dropped, so it may span
    lines and nothing inside it is taken for a variable. Other lines (``umask 077``,
    ``if ...``) are skipped. Only the variables in ``_USED`` are kept, so memory does
    not grow with the header. One of those assigned twice is damage: the shell would
    take the last, and a reader should not have to guess which one makeself wrote.

    ``feed`` goes on from where the last call stopped and reads each byte about once:
    a newline is looked for only past where the last search ended, a line is matched
    only once its newline is in, and a value that runs over lines is read on from the
    point it was read to.
    """

    def __init__(self) -> None:
        self.variables: dict[bytes, bytes] = {}
        self.block_end = 0
        self._pos = -1  # the start of the next line; -1 before the magic line ends
        self._name: bytes | None = None  # the variable whose value is being read
        self._value_start = 0
        self._value_end = 0
        self._searched = 0  # no newline between the last search's start and here

    def feed(self, buffer: bytearray) -> bool:
        """Read on in ``buffer``; ``True`` once the variable block has ended."""
        if self._pos < 0:
            found = self._newline(buffer, len(MAGIC))
            if found < 0:
                return False
            self._pos = found + 1
        while True:
            if self._name is None:
                eol = self._newline(buffer, self._pos)
                if eol < 0:
                    return False
                whole = _LINE_ASSIGNMENT.match(buffer, self._pos, eol + 1)
                if whole is not None:
                    self._keep(whole.group(1), whole.group(2), whole.group(3))
                    self._pos = whole.end()
                    continue
                if _FUNCTION.fullmatch(buffer, self._pos, eol):
                    self.block_end = self._pos
                    return True
                match = _ASSIGNMENT.match(buffer, self._pos, eol)
                if match is None:
                    self._pos = eol + 1
                    continue
                self._name = bytes(match.group(1))
                self._value_start = self._value_end = match.end()
            # The value: go on from the last stop, which is never inside an escape.
            read = _VALUE.match(buffer, self._value_end)
            assert read is not None  # it matches the empty string
            stop = read.end()
            if stop >= len(buffer) or buffer[stop] != 0x22:  # no closing quote yet
                self._value_end = stop
                return False
            eol = self._newline(buffer, stop)
            if eol < 0:
                self._value_end = stop
                return False
            self._keep(
                self._name, buffer[self._value_start : stop], buffer[stop + 1 : eol]
            )
            self._name = None
            self._pos = eol + 1

    def _newline(self, buffer: bytearray, start: int) -> int:
        """The next newline from ``start``, or -1. The searches start in order, so
        the bytes an earlier one passed over are not searched again."""
        found = _find_newline(buffer, max(start, self._searched))
        self._searched = len(buffer) if found < 0 else found
        return found

    def _keep(
        self, name: bytes, raw: bytes | bytearray, after: bytes | bytearray
    ) -> None:
        """One assignment: ``raw`` is the value as quoted, ``after`` the rest of the
        line after its closing quote."""
        name = bytes(name)
        # makeself writes ``; export USER_PWD`` after one value; a quote there would
        # open a word this parse does not follow.
        if any(quote in after for quote in (b'"', b"'", b"`")):
            raise CorruptionError(
                f"makeself header: a quote after the value of {_shown(name)}"
            )
        if name not in _USED:
            return
        if name in self.variables:
            raise CorruptionError(f"makeself header assigns {_shown(name)} twice")
        self.variables[name] = _ESCAPE.sub(_unescape_one, bytes(raw))


# The header's newline searches, each over ``buffer[start:]``.
def _find_newline(buffer: bytearray, start: int) -> int:
    return buffer.find(b"\n", start)


def _rfind_newline(buffer: bytearray, start: int) -> int:
    return buffer.rfind(b"\n", start)


def _unescape_one(match: re.Match[bytes]) -> bytes:
    escaped = match.group(1)
    return b"" if escaped == b"\n" else escaped


class _LineCounter:
    """The offset after a buffer's ``lines``-th newline, counted as the buffer grows."""

    def __init__(self) -> None:
        self._counted = 0  # newlines before ``_pos``
        self._pos = 0

    def after(self, buffer: bytearray, lines: int) -> int | None:
        """That offset, or ``None`` while ``buffer`` holds fewer newlines."""
        new = buffer.count(b"\n", self._pos)
        if self._counted + new < lines:
            self._counted += new
            self._pos = len(buffer)
            return None
        pos = self._pos
        for _ in range(lines - self._counted):
            pos = buffer.index(b"\n", pos) + 1
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


def _count_mismatch(name: bytes, listed: int, payloads: int) -> str:
    return (
        f"makeself header: {name.decode()} lists {listed} "
        f"value{'' if listed == 1 else 's'} for {payloads} "
        f"payload{'' if payloads == 1 else 's'}"
    )


def _digests_for(header: _Header, index: int) -> _Digests:
    """The hashers for the digests the header states for payload ``index``."""
    digests = _Digests()
    if header.crcs[index] != _NO_CRC:
        digests.crc = _Cksum()
        digests.hashers.append(digests.crc)
    if header.md5s[index] != _ZERO_MD5:
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
    """A base64 payload decoded as ``base64 -d -i`` decodes it: bytes outside the
    alphabet (line breaks) are skipped, and text after a padded group of four is
    decoded on, as the start of more base64."""

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
                self._out = _decode_base64(text[:whole])
            except binascii.Error as e:
                raise CorruptionError(
                    f"makeself payload {self._index + 1} is not valid base64"
                ) from e
        data = self._out[: len(buffer)]
        self._out = self._out[len(data) :]
        buffer[: len(data)] = data
        return len(data)


def _decode_base64(text: bytes) -> bytes:
    """Whole groups of four from the alphabet, decoded; a group with padding ends a
    run, and the next group starts another (``binascii`` alone would drop the rest).
    Padding that is not at the end of its group is damage."""
    if b"=" not in text:
        return binascii.a2b_base64(text, strict_mode=True)
    out = []
    start = 0
    while (pad := text.find(b"=", start)) >= 0:
        end = pad - pad % 4 + 4
        out.append(binascii.a2b_base64(text[start:end], strict_mode=True))
        start = end
    out.append(binascii.a2b_base64(text[start:], strict_mode=True))
    return b"".join(out)


class MakeselfHandler(SequentialFormatHandler):
    """makeself self-extracting archives (``.run`` installers)."""

    format = ArchiveFormat.MAKESELF
    magic = (Magic(0, MAGIC),)
    uses_encoding = True

    @override
    def open_sequential(self, context: ReaderContext) -> MakeselfReader:
        return MakeselfReader(context)


MakeselfReadBackend = register_builtin_format(MakeselfHandler)
