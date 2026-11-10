r"""uuencode and base64: binary files written as lines of text, read as single files.

They compress nothing, but they wrap a file the way a compressor does, and old mail,
Usenet posts and pasted archives arrive in them, so archivey peels them like one: a
``.tar.gz.uu`` lists the tar.

**uuencode** (``.uu``, ``.uue``). A ``begin MODE NAME`` line, then lines that each
start with a length character, then a line holding only a length of zero and an
``end`` line::

    begin 644 notes.tar.gz
    M'XL(`````````^W/,0J`,`Q%T;O\T@...
    `
    end

``begin-base64 MODE NAME`` is the same frame (``uuencode -m``) with base64 lines,
closed by ``====``. Text before ``begin`` is skipped, up to :data:`MAX_LEADING_TEXT`
bytes: a mail or news post keeps its headers there. Only the first file is read; text
after its end line is trailing data. The name and mode are the member's
``raw_name``, ``extra["uu.original_filename"]`` and ``mode``, as lzop's are; the
member keeps the name it gets from the file name, so the stored name never chooses a
path.

**base64** (``.b64``, ``.base64``). Base64 text with no frame at all: lines of one
length (64 for PEM and ``openssl``, 76 for MIME and GNU ``base64``) or one long line.
The decoder skips line breaks, ends at ``=`` padding or at the end of the input, and
refuses any other byte, spaces included.

**Detection.** Both are text, so neither has magic. Each check is a
:meth:`~archivey.internal.streams.codecs.base.StreamCodec.header_check` on the
detector's first window, reported as ``PROBABLE`` from a content test:

- A ``begin`` line at offset 0 with a well-formed mode and name, followed by a line
  that is a valid encoded line (or the empty file's closing lines). With a name that
  says ``.uu``/``.uue``, text before the ``begin`` line is allowed too.
- Base64 with no name for it is accepted only when the window opens with at least
  :data:`_MIN_B64_LINES` full lines of one length, all of base64 characters, and their
  decoded bytes start with a known format's magic (a base64'd ZIP, gzip or tar). Lines
  of letters and digits alone are common in plain text, hex dumps and ID lists, and
  hex digits are base64 characters, so the magic is what makes the guess safe. A
  ``.b64`` name skips the magic check.

**Size.** Decoding shrinks the data (by a quarter for base64, a bit more for
uuencode), and the decoders hold at most one line or one 4-character group of input
beyond what they return, so neither needs a memory check. A uuencode line is capped
at :data:`_MAX_LINE` bytes.
"""

from __future__ import annotations

import binascii
import re
import stat
from itertools import takewhile
from typing import TYPE_CHECKING

from archivey.config import ProcessIsolation
from archivey.exceptions import CorruptionError
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import (
    Codec,
    CodecParams,
    MetadataContext,
    ProbeChargeDecode,
    ProbeReadAt,
    StreamCodec,
)
from archivey.types import ArchiveFormat, ArchiveMember, StreamFormat

if TYPE_CHECKING:
    from archivey.formats import Decompressor
    from archivey.internal.config import StreamConfig

# How much text may come before a ``begin`` line: a mail or news post's headers and
# body. Past this the source is refused rather than read to its end in search of one.
MAX_LEADING_TEXT = 64 * 1024
# The longest line a uuencode reader buffers. A uuencoded line is at most 62 bytes (a
# length, 60 data characters and the checksum character some old encoders add); base64
# lines in ``begin-base64`` are 76 at most. This is generous.
_MAX_LINE = 4096
_HEADER = re.compile(rb"\Abegin(-base64)? +([0-7]{3,6}) +(\S.*?)[ \t]*\r?\Z")
_WHITESPACE = b" \t\r\n"
# What the base64 decoder skips between groups: line breaks only. A space or a tab is
# outside the alphabet, so prose after unpadded base64 fails instead of decoding.
_LINE_ENDS = b"\r\n"
_B64_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
# Unnamed base64 needs this many full lines of one length in the first window.
_MIN_B64_LINES = 4
# And lines at least this long: a column of short IDs is not a base64 file.
_MIN_B64_LINE = 40


class _UuHeader:
    __slots__ = ("base64", "end", "mode", "name")

    def __init__(self, match: re.Match[bytes], end: int) -> None:
        self.base64 = match.group(1) is not None
        self.mode = int(match.group(2), 8)
        self.name = match.group(3)
        self.end = end  # offset just past the header line's newline


def _find_header(data: bytes, *, leading: bool) -> _UuHeader | None:
    """The first ``begin`` line in ``data``: at offset 0, or anywhere when ``leading``.
    Only whole lines (ending in a newline) are looked at."""
    pos = 0
    while True:
        nl = data.find(b"\n", pos)
        if nl < 0:
            return None
        match = _HEADER.match(data[pos:nl])
        if match is not None:
            return _UuHeader(match, nl + 1)
        if not leading:
            return None
        pos = nl + 1


def _uu_line_valid(line: bytes) -> bool:
    """Whether ``line`` (no newline) is a uuencoded data line: a length character from
    1 to 45, and characters in the uuencode range for at least the bytes it declares
    (trailing spaces are often stripped, so a short line may still be whole)."""
    if not line or len(line) > 62:
        return False
    n = (line[0] - 32) & 63
    if n == 0 or n > 45 or any(c < 32 or c > 96 for c in line):
        return False
    return len(line) - 1 >= -(-n * 4 // 3) - 2


def _uu_body_starts(data: bytes, header: _UuHeader) -> bool:
    """Whether the line after ``header`` is a valid first line of its body."""
    nl = data.find(b"\n", header.end)
    if nl < 0:
        return False
    line = data[header.end : nl].rstrip(b"\r")
    if header.base64:
        if line == b"====":
            return True
        if not (
            len(line) % 4 == 0
            and len(line) >= 4
            and all(c in _B64_ALPHABET or c == 0x3D for c in line)
        ):
            return False
        # A short word is base64 characters too: the line must be as long as the
        # encoders write, end in padding, or be the whole body before ``====``.
        if len(line) >= _MIN_B64_LINE or line.endswith(b"="):
            return True
        nl2 = data.find(b"\n", nl + 1)
        return nl2 >= 0 and data[nl + 1 : nl2].rstrip(b"\r") == b"===="
    if line in (b"`", b" ", b"end"):
        return True  # an empty file
    return _uu_line_valid(line)


def _lines(data: bytes) -> list[bytes]:
    """``data``'s whole lines, without their line ends (a partial last one is left
    out)."""
    return [line.rstrip(b"\r") for line in data.split(b"\n")[:-1]]


def _b64_lines_check(lines: list[bytes]) -> bool:
    """Whether ``lines`` open a base64 text: full lines of one length, a multiple of
    4 and at least :data:`_MIN_B64_LINE`, of base64 characters only, and maybe one
    shorter last line that may end in padding."""
    if len(lines) < 2:
        return False
    width = len(lines[0])
    if width < _MIN_B64_LINE or width % 4:
        return False
    for i, line in enumerate(lines):
        last = i == len(lines) - 1
        body = line.rstrip(b"=") if last else line
        if not all(c in _B64_ALPHABET for c in body):
            return False
        if len(line) != width and not (last and 0 < len(line) < width):
            return False
    return True


def _mixed(chars: bytes) -> bool:
    """Whether ``chars`` holds at least two of: capitals, small letters, other."""
    kinds = {
        "upper" if 65 <= c <= 90 else "lower" if 97 <= c <= 122 else "other"
        for c in chars
    }
    return len(kinds) >= 2


def _decodes(chars: bytes) -> bool:
    try:
        binascii.a2b_base64(chars, strict_mode=True)
    except binascii.Error:
        return False
    return True


def _decoded_has_magic(decoded: bytes) -> bool:
    """Whether ``decoded`` holds a known format's exact magic where that format puts
    it. gzip's and ``.Z``'s are two bytes each, so a chance hit on base64 of random
    bytes is about one in 32 768; such a file is still base64, which is all this
    format claims."""
    # Imported here: the registry imports the codecs.
    from archivey.internal.registry import get_registry

    for entry in get_registry().magic_entries():
        if entry.format in (ArchiveFormat.UU, ArchiveFormat.BASE64):
            continue
        end = entry.offset + len(entry.magic)
        if end <= len(decoded) and decoded[entry.offset : end] == entry.magic:
            return True
    return False


# --- decoders --------------------------------------------------------------------------


class _Output:
    """Decoded bytes waiting for a ``max_length`` to let them out."""

    def __init__(self) -> None:
        self._held = bytearray()

    def take(self, max_length: int) -> bytes:
        if max_length < 0 or max_length >= len(self._held):
            out = bytes(self._held)
            self._held.clear()
            return out
        out = bytes(self._held[:max_length])
        del self._held[:max_length]
        return out

    def add(self, data: bytes) -> None:
        self._held += data

    def __len__(self) -> int:
        return len(self._held)


class UuDecompressor:
    """One uuencoded or ``begin-base64`` file, line by line."""

    def __init__(self) -> None:
        self._input = bytearray()
        self._skipped = 0  # leading text passed over so far
        self._header: _UuHeader | None = None
        self._done = False
        self._ended = False  # the input ended (end_input)
        self._out = _Output()
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._done:
            self._after_end(data)
        else:
            self._input += data
            self._consume()
        return self._out.take(max_length)

    def _consume(self) -> None:
        while not self._done:
            nl = self._input.find(b"\n")
            if nl < 0:
                if len(self._input) > _MAX_LINE:
                    raise CorruptionError(
                        f"uuencoded line longer than {_MAX_LINE} bytes"
                    )
                return
            line = bytes(self._input[:nl]).rstrip(b"\r")
            del self._input[: nl + 1]
            self._line(line, nl + 1)
        rest = bytes(self._input)
        self._input = bytearray()
        self._after_end(rest)

    def _line(self, line: bytes, length: int) -> None:
        header = self._header
        if header is None:
            match = _HEADER.match(line)
            if match is not None:
                self._header = _UuHeader(match, 0)
                return
            self._skipped += length
            if self._skipped > MAX_LEADING_TEXT:
                raise CorruptionError(
                    f"no uuencode 'begin' line in the first {MAX_LEADING_TEXT} bytes"
                )
            return
        if header.base64:
            if line == b"====":
                self._done = True
                return
            try:
                self._out.add(binascii.a2b_base64(line.strip(), strict_mode=True))
            except binascii.Error as exc:
                raise CorruptionError(f"bad begin-base64 line: {exc}") from None
            return
        if line == b"end":
            self._done = True
            return
        if line in (b"", b"`", b" "):
            return  # the zero-length line before 'end'
        if not _uu_line_valid(line):
            raise CorruptionError(f"bad uuencoded line {line[:64]!r}")
        # Only the groups the length character declares: some old encoders write a
        # checksum character after them, which a2b_uu would refuse.
        n = (line[0] - 32) & 63
        try:
            self._out.add(binascii.a2b_uu(line[: 1 + 4 * -(-n // 3)]))
        except binascii.Error as exc:
            raise CorruptionError(f"bad uuencoded line: {exc}") from None

    def _after_end(self, data: bytes) -> None:
        """Input after the end line: whitespace is the file's own line ends, anything
        else is left as :attr:`unused_data` (trailing data)."""
        if self.unused_data:
            self.unused_data += data
            return
        stripped = data.lstrip(_WHITESPACE)
        if stripped:
            self.unused_data = stripped

    @property
    def eof(self) -> bool:
        return self._done and not len(self._out)

    @property
    def needs_input(self) -> bool:
        return not self._done and not len(self._out)

    def end_input(self) -> None:
        if self._ended or self._done:
            return
        self._ended = True
        if self._input:
            # A last line with no newline after it.
            line = bytes(self._input).rstrip(b"\r")
            self._input = bytearray()
            self._line(line, len(line))
        if self._header is None:
            raise CorruptionError("not a uuencoded file: no 'begin' line")
        if not self._done:
            closing = "'===='" if self._header.base64 else "'end'"
            raise EOFError(f"uuencoded file ends before its {closing} line")


class Base64Decompressor:
    """Bare base64 text: groups of four characters, line breaks skipped,
    ending at ``=`` padding or at the end of the input."""

    def __init__(self) -> None:
        self._pending = b""  # fewer than 4 characters, no whitespace, no '='
        self._done = False
        self._ended = False
        self._out = _Output()
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        if self._done:
            self._after_end(data)
        elif data:
            self._feed(data)
        return self._out.take(max_length)

    def _feed(self, data: bytes) -> None:
        pad = data.find(b"=")
        if pad < 0:
            chars = self._pending + data.translate(None, _LINE_ENDS)
            whole = len(chars) - len(chars) % 4
            self._decode(chars[:whole])
            self._pending = chars[whole:]
            return
        # The group the first '=' is in is the last one. Count the characters before
        # it, then walk on through '=' and whitespace until the group is complete.
        head = self._pending + data[:pad].translate(None, _LINE_ENDS)
        need = (len(head) // 4 + 1) * 4 - len(head)
        pos = pad
        tail = bytearray()
        while pos < len(data) and len(tail) < need:
            c = data[pos]
            if c == 0x3D:
                tail.append(c)
            elif c not in _LINE_ENDS:
                break
            pos += 1
        if len(tail) < need:
            if pos == len(data):
                # The padding runs on into the next call.
                self._pending = b""
                self._decode(head[: len(head) - len(head) % 4])
                self._pending = head[len(head) - len(head) % 4 :] + bytes(tail)
                return
            raise CorruptionError("base64 padding ends a group early")
        self._decode(head + bytes(tail))
        self._pending = b""
        self._done = True
        self._after_end(data[pos:])

    def _decode(self, chars: bytes) -> None:
        if not chars:
            return
        try:
            decoded = binascii.a2b_base64(chars, strict_mode=True)
        except binascii.Error as exc:
            raise CorruptionError(f"not base64 text: {exc}") from None
        self._out.add(decoded)

    def _after_end(self, data: bytes) -> None:
        if self.unused_data:
            self.unused_data += data
            return
        stripped = data.lstrip(_WHITESPACE)
        if stripped:
            self.unused_data = stripped

    @property
    def eof(self) -> bool:
        return self._done and not len(self._out)

    @property
    def needs_input(self) -> bool:
        return not self._done and not len(self._out)

    def end_input(self) -> None:
        if self._ended or self._done:
            return
        self._ended = True
        pending = self._pending
        self._pending = b""
        if b"=" in pending:
            raise EOFError("base64 text ends inside its padding")
        if len(pending) == 1:
            raise CorruptionError("base64 text ends one character into a group")
        if pending:
            # Unpadded, as some encoders write the end.
            self._decode(pending + b"=" * (4 - len(pending)))
        # No characters at all is the encoding of an empty file, as `base64` writes it.
        self._done = True


# --- codecs ----------------------------------------------------------------------------


class UuCodec(StreamCodec):
    """uuencode and ``begin-base64`` files."""

    codec = Codec.UU
    stream_format = StreamFormat.UU
    extension_aliases = (".uue",)
    codec_name = "uuencode"
    # One file per begin/end pair: a second pair after it is trailing data, not more
    # of the output.
    concatenated = False

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        del params, config
        return UuDecompressor()

    @override
    def header_check(self, prefix: bytes) -> bool:
        """A ``begin`` line at offset 0, followed by a valid first body line."""
        header = _find_header(prefix, leading=False)
        return header is not None and _uu_body_starts(prefix, header)

    @override
    def content_probe(
        self,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: ProbeReadAt | None = None,
        charge_decode: ProbeChargeDecode | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        """For a source named ``.uu``/``.uue``: a ``begin`` line anywhere in the
        sample, after mail or news text, followed by a valid first body line."""
        del source_length, read_at, charge_decode, isolation
        header = _find_header(prefix, leading=True)
        return header is not None and _uu_body_starts(prefix, header)

    @override
    def extract_metadata(self, ctx: MetadataContext, member: ArchiveMember) -> None:
        """The name and mode the ``begin`` line stores."""
        head = ctx.peek_header(MAX_LEADING_TEXT + _MAX_LINE)
        header = _find_header(head, leading=True)
        if header is None:
            return
        member.raw_name = header.name
        member.extra["uu.original_filename"] = header.name.decode(
            "utf-8", "surrogateescape"
        )
        if header.mode:
            member.mode = stat.S_IMODE(header.mode)


class Base64Codec(StreamCodec):
    """Bare base64 text."""

    codec = Codec.BASE64
    stream_format = StreamFormat.BASE64
    extension_aliases = (".base64",)
    codec_name = "base64"
    concatenated = False

    @override
    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        del params, config
        return Base64Decompressor()

    @override
    def header_check(self, prefix: bytes) -> bool:
        """Full base64 lines of one length whose decoded bytes start with a known
        format's magic."""
        lines = _lines(prefix)
        full = list(takewhile(lambda line: len(line) == len(lines[0]), lines))
        if len(full) < _MIN_B64_LINES or not _b64_lines_check(full):
            return False
        try:
            decoded = binascii.a2b_base64(b"".join(full), strict_mode=True)
        except binascii.Error:
            return False
        return _decoded_has_magic(decoded)

    @override
    def content_probe(
        self,
        prefix: bytes,
        *,
        source_length: int | None = None,
        read_at: ProbeReadAt | None = None,
        charge_decode: ProbeChargeDecode | None = None,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> bool:
        """For a source named ``.b64``/``.base64``: base64 lines of one length, or one
        long line, with no magic needed."""
        del read_at, charge_decode, isolation
        whole = source_length is not None and len(prefix) >= source_length
        lines = _lines(prefix + b"\n") if whole else _lines(prefix)
        lines = [line for line in lines if line]
        if not lines:
            # One long line still arriving: its characters are all there is.
            body = prefix.strip(_WHITESPACE)
            return len(body) >= 16 and all(c in _B64_ALPHABET for c in body)
        if len(lines) == 1:
            line = lines[0]
            # One line: a word or an identifier is base64 characters too. Encoded
            # bytes mix letter cases and digits, so a line of one kind of character
            # is turned away; under 16 characters it must end in padding as well.
            if not _mixed(line.rstrip(b"=")):
                return False
            if whole:
                # The whole source: it must decode as it is, padding and all.
                short_ok = len(line) >= 16 or line.endswith(b"=")
                return len(line) >= 8 and short_ok and _decodes(line)
            return len(line) >= 16 and all(c in _B64_ALPHABET for c in line)
        return _b64_lines_check(lines)
