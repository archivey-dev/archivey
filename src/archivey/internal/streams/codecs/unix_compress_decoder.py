"""Unix-compress (``.Z``) LZW decoder for :class:`~.decompressor_stream.DecompressorStream`.

Opened via :class:`~.codecs.UnixCompressCodec`. The LZW kernel is adapted from
`uncompresspy` (https://github.com/kYwzor/uncompresspy), Copyright (c) 2025 Tiago
Gomes, used under the BSD 3-Clause License (see the notice at the bottom of this
file). CLEAR boundaries become seek points; forward decode never needs a seekable
source.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import BinaryIO

from archivey.exceptions import CorruptionError, TruncatedError, UnsupportedFeatureError
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    DecompressorStream,
    SeekPoint,
    truncated_message,
)

_INITIAL_CODE_WIDTH = 9
_MAX_CODE_WIDTH = 16  # classic compress / ncompress format ceiling
_INITIAL_MASK = 2**_INITIAL_CODE_WIDTH - 1
_CLEAR_CODE = 256
_MAGIC_BYTE0 = 0x1F
_MAGIC_BYTE1 = 0x9D
_BLOCK_MODE_FLAG = 0x80
_CODE_WIDTH_FLAG = 0x1F
_RESERVED_FLAGS = 0x60
_HEADER_SIZE = 3
_MAGIC = bytes([_MAGIC_BYTE0, _MAGIC_BYTE1])

# Dictionary entry representation. An LZW entry is its prefix entry plus one byte, so
# storing every entry as its full expansion costs up to ~65 536**2 / 2 bytes (2 GiB) at
# 16 bits, and a long zero run builds that shape. An entry up to _MAX_FLAT_ENTRY bytes
# is stored flat in the dictionary list as bytes. A longer one is stored there as a
# (base code, tail) link meaning "the expansion of base, then tail". The tail grows to
# _MAX_ENTRY_TAIL bytes before a new link starts from the previous code, so every link
# but the first in a walk carries a full tail: rebuilding an entry takes about one step
# per 128 bytes of it. With CPython object overhead the dictionary stays under about
# 19 MiB: a full table of flat 256-byte entries measures 18.5 to 18.8 MiB on CPython
# 3.11 to 3.14 (up to 20.3 MiB on a free-threaded build, whose object headers are
# larger), and a full table of links with full tails about 14 MiB. Links sit in the list
# itself, not in a side dict keyed by code: that saves a dict slot and a key object per
# long entry, and decoded the all-links table about 1.3x faster. The price is an
# isinstance check per code (about 16 ns more than a truthiness test), which stayed
# within noise on ordinary compress files.
#
# The two caps trade speed against that bound. Shorter tails mean more Python steps per
# output byte: one-byte links rebuilt 64 KiB entries at about 18 MB/s, against about
# 1.6 GB/s at 128. Longer tails or a higher flat cap raise the worst case: 256-byte
# tails measured 26 MiB.
_MAX_FLAT_ENTRY = 256
_MAX_ENTRY_TAIL = 128


_Entry = bytes | tuple[int, bytes]

# A 9-bit stream comes in two layouts once its table fills. The original compress (4.0,
# 1985) and BSD's, which GNU gzip, ncompress 5.0's reader and 7-Zip 26.05 follow, pad to
# the end of the group of eight codes and write the rest 10 bits wide; the values stay
# below 512. ncompress 4.2 to 5.0 (and its unreleased fix, 3303f31) keep 9-bit codes,
# which unar and 7-Zip up to 26.04 read. Nothing in the header says which, so the
# decoder reads the next _NINE_BIT_PROBE_BYTES as 10-bit codes: the original layout never
# sets bit 9 of one, and every 9-bit stream measured set it within seven codes. A source
# that ends first is decided on what it has, and the original layout wins a tie.
_NINE_BIT_PROBE_BYTES = 40  # 32 codes of 10 bits


def _expand(dictionary: Sequence[_Entry | None], link: tuple[int, bytes]) -> bytes:
    """Rebuild a long entry by walking its links back to a flat entry.

    A link's base is always a code that was output, so the walk never meets block
    mode's CLEAR placeholder. A base that did would end the walk at that b"" and
    silently drop the prefix, not raise.

    ZIP's Shrink decoder shares this layout, and its table also holds None for a free
    slot or one that walks its parents. A link's base there is the parent, or an
    ancestor, of a live slot, and a partial clear frees only slots with no children,
    so the walk never meets None either; one that did is refused as corrupt.
    """
    base, tail = link
    parts = [tail]
    while isinstance(head := dictionary[base], tuple):
        base, tail = head
        parts.append(tail)
    if head is None:
        raise CorruptionError("LZW code table links to a free code")
    parts.append(head)
    parts.reverse()
    return b"".join(parts)


def _parse_header(header: bytes) -> tuple[int, bool]:
    """Validate the 3-byte ``.Z`` header → ``(max_width, block_mode)``."""
    if len(header) < _HEADER_SIZE:
        raise CorruptionError("unix-compress (.Z) stream is too short (missing header)")
    if header[0] != _MAGIC_BYTE0 or header[1] != _MAGIC_BYTE1:
        raise CorruptionError(
            f"unix-compress (.Z) magic mismatch (expected {_MAGIC_BYTE0:02x} "
            f"{_MAGIC_BYTE1:02x}, got {header[0]:02x} {header[1]:02x})"
        )
    flag_byte = header[2]
    reserved = flag_byte & _RESERVED_FLAGS
    if reserved:
        raise UnsupportedFeatureError(
            f"unix-compress (.Z) header has unknown reserved flags "
            f"(0x{reserved:02x} in flag byte 0x{flag_byte:02x}); a damaged header "
            "reads the same way"
        )
    max_width = flag_byte & _CODE_WIDTH_FLAG
    if max_width < _INITIAL_CODE_WIDTH:
        raise CorruptionError(
            f"unix-compress (.Z) max code width {max_width} is below the minimum "
            f"of {_INITIAL_CODE_WIDTH}"
        )
    if max_width > _MAX_CODE_WIDTH:
        # gzip and ncompress: "compressed with 17 bits, can only handle 16 bits".
        raise UnsupportedFeatureError(
            f"unix-compress (.Z) max code width {max_width} is not supported: "
            f"decoders handle up to {_MAX_CODE_WIDTH} bits; a damaged header reads the "
            "same way"
        )
    block_mode = bool(flag_byte & _BLOCK_MODE_FLAG)
    return max_width, block_mode


class LzwState:
    """Push LZW decoder: ``feed`` / ``flush`` → ``(bytes, segment_units)``.

    Each CLEAR ends a segment unit ``(decompressed_size, compressed_size)`` measured
    from the previous CLEAR (or from just after the header). Absolute offsets and
    :class:`SeekPoint` registration belong to the stream wrapper.

    Format errors raise :class:`CorruptionError` directly (same pattern as native
    xz/lzip). Unknown reserved header flags and a maximum code width over 16 raise
    :class:`UnsupportedFeatureError`.
    A 9-bit stream whose table fills is read in the layout :data:`_NINE_BIT_PROBE_BYTES`
    describes; ``nine_bit_widens`` fixes it instead (a recreated decoder keeps the one
    the stream was read with).
    At EOF, :attr:`truncation` names the evidence of a cut when there is some: a source
    that ended inside the header, inside a CLEAR's realignment padding, or with nonzero
    leftover bits after the last complete code. Zero leftover bits are normal for
    finished streams, so a cut that leaves only those stays undetectable.
    """

    def __init__(
        self,
        *,
        max_width: int | None = None,
        block_mode: bool | None = None,
        nine_bit_widens: bool | None = None,
    ) -> None:
        self._buf = bytearray()
        self._nine_bit_widens = nine_bit_widens
        # Set when a 9-bit table filled and the layout step has not run yet.
        self._at_nine_bit_fill = False
        self._finished = False
        self._truncation: str | None = None
        self._header_params: tuple[int, bool] | None = None
        self._need_header = max_width is None
        self._seg_comp = 0
        self._seg_decomp = 0
        self._pending_skip = 0
        self._skip_may_end_at = 0
        self._skip_reason = "after a CLEAR"
        if not self._need_header:
            assert max_width is not None and block_mode is not None
            self._init_dictionary(max_width, block_mode)
            self._header_params = (max_width, block_mode)

    @property
    def header_params(self) -> tuple[int, bool] | None:
        """``(max_width, block_mode)`` once the header is known, else ``None``."""
        return self._header_params

    @property
    def nine_bit_widens(self) -> bool | None:
        """Whether a full 9-bit table moved to 10-bit codes; ``None`` until one filled."""
        return self._nine_bit_widens

    @property
    def truncated(self) -> bool:
        """True after ``flush`` when the stream shows evidence of being cut short."""
        return self._truncation is not None

    @property
    def truncation(self) -> str | None:
        """After ``flush``, what showed the stream was cut short, else ``None``."""
        return self._truncation

    def feed(
        self, data: bytes, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        if self._finished:
            return b"", []
        self._buf.extend(data)
        return self._process(eof=False, max_length=max_length)

    def flush(self) -> tuple[bytes, list[tuple[int, int]]]:
        out, units = self._process(eof=True, max_length=-1)
        if self._pending_skip and self._pending_skip != self._skip_may_end_at:
            # A compressor writes realignment padding in full, so a source that ends
            # while padding is still owed was cut inside it. The one exception: padding
            # at a width bump is written only when another code follows, so a stream
            # may end there with none of it.
            self._truncation = f"it ends {self._pending_skip} byte(s) short of the padding {self._skip_reason}"
        # Finished compressors zero-pad the last incomplete code slot. Nonzero leftover
        # bits are a best-effort truncation / corrupt-padding signal (exact mid-code
        # cuts that leave only zero bits remain undetectable — no length trailer).
        elif self._header_params is not None and self._bits_in_buffer > 0:
            leftover = self._bit_buffer & ((1 << self._bits_in_buffer) - 1)
            if leftover:
                self._truncation = (
                    "nonzero leftover bits after the last complete LZW code"
                )
        if self._header_params is not None:
            del self._dictionary[self._starting_code :]
        self._finished = True
        return out, units

    def is_finished(self) -> bool:
        return self._finished

    @property
    def needs_input(self) -> bool:
        """False only when ``feed(b"")`` can make progress without new input.

        That is: a complete header is buffered but not yet parsed, or any bytes are
        buffered after it. Every buffered byte past the header either feeds the bit
        buffer or pays down CLEAR padding, so both count as progress. A partial header,
        padding still owed with nothing buffered, or a full 9-bit table whose layout
        probe is not all buffered yet, needs more input.
        """
        if self._finished:
            return True
        if self._need_header:
            return len(self._buf) < _HEADER_SIZE
        if self._at_nine_bit_fill and self._nine_bit_widens is None:
            pad = -self._bytes_in_era % _INITIAL_CODE_WIDTH
            return len(self._buf) < pad + _NINE_BIT_PROBE_BYTES
        return not self._buf

    def _init_dictionary(self, max_width: int, block_mode: bool) -> None:
        self._max_width = max_width
        self._block_mode = block_mode
        self._dictionary: list[_Entry] = [i.to_bytes() for i in range(256)]
        if block_mode:
            self._dictionary.append(b"")
        self._starting_code = len(self._dictionary)
        self._next_code = self._starting_code
        self._bit_buffer = 0
        self._bits_in_buffer = 0
        self._prev_entry: bytes | None = None
        self._prev_code = 0
        self._code_width = _INITIAL_CODE_WIDTH
        self._current_mask = _INITIAL_MASK
        self._bytes_in_era = 0
        # Counts the era's codes toward `codes_per_era` (2 ** (width - 1)). 9-bit codes
        # end once free code 512 is used. In both modes the first code adds no entry. Block
        # mode starts free codes at 257, so it spends 255 entries plus that code: 256
        # codes. Without block mode free codes start at 256, so the first era is 257
        # codes, and starting at -1 absorbs the extra one. Later eras have no code that
        # adds no entry, so they are 2 ** (width - 1) codes in both modes.
        self._codes_in_era = 0 if block_mode else -1
        self._pending_skip = 0
        self._skip_may_end_at = 0
        self._skip_reason = "after a CLEAR"

    def _process(
        self, *, eof: bool, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        output = bytearray()
        units: list[tuple[int, int]] = []
        stepped = False
        # A 9-bit table fill ends a step; settle its layout and go on while the buffer
        # and the budget allow.
        while not self._at_nine_bit_fill or self._settle_nine_bit_fill(eof):
            if stepped and 0 <= max_length <= len(output):
                break
            more, more_units = self._process_step(
                eof=eof,
                max_length=-1 if max_length < 0 else max_length - len(output),
            )
            output += more
            units += more_units
            stepped = True
            if not self._at_nine_bit_fill:
                break
        return bytes(output), units

    def _settle_nine_bit_fill(self, eof: bool) -> bool:
        """Apply the layout at a full 9-bit table; False while the probe needs input."""
        widens = self._nine_bit_widens
        pad = -self._bytes_in_era % _INITIAL_CODE_WIDTH
        if widens is None:
            probe = self._buf[pad : pad + _NINE_BIT_PROBE_BYTES]
            if len(probe) < _NINE_BIT_PROBE_BYTES and not eof:
                return False
            value = int.from_bytes(probe, "little")
            codes = len(probe) * 8 // 10
            widens = not any(value >> (10 * k + 9) & 1 for k in range(codes))
            if widens and len(probe) < _NINE_BIT_PROBE_BYTES:
                # The source ends inside the probe. A writer stops at the byte holding
                # its last code's final bit, so a whole byte left over after the last
                # 10-bit code, or padding cut short, rules the 10-bit reading out.
                tail = len(self._buf)
                widens = (tail == 0 or tail >= pad) and len(probe) * 8 % 10 != 8
            self._nine_bit_widens = widens
        self._at_nine_bit_fill = False
        if not widens:
            return True
        # As at any width increase: pad to the end of the group of eight codes, drop the
        # rest of the byte's bits, and start a 10-bit era. The table stays at 511: the
        # next free code moves past the 10-bit mask, so no code adds an entry and code
        # 512, which has none, is an invalid code rather than a KwKwK one.
        if pad:
            skip = min(pad, len(self._buf))
            del self._buf[:skip]
            self._seg_comp += pad
            if skip < pad:
                self._pending_skip = pad - skip
                self._skip_may_end_at = pad if skip == 0 else 0
                self._skip_reason = "at a code-width increase"
        self._code_width = _INITIAL_CODE_WIDTH + 1
        self._current_mask = (1 << self._code_width) - 1
        self._next_code = self._current_mask + 1
        self._bit_buffer = 0
        self._bits_in_buffer = 0
        self._bytes_in_era = 0
        self._codes_in_era = 0
        return True

    def _process_step(
        self, *, eof: bool, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        output = bytearray()
        units: list[tuple[int, int]] = []

        if self._need_header:
            if len(self._buf) < _HEADER_SIZE:
                if eof:
                    # An empty source is not a valid empty .Z (zcat refuses it too).
                    # Nothing, or the start of the magic, is a cut-short header;
                    # anything else was never a .Z stream.
                    head = bytes(self._buf)
                    if head != _MAGIC[: len(head)]:
                        raise CorruptionError(
                            "unix-compress (.Z) stream is too short (missing header)"
                        )
                    self._truncation = "it ends inside the 3-byte header"
                return b"", []
            header = bytes(self._buf[:_HEADER_SIZE])
            del self._buf[:_HEADER_SIZE]
            max_width, block_mode = _parse_header(header)
            self._init_dictionary(max_width, block_mode)
            self._header_params = (max_width, block_mode)
            self._need_header = False

        if self._pending_skip:
            skip = min(self._pending_skip, len(self._buf))
            del self._buf[:skip]
            self._pending_skip -= skip
            if self._pending_skip:
                return b"", []

        # Local aliases — hot path (same trick as uncompresspy, ~2x).
        bit_buffer = self._bit_buffer
        bits_in_buffer = self._bits_in_buffer
        code_width = self._code_width
        current_mask = self._current_mask
        next_code = self._next_code
        prev_entry = self._prev_entry
        prev_code = self._prev_code
        prev_len = len(prev_entry) if prev_entry is not None else 0
        # Only the flat cap is read for every new entry; _MAX_ENTRY_TAIL is read only on
        # the long-entry branch, so it stays a module global.
        max_flat_entry = _MAX_FLAT_ENTRY
        dictionary = self._dictionary
        max_width = self._max_width
        # The width past which no era ends. A 9-bit stream's era also ends at a full
        # table unless it is known to keep 9-bit codes; the layout step takes it there.
        width_limit = max_width
        if max_width == _INITIAL_CODE_WIDTH and self._nine_bit_widens is not False:
            width_limit += 1
        block_mode = self._block_mode
        starting_code = self._starting_code
        seg_comp = self._seg_comp
        seg_decomp = self._seg_decomp
        # Bytes/codes since the last CLEAR or code-width bump (era start). uncompresspy
        # reads one era-block of size code_width * 2**(code_width-4) at a time; we process
        # push chunks byte-by-byte but keep the same alignment and width-bump rules.
        bytes_in_era = self._bytes_in_era
        codes_in_era = self._codes_in_era
        codes_per_era = 1 << (code_width - 1)

        buf_i = 0
        budget_hit = False
        while buf_i < len(self._buf):
            cur_byte = self._buf[buf_i]
            buf_i += 1
            bytes_in_era += 1
            bit_buffer += cur_byte << bits_in_buffer
            bits_in_buffer += 8
            seg_comp += 1

            cleared = False
            while bits_in_buffer >= code_width:
                code = bit_buffer & current_mask
                bit_buffer >>= code_width
                bits_in_buffer -= code_width
                codes_in_era += 1

                if code == _CLEAR_CODE and block_mode:
                    # Realign to the next code_width-byte boundary within this era,
                    # then unread the remainder (in-memory stand-in for file.seek).
                    # bytes_in_era is the 1-based count of bytes consumed in the era;
                    # uncompresspy's `i` is 0-based within the current read chunk, which
                    # always starts at an era boundary — so i == bytes_in_era - 1.
                    i = bytes_in_era - 1
                    if advanced := i % code_width:
                        i += code_width - advanced
                    era_start = buf_i - bytes_in_era
                    target = era_start + i
                    # Padding forward, or re-read the CLEAR-completing byte when it
                    # already sits on a code_width boundary (matches uncompresspy).
                    if target > buf_i:
                        seg_comp += target - buf_i
                    elif target < buf_i:
                        seg_comp -= buf_i - target
                    units.append((seg_decomp, seg_comp))
                    seg_comp = 0
                    seg_decomp = 0
                    del dictionary[starting_code:]
                    next_code = starting_code
                    code_width = _INITIAL_CODE_WIDTH
                    current_mask = _INITIAL_MASK
                    bit_buffer = 0
                    bits_in_buffer = 0
                    prev_entry = None
                    bytes_in_era = 0
                    codes_in_era = 0
                    codes_per_era = 1 << (code_width - 1)
                    if target > len(self._buf):
                        # CLEAR realignment extends past this feed — skip the rest
                        # of the padding at the start of the next feed.
                        self._pending_skip = target - len(self._buf)
                        self._skip_may_end_at = 0
                        self._skip_reason = "after a CLEAR"
                        buf_i = len(self._buf)
                    else:
                        buf_i = target
                    cleared = True
                    break

                try:
                    entry = dictionary[code]
                except IndexError:
                    if code == next_code:
                        if prev_entry is None:
                            # First code after CLEAR/start must be a literal; KwKwK
                            # needs a previous entry. Corrupt or non-block-mode abuse.
                            raise CorruptionError(
                                f"unix-compress (.Z) invalid code {code} "
                                "(expected a literal)"
                            ) from None
                        entry = prev_entry + prev_entry[:1]
                    else:
                        raise CorruptionError(
                            f"unix-compress (.Z) invalid code {code} in bitstream"
                        ) from None

                if isinstance(entry, tuple):
                    # A long entry. Entries never change once written, so a repeated
                    # code reuses the expansion it produced last time instead of
                    # walking again.
                    if code == prev_code and prev_entry is not None:
                        entry = prev_entry
                    else:
                        entry = _expand(dictionary, entry)
                output += entry
                entry_len = len(entry)
                seg_decomp += entry_len

                if next_code <= current_mask and prev_entry is not None:
                    if prev_len < max_flat_entry:
                        dictionary.append(prev_entry + entry[:1])
                    else:
                        # Long: extend the previous entry's tail while it has room,
                        # else start a new link from the previous code. prev_code
                        # always indexes a live entry: a CLEAR sets prev_entry to
                        # None, so this branch waits for a fresh code, and a KwKwK
                        # code equals next_code <= current_mask, so its entry was
                        # appended in the same iteration.
                        link = dictionary[prev_code]
                        if isinstance(link, tuple) and len(link[1]) < _MAX_ENTRY_TAIL:
                            base, tail = link
                            dictionary.append((base, tail + entry[:1]))
                        else:
                            dictionary.append((prev_code, entry[:1]))
                    next_code += 1

                prev_entry = entry
                prev_code = code
                prev_len = entry_len

                if codes_in_era >= codes_per_era and code_width < width_limit:
                    if code_width == max_width:
                        # A full 9-bit table: the layout step decides what follows.
                        self._at_nine_bit_fill = True
                        budget_hit = True
                        break
                    # The writer pads to the end of the current group of eight codes.
                    # Eight codes of width `code_width` are exactly `code_width` bytes,
                    # so a group boundary is a multiple of `code_width` bytes from the
                    # era start. A block-mode era is a whole number of groups, so this
                    # skips nothing there; without block mode the first era is one
                    # code longer.
                    if pad := -bytes_in_era % code_width:
                        seg_comp += pad
                        if buf_i + pad > len(self._buf):
                            self._pending_skip = buf_i + pad - len(self._buf)
                            # Only a source that stops before any of the padding
                            # ends here legitimately; part of it means a cut.
                            self._skip_may_end_at = (
                                pad if buf_i == len(self._buf) else 0
                            )
                            self._skip_reason = "at a code-width increase"
                            buf_i = len(self._buf)
                        else:
                            buf_i += pad
                    code_width += 1
                    current_mask = (1 << code_width) - 1
                    bit_buffer = 0
                    bits_in_buffer = 0
                    bytes_in_era = 0
                    codes_in_era = 0
                    codes_per_era = 1 << (code_width - 1)
                    # Remainder bits from the current byte are discarded (matches
                    # uncompresspy clearing the bit buffer at a width bump).
                    break

                if max_length >= 0 and len(output) >= max_length:
                    budget_hit = True
                    break

            if cleared:
                continue
            if budget_hit:
                break

        del self._buf[:buf_i]

        self._bit_buffer = bit_buffer
        self._bits_in_buffer = bits_in_buffer
        self._code_width = code_width
        self._current_mask = current_mask
        self._next_code = next_code
        self._prev_entry = prev_entry
        self._prev_code = prev_code
        self._seg_comp = seg_comp
        self._seg_decomp = seg_decomp
        self._bytes_in_era = bytes_in_era
        self._codes_in_era = codes_in_era
        return bytes(output), units


class UnixCompressDecoder(BaseDecoder):
    """LZW decoder: CLEAR seek points (after-placement) + deferred truncation."""

    def __init__(
        self,
        state: LzwState,
        *,
        comp_cursor: int,
        decomp_cursor: int,
        max_width: int | None = None,
        block_mode: bool | None = None,
        header_committed: bool = False,
    ) -> None:
        self._state = state
        self._comp_cursor = comp_cursor
        self._decomp_cursor = decomp_cursor
        self._max_width = max_width
        self._block_mode = block_mode
        self._header_committed = header_committed

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> UnixCompressDecoder:
        del inner
        if self._max_width is not None and self._block_mode is not None:
            state = LzwState(
                max_width=self._max_width,
                block_mode=self._block_mode,
                nine_bit_widens=self._state.nine_bit_widens,
            )
            header_committed = True
        else:
            state = LzwState()
            header_committed = False
        return UnixCompressDecoder(
            state,
            comp_cursor=point.compressed_offset,
            decomp_cursor=point.decompressed_offset,
            max_width=self._max_width,
            block_mode=self._block_mode,
            header_committed=header_committed,
        )

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        data, units = self._state.feed(chunk, max_length=max_length)
        points = self._commit_header_points()
        points.extend(self._points_for_units(units))
        return DecodeOut(data, points)

    def flush(self) -> DecodeOut:
        data, units = self._state.flush()
        points = self._commit_header_points()
        points.extend(self._points_for_units(units))
        if self._state.truncation is not None:
            self._pending_error = TruncatedError(
                f"{truncated_message('unix-compress (.Z)')} ({self._state.truncation})"
            )
        return DecodeOut(data, points)

    @property
    def finished(self) -> bool:
        return self._state.is_finished()

    @property
    def needs_input(self) -> bool:
        return self._state.needs_input

    def _commit_header_points(self) -> list[SeekPoint]:
        if self._header_committed:
            return []
        params = self._state.header_params
        if params is None:
            return []
        self._max_width, self._block_mode = params
        self._comp_cursor = _HEADER_SIZE
        self._decomp_cursor = 0
        self._header_committed = True
        # Refine origin: resume after the 3-byte header (same decompressed offset).
        return [SeekPoint(0, _HEADER_SIZE)]

    def _points_for_units(self, units: list[tuple[int, int]]) -> list[SeekPoint]:
        points: list[SeekPoint] = []
        for decomp_size, comp_size in units:
            # After-placement: advance past CLEAR realignment, then emit the point.
            self._comp_cursor += comp_size
            self._decomp_cursor += decomp_size
            point = SeekPoint(self._decomp_cursor, self._comp_cursor)
            # Consecutive CLEARs (zero decompressed output between them) share a
            # decompressed_offset; keep the later compressed resume point only.
            if points and points[-1].decompressed_offset == point.decompressed_offset:
                points[-1] = point
            else:
                points.append(point)
        return points


def UnixCompressDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    collector: DiagnosticCollector | None = None,
    seekable: bool = True,
) -> DecompressorStream:
    """Seekable unix-compress stream: CLEAR → :class:`SeekPoint` when indexing is on."""

    def make_decoder(point: SeekPoint, inner: BinaryIO) -> UnixCompressDecoder:
        del inner
        return UnixCompressDecoder(
            LzwState(),
            comp_cursor=point.compressed_offset,
            decomp_cursor=point.decompressed_offset,
        )

    return DecompressorStream(
        path,
        make_decoder=make_decoder,
        collector=collector,
        codec_name="unix_compress",
        seekable=seekable,
    )


# ---------------------------------------------------------------------------
# BSD 3-Clause License notice for the adapted LZW kernel (from uncompresspy)
# ---------------------------------------------------------------------------
#
# Copyright (c) 2025, Tiago Gomes
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
