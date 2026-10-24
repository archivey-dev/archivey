"""The PPMd decoder (pyppmd), in process or in a child process."""

from __future__ import annotations

import os
from typing import BinaryIO, NoReturn, Protocol

from archivey.config import DecoderLimits, ProcessIsolation
from archivey.exceptions import (
    CorruptionError,
    ResourceUnavailableError,
    TruncatedError,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.codecs.decoder_child import (
    DecoderChildStartError,
    isolation_error,
)
from archivey.internal.streams.codecs.isolated import ChildPpmdDecoder
from archivey.internal.streams.codecs.ppmd_child import (
    ISOLATED_UNLESS_NONE,
    PpmdChildAllocationError,
    open_ppmd_child,
    ppmd_child_unavailable_reason,
)
from archivey.internal.streams.decompressor_stream import (
    BaseDecoder,
    DecodeOut,
    DecompressorStream,
    SeekPoint,
)

# Per-call output request for PPMd8 decodes without a declared size; 64 KiB matches
# the stream layer's read chunk. The bound avoids pyppmd's ``-1`` path. On pyppmd
# 1.3.x a request past the stream's true output leaves the worker waiting for input
# once it runs past what the range coder's tail lookahead can satisfy, and freeing
# the decoder in that state corrupts the heap (bare pyppmd, no quiesce: +64/+4096
# over → 0/20 crashes, +65536 over → 13/20); ``_quiesce_worker`` is what prevents
# that. PPMd8's end mark stops the worker on valid data; PPMd7 has none, which is
# why PpmdDecoder refuses to decode it without ``unpack_size``.
_PPMD_UNSIZED_DECODE_CHUNK = 65536

# Per-call ceiling for extra-NUL recovery and post-NUL empty drains. A single
# ``decode(b"\0", large_remaining)`` on truncated mid-stream input is the
# exit-after-green / mid-suite abort on pyppmd 1.3.x; chunking at 64 avoids that
# call shape. When the container pack is known-complete, empty ``decode(b"", 64)``
# drains may still finish a large tail (including past premature ``eof``); when the
# pack is known-incomplete, we refuse those post-eof drains (near-EOF MemoryError
# otherwise). See ``dev-docs/investigations/ppmd-exit-after-green-exploration.md``.
_PPMD_EXTRA_NUL_MAX_OUTPUT = 64

# Bounded number of single-symbol NUL decodes used to quiesce a parked native
# worker before the decoder is freed (see ``PpmdDecoder._quiesce_worker``). A
# parked worker only needs the range coder's few-byte tail lookahead satisfied to
# reach its 1-symbol budget and exit; 8 is a safe cushion over the observed need.
_PPMD_QUIESCE_MAX_CALLS = 8

# pyppmd parses ``decode``'s ``length`` as a C ``int``; anything larger raises a bare
# ``OverflowError``. A request is capped here and the rest is asked for on the next
# call. The oversized request comes from ``feed(chunk, -1)`` — what ``readall()`` /
# ``read(-1)`` sends — whose limit is the whole remaining ``unpack_size``, and from
# one large ``read(n)``; either reaches it on a member over 2 GiB, or on a header
# that overstates ``unpack_size`` past that.
_PPMD_MAX_REQUEST = (1 << 31) - 1

# How PPMd avoids pyppmd's crash on corrupt input: pyppmd segfaults when asked to
# decode after a corrupt stream has ended early, and a caller feeding it in pieces
# cannot tell that state from a valid stream waiting for input (see ``ppmd_child``).
# Handed the whole member at once, a short return is the end and little more is asked
# of pyppmd, so ``PpmdDecoder`` holds compressed input until it has the whole member,
# or compressed EOF, or ``DecoderLimits.max_ppmd_held_input``; past that it is fed in
# pieces. That holds under every ``process_isolation``, which decides only where the
# decode runs: in a child process, where a crash costs the member only, unless it is
# ``NONE``, where a crash on a member fed in pieces takes down this process.

_DEFAULT_MAX_HELD_INPUT = DecoderLimits().max_ppmd_held_input

# Input after a member's declared output that a ``refuse_input_after_end`` decoder
# collects before its end check: room for an end mark and its range-coder flush.
# Measured on pyppmd 1.3.1 and 7-Zip 23.01, that is at most 3 bytes for PPMd8 and 1
# for PPMd7; the bound leaves slack over it, so that a producer that flushes a little
# more reaches the end check rather than being refused for its length. More is input
# the member does not use (see ``PpmdDecoder._check_end``).
_PPMD_TAIL_MAX = 16

# The five bytes 7-Zip's PPMd7 range coder writes for a stream with no symbols.
_PPMD7_EMPTY_STREAM = b"\x00" * 5

# Output asked of pyppmd per call once a held member is handed over at compressed EOF
# (a truncated member, or a password check's capped input): the stream drains the rest
# through further calls rather than taking it all from ``flush``.
_PPMD_FLUSH_DRAIN_CHUNK = 65536


def _request_size(max_length: int) -> int:
    """The output one native ``decode`` asks for, given the caller's ``max_length``.

    ``-1`` (unsized) becomes one bounded chunk, never pyppmd's ``-1``.
    """
    if max_length < 0:
        return _PPMD_UNSIZED_DECODE_CHUNK
    return min(max_length, _PPMD_MAX_REQUEST)


class _PpmdNativeDecoder(Protocol):
    """The ``pyppmd.Ppmd7Decoder`` / ``Ppmd8Decoder`` methods this adapter calls.

    ``length`` is the library's keyword. ``needs_input`` is read via ``getattr``
    as defensive coverage; the pinned floor (``pyppmd>=1.3.1``) exposes it on
    both decoders, and no known build lacks it.
    """

    def decode(self, data: bytearray | bytes | memoryview, length: int) -> bytes: ...

    @property
    def eof(self) -> bool: ...


class PpmdDecoder(BaseDecoder):
    """Decode a PPMd stream via ``pyppmd``.

    Variant 7 (``Ppmd7Decoder``) is the 7z var.H coder. Variant 8 (``Ppmd8Decoder``)
    is ZIP method 98 / WinZip ZIPX PPMd, which also carries a restore-method parameter.

    ``unpack_size`` (the 7z folder / ZIP member size) is passed through as
    ``max_length`` on every ``decode`` call, matching py7zr's
    ``PpmdDecompressor.decompress(..., max_length)``. On pyppmd 1.3.x a request past
    the true end of stream leaves the native worker thread waiting for input once it
    runs past what the range coder's tail lookahead can satisfy (measured: +64 and
    +4096 over did not, +65536 over did), and freeing the decoder in that state
    corrupts the heap (Linux ``malloc`` abort/SIGSEGV, Windows
    ``STATUS_HEAP_CORRUPTION``); ``-1`` also runs it on a desynchronised model.
    Requesting exactly the remaining output keeps a valid member out of that state. A
    container that overstates ``unpack_size`` cannot be detected before decoding;
    there the spent-payload stop (:meth:`_note_decoded`) and :meth:`_quiesce_worker`
    hold (crafted members overstated by 64 KiB, 1 MiB and 15 MiB measured clean); see
    ``dev-docs/known-issues.md``.

    Because PPMd7 has no end mark, there is no safe request size without knowing the
    payload length — so ``unpack_size`` is **required** for variant 7 (the 7z header
    always provides it). PPMd8 carries an end mark that stops the native worker on
    valid data, so variant 8 may be unsized; it is then decoded via bounded
    :data:`_PPMD_UNSIZED_DECODE_CHUNK` requests in a drain loop, never ``-1``.

    ``pack_size`` is the container-declared compressed length (7z pack stream / ZIP
    compressed size, or the sized view length). When set, empty post-``eof`` drains
    that chase ``unpack_size`` are allowed only after ``fed_compressed >= pack_size``;
    a short pack delivery stops instead (avoids near-EOF ``MemoryError`` on
    truncated members). It is **required for PPMd7** (see ``__init__``): without it a
    premature native ``eof`` cannot be told from truncation, and the only safe choice
    left is to refuse the drain, which silently truncates valid members on chunked
    reads. ``PpmdCodec`` fills it from the sized source (``compressed_input_size``) or,
    for chained 7z folders whose PPMd input is unsized (AES), from the plumbed coder
    input size. PPMd8 may leave it unknown; recovery is then conservative — at most one
    capped NUL and **no** chunked empty drains. At compressed EOF, at most one
    documented extra NUL is injected with a per-call budget of
    :data:`_PPMD_EXTRA_NUL_MAX_OUTPUT`; unsized PPMd8 gets **no** post-eof drain at all
    (its end mark terminates valid decodes; a drain would only fabricate trailing bytes).

    ``refuse_input_after_end`` (``StreamConfig.refuse_input_after_end``: a ZIP member,
    a 7z coder) checks that the member's input ends where its declared output does, as
    7-Zip does (:meth:`_check_end`); a byte it leaves is ``DataAfterEndError`` through
    the stream.

    ``input_runs_on`` (PPMd8 without ``unpack_size`` only) says the input does not
    end where the stream does: a ZIP member read from a pipe, whose sizes come after
    its data, is followed by the rest of the archive. Holding input until the source
    ends would hold the rest of the archive, so pyppmd is fed in pieces, in-process
    too under ``ProcessIsolation.NONE``. The stream ends at the end mark, and a byte after it is
    :attr:`input_after_end`, so the ``refuse_input_after_end`` stream it requires stops
    there.

    **Invariant:** ``pack_size`` must measure the same byte stream that
    ``feed()`` accumulates into ``_fed_compressed`` (the PPMd coder's compressed
    input — after ZIP method-98 header stripping / as the 7z pack ``SlicingStream``
    length). If a wrapper sets ``compressed_input_size`` to a larger enclosing
    member while feeding only a subset, the gate would wrongly treat a complete
    pack as short and suppress legitimate post-eof drains.
    """

    def __init__(
        self,
        *,
        order: int,
        mem_size: int,
        variant: int = 7,
        restore_method: int = 0,
        unpack_size: int | None = None,
        pack_size: int | None = None,
        max_held_input: int | None = _DEFAULT_MAX_HELD_INPUT,
        refuse_input_after_end: bool = False,
        input_runs_on: bool = False,
        isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
    ) -> None:
        if input_runs_on and (
            variant != 8 or unpack_size is not None or not refuse_input_after_end
        ):
            raise ValueError(
                "input_runs_on is for PPMd8 without unpack_size, in a "
                "refuse_input_after_end stream: only an end mark can end a stream "
                "whose input runs on, and only that stream stops there"
            )
        if variant != 8 and unpack_size is None:
            raise ValueError(
                "PPMd7 (7z var.H) requires unpack_size: the format has no end mark, "
                "and decoding without the exact output bound runs pyppmd past the "
                "end of stream (native heap corruption on 1.3.x — see "
                "dev-docs/known-issues.md)"
            )
        if variant != 8 and pack_size is None:
            # Without pack_size, a premature native ``eof`` (pyppmd flips it early on a
            # small ``max_length`` over compressible data) is indistinguishable from
            # truncation: draining toward unpack_size to finish the tail can MemoryError
            # on 1.3.x, so the decoder must refuse it — which silently truncates a valid
            # member on chunked reads. PPMd7 is 7z-only and 7z always knows the pack
            # length (sized pack slice, or the preceding coder's output for AES folders),
            # so require it rather than choose between truncation and a crash.
            raise ValueError(
                "PPMd7 (7z var.H) requires pack_size: it has no end mark, so completing "
                "a member past a premature native eof needs the declared compressed "
                "length to tell full delivery from truncation (see "
                "dev-docs/known-issues.md)"
            )
        self._order = order
        self._mem_size = mem_size
        self._variant = variant
        self._restore_method = restore_method
        self._unpack_size = unpack_size
        self._pack_size = pack_size
        self._produced = 0
        self._fed_compressed = 0
        self._nul_injected = False
        self._compressed_eof = False
        # Set once the payload is provably spent (see ``_note_decoded``); from then on
        # nothing on the decode path calls the native decoder. Teardown still does:
        # ``_quiesce_worker`` sends its bounded NUL in exactly this state.
        self._exhausted = False
        # Every member decodes in a child process, or ``ResourceUnavailableError`` where
        # none can start, unless ``isolation`` is ``NONE``.
        self._isolation = isolation
        self._in_child = isolation is not ProcessIsolation.NONE
        # ``DecoderLimits.max_ppmd_held_input``: a member up to it is handed to
        # pyppmd whole, one past it in pieces, under every ``isolation`` (which decides
        # only where the decode runs). ``None``: held whole whenever the size is known.
        self._max_held_input = max_held_input
        # Compressed input held back from pyppmd until the whole member is here, or
        # compressed EOF, or ``max_held_input`` is passed. ``None`` once handed
        # over: from then on ``_decomp`` exists and the rest of this class works as
        # a plain chunked decoder.
        self._held: bytearray | None = bytearray()
        # Set by ``flush`` when it hands the held input over: the stream keeps pulling
        # output through ``feed(b"")`` until this decoder has none left
        # (``drains_after_flush``), then calls ``flush`` again.
        self._draining = False
        # Set when a member was refused (no child process could start): every later
        # ``feed`` and ``flush`` raises ``ResourceUnavailableError`` again, since there is
        # no decoder to go on with.
        self._refusal: str | None = None
        self._decomp: _PpmdNativeDecoder | None = None
        # Set once ``_native_decode`` has made its first call (see there).
        self._native_called = False
        self._refuse_input_after_end = refuse_input_after_end
        self._input_runs_on = input_runs_on
        # Set once an ``input_runs_on`` stream has decoded its end mark.
        self._end_marked = False
        # Input fed after the output reached ``unpack_size``, before the end check
        # (``_check_end``), and whether that check has run.
        self._tail = b""
        self._end_checked = False
        # Set when the end check's one-symbol probe left the worker waiting for input
        # (a PPMd8 stream with no end mark), so ``_quiesce_worker`` must still run.
        self._probe_parked = False
        # Set by ``spoil_child``: a check above this decoder failed.
        self._spoiled = False

    def _open_native(self, *, in_child: bool) -> None:
        """Create the decoder ``_decomp``, in this process or in a child one.

        ``mem_size`` is bounded one layer up, by ``check_decoder_memory`` in
        ``codecs/ppmd_codec.py``, against ``DecoderLimits.max_decoder_memory`` — not here,
        because these constructor calls are the allocation and there is no catching
        it once it has been made (pyppmd 1.3.1 aborts the process rather than raising
        when it is refused). Two paths reach this class without passing that guard: a
        direct ``PpmdDecompressorStream`` in the tests, and ``recreate()`` rebuilding
        from a ``mem_size`` the guard already passed. Anything new that constructs a
        decoder from an archive-declared number calls the guard first.
        """
        if self._decomp is not None:  # a test double installed before first use
            return
        if in_child:
            self._decomp = open_ppmd_child(
                variant=self._variant,
                order=self._order,
                mem_size=self._mem_size,
                restore_method=self._restore_method,
                setting=self._isolation.name,
            )
            return
        import pyppmd

        if self._variant == 8:
            self._decomp = pyppmd.Ppmd8Decoder(
                self._order, self._mem_size, self._restore_method
            )
        else:
            self._decomp = pyppmd.Ppmd7Decoder(self._order, self._mem_size)

    def _release_held(self, *, in_child: bool) -> bytes:
        """Hand the held input over: open ``_decomp`` and return the bytes to feed it."""
        held = self._held
        assert held is not None
        self._held = None
        self._open_native(in_child=in_child)
        return bytes(held)

    def recreate(self, point: SeekPoint, inner: BinaryIO) -> PpmdDecoder:
        del point, inner
        return PpmdDecoder(
            order=self._order,
            mem_size=self._mem_size,
            variant=self._variant,
            restore_method=self._restore_method,
            unpack_size=self._unpack_size,
            pack_size=self._pack_size,
            max_held_input=self._max_held_input,
            refuse_input_after_end=self._refuse_input_after_end,
            input_runs_on=self._input_runs_on,
            isolation=self._isolation,
        )

    @property
    def _native(self) -> _PpmdNativeDecoder:
        """The decoder, once the held input has been handed over (never before)."""
        assert self._decomp is not None
        return self._decomp

    def _max_length(self) -> int:
        if self._unpack_size is None:
            return -1
        return max(0, self._unpack_size - self._produced)

    def _pack_complete(self) -> bool | None:
        """True if declared pack fully fed, False if known short, None if unknown."""
        if self._pack_size is None:
            return None
        return self._fed_compressed >= self._pack_size

    def _note_decoded(self, out: bytes, requested: int) -> bytes:
        """Record whether a sized native call proved the payload spent; return ``out``.

        On pyppmd 1.3.1 a ``decode`` returns short of ``requested`` only when its
        worker blocked on empty input or decoded the model's end. Short **and** at
        ``eof`` **and** with every compressed byte already fed, no more input is
        coming and the payload has nothing left: another decode-path call could only
        resume a worker parked on empty input, which raises a spurious
        ``MemoryError`` (it reads past the input buffer) rather than returning. So
        ``feed`` and ``flush`` make no further call; ``_quiesce_worker`` still sends
        its bounded NUL at teardown, which is what keeps the parked worker from
        writing into freed memory when the decoder is freed. While input is still
        arriving, a short return is the worker waiting for the next piece, and
        ``eof`` can already be up then (the ``Code == 0`` proxy rises early), so the
        stop needs all three: short, ``eof``, and every compressed byte fed. A valid
        member never meets them, because its ``unpack_size`` matches the payload:
        once all input is in, its requests are met in full. Fed in pieces, that
        holds because :meth:`_native_decode` makes a short return there mean that
        the worker waited for input, not a resumed worker's miscount. Reached when
        the container overstates ``unpack_size``; ``flush`` then reports
        ``TruncatedError``.

        ``_decode_unsized`` (PPMd8 without ``unpack_size``) is deliberately not
        wrapped: its end mark stops the worker on valid data, ``_decode`` refuses to
        call it again once ``eof`` is set, and ``flush`` runs no post-eof drain without
        a size, so it never reaches the parked-worker resume this guards against.
        """
        if (
            len(out) < requested
            and self._native.eof
            and (self._compressed_eof or self._pack_complete() is True)
        ):
            self._exhausted = True
        return out

    def _native_decode(self, data: bytes, length: int) -> bytes:
        """One ``decode`` of new input, made so that a short return means what it says.

        pyppmd 1.3.1 runs each decode in a worker thread that keeps its own output
        budget and output count from the call that started it. A worker that ran out
        of input stays parked, and the next ``decode`` with input resumes it with that
        old budget and count. When the resumed worker stops, pyppmd subtracts its whole
        count, output of earlier calls included, from this call's request, so the call
        can return short of its request although the stream has more output and the
        worker did not wait for input. With ``eof`` up that looks like a spent payload,
        and a valid member fed in pieces ended in ``TruncatedError`` some KiB short.

        So a call with new input after the first one asks for 1 byte, which makes a
        resumed worker stop after one symbol: its output buffer is full. A full 1-byte
        return means that the worker has stopped, so the rest is asked of a new worker
        with ``decode(b"", length - 1)``, which starts from zero and reads only input
        that pyppmd holds; it never resumes a parked worker on empty input (the
        spurious ``MemoryError``). An empty return means the worker parked again, and
        no second call is made. The first call is not split: no worker exists yet,
        and a member handed over whole goes to pyppmd in one ``decode``, as before.
        A request of 1 byte is not split either: it already is the first half. Its
        output buffer holds 1 byte, so a resumed worker stops after one symbol, and
        the return is that byte or empty, never short of it by a miscount. The two
        1-byte calls made without this helper (``_check_end``'s end-mark probe and
        ``_quiesce_worker``'s NUL) rely on the same.
        """
        native = self._native
        if not data or length <= 1 or not self._native_called:
            self._native_called = True
            return native.decode(data, length)
        first = native.decode(data, 1)
        if not first:
            return first
        return first + native.decode(b"", length - 1)

    def _decode_unsized(self, data: bytes) -> bytes:
        # Unsized PPMd8 only (PPMd7 without a size is rejected in __init__). Never
        # hand pyppmd max_length=-1; request one bounded chunk per call. Valid PPMd8
        # stops at its end mark before any over-decode; the bound avoids the -1
        # allocation path and caps the damage on corrupt data. One chunk, not a
        # drain loop: a held member arrives whole, and draining it here would build
        # its entire output in one call. The stream asks again while ``needs_input``
        # is False.
        return self._native_decode(data, _request_size(-1))

    def _nul_budget(self, max_length: int) -> int:
        budget = _PPMD_EXTRA_NUL_MAX_OUTPUT
        if max_length >= 0:
            budget = min(max_length, budget)
        return budget

    def _inject_nul_once(self, max_length: int) -> bytes:
        """Documented single extra NUL (pyppmd / py7zr); never loop fabricated input.

        On a pack known short, or of unknown size, the NUL is one
        ``decode(b"\\0", budget)``. Split, its second half would be an empty decode,
        and if the 1-byte call lifted ``eof`` that is an empty decode past native
        ``eof`` on such a pack: the shape ``feed``'s gate and ``_finish_input``
        refuse (the near-EOF ``MemoryError``, the exit-after-green abort).

        On a pack known complete the NUL goes through :meth:`_native_decode`, so a
        resumed worker's miscount cannot make the payload look spent. That arm is
        defence in depth for a corrupt pack that declares itself complete: on the
        valid members measured, pyppmd was at ``eof`` by then and sent no NUL. No
        test pins it, deliberately: the inputs found to reach it crash pyppmd
        in-process.
        """
        if self._exhausted or self._nul_injected or self._native.eof:
            return b""
        if not getattr(self._native, "needs_input", False):
            return b""
        self._nul_injected = True
        budget = self._nul_budget(max_length)
        if self._pack_complete() is True:
            out = self._native_decode(b"\0", budget)
        else:
            # A call with input: a worker may now exist (see ``_native_decode``).
            self._native_called = True
            out = self._native.decode(b"\0", budget)
        return self._note_decoded(out, budget)

    def _drain_empty_chunked(self, max_length: int) -> bytes:
        """Pull remaining output in ``_PPMD_EXTRA_NUL_MAX_OUTPUT`` empty decodes.

        Only for a **known-complete** pack (see :meth:`flush`): premature native
        ``eof`` after a small ``max_length`` can still leave legitimate symbols
        reachable via ``decode(b"", …)`` — so this intentionally continues past
        native ``eof`` (breaking on eof would defeat premature-eof recovery).
        Stops on ``needs_input``, a short return at ``eof`` (the payload is spent;
        see :meth:`_note_decoded`), quiet empty, or budget exhaustion. Does **not**
        run when ``pack_size`` is unknown or short. Corrupt-but-declared-complete
        packs can still fill toward ``unpack_size`` here; container CRC is the
        backstop. Worst-case iteration count is ``remaining + 2`` at 64 bytes
        per call (perf cliff on huge members if this path is hit).
        """
        if max_length == 0:
            return b""
        parts: list[bytes] = []
        remaining = max_length
        quiet = 0
        # Bound iterations: worst case one byte per call up to remaining.
        for _ in range(remaining + 2):
            if remaining <= 0:
                break
            if getattr(self._native, "needs_input", False):
                break
            budget = min(_PPMD_EXTRA_NUL_MAX_OUTPUT, remaining)
            chunk = self._note_decoded(self._native.decode(b"", budget), budget)
            parts.append(chunk)
            remaining -= len(chunk)
            if self._exhausted:
                break
            if not chunk:
                quiet += 1
                if quiet >= 2:
                    break
                continue
            quiet = 0
        return b"".join(parts)

    def _decode(self, data: bytes, max_length: int) -> bytes:
        if max_length == 0 or self._exhausted:
            return b""
        # Decoding after native EOF is trailing garbage at best (and the crashy
        # runaway path on pyppmd 1.3.x when unbounded) — drop the input instead.
        if self._native.eof and max_length < 0:
            return b""
        # Empty + needs_input after compressed EOF: at most one documented NUL.
        # Before compressed EOF, empty+needs_input means "read more pack bytes" —
        # do not fabricate input.
        if (
            not data
            and getattr(self._native, "needs_input", False)
            and not self._native.eof
        ):
            if not self._compressed_eof:
                return b""
            return self._inject_nul_once(max_length)
        if max_length < 0:
            return self._decode_unsized(data)
        max_length = _request_size(max_length)
        return self._note_decoded(self._native_decode(data, max_length), max_length)

    def _refuse(self, reason: str, cause: BaseException | None = None) -> NoReturn:
        """Refuse this member for good; see ``_refusal``."""
        self._refusal = reason
        self._held = None
        raise ResourceUnavailableError(reason) from cause

    def _check_refusal(self) -> None:
        if self._refusal is not None:
            raise ResourceUnavailableError(self._refusal)

    def _release_to_child(self) -> bytes:
        reason = (
            "This PPMd member can only be decoded in a child process (pyppmd can crash "
            "the process on corrupt input), and none can be started"
        )
        setting = self._isolation.name

        def refusal(detail: object) -> str:
            error = isolation_error(
                f"{reason} ({detail})",
                setting,
                isolated_unless_none=ISOLATED_UNLESS_NONE,
            )
            return str(error)

        unavailable = ppmd_child_unavailable_reason()
        if unavailable is not None:
            self._refuse(refusal(unavailable))
        try:
            return self._release_held(in_child=True)
        except DecoderChildStartError as exc:
            self._refuse(refusal(exc), exc)
        except PpmdChildAllocationError as exc:
            # The child started, so the advice above does not apply: in-process, the
            # same allocation would abort this process.
            self._refuse(str(exc), exc)

    def _release_now(self) -> bytes:
        """Hand the held input over where this member decodes."""
        if self._in_child:
            return self._release_to_child()
        return self._release_held(in_child=False)

    def feed(self, chunk: bytes, max_length: int = -1) -> DecodeOut:
        self._check_refusal()
        if self._end_marked:
            if chunk:
                self._input_after_end = True
            return DecodeOut(b"")
        if chunk:
            self._fed_compressed += len(chunk)
        if self._held is not None:
            self._held += chunk
            limit = self._max_held_input
            if self._input_runs_on:
                # No size to hold it to: fed in pieces from the first input.
                if not self._held:
                    return DecodeOut(b"")
                chunk = self._release_now()
            elif (limit is not None and len(self._held) > limit) or (
                self._pack_complete() is True
            ):
                # Whole when the member fits under the limit, in pieces past it. A
                # child gets the same: whole, pyppmd is asked least after a corrupt
                # stream ends early, and it is the path measured most. Both tests
                # lead to the same hand-over, so their order does not matter; where
                # the member decodes is ``isolation``'s alone.
                chunk = self._release_now()
            else:
                return DecodeOut(b"")
        if self._at_declared_size():
            return self._feed_after_size(chunk)
        # Honour both the container unpack_size cap and the stream-layer read budget.
        unpack_cap = self._max_length()
        if max_length >= 0 and unpack_cap >= 0:
            limit = min(max_length, unpack_cap)
        elif max_length >= 0:
            limit = max_length
        else:
            limit = unpack_cap
        if self._compressed_eof:
            # After compressed EOF (``flush`` has handed the held input over): the same
            # bounded request as its first call, never the whole declared remainder,
            # whether or not the drain is still running.
            limit = (
                _PPMD_FLUSH_DRAIN_CHUNK
                if limit < 0
                else min(limit, _PPMD_FLUSH_DRAIN_CHUNK)
            )
        # Empty drains past native eof are only safe when every compressed byte the
        # decoder will ever get has been handed over: the declared pack was fully
        # delivered, or ``flush`` handed over everything up to compressed EOF (and
        # then a short return ends the drain, below). Otherwise refuse (near-EOF
        # MemoryError / garbage fill). Callers must pass pack_size (or sized-view
        # compressed_input_size) for correct premature-eof completion.
        if (
            not chunk
            and not (self._draining or self._pack_complete() is True)
            and self._native.eof
        ):
            return DecodeOut(b"")
        out = self._decode(chunk, limit)
        self._produced += len(out)
        if self._input_runs_on:
            self._note_end_mark(len(out), limit)
        if self._draining and len(out) < limit:
            # All input is in, so a short return is the end: ask pyppmd nothing more
            # on the drain; the stream's next ``flush`` settles the member.
            self._draining = False
        self._maybe_check_end()
        return DecodeOut(out)

    def _note_end_mark(self, produced: int, limit: int) -> None:
        """Mark an ``input_runs_on`` stream ended once a decode reached its end mark.

        A decode that stops short of its request at ``eof`` has decoded the end mark
        (see :meth:`_note_decoded`); a full one at ``eof`` may be pyppmd's early
        ``eof`` on a small request, so it does not count. pyppmd's ``unused_data``
        is then the input after the end mark, exactly.
        """
        if self._end_marked or not self._native.eof:
            return
        if produced < _request_size(limit):
            self._end_marked = True
            if _unused(self._native):
                self._input_after_end = True

    def _at_declared_size(self) -> bool:
        """Whether a ``refuse_input_after_end`` member has all its output, its input
        handed over to the native decoder."""
        return (
            self._refuse_input_after_end
            and self._unpack_size is not None
            and self._decomp is not None
            and self._produced >= self._unpack_size
        )

    def _feed_after_size(self, chunk: bytes) -> DecodeOut:
        """Take input fed after the declared output: an end mark, or surplus."""
        if chunk:
            if self._end_checked:
                self._input_after_end = True
                return DecodeOut(b"")
            self._tail += chunk
            if len(self._tail) > _PPMD_TAIL_MAX:
                self._end_checked = True
                self._input_after_end = True
                return DecodeOut(b"")
        self._maybe_check_end()
        return DecodeOut(b"")

    def _maybe_check_end(self) -> None:
        """Run the end check once the output is complete and all input is in."""
        if (
            self._end_checked
            or not self._at_declared_size()
            or not (self._compressed_eof or self._pack_complete() is True)
        ):
            return
        self._end_checked = True
        if not self._check_end():
            self._input_after_end = True

    def _check_end(self) -> bool:
        """Whether the input ends where the declared output does, as 7-Zip checks.

        The input given to pyppmd past the last symbol is ``unused_data``, and the
        input fed after the output was complete is :attr:`_tail`. pyppmd 1.3.1 builds
        ``unused_data`` on its first read after ``eof`` and keeps it, and ``eof`` can
        rise early and stay up (``ppmd_child``), so it is read here only, once the
        output is complete. The extra NUL fed at compressed EOF (:meth:`_inject_nul_once`)
        is not the member's input, and may be left over. A PPMd7 stream (7z) has no
        end mark: it ends where its range
        coder's code is zero, which is what pyppmd's ``eof`` reports, and every byte
        of its input is used by then (7-Zip's range decoder, which pyppmd runs, reads
        ahead eagerly). Measured on 7-Zip 23.01 and py7zr output: ``eof``, and no
        ``unused_data``. A PPMd8 stream (ZIP) ends with an end mark, which one more
        one-symbol decode reaches without output; 7-Zip refuses a member without
        one. A member that declares no output has the empty stream's bytes, or
        nothing, as its whole input.
        """
        native = self._native
        if self._variant != 8:
            if self._produced == 0:
                return self._tail in (b"", _PPMD7_EMPTY_STREAM)
            return native.eof and self._unused_ok(native) and not self._tail
        if not native.eof:
            out = native.decode(self._tail, 1)
            self._tail = b""
            if out:
                return False
            if not native.eof:
                # No end mark: the worker waits for input that is not coming.
                self._probe_parked = True
                self._pending_error = CorruptionError(
                    "PPMd8 stream has no end mark after its declared size"
                )
                return True
        return self._unused_ok(native) and not self._tail

    def _unused_ok(self, native: _PpmdNativeDecoder) -> bool:
        """Whether pyppmd's leftover input is none, or only the injected NUL."""
        unused = _unused(native)
        return not unused or (self._nul_injected and unused == b"\0")

    def flush(self) -> DecodeOut:
        self._check_refusal()
        self._compressed_eof = True
        if self._held is not None:
            # Compressed EOF with input still held: a member shorter than its pack
            # (truncated, or a password check's capped read), or one with no declared
            # pack size. Everything that will ever arrive is here, so hand it over
            # whole and take the first chunk of output; the stream drains the rest
            # through ``feed(b"")`` and then calls ``flush`` again.
            data = self._release_now()
            limit = self._max_length()
            limit = (
                _PPMD_FLUSH_DRAIN_CHUNK
                if limit < 0
                else min(limit, _PPMD_FLUSH_DRAIN_CHUNK)
            )
            out = self._decode(data, limit) if limit else b""
            self._produced += len(out)
            # Only a full return leaves output to drain: short, the member has ended
            # and pyppmd is asked nothing more (see ``feed``).
            if len(out) == limit and not self.finished and not self._exhausted:
                self._draining = True
                return DecodeOut(out)
            return DecodeOut(out + self._finish_input().data)
        return self._finish_input()

    @property
    def drains_after_flush(self) -> bool:
        """True while ``flush`` has handed input over and output may still follow."""
        return self._draining and not self.finished and not self._exhausted

    def _finish_input(self) -> DecodeOut:
        # Compressed EOF: optionally one documented extra NUL, then (only when the
        # pack is known-complete) chunked empty drains. Never inject fabricated
        # NULs in a loop. Unknown pack_size is treated like incomplete for drains:
        # single capped NUL only — do not chase unpack_size.
        self._draining = False
        max_length = self._max_length()
        if max_length == 0:
            self._maybe_check_end()
            return DecodeOut(b"")
        out = b""
        if not self._native.eof and getattr(self._native, "needs_input", False):
            more = self._inject_nul_once(max_length)
            out += more
            self._produced += len(more)
            max_length = self._max_length()
        # Empty drains past a premature native ``eof`` only run when the pack is
        # known-complete AND a container ``unpack_size`` bounds them (``max_length >= 0``).
        # Without that bound the drain is pure fabrication: an unsized PPMd8 stream ends
        # at its end mark, so any post-eof pull is trailing garbage (measured: +N bytes
        # on compressible payloads). Corrupt-but-declared-complete sized packs can still
        # fill toward ``unpack_size`` here — container CRC is the backstop.
        if (
            max_length > 0
            and self._pack_complete() is True
            and not self._exhausted
            and not getattr(self._native, "needs_input", False)
        ):
            drained = self._drain_empty_chunked(max_length)
            out += drained
            self._produced += len(drained)
        if not self.finished:
            self._pending_error = TruncatedError("File is truncated")
        self._maybe_check_end()
        return DecodeOut(out)

    @property
    def finished(self) -> bool:
        # Prefer the container size when known: it detects truncation (short output
        # at compressed EOF) and ends the member exactly at its boundary — PPMd7 has
        # no end mark, so native eof alone cannot do either.
        if self._unpack_size is not None:
            return self._produced >= self._unpack_size
        return self._decomp is not None and bool(self._decomp.eof)

    @property
    def needs_input(self) -> bool:
        if self._decomp is None:
            return True
        return bool(getattr(self._decomp, "needs_input", True))

    def _quiesce_worker(self) -> None:
        """Drive a parked native decode worker to exit before the decoder is freed.

        On pyppmd 1.3.x the decode worker thread is left blocked in the reader
        whenever a ``decode`` requested more output than the fed input could
        produce (a truncated or abandoned member). ``Ppmd7T_Free`` — run from the
        pyppmd decoder's ``dealloc`` — then wakes that worker with no new input,
        and it free-runs into the output block already released by the previous
        ``decode`` call: a use-after-free that intermittently aborts the process
        at GC (the "exit-after-green" residual in ``known-issues.md``).

        Feeding one bounded single-symbol NUL makes the worker consume its tail
        lookahead and exit on its own 1-symbol budget, so ``Ppmd7T_Free`` sees a
        finished worker and becomes a no-op. Measured: valgrind 8154 → 0 invalid
        writes on a truncated-pack teardown. Best-effort and idempotent; safe to
        call more than once. See ``dev-docs/investigations/ppmd-native-investigation-results.md``
        (§D root cause, §I mitigation).
        """
        decomp = getattr(self, "_decomp", None)
        if decomp is None:
            return
        try:
            # A fully-decoded member exited its worker on budget / the end mark;
            # only an incomplete (truncated / abandoned) decode can leave one
            # parked, or the end check's probe of a PPMd8 stream with no end mark.
            # Skip the happy path so valid closes cost nothing.
            if self.finished and not self._probe_parked:
                return
            for _ in range(_PPMD_QUIESCE_MAX_CALLS):
                # ``not needs_input`` is the "worker not parked" signal — the last
                # call exited on budget, so Free is already a no-op. The ``eof``
                # short-circuit is deliberately kept ahead of it: at native eof the
                # worker is finished AND feeding a NUL here would be a decode-after-eof
                # (the unbounded form of which is itself a crash path on 1.3.x), so
                # never issue one — skip instead. The exception is a spent payload
                # (``_exhausted``): its last call returned short at ``eof``, which
                # pyppmd reports with ``needs_input`` False even when the worker is
                # parked on empty input, so neither flag can be trusted and the NUL
                # is sent anyway. Measured on an overstated ``unpack_size``: without
                # it valgrind shows the Free-time invalid write and a later decoder
                # in the same process can start from corrupted state. The cost: when
                # the short return was the model's end rather than a wait for input,
                # this NUL is a decode after the end. It measured clean in isolation
                # and stays a candidate residual (``dev-docs/known-issues.md``). After
                # a ``ValueError`` pyppmd reports ``eof``, so the check above returns
                # without decoding, which matters: a NUL there does crash pyppmd.
                if not self._exhausted and (
                    decomp.eof or not getattr(decomp, "needs_input", False)
                ):
                    return
                # One-symbol budget: the worker resumes, consumes the NUL, and
                # exits on budget (returns the byte), or blocks needing one more
                # tail byte — the next iteration feeds it. A non-empty return means
                # the worker hit its budget and exited, so it will not be resumed.
                if decomp.decode(b"\0", 1):
                    return
        except Exception:  # noqa: BLE001, S110
            # Teardown hygiene; never raise from close()/__del__.
            pass

    def spoil_child(self) -> None:
        self._spoiled = True

    def _ended_cleanly(self) -> bool:
        """Whether the member decoded to its end with nothing left wrong: the one state
        a child may serve another member from. Anything else may have left pyppmd's
        memory corrupt without a crash, and ``_quiesce_worker`` may still send its NUL
        after the model ended."""
        return (
            self.finished
            and not self._spoiled
            and not self._exhausted
            and not self._probe_parked
            and self._pending_error is None
            and self._refusal is None
            and not self._input_after_end
        )

    def close(self) -> None:
        decomp = getattr(self, "_decomp", None)
        if isinstance(decomp, ChildPpmdDecoder) and not self._ended_cleanly():
            decomp.spoil()
        self._quiesce_worker()
        if isinstance(decomp, ChildPpmdDecoder):
            decomp.close()

    def __del__(self) -> None:
        # GC safety net: quiesce even when the owning stream's close() did not run
        # (decoder used directly, or stream leaked). Runs before self._decomp is
        # dropped, so the native worker is finished before Ppmd7T_Free executes.
        self.close()


def PpmdDecompressorStream(
    path: str | os.PathLike[str] | BinaryIO,
    *,
    order: int,
    mem_size: int,
    variant: int = 7,
    restore_method: int = 0,
    unpack_size: int | None = None,
    pack_size: int | None = None,
    max_held_input: int | None = _DEFAULT_MAX_HELD_INPUT,
    refuse_input_after_end: bool = False,
    input_runs_on: bool = False,
    collector: DiagnosticCollector | None = None,
    isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES,
) -> DecompressorStream:
    """Decode a PPMd stream (forward-only).

    ``variant=7`` is 7z PPMd var.H; ``variant=8`` is ZIP method 98 (PPMd8).
    ``unpack_size`` and ``pack_size`` are required for PPMd7 (no end mark — see
    :class:`PpmdDecoder`). ``pack_size`` is the container-declared compressed length
    (or sized view); post-eof empty drains are gated on full pack delivery.
    For PPMd8, ``unpack_size`` / ``pack_size`` are recommended when the container
    declares them; unsized PPMd8 relies on the end mark (no post-eof drain).
    """
    return DecompressorStream(
        path,
        make_decoder=lambda _p, _i: PpmdDecoder(
            order=order,
            mem_size=mem_size,
            variant=variant,
            restore_method=restore_method,
            unpack_size=unpack_size,
            pack_size=pack_size,
            max_held_input=max_held_input,
            refuse_input_after_end=refuse_input_after_end,
            input_runs_on=input_runs_on,
            isolation=isolation,
        ),
        collector=collector,
        codec_name="ppmd",
        refuse_input_after_end=refuse_input_after_end,
    )


def _unused(native: _PpmdNativeDecoder) -> bytes:
    """pyppmd's input left after the stream's end (only meaningful at ``eof``)."""
    return bytes(getattr(native, "unused_data", b"") or b"")
