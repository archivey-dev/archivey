"""Decompressed-output digest (and length) verification.

Container digests (``ArchiveMember.hashes``) and optional declared decompressed
length are checked on a clean sequential read to EOF.

Two delivery shapes (same rules, different wrappers):

- :class:`MemberVerifier` — the logic object. **Fused into**
  :class:`~archivey.internal.streams.archive_stream.ArchiveStream` on the member
  hot path (one fewer Python layer; nested codec ``ArchiveStream``s can collapse).
- :class:`VerifyingStream` — standalone ``BinaryIO`` wrapper around an inner +
  verifier. Kept for codec length backstops and tests; prefer fusion for members.

Per ADR 0014 / ``compressed-streams``:

- Public ``read(n)`` (``n ≥ 1``) is **full-count**: ``n`` bytes or a terminal boundary,
  from one ``inner.read(n)`` — the guarantee is the inner's (fill-or-EOF), and a short
  non-empty return is terminal, never "ask again" (ADR 0014).
- Verification runs on a read that **reaches the end** (declared size, or decoder
  EOS). A partial read is never verified. ``read(0)`` is a no-op (not EOF).
- A seek to position 0 re-arms every check (fresh hashers, no frontier), so a read
  from 0 to the end after any seeks is verified in full. The hashers cover the bytes
  from 0 up to the **hashing frontier** (``_hashed_to``), so a backward seek keeps the
  **checksum**: later reads hash only what lies past the frontier. A forward seek past
  the frontier keeps it too when the inner would decode the skipped bytes anyway (its
  ``nearest_resume_offset`` for the target is at or before the frontier): the next
  read reads those bytes through the hashers first (``MemberVerifier.seek``), so the
  seek itself stays lazy. A seek to or past the declared size keeps it as well:
  concluding hashes the gap. A read that starts past the frontier, after a seek that
  jumped there by an index, an accelerator or random access, **pauses** the checksum:
  the frontier stays where it was, and a seek back to it or behind it followed by a
  read on to the end completes the hash and checks it (the digest verdict is then
  given by that read, after the length verdict was given by the first read to reach
  the end). Length / truncation / over-run stay on and key off bytes **actually
  read** (``_furthest_read_pos``). If a seek jumps to/past the declared size without
  reading the intervening bytes, concluding reads the skipped gap and probes one byte
  past the declared size (``_conclude``) rather than returning ``b""`` blind, so a
  past-EOF ``seek(declared_size)`` still catches truncation (short) *and* over-run
  (long). A member already concluded (``_concluded``) returns with no extra I/O.
- **Size-declared corruption** (digest mismatch / over-run at the declared size):
  the reaching read raises and **withholds** that chunk.
- **Size-unknown corruption**: deliver data bytes; raise on the EOS-observing
  (typically empty) read — no mandatory lookahead withhold.
- **Truncation-shaped**: first read past available returns a short prefix; the
  next empty read raises ``TruncatedError``.
- On ``read(-1)`` / ``readall``, the complete-stream call includes the EOF verdict
  and raises (so ``read(); close()`` cannot silently accept bad content).
- ``close()`` / ``finish_on_close`` MUST NOT introduce a first content
  ``TruncatedError`` / ``CorruptionError`` (teardown errors may still propagate).
- Missing/unknown digest algorithms emit ``DIGEST_UNVERIFIABLE`` and are skipped.
"""

from __future__ import annotations

import hashlib
import zlib
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, BinaryIO, Protocol

from archivey.diagnostics import DiagnosticCode, DigestContext
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.diagnostics_collector import (
    DiagnosticCollector,
    resolve_collector,
)
from archivey.internal.hashing.blake2sp import Blake2sp
from archivey.internal.logs import integrity as logger
from archivey.internal.streams.decompressor_stream import (
    _COMPRESSED_READ_SIZE_MAX,
    retire_decoder_children,
)
from archivey.internal.streams.resume import (
    ask_resume_offset,
    ask_seek_resume_offset,
)
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    is_closed_file_error,
    is_seekable,
)
from archivey.internal.streams.verification import (
    VerificationProofs,
    ask_verification_proofs,
)
from archivey.types import HashAlgorithm

if TYPE_CHECKING:
    from archivey.types import ArchiveMember

# Keys are ``HashAlgorithm`` (``member.hashes``). Values are digest ``bytes``
# (CRC-32 as four big-endian bytes). Mapping's key parameter is invariant, so
# this matches every typed caller rather than ``HashAlgorithm | str``.
# Name strings still work at runtime (``_algo_key`` / hashlib lookup) but sit
# outside the typed contract; ``algorithms_available`` is also how a future
# enum member gets a hasher for free.
_ExpectedHashes = Mapping[HashAlgorithm, bytes]
_DigestTransforms = Mapping[HashAlgorithm, Callable[[bytes], bytes]]

# Bounded drain step for sized ``read(-1)``. Must not use ``inner.read(-1)`` on the
# sized branch: ``expected_size`` is a decompression-bomb cap. The step itself is not
# the bound (the drain stops at ``expected_size`` whatever the step), so it is sized
# for speed: a member up to one step arrives as one piece, which ``b"".join`` returns
# without copying, and it is the decoder's largest compressed feed, so one step is one
# inflate call.
_SIZED_DRAIN_CHUNK = _COMPRESSED_READ_SIZE_MAX


def _algo_key(algorithm: HashAlgorithm | str) -> str:
    """Return the lowercase algorithm name used to choose a hasher.

    A ``HashAlgorithm`` stringifies to its value because it is a ``StrEnum``,
    which ``tests/test_str_enums.py`` pins. A bare string is folded the same
    way, so ``"CRC32"`` and the enum member share one lookup key. A plain
    ``Enum`` base would stringify as ``HashAlgorithm.CRC32``. That name matches
    no hasher, so ``MemberVerifier`` reports ``DIGEST_UNVERIFIABLE`` and does
    not compare the stored digest.
    """
    return str(algorithm).lower()


class _IncrementalHasher(Protocol):
    """The subset of the ``hashlib`` hash interface this stage uses."""

    @property
    def digest_size(self) -> int: ...
    def update(self, data: bytes, /) -> None: ...
    def digest(self) -> bytes: ...


class _Crc32Hasher:
    """A ``hashlib``-shaped wrapper over ``zlib.crc32`` so all algorithms share an interface."""

    digest_size = 4

    def __init__(self) -> None:
        self._value = 0

    def update(self, data: bytes, /) -> None:
        self._value = zlib.crc32(data, self._value)

    def digest(self) -> bytes:
        return (self._value & 0xFFFFFFFF).to_bytes(self.digest_size, "big")


def _make_hasher(
    algorithm: HashAlgorithm | str,
) -> Callable[[], _IncrementalHasher] | None:
    """Return a zero-arg factory for an incremental hasher, or ``None`` if unavailable."""
    name = _algo_key(algorithm)
    if name == "crc32":
        return _Crc32Hasher
    if name == "blake2sp":
        # RAR5 BLAKE2sp — not in hashlib; zero-dep tree hash on blake2s (see hashing/).
        return Blake2sp
    if name in hashlib.algorithms_available:
        return lambda: hashlib.new(name)
    return None


def _probe_past_declared(inner: BinaryIO) -> bytes:
    """Read one byte past a member's declared size; ``b""`` means the member ends there.

    A decoder error propagates: the body goes on past the declared size and does not
    decode, which is damage the read must not hand over as clean. The one error that
    counts as "nothing more" is a closed source. Closing an archive waits for a read in
    its source, not for the whole member read, so ``close()`` can land between the read
    that delivered the last declared byte and this probe. A stored ZIP member's bounded
    view then refuses the probe with the closed-file ``ValueError``, though the probe
    would read no source byte (``test_archive_closed_before_the_overrun_probe``). Every
    declared byte has been delivered, so the over-run verdict is what is given up. On a
    read the digests, checked after this probe, still judge the content, unless a
    read skipped bytes past the hashing frontier and paused them; then a seek back to
    the frontier and a read on to the end is what judges it.
    """
    try:
        return inner.read(1)
    except ValueError as exc:
        if is_closed_file_error(exc):
            return b""
        raise


class MemberVerifier:
    """Incremental digest/length checker over bytes read from an inner stream.

    Not a ``BinaryIO`` itself — :class:`VerifyingStream` and
    :class:`~archivey.internal.streams.archive_stream.ArchiveStream` own one and
    call :meth:`read` / :meth:`note_seek` / :meth:`finish_on_close` against their
    inner handle.
    """

    def __init__(
        self,
        expected: _ExpectedHashes,
        *,
        expected_size: int | None = None,
        collector: DiagnosticCollector | None = None,
        member: ArchiveMember | None = None,
        archive_name: str | None = None,
        digest_transforms: _DigestTransforms | None = None,
        end_check: Callable[[int], None] | None = None,
        fill_size: bool = False,
    ) -> None:
        self._expected_size = expected_size
        # With no declared size: called with the member's length before the digest
        # verdict, to refuse a length the archive rules out (it raises).
        self._end_check = end_check
        # With no declared size: give ``member.size`` the length once the digests
        # matched over the whole member (``_check_digests_if_complete``), or, with no
        # digest to check, once a read from the start that skips no byte finds the
        # end (``_note_end_seen``).
        self._fill_member = member if fill_size and expected_size is None else None
        self._expected: dict[str, bytes] = {}
        self._hashers: dict[str, _IncrementalHasher] = {}
        self._digest_transforms: dict[str, Callable[[bytes], bytes]] = {}
        if digest_transforms:
            for key, transform in digest_transforms.items():
                self._digest_transforms[_algo_key(key)] = transform
        # Kept so a rewind to the start can begin each digest again (``note_seek``).
        self._hasher_factories: dict[str, Callable[[], _IncrementalHasher]] = {}
        for algorithm, value in expected.items():
            key = _algo_key(algorithm)
            factory = _make_hasher(key)
            if factory is None:
                message = (
                    f"Cannot verify digest {key!r} (unknown algorithm or backend "
                    f"not installed); skipping integrity check for it."
                )
                resolve_collector(collector).emit(
                    code=DiagnosticCode.DIGEST_UNVERIFIABLE,
                    message=message,
                    context=DigestContext(
                        archive_name=archive_name,
                        member_name=member.name if member is not None else "",
                        member_id=member._member_id if member is not None else None,
                        algorithm=key,
                        reason="unknown_algorithm_or_backend",
                    ),
                    member=member,
                    attach_to_member=member is not None,
                    logger=logger,
                )
                continue
            self._hasher_factories[key] = factory
            self._hashers[key] = factory()
            self._expected[key] = value
        # The length / over-run verdict has been given (``_conclude``).
        self._concluded = False
        # The digest verdict has been given: the hashers reached the end and matched.
        # Lags ``_concluded`` when a read skipped bytes (``_record_read``) and a later
        # read from at or behind the hashing frontier completes the hash.
        self._digest_checked = False
        self._pos = 0  # logical position (updated by read and seek)
        # Furthest position an actual read has reached — length / truncation / over-run
        # key off this, not seek-updated ``_pos``, so ``seek(declared_size)`` on a short
        # body cannot fabricate a clean end (ADR 0014). Reaching the declared size here
        # also marks the member length-verified, so a later seek past the end is cheap.
        self._furthest_read_pos = 0
        # The hashing frontier: the hashers have seen exactly ``[0, _hashed_to)``. Equal
        # to ``_furthest_read_pos`` until a read starts past it, after a seek that
        # jumped over bytes without decoding them; it then stays put, and a read that
        # starts at or behind it moves it on again (ADR 0014).
        self._hashed_to = 0
        # Decode-error abandon: skip all end-of-stream checks on later reads.
        self._abandoned = False
        # What the checks have proved, kept across a rewind (``_rearm``): the member's
        # bytes do not change, so a check that passed once stays passed. Read by the
        # stream's verification level (``proofs``).
        self._ended_clean = False
        self._digest_matched = False
        # Where a size-unknown member was seen to end, once a read reached its end at
        # the read frontier. ``None`` until then, and unused with a declared size.
        self._end_seen: int | None = None
        # A forward seek whose skipped bytes the next read will hash first: the target
        # (``_pos`` already holds it) and where the inner was left. ``None`` when no
        # read-through is due.
        self._read_through_due: tuple[int, int] | None = None

    def _rearm(self) -> None:
        """Put every check back to its state before the first read.

        Runs on a seek to position 0 (``note_seek``): the hashers start again, both
        frontiers go back to 0, and the concluded, digest-checked and abandoned state
        is cleared, so a read from the start to the end after a rewind is verified as
        a first one is.
        """
        for key, factory in self._hasher_factories.items():
            self._hashers[key] = factory()
        self._concluded = False
        self._digest_checked = False
        self._pos = 0
        self._furthest_read_pos = 0
        self._hashed_to = 0
        self._abandoned = False
        self._end_seen = None
        self._read_through_due = None

    def _note_end_seen(self) -> None:
        """Record that a read at the read frontier found the end of a size-unknown member.

        With ``fill_size``, the member's ``size`` becomes that position when every
        byte before it passed the hashers in order (the hashing frontier is there), the
        condition DR-4a keeps a digest under: a seek back keeps it, and so does a
        forward seek whose gap must be decoded anyway (``seek`` reads the gap through).
        A jump over bytes nothing decoded (an index, an accelerator) does not, until a
        seek back to the frontier and a read on to the end. The decoder's own end
        checks passed, since an error raises before the empty read that brings us here.
        """
        self._end_seen = self._pos
        member = self._fill_member
        # A member with a digest is filled once the digest matches instead
        # (``_check_digests_if_complete``).
        if member is None or self._expected or self._hashed_to != self._pos:
            return
        if self._end_check is not None:
            self._end_check(self._pos)
        if member.size is None:
            member.size = self._pos
        member._size_unread = False

    @property
    def enabled(self) -> bool:
        """True when end-of-stream checks may still run (not abandoned by a decode error)."""
        return not self._abandoned

    @property
    def expected_algorithms(self) -> frozenset[str]:
        """The digests this verifier will actually check.

        Narrower than the ``expected`` it was built from: an algorithm with no
        hasher available is dropped at construction (with ``DIGEST_UNVERIFIABLE``).
        A caller that reads a stream *in order to* establish something from its
        digest — rather than checking one alongside a read it wanted anyway — must
        consult this, since a verifier left with nothing to check reports no fault.
        """
        return frozenset(self._expected)

    @property
    def _digest_pending(self) -> bool:
        """True while a digest is still to be checked (none has run, none abandoned)."""
        return bool(self._expected) and not self._digest_checked and not self._abandoned

    @property
    def _frontier_pending(self) -> bool:
        """True while the hashing frontier still decides something: a digest, or a fill.

        A size fill waits on the frontier as a digest does (``_note_end_seen``), so the
        deferred forward seek and the re-check after a later read serve it too.
        """
        member = self._fill_member
        return self._digest_pending or (
            member is not None
            # A member with a digest is filled by the digest verdict alone.
            and not self._expected
            and member.size is None
            and not self._abandoned
        )

    def _end(self) -> int | None:
        """The member's end: its declared size, or where it was seen to end."""
        if self._expected_size is not None:
            return self._expected_size
        return self._end_seen

    @property
    def digest_intact(self) -> bool | None:
        """Whether the stored digest has run, or will run on a read on to the end.

        ``None`` when this verifier checks no digest (a length-only backstop). False
        while the position sits past the hashing frontier and short of the end: a read
        on from there would skip bytes the hashers never saw. A seek back to the
        frontier or behind it makes it True again, even after such a read. So does a
        seek to the declared size before the member concluded, whose conclusion reads
        the gap from the frontier.
        """
        if not self._expected:
            return None
        if self._abandoned:
            return False
        if (
            self._digest_checked
            or self._pos <= self._hashed_to
            or self._read_through_due is not None
        ):
            return True
        end = self._end()
        if end is not None and self._hashed_to >= end:
            # Every byte is hashed; only the verdict is left.
            return True
        # At the declared size before concluding: the conclusion's gap read starts at
        # the read frontier, so it reaches the hashers only while the hashing frontier
        # still sits there, i.e. no read has skipped bytes yet (``_hash_span``).
        return (
            not self._concluded
            and self._expected_size is not None
            and self._pos >= self._expected_size
            and self._hashed_to == self._furthest_read_pos
        )

    def proofs(self) -> VerificationProofs:
        """What this verifier has proved, for the stream's verification level."""
        return VerificationProofs(
            ended=self._ended_clean,
            content=self._digest_matched,
            content_possible=bool(self._expected),
        )

    @property
    def pos(self) -> int:
        return self._pos

    def tell(self, inner: BinaryIO) -> int:
        """The caller's position: the seek target while a read-through is due."""
        if self._read_through_due is not None:
            return self._pos
        return inner.tell()

    def _verify_digests(self) -> None:
        """Check every computable digest; raise on the first mismatch."""
        for algorithm, expected in self._expected.items():
            computed = self._hashers[algorithm].digest()
            transform = self._digest_transforms.get(algorithm)
            if transform is not None:
                computed = transform(computed)
            if computed != expected:
                raise CorruptionError(
                    f"Digest mismatch for {algorithm!r}: stored value does not match the "
                    f"decompressed content."
                )

    def _record_read(self, data: bytes) -> None:
        """Advance logical position and furthest-read position after a returning read.

        Only the part of ``data`` past the hashing frontier reaches the hashers: a read
        after a backward seek returns bytes they have already seen. A read that starts
        past the frontier leaves it where it is (``_hash_span``).
        """
        if not data:
            return
        start = self._pos
        self._pos = start + len(data)
        self._furthest_read_pos = max(self._furthest_read_pos, self._pos)
        self._hash_span(start, data)

    def _hash_span(self, start: int, data: bytes) -> None:
        """Hash the part of ``data`` (read from ``start``) past the hashing frontier.

        A span that starts past the frontier skips bytes the hashers never saw: it is
        not hashed and the frontier stays, so a later read from at or behind it can
        still complete the hash (ADR 0014). Length checks are not affected.
        """
        frontier = self._hashed_to
        end = start + len(data)
        if not start <= frontier < end:
            return
        self._hashed_to = end
        if self._digest_pending:
            if start < frontier:
                data = data[frontier - start :]
            for hasher in self._hashers.values():
                hasher.update(data)

    def _check_digests_if_complete(self) -> None:
        """Give the digest verdict once the hashers have seen the whole member.

        Runs after the length verdict: from ``_conclude``, and from a read after it
        that moves the hashing frontier (a seek back after a read that skipped bytes).
        """
        if not self._digest_pending:
            return
        end = self._end()
        if end is None or self._hashed_to < end:
            return
        self._digest_checked = True
        if self._expected_size is None and self._end_check is not None:
            self._end_check(end)
        self._verify_digests()
        self._digest_matched = True
        fill = self._fill_member
        if fill is not None:
            if fill.size is None:
                fill.size = end
            fill._size_unread = False

    def _conclude(self, inner: BinaryIO) -> None:
        """Run end-of-stream checks once (read path only — never called from close).

        Short bodies raise :class:`~archivey.exceptions.TruncatedError` and digest
        mismatches raise :class:`~archivey.exceptions.CorruptionError`. A short body
        that also carries a hash raises ``TruncatedError`` (best-effort: shortfall vs
        digest mismatch are not always separable). Length / over-run use
        :attr:`_furthest_read_pos` (bytes actually read), not seek-updated ``_pos``.
        Digests run only once the hashing frontier has reached the end; otherwise the
        digest verdict waits for a read that completes the hash
        (``_check_digests_if_complete``).

        When a seek jumped the logical position to/past the declared size without
        reading the intervening bytes, a complete member is indistinguishable from a
        short or long one. Rather than return ``b""`` and hide the fault, read the
        ``[_furthest_read_pos, expected_size)`` gap first, through the hashers when
        the hashing frontier sits at its start, then apply the same length and over-run
        checks, and on success restore the inner to the caller's position. Bounded by
        the declared size (a decompression-bomb cap).

        With no declared size, the read that concludes at the read frontier saw where
        the member ends. One at a position past it (a seek past the end) did not: the
        digests then wait, as they do after a read that skipped bytes.
        """
        self._concluded = True
        expected_size = self._expected_size
        resume: int | None = None
        if (
            expected_size is None
            and self._end_seen is None
            and self._pos == self._furthest_read_pos
        ):
            self._note_end_seen()
        if (
            expected_size is not None
            and self._furthest_read_pos < expected_size <= self._pos
        ):
            resume = inner.tell()
            inner.seek(self._furthest_read_pos)
            try:
                while self._furthest_read_pos < expected_size:
                    want = min(
                        _SIZED_DRAIN_CHUNK, expected_size - self._furthest_read_pos
                    )
                    piece = inner.read(want)
                    if not piece:
                        break
                    self._hash_span(self._furthest_read_pos, piece)
                    self._furthest_read_pos += len(piece)
            except BaseException:
                # A decoder truncation/corruption error propagating from the gap read is
                # the member's own honest verdict; the stream is faulted — abandon and let
                # it surface (skip the pointless best-effort position restore).
                self._abandon()
                raise
        delivered = self._furthest_read_pos
        if expected_size is not None and delivered >= expected_size:
            # Delivered the declared size; the underlying must have nothing more. Any
            # trailing byte is corruption independent of the checksum, so a seek that
            # reached the size must not silence it. This probe also drains post-payload
            # authenticators (e.g. WinZip AES HMAC).
            if _probe_past_declared(inner):
                raise CorruptionError(
                    "Decompressed content exceeds its declared size of "
                    f"{expected_size} bytes."
                )
        elif expected_size is not None:
            # Short of declared size by actual reads — TruncatedError even when a hash
            # is present (best-effort verdict). Seek alone cannot satisfy this check.
            # After a gap read the inner sits at that EOF (no restore — we are raising).
            raise TruncatedError(
                f"Decompressed content ended after {delivered} of "
                f"{expected_size} expected bytes."
            )
        if resume is not None:
            inner.seek(resume)
        self._check_digests_if_complete()
        self._ended_clean = True

    def _after_conclusion(self, data: bytes, *, at_eof: bool) -> bytes:
        """Record a read made after the length verdict; it may complete the hash.

        A read that skipped bytes concluded the length with the digest still pending.
        A read from at or behind the hashing frontier moves it on, and the one that
        brings it to the end gives the digest verdict, withholding its bytes on a
        mismatch as a first reaching read does. ``at_eof`` says the read reached the
        end of the inner (``read(-1)``, or an empty return).
        """
        self._record_read(data)
        if (
            at_eof
            and self._expected_size is None
            # A read that skipped bytes may have found the end first: reaching it
            # again from the frontier is what the fill waits for.
            and self._end_seen in (None, self._pos)
            and self._pos == self._furthest_read_pos
        ):
            self._note_end_seen()
        try:
            self._check_digests_if_complete()
        except BaseException:
            del data  # withheld: the kept traceback must not pin it
            raise
        return data

    def _abandon(self) -> None:
        self._abandoned = True

    def _read_sized_all(self, inner: BinaryIO) -> bytes:
        """Drain to genuine EOF in bounded steps, capped by the declared size.

        ``expected_size`` is a decompression-bomb bound: do **not** delegate to
        ``inner.read(-1)``, which would pull an over-long adversarial payload into
        RAM. A single ``inner.read(remaining)`` is also insufficient — ``BinaryIO``
        may short-read without EOF — so this loop re-asks until empty. Unlike a
        bounded ``read(n)``, continuing past a short is *wanted* here: this call
        drains to EOF, so a decoder's deferred truncation belongs in it.

        On digest / over-run fault the verdict raises here and returns no bytes
        (withhold), matching ADR 0014's size-declared reaching-read rule.
        """
        assert self._expected_size is not None
        chunks: list[bytes] = []
        try:
            while self._pos < self._expected_size:
                remaining = self._expected_size - self._pos
                want = min(_SIZED_DRAIN_CHUNK, remaining)
                try:
                    piece = inner.read(want)
                except BaseException:
                    # The decoder's own error is the verdict, as on the bounded path
                    # in read(): the translator above this verifier classifies it.
                    # Relabelling every raw error as TruncatedError here made a
                    # corrupt deflate body read as truncated through read() and as
                    # corrupt through read(n).
                    self._abandon()
                    raise
                if not piece:
                    break
                self._record_read(piece)
                chunks.append(piece)
            # EOF verdict in this complete-stream call — raise withholds the body.
            if not self._abandoned and not self._concluded:
                self._conclude(inner)
        except BaseException:
            # The raise withholds these bytes, and its traceback keeps this frame
            # alive for as long as the caller keeps the error: let the body go —
            # the list and the last piece read, which can be the whole member.
            chunks.clear()
            piece = b""
            raise
        return b"".join(chunks)

    def read(self, inner: BinaryIO, n: int | None = -1) -> bytes:
        """Read from ``inner``, update digests/bounds, and verify on clean EOF.

        Bounded ``read(n)`` is full-count by way of one ``inner.read`` — the inner is
        fill-or-EOF, and a short non-empty return is a terminal boundary to forward
        rather than retry (ADR 0014). A size-declared reaching read that fails
        digest / over-run raises and returns no bytes for that call.
        """
        # ``None`` reads to EOF, as on any ``io`` stream.
        if n is None:
            n = -1
        # read(0) is a no-op — never treat it as EOF (stdlib file / BytesIO contract).
        if n == 0:
            return b""
        if self._read_through_due is not None:
            self._settle_read_through(inner)
        if n < 0:
            # Complete-stream read: include the EOF verdict in this call.
            if (
                not self._abandoned
                and self._expected_size is not None
                and not self._concluded
            ):
                return self._read_sized_all(inner)
            try:
                data = inner.read(-1)
            except Exception:  # abandon verify; re-raise decoder error
                self._abandon()
                raise
            if self._concluded and self._frontier_pending:
                return self._after_conclusion(data, at_eof=True)
            if data:
                self._record_read(data)
            if not self._abandoned and not self._concluded:
                try:
                    self._conclude(inner)
                except BaseException:
                    del data  # withheld: the kept traceback must not pin it
                    raise
            return data

        # Bounded full-count read.
        if self._abandoned or self._concluded:
            try:
                data = inner.read(n)
            except Exception:  # abandon verify; re-raise decoder error
                self._abandon()
                raise
            if self._frontier_pending:
                return self._after_conclusion(data, at_eof=not data)
            return data

        want = n
        reaches_declared = False
        if self._expected_size is not None:
            remaining = self._expected_size - self._pos
            if remaining <= 0:
                # Declared size 0 read from the start, or a seek at/past the declared
                # size (a sequential read reaching the size verifies inline): conclude
                # here, reading any seek-skipped gap rather than trusting the seek.
                self._conclude(inner)
                return b""
            want = min(n, remaining)
            reaches_declared = want == remaining

        try:
            data = inner.read(want)
        except Exception:  # abandon verify; re-raise decoder error
            self._abandon()
            raise

        if data:
            self._record_read(data)
            if (
                reaches_declared
                and self._expected_size is not None
                and self._furthest_read_pos >= self._expected_size
            ):
                # Size-declared verifying event: withhold this chunk on fault.
                try:
                    self._conclude(inner)
                except BaseException:
                    del data  # withheld: the kept traceback must not pin it
                    raise
            return data

        # Empty: size-unknown digest / truncation-shaped terminal read.
        if not self._concluded:
            self._conclude(inner)
        return data

    def seek(self, inner: BinaryIO, offset: int, whence: int = 0) -> int:
        """Seek, keeping the checksum when reaching the target decodes the gap anyway.

        A forward seek past the hashing frontier on a decompressing inner decodes every
        byte between its resume point and the target. When that resume point is at or
        before the frontier (``nearest_resume_offset``), the skipped bytes cost the
        same whether the inner discards them or this verifier reads them. The seek
        then leaves the inner where it is and records the target; the next read reads
        the gap through the hashers first (``_settle_read_through``). The seek stays
        lazy: a later seek replaces the target, and a member closed with no read
        decodes nothing. The hashers see the first pass over each byte only: bytes
        read again after a seek back are not checked again.

        Every other seek is passed on (``note_seek``). One to or behind the frontier
        keeps the checksum. So does one to or past the declared size: the read that
        concludes reads the gap through the hashers (``_conclude``), so the seek need
        not, and a ``seek(0, SEEK_END)`` that a caller undoes stays as cheap as the
        inner makes it. A seek past the frontier that the inner can jump (a seek
        index, an accelerator, a stored or decrypt-only member) or cannot price
        pauses the checksum once a read skips the gap (``_record_read``): a seek back
        to the frontier or behind it, then a read on to the end, completes it.
        """
        target = self._seek_target(offset, whence)
        due = self._read_through_due
        end = self._end()
        planned: Exception | None = None
        if (
            target is not None
            and target > self._hashed_to
            # Parked past the frontier (a jump, or the end already found there):
            # reaching the frontier again would mean a rewind, not a decode forward.
            and (self._pos <= self._hashed_to or due is not None)
            and (end is None or target < end)
            and self._frontier_pending
        ):
            # A report the planning escalated (an index build) is this seek's: it
            # raises once the seek has moved, as the inner's own seek raises it.
            resume, planned = ask_seek_resume_offset(inner, target)
            if resume is not None and resume <= self._hashed_to:
                left_at = due[1] if due is not None else self._pos
                self._read_through_due = (target, left_at)
                self._pos = target
                if planned is not None:
                    raise planned
                return target
        if due is not None and target is not None:
            # The inner is still where the deferred seek left it, not at ``_pos``: a
            # relative ``whence`` must not apply to it as given. ``SEEK_CUR`` stays
            # relative to where the inner is, so a target before 0 is the inner's to
            # clamp or refuse, as it would be with no deferred seek.
            if whence == 1:
                offset = target - due[1]
            else:
                offset, whence = target, 0
        self._read_through_due = None
        result = inner.seek(offset, whence)
        self.note_seek(result)
        if planned is not None:
            raise planned
        return result

    def _seek_target(self, offset: int, whence: int) -> int | None:
        """The position a seek asks for, or ``None`` when it needs the unknown size."""
        if whence == 0:
            return offset
        if whence == 1:
            return self._pos + offset
        if self._expected_size is not None:
            return self._expected_size + offset
        return None

    def _settle_read_through(self, inner: BinaryIO) -> None:
        """Read and hash from the frontier up to a deferred seek's target.

        The target is short of the declared size (``seek`` sends the rest to
        ``_conclude``), so this read never concludes. A decoder error abandons the
        checks and propagates from the read that settles, as it would had the inner's
        own lazy seek decoded the same bytes there. With no declared size, reaching the
        end first is recorded, so the position past it skips no byte. The inner ends
        with a seek to the target. The bytes between the hashing frontier and the read
        frontier may have been read once already, by a read that skipped bytes before
        them; they are hashed now all the same.
        """
        due = self._read_through_due
        assert due is not None
        target, left_at = due
        self._read_through_due = None
        self._pos = left_at
        try:
            if self._pos < self._hashed_to:
                # Behind the frontier after a backward seek: let the inner reach the
                # frontier its own cheapest way, then read on from there.
                self._pos = inner.seek(self._hashed_to)
            while self._pos < target:
                piece = inner.read(min(_SIZED_DRAIN_CHUNK, target - self._pos))
                if not piece:
                    if self._pos == self._furthest_read_pos:
                        self._note_end_seen()
                    break
                self._record_read(piece)
        except BaseException:
            self._abandon()
            raise
        self._pos = inner.seek(target)

    def note_seek(self, result: int) -> None:
        """Update the position after a successful (or raised but moved) inner seek.

        A seek to position 0 re-arms every check (``_rearm``): the hashers start again
        and the frontiers, concluded and digest-checked state are cleared, so a read
        from 0 to the end is verified as a first read is, digests included. Any other
        seek only moves the position: the hashers cover ``[0, frontier)``, a read from
        at or behind the frontier hashes only what lies past it, and a read that starts
        past it pauses the **checksum** until a read from at or behind the frontier
        again (``_record_read``). Length / truncation / over-run checks stay enabled and
        key off bytes actually read (``_furthest_read_pos``); a seek that jumps to/past
        the declared size has the skipped gap read back and a byte probed past the size
        at conclusion (``_conclude``), so ``seek(declared_size)`` cannot silence
        truncation (short) or over-run (long) (ADR 0014).
        """
        self._read_through_due = None
        if result == 0:
            self._rearm()
            return
        self._pos = result

    def finish_on_close(self, inner: BinaryIO) -> None:
        """Close ``inner`` — teardown only, never a content-fault surface.

        Every content verdict (digest mismatch, hash-less short, over-length) fires
        from a completing read. ``close`` therefore does **not** read, probe, or
        drain the inner to force a late verdict — a partial read before clean EOF is
        a deliberate abandon with no verdict. A teardown error raised by
        ``inner.close()`` itself (a subprocess exit code, ``OSError``) still
        propagates. WinZip AES HMAC is a content verdict and fires from the
        completing read, not from ``close`` (ADR 0014).
        """
        inner.close()


def note_raised_seek(verifier: MemberVerifier | None, inner: BinaryIO) -> int | None:
    """Tell ``verifier`` where a seek that raised left ``inner``; return that position.

    A seek can raise after it moved: a decompressor stream raises an escalated
    report once its own seek has finished (see ``DecompressorStream``), so a caller
    that catches it reads on from the new position. The verifier must know, or it
    keeps hashing as if the read were still linear and checks length against a
    frontier the stream has left. Both wrappers that drive a verifier
    (:class:`VerifyingStream` and ``ArchiveStream``) call this from their seek.
    Returns ``None`` when ``inner`` cannot say where it is; the seek's own error is
    the one that propagates. A seek the verifier deferred (``MemberVerifier.seek``)
    raised after it moved, with the inner left where it was: the verifier's position
    stands.
    """
    if verifier is not None and verifier._read_through_due is not None:
        return verifier.pos
    try:
        after = inner.tell()
    except Exception:  # noqa: BLE001 - the seek's own error propagates instead
        return None
    if verifier is not None:
        verifier.note_seek(after)
    return after


def ask_digest_intact(stream: object) -> bool | None:
    """Ask ``stream`` whether the digest its verifier checks can still run.

    Duck-typed on a ``_digest_intact()`` method, as :func:`ask_resume_offset` is on
    ``nearest_resume_offset``: :class:`VerifyingStream` and an ``ArchiveStream`` with
    a fused verifier answer (see :attr:`MemberVerifier.digest_intact`). Private, so
    the public ``ArchiveStream`` gains no published method. ``None`` means the stream
    cannot say: it has no verifier, or one that checks no digest.
    """
    ask = getattr(stream, "_digest_intact", None)
    if ask is None:
        return None
    answer = ask()
    return answer if isinstance(answer, bool) else None


def build_member_verifier(
    expected: _ExpectedHashes | None,
    *,
    expected_size: int | None = None,
    collector: DiagnosticCollector | None = None,
    member: ArchiveMember | None = None,
    archive_name: str | None = None,
    digest_transforms: _DigestTransforms | None = None,
    end_check: Callable[[int], None] | None = None,
    fill_size: bool = False,
) -> MemberVerifier | None:
    """Return a :class:`MemberVerifier` when there is something to check, else ``None``.

    ``fill_size`` with a ``member`` and no ``expected_size`` is something to do: the
    verifier sets ``member.size`` when a read that skipped no byte reaches the end.

    Building the verifier emits only ``DIGEST_UNVERIFIABLE``, once for each entry of
    ``expected`` that has no hasher. A lazy ``ArchiveStream`` that builds its own
    verifier relies on that: it enters its diagnostic scope for the build only when
    ``expected`` is non-empty.
    """
    hashes = expected if expected is not None else {}
    fills = fill_size and member is not None and expected_size is None
    if not hashes and expected_size is None and not fills:
        return None
    return MemberVerifier(
        hashes,
        expected_size=expected_size,
        collector=collector,
        member=member,
        archive_name=archive_name,
        digest_transforms=digest_transforms,
        end_check=end_check,
        fill_size=fills,
    )


class VerifyingStream(ReadOnlyIOStream):
    """Wrap ``inner`` and verify digests/length via a :class:`MemberVerifier`.

    Kept for codec length backstops and tests. Member backends fuse the same
    verifier into :class:`~archivey.internal.streams.archive_stream.ArchiveStream`.
    """

    def __init__(
        self,
        inner: BinaryIO,
        expected: _ExpectedHashes,
        *,
        expected_size: int | None = None,
        collector: DiagnosticCollector | None = None,
        member: ArchiveMember | None = None,
        archive_name: str | None = None,
        digest_transforms: _DigestTransforms | None = None,
    ) -> None:
        super().__init__()
        self._inner = inner
        # This wrapper is used explicitly (codec length backstops, tests), so it always
        # owns a verifier even when there is nothing to check — unlike the fused path,
        # which uses ``build_member_verifier`` to skip the wrapper entirely in that case.
        try:
            self._verifier = MemberVerifier(
                expected,
                expected_size=expected_size,
                collector=collector,
                member=member,
                archive_name=archive_name,
                digest_transforms=digest_transforms,
            )
        except BaseException:
            # The build can raise (a digest diagnostic under a RAISE policy), and
            # ``IOBase.__del__`` still calls ``close()``, which needs the verifier.
            # Close the inner this wrapper owns and mark it closed, so the finalizer
            # has nothing left to do.
            try:
                inner.close()
            except Exception:  # noqa: BLE001, S110 - the refusal below is the error to report
                pass
            finally:
                super().close()
            raise

    def read(self, n: int | None = -1, /) -> bytes:
        try:
            return self._verifier.read(self._inner, n)
        except CorruptionError:
            retire_decoder_children(self._inner)
            raise

    def seekable(self) -> bool:
        return is_seekable(self._inner)

    def seek(self, offset: int, whence: int = 0, /) -> int:
        try:
            return self._verifier.seek(self._inner, offset, whence)
        except Exception:
            note_raised_seek(self._verifier, self._inner)
            raise

    def _digest_intact(self) -> bool | None:
        return self._verifier.digest_intact

    def _verification_proofs(self) -> VerificationProofs:
        return self._verifier.proofs().combine(ask_verification_proofs(self._inner))

    def tell(self) -> int:
        return self._verifier.tell(self._inner)

    def nearest_resume_offset(self, target: int) -> int | None:
        # Length backstop around a codec stream; preserve the inner's offset space.
        return ask_resume_offset(self._inner, target)

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._verifier.finish_on_close(self._inner)
        finally:
            # finish_on_close closes the inner; always mark the wrapper closed even
            # when a teardown error from inner.close() propagates.
            if not self.closed:
                super().close()
