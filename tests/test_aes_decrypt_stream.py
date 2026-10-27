"""Seek, tell, and ownership for the 7z AES-CBC pull stream.

Needs ``cryptography`` (``[all]`` / ``[all-lowest]``). The ``[core-only]`` leg
skips the whole module: there is no decryptor to wrap. The Hypothesis property
on ``nearest_resume_offset`` skips itself when that import is missing.
"""

from __future__ import annotations

import io
from collections.abc import Callable

import pytest

try:
    from hypothesis import example, given, strategies as st
except ImportError:  # pragma: no cover - hypothesis is a dev-group dep
    example = given = st = None  # type: ignore[misc, assignment]

from archivey.exceptions import TruncatedError
from archivey.internal.streams import crypto
from archivey.internal.streams.crypto import AES_BLOCK_SIZE, AesDecryptStream, AesParams
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO

pytestmark = requires("cryptography")

_KEY = b"\x11" * 32
_IV = b"\x22" * AES_BLOCK_SIZE
# 53 bytes so tests hit both writer-style plaintext pad and truncated ciphertext.
_PLAIN = bytes(range(53))


def _encrypt(plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(plaintext) % AES_BLOCK_SIZE:
        raise ValueError("test helper encrypts whole AES blocks only")
    encryptor = Cipher(algorithms.AES(_KEY), modes.CBC(_IV)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def _stage_decrypt(cipher: bytes) -> bytes:
    """Same stage the pull stream uses. A short last block raises TruncatedError."""
    stage = crypto.open_aes_decrypt_stage(AesParams(key=_KEY, iv=_IV))
    return stage.update(cipher) + stage.finalize()


def _open(cipher: bytes, *, owns_inner: bool = False) -> AesDecryptStream:
    return AesDecryptStream(
        io.BytesIO(cipher),
        AesParams(key=_KEY, iv=_IV),
        owns_inner=owns_inner,
    )


def test_aligned_roundtrip_via_open_helper() -> None:
    plaintext = _PLAIN[:48]
    cipher = _encrypt(plaintext)
    with crypto.open_aes_decrypt_stream(
        io.BytesIO(cipher), AesParams(key=_KEY, iv=_IV)
    ) as stream:
        assert stream.read() == plaintext


def test_writer_pads_plaintext_so_ciphertext_is_block_aligned() -> None:
    """7z AES encoder zero-pads plaintext, then stores a full ciphertext block.

    Pack size is therefore a multiple of AES_BLOCK_SIZE. A short last ciphertext
    block is truncated input, not the writer convention.
    """
    payload = _PLAIN  # 53 bytes
    padded = payload + bytes(AES_BLOCK_SIZE - (len(payload) % AES_BLOCK_SIZE))
    cipher = _encrypt(padded)
    assert len(cipher) % AES_BLOCK_SIZE == 0
    with _open(cipher) as stream:
        assert stream.read() == padded
        assert stream.seek(0, io.SEEK_END) == len(padded)


def test_short_ciphertext_finalize_raises_truncated() -> None:
    # Truncate a 64-byte ciphertext to 53: three full blocks plus five. AES
    # cannot recover the last block, so finalize raises rather than emitting
    # 16 garbage plaintext bytes. size / SEEK_END report the intact 48.
    cipher = _encrypt(bytes(range(64)))[:53]
    # Mutation A: restore zero-pad drain in finalize — DID NOT RAISE.
    # Mutation E: raise base TruncatedError instead of the origin-tagged
    # subclass — type(exc) is TruncatedError.
    with pytest.raises(TruncatedError, match="mid-block") as info:
        _stage_decrypt(cipher)
    assert type(info.value) is crypto._AesCbcTruncatedError
    with _open(cipher) as stream:
        # Mutation B: round _plaintext_size up to a whole block — reports 64.
        assert stream.size == 48
        assert stream.seek(0, io.SEEK_END) == 48
        # SEEK_END describes the recoverable payload; it does not itself raise.
        # The next read is empty because the cursor is already at that end.
        assert stream.read() == b""
    with _open(cipher) as stream, pytest.raises(TruncatedError, match="mid-block"):
        stream.read()
    with _open(cipher) as stream:
        assert stream.read(48) == bytes(range(48))
        with pytest.raises(TruncatedError, match="mid-block"):
            stream.read(1)


def test_seek_end_on_sub_block_truncation_still_raises() -> None:
    """5 ciphertext bytes: size=0, SEEK_END at origin is a no-op, read raises.

    The 53-byte case above lands SEEK_END at 48 and the next read is empty.
    Identical damage, two answers — both are the recoverable-payload policy,
    not a side effect of the ``new_pos == _pos`` short-circuit. Marking eof
    whenever ``new_pos >= size`` (before that short-circuit) would make
    ``seek(0)`` on this stream silent-empty.
    """
    cipher = _encrypt(bytes(range(16)))[:5]
    with _open(cipher) as stream:
        assert stream.size == 0
        assert stream.seek(0, io.SEEK_END) == 0
        assert stream.tell() == 0
        with pytest.raises(TruncatedError, match="mid-block"):
            stream.read()


def test_intact_prefix_readable_after_truncated_raise() -> None:
    """A completing read that raises leaves the intact prefix drainable.

    ``finalize`` raises before ``read`` sets ``_eof`` or clears ``_buf``.
    Catch and read the buffered blocks; only a read that reaches the
    truncated tail raises again.
    """
    cipher = _encrypt(bytes(range(64)))[:53]
    with _open(cipher) as stream:
        with pytest.raises(TruncatedError, match="mid-block"):
            stream.read()
        assert stream.tell() == 0
        assert stream.read(48) == bytes(range(48))
        with pytest.raises(TruncatedError, match="mid-block"):
            stream.read(1)


def test_seekable_follows_source() -> None:
    cipher = _encrypt(_PLAIN[:32])
    with _open(cipher) as stream:
        assert stream.seekable() is True
    wrapped = AesDecryptStream(NonSeekableBytesIO(cipher), AesParams(key=_KEY, iv=_IV))
    try:
        assert wrapped.seekable() is False
        with pytest.raises(io.UnsupportedOperation):
            wrapped.seek(0)
        assert wrapped.read() == _PLAIN[:32]
    finally:
        wrapped.close()


def test_seek_block_boundary() -> None:
    plaintext = _PLAIN[:48]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.seek(16) == 16
        assert stream.tell() == 16
        assert stream.read() == plaintext[16:]


def test_seek_mid_block() -> None:
    plaintext = _PLAIN[:48]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.seek(17) == 17
        assert stream.read() == plaintext[17:]


def test_seek_backwards_after_partial_read() -> None:
    plaintext = _PLAIN[:48]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.read(10) == plaintext[:10]
        assert stream.tell() == 10
        stream.seek(0)
        assert stream.read() == plaintext


def test_seek_past_eof_then_read_is_empty() -> None:
    plaintext = _PLAIN[:32]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.seek(1000) == 1000
        assert stream.tell() == 1000
        assert stream.read() == b""
        stream.seek(0)
        assert stream.read() == plaintext


def test_seek_end_and_relative() -> None:
    plaintext = _PLAIN[:32]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.seek(0, io.SEEK_END) == 32
        assert stream.seek(-8, io.SEEK_CUR) == 24
        assert stream.read() == plaintext[24:]


def test_read_all_then_rewind() -> None:
    """A spent CBC decryptor must not be reused after finalize."""
    plaintext = _PLAIN[:48]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.read() == plaintext
        stream.seek(0)
        assert stream.read() == plaintext
        stream.seek(16)
        assert stream.read(8) == plaintext[16:24]


def test_short_last_block_mid_seek() -> None:
    cipher = _encrypt(bytes(range(64)))[:53]
    with _open(cipher) as stream:
        stream.seek(40)
        # Mutation A: restore zero-pad drain in finalize — returns leftover
        # intact bytes plus 16 garbage instead of raising.
        with pytest.raises(TruncatedError, match="mid-block"):
            stream.read()


def test_owns_inner_false_borrows_source() -> None:
    source = io.BytesIO(_encrypt(_PLAIN[:16]))
    stream = AesDecryptStream(source, AesParams(key=_KEY, iv=_IV), owns_inner=False)
    stream.close()
    assert not source.closed
    with pytest.raises(ValueError, match="closed file"):
        stream.read()
    with pytest.raises(ValueError, match="closed file"):
        stream.tell()
    with pytest.raises(ValueError, match="closed file"):
        stream.seek(0)


def test_owns_inner_true_closes_source() -> None:
    source = io.BytesIO(_encrypt(_PLAIN[:16]))
    stream = AesDecryptStream(source, AesParams(key=_KEY, iv=_IV), owns_inner=True)
    stream.close()
    assert source.closed


def test_unbounded_read_still_allowed() -> None:
    """RAR headers reject read(-1); the 7z member stream must not."""
    plaintext = _PLAIN[:32]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.read(-1) == plaintext


def test_relative_underflow_clamps_like_bytesio() -> None:
    plaintext = _PLAIN[:32]
    with _open(_encrypt(plaintext)) as stream:
        assert stream.seek(-5, io.SEEK_CUR) == 0
        assert stream.seek(-99, io.SEEK_END) == 0
        with pytest.raises(ValueError, match="Negative seek"):
            stream.seek(-1, io.SEEK_SET)


class _UnknownSizeSeekable(io.RawIOBase):
    """Seekable, but not a type ``source_byte_size`` will measure."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        return self._inner.read(n)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._inner.seek(offset, whence)

    def tell(self) -> int:
        return self._inner.tell()


def test_seek_end_refused_when_ciphertext_length_unknown() -> None:
    cipher = _encrypt(_PLAIN[:32])
    stream = AesDecryptStream(_UnknownSizeSeekable(cipher), AesParams(key=_KEY, iv=_IV))
    try:
        with pytest.raises(io.UnsupportedOperation, match="SEEK_END"):
            stream.seek(0, io.SEEK_END)
        assert stream.read() == _PLAIN[:32]
    finally:
        stream.close()


def test_set_and_cur_seek_work_when_ciphertext_length_unknown() -> None:
    """Only SEEK_END needs the length; SEEK_SET and SEEK_CUR must not ask for it."""
    cipher = _encrypt(_PLAIN[:32])
    stream = AesDecryptStream(_UnknownSizeSeekable(cipher), AesParams(key=_KEY, iv=_IV))
    try:
        assert stream.seek(5) == 5
        assert stream.read(3) == _PLAIN[5:8]
        assert stream.seek(-99, io.SEEK_CUR) == 0
        assert stream.read() == _PLAIN[:32]
    finally:
        stream.close()


def test_read_asks_source_in_block_multiples() -> None:
    cipher = _encrypt(_PLAIN[:48])
    source = io.BytesIO(cipher)
    with AesDecryptStream(source, AesParams(key=_KEY, iv=_IV)) as stream:
        assert stream.read(5) == _PLAIN[:5]
        assert source.tell() == AES_BLOCK_SIZE
        assert stream.nearest_resume_offset(17) == AES_BLOCK_SIZE


class _ResumeSource(io.BytesIO):
    """Seekable ciphertext whose resume offset is injected, not derived."""

    def __init__(self, data: bytes, resume: Callable[[int], int | None] | None) -> None:
        super().__init__(data)
        self._resume = resume

    def nearest_resume_offset(self, target: int) -> int | None:
        if self._resume is None:
            return None
        return self._resume(target)


def _resume_answer(cipher_start: int, target: int, resume: int) -> int:
    """Ask ``nearest_resume_offset`` of a source pinned at ``resume``.

    The inner clamps to ``<= target`` like a real resumable stream. The step
    probe never asks past the IV block, so that clamp does not fire there.
    """
    payload = b"\x00" * cipher_start + _encrypt(_PLAIN[:16])
    source = _ResumeSource(payload, lambda t, r=resume: max(0, min(r, t)))
    source.seek(cipher_start)
    with AesDecryptStream(source, AesParams(key=_KEY, iv=_IV)) as stream:
        return stream.nearest_resume_offset(target)


@pytest.mark.parametrize(
    ("cipher_start", "target", "inner_resume", "expected"),
    [
        # Inner can resume at the IV block we ask for: composed answer equals
        # block_start (the + AES_BLOCK_SIZE un-shift). Without it: 399_984.
        (0, 400_000, lambda t: t, 400_000),
        # Inner at or before cipher_start: plaintext block 0 uses the stream IV,
        # so the first resume point is 0, not 16.
        (0, 400_000, lambda t: 0, 0),
        # q in 1..16 still needs the IV block at cipher_start, which is behind
        # the inner's resume, so the answer steps to 32.
        (0, 400_000, lambda t: 1, 32),
        (0, 400_000, lambda t: 200_000, 200_016),
        # Inner codec block not AES-aligned: round UP so the IV block
        # does not precede the inner's seek point.
        (0, 400_000, lambda t: 200_005, 200_032),
        (0, 400_000, lambda t: 199_999, 200_016),
        (0, 400_000, lambda t: 200_001, 200_032),
        (0, 7, lambda t: t, 0),
        (100, 400_000, lambda t: t, 400_000),
        # Inner declines (no method / None); composition is a no-op.
        (0, 400_000, None, 400_000),
    ],
    ids=(
        "inner_free",
        "inner_origin",
        "inner_one_byte",
        "inner_midway",
        "inner_unaligned",
        "inner_unaligned_below",
        "inner_unaligned_plus_one",
        "block_zero",
        "nonzero_cipher_start",
        "inner_declines",
    ),
)
def test_nearest_resume_offset_composes_with_inner(
    cipher_start: int,
    target: int,
    inner_resume: Callable[[int], int | None] | None,
    expected: int,
) -> None:
    cipher = _encrypt(_PLAIN[:16])
    source = _ResumeSource(b"\x00" * cipher_start + cipher, inner_resume)
    source.seek(cipher_start)
    with AesDecryptStream(source, AesParams(key=_KEY, iv=_IV)) as stream:
        assert stream.nearest_resume_offset(target) == expected


@pytest.mark.parametrize("cipher_start", [0, 1, 7, 16, 100])
@pytest.mark.parametrize("block_index", [0, 1, 2, 7, 12500])
def test_nearest_resume_offset_steps_at_a_ciphertext_block(
    cipher_start: int, block_index: int
) -> None:
    """The answer is a step function of the inner's resume point.

    An inner that resumes exactly at the IV block ``cs + 16m`` for ``m ≥ 1``
    yields ``16m + 16``. One byte later needs a new IV block, so the answer is
    exactly one AES block later; one byte earlier is still inside the same
    block, so it must not move; a full block earlier must step down.

    ``m == 0`` is the exception: plaintext block 0 uses the stream IV, so
    resuming at ``cipher_start`` yields 0. One byte later (``q`` in 1..16)
    still needs the IV block at ``cipher_start``, which is behind that
    resume, so the answer is 32.

    ``target`` sits well above the IV block so ``min(block_start, …)`` never
    caps — the cap is covered by the ``inner_free`` row of the table test.
    """
    iv_block = AES_BLOCK_SIZE * block_index
    target = iv_block + 10 * AES_BLOCK_SIZE

    at = _resume_answer(cipher_start, target, cipher_start + iv_block)
    if block_index == 0:
        assert at == 0
        above = _resume_answer(cipher_start, target, cipher_start + 1)
        assert above == 2 * AES_BLOCK_SIZE
        return
    assert at == iv_block + AES_BLOCK_SIZE

    above = _resume_answer(cipher_start, target, cipher_start + iv_block + 1)
    assert above == at + AES_BLOCK_SIZE, (
        "one byte past the IV block must restart exactly one AES block later"
    )

    # One byte earlier stays in the same ciphertext block. A full block
    # earlier must step down; at m=1 that lower step is 0 (plaintext
    # block 0), not 16.
    same = _resume_answer(cipher_start, target, cipher_start + iv_block - 1)
    assert same == at, "the answer must be flat across a ciphertext block"
    below = _resume_answer(
        cipher_start, target, cipher_start + iv_block - AES_BLOCK_SIZE
    )
    assert below < at


if given is not None:

    @example(cipher_start=0, target=400_000, spec=("none", 0))
    @example(cipher_start=0, target=400_000, spec=("absent", 0))
    @example(cipher_start=0, target=400_000, spec=("lag", 0))
    @example(cipher_start=0, target=400_000, spec=("lag", 1))
    @example(cipher_start=0, target=7, spec=("lag", 0))
    @example(cipher_start=100, target=400_000, spec=("lag", 0))
    @given(
        cipher_start=st.one_of(
            st.sampled_from([0, 1, 7, 16, 100]),
            st.integers(min_value=0, max_value=1024),
        ),
        target=st.one_of(
            st.sampled_from([0, 1, 7, 15, 16, 17, 31, 32, 400_000]),
            st.integers(min_value=0, max_value=500_000),
        ),
        spec=st.one_of(
            st.just(("none", 0)),
            st.just(("absent", 0)),
            st.tuples(st.just("lag"), st.integers(min_value=0, max_value=500_000)),
        ),
    )
    def test_nearest_resume_offset_invariant(
        cipher_start: int, target: int, spec: tuple[str, int]
    ) -> None:
        """Docstring contract for ``nearest_resume_offset``, over random inners.

        For any target and any inner resume point, the returned ``P`` is a CBC
        restart (``P % 16 == 0``) in ``[0, block_start]``. When the inner
        answers, a ``P > 0`` never needs an IV block behind that resume — callers
        may act on this value, so rounding down costs them replay. When the inner
        declines (no method, or ``None``), ``P == block_start``.

        These four rules are one-sided (``block_start`` satisfies all of them).
        Composition — that the answer actually moves with the inner — is pinned
        by ``test_nearest_resume_offset_steps_at_a_ciphertext_block``.

        Resume is generated as a lag behind the asked offset so the fake
        satisfies ``nearest_resume_offset(t) <= t``, like a real resumable
        stream.

        CI budget is the shared ``archivey`` Hypothesis profile in
        ``conftest.py`` (``max_examples=100``, ``deadline=None``,
        ``derandomize=True``). Deepen locally with
        ``ARCHIVEY_FUZZ_EXAMPLES=2000``. Hypothesis is a ``dev``-group
        dependency; this test skips when it is missing so the rest of the
        module still runs.
        """
        kind, lag = spec
        cipher = _encrypt(_PLAIN[:16])
        payload = b"\x00" * cipher_start + cipher
        recorded: list[int] = []
        if kind == "absent":
            source: io.BytesIO = io.BytesIO(payload)
        elif kind == "none":
            source = _ResumeSource(payload, None)
        else:

            def recording_resume(t: int, behind: int = lag) -> int:
                r = max(0, t - behind)
                recorded.append(r)
                return r

            source = _ResumeSource(payload, recording_resume)
        source.seek(cipher_start)
        with AesDecryptStream(source, AesParams(key=_KEY, iv=_IV)) as stream:
            result = stream.nearest_resume_offset(target)

        block_start = target - (target % AES_BLOCK_SIZE)
        assert result % AES_BLOCK_SIZE == 0, f"P={result} is not a CBC block boundary"
        assert 0 <= result <= block_start, (
            f"P={result} not in [0, block_start={block_start}] for target={target}"
        )
        if kind in ("absent", "none"):
            assert result == block_start, (
                f"declining inner must yield block_start={block_start}, got P={result}"
            )
            return
        assert len(recorded) == 1, (
            f"lag inner must be asked once, got {len(recorded)} calls"
        )
        inner_resume = recorded[0]
        if result > 0:
            iv_block = cipher_start + result - AES_BLOCK_SIZE
            assert iv_block >= inner_resume, (
                f"IV block at {iv_block} is behind inner resume {inner_resume} "
                f"(P={result}, cipher_start={cipher_start}, target={target})"
            )

else:

    def test_nearest_resume_offset_invariant() -> None:
        pytest.skip("hypothesis not installed (dev group)")


def test_aes_params_repr_hides_key() -> None:
    params = AesParams(key=_KEY, iv=_IV)
    text = repr(params)
    assert "key=" not in text
    assert str(_KEY) not in text
    assert "iv=" in text
