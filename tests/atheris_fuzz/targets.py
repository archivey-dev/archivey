"""Atheris target callables (typed ArchiveyError → soft return)."""

from __future__ import annotations

import io
import lzma
import os
import zlib
from collections.abc import Callable
from dataclasses import replace

from archivey import (
    AcceleratorMode,
    ArchiveFormat,
    ArchiveReader,
    ArchiveyConfig,
    ArchiveyError,
    ContainerFormat,
    DecoderLimits,
    ForwardArchiveReader,
    StreamFormat,
    detect_format,
    format_availability,
    open_archive,
)
from archivey.exceptions import PackageNotInstalledError
from archivey.internal.backends.rar_detect import validate_rar_main_header
from archivey.internal.backends.rar_parser import parse_rar_archive
from archivey.internal.backends.rar_unrar import find_rarlab_unrar
from archivey.internal.backends.sevenzip_detect import (
    validate_sevenzip_signature_header,
)
from archivey.internal.backends.sevenzip_reader import load_sevenzip_archive
from archivey.internal.backends.zip_detect import validate_zip_local_header
from archivey.internal.config import StreamConfig
from archivey.internal.password import _PasswordCandidates
from archivey.internal.streams.codecs import (
    Codec,
    is_codec_available,
    open_codec_stream,
)
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64, arm64_decode
from archivey.internal.streams.codecs.bcj2_filter import Bcj2DecoderStream
from archivey.internal.streams.codecs.lzma_filter_decoder import FilterStream
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV, riscv_decode
from archivey.types import FormatSupport
from tests.atheris_fuzz.crc_fixup import (
    fixup_rar_header_crcs,
    fixup_sevenzip_header_crcs,
    fixup_tar_header_checksums,
    fixup_zip_local_and_cd_crc,
)
from tests.atheris_fuzz.seeds import (
    accel_bzip2_seeds,
    accel_deflate_seeds,
    accel_gzip_seeds,
    accel_zlib_seeds,
    brotli_seeds,
    bzip2_seeds,
    deflate64_seeds,
    detect_format_seeds,
    filter_seeds,
    gzip_seeds,
    iso_seeds,
    lz4_seeds,
    lzip_seeds,
    lzma_alone_seeds,
    open_detected_seeds,
    rar_seeds,
    sevenzip_seeds,
    tar_seeds,
    unix_compress_seeds,
    xz_seeds,
    zip_seeds,
    zlib_seeds,
    zstd_seeds,
)
from tests.detection_cost_util import within_budget
from tests.streams_util import NonSeekableBytesIO

# 64 MiB, not the 2 GiB default. A mutated 7z or ZIP can declare a dictionary of
# that default, and the read below would reserve it. Real seeds in this harness
# use a 1 MiB dictionary or none.
_FUZZ_DECODER_LIMITS = DecoderLimits(max_decoder_memory=64 * 1024 * 1024)
_FUZZ_CONFIG = ArchiveyConfig(
    use_rapidgzip=AcceleratorMode.OFF,
    use_indexed_bzip2=AcceleratorMode.OFF,
    decoder_limits=_FUZZ_DECODER_LIMITS,
)

# Seekable indexing on (interesting crash class); accelerators forced off.
_STREAM_CONFIG = StreamConfig(
    streaming=False,
    seekable=True,
    use_rapidgzip=AcceleratorMode.OFF,
    use_indexed_bzip2=AcceleratorMode.OFF,
)

# The accelerator targets run the same open twice, accelerators forced on and forced off,
# and compare. Everything else matches ``_STREAM_CONFIG``.
_ACCEL_ON_CONFIG = replace(
    _STREAM_CONFIG,
    use_rapidgzip=AcceleratorMode.ON,
    use_indexed_bzip2=AcceleratorMode.ON,
)

# Cap listing work so a pathological member table cannot burn the whole slice.
_MAX_MEMBERS = 10_000
# Bounded member reads — exercise codec/AES/folder decode without full extract.
_MAX_ZIP_READ_MEMBERS = 8
_MAX_MEMBER_READS = 4
_MAX_ZIP_READ_BYTES = 64 * 1024
_MAX_STREAM_READ_BYTES = 256 * 1024
# Bounded TAR member reads: the walk's data skip and sparse expansion.
_MAX_TAR_READ_MEMBERS = 8
_MAX_TAR_READ_BYTES = 64 * 1024
# Filter payloads. A BCJ2 main stream of E8 bytes is the slow case; keep it here.
_MAX_FILTER_BYTES = 64 * 1024

# Empty + common corpus password for the encrypted ZIP and 7z seeds.
_PASSWORD_CANDIDATES: list[str | bytes] = ["", "password"]


def sevenzip_header_one(data: bytes) -> None:
    # With a password, an AES-coded encoded header reaches the folder pipeline and
    # the O8 check; with none, the open stops at "Password required".
    passwords = _PasswordCandidates.from_input(_PASSWORD_CANDIDATES)
    try:
        load_sevenzip_archive(io.BytesIO(data), passwords=passwords)
    except ArchiveyError:
        return


def sevenzip_open_one(data: bytes) -> None:
    """List a 7z archive and read the first file members.

    Listing stops at the folder graph. The read is what runs the coder pipeline,
    solid demux, AES and the BCJ2 / Delta / ARM64 filters.
    """
    try:
        with open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.SEVEN_Z,
            config=_FUZZ_CONFIG,
            password=_PASSWORD_CANDIDATES,
        ) as arc:
            _sample_seekable(
                arc, max_reads=_MAX_MEMBER_READS, max_bytes=_MAX_ZIP_READ_BYTES
            )
    except ArchiveyError:
        return


def detect_format_one(data: bytes) -> None:
    from archivey.detection_cost import BALANCED_BUDGET

    # The fuzzer has no file name to give, so by default no content probe would run;
    # always_probe_content keeps the probe decoders under the fuzzer.
    # Validators run even when detection refuses the bytes: a scan that never
    # accepts the magic never calls them.
    _exercise_hit_validators(data)
    try:
        info = detect_format(
            io.BytesIO(data),
            config=ArchiveyConfig(
                detection_budget=BALANCED_BUDGET, always_probe_content=True
            ),
        )
    except ArchiveyError:
        return
    # Aggregate cost must stay inside the declared budget — pins the invariant whether
    # limits are later resolved as per-detection or per-candidate.
    if info.cost_receipt is not None:
        assert within_budget(info.cost_receipt, BALANCED_BUDGET), info.cost_receipt


def zip_open_one(data: bytes) -> None:
    """ZIP open → list a few members → bounded ``open``/``read`` (native codec/AES).

    The second open is a pipe. That selects the forward reader, which walks local
    headers and data descriptors instead of the central directory.
    """
    fixed = fixup_zip_local_and_cd_crc(data)
    _zip_seekable(fixed)
    _zip_forward(fixed)


def _zip_seekable(data: bytes) -> None:
    try:
        with open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.ZIP,
            config=_FUZZ_CONFIG,
            password=_PASSWORD_CANDIDATES,
        ) as arc:
            _sample_seekable(
                arc, max_reads=_MAX_ZIP_READ_MEMBERS, max_bytes=_MAX_ZIP_READ_BYTES
            )
    except ArchiveyError:
        return


def _zip_forward(data: bytes) -> None:
    try:
        with open_archive(
            NonSeekableBytesIO(data),
            format=ArchiveFormat.ZIP,
            streaming=True,
            config=_FUZZ_CONFIG,
            password=_PASSWORD_CANDIDATES,
        ) as arc:
            _sample_forward(
                arc, max_reads=_MAX_ZIP_READ_MEMBERS, max_bytes=_MAX_ZIP_READ_BYTES
            )
    except ArchiveyError:
        return


def tar_open_one(data: bytes) -> None:
    """List a TAR archive and read the first members' data, sparse maps included."""
    try:
        with open_archive(
            io.BytesIO(data), format=ArchiveFormat.TAR, config=_FUZZ_CONFIG
        ) as arc:
            for i, (member, stream) in enumerate(arc.stream_members()):
                if i >= _MAX_MEMBERS:
                    break
                _ = member.name
                if stream is not None and i < _MAX_TAR_READ_MEMBERS:
                    try:
                        stream.read(_MAX_TAR_READ_BYTES)
                    except ArchiveyError:
                        # A damaged member's data; keep walking.
                        continue
    except ArchiveyError:
        return


def iso_open_one(data: bytes) -> None:
    """List an ISO and read the first files. The directory walk is not the only path."""
    try:
        with open_archive(
            io.BytesIO(data), format=ArchiveFormat.ISO, config=_FUZZ_CONFIG
        ) as arc:
            _sample_seekable(
                arc, max_reads=_MAX_MEMBER_READS, max_bytes=_MAX_ZIP_READ_BYTES
            )
    except ArchiveyError:
        return


def rar_available() -> bool:
    availability = format_availability(ArchiveFormat.RAR)
    return availability.support is not FormatSupport.NONE


def unrar_available() -> bool:
    try:
        find_rarlab_unrar()
    except PackageNotInstalledError:
        return False
    return True


def rar_open_available() -> bool:
    """Open+list RAR target: backend registered and RARLAB ``unrar`` present.

    Header-only fuzz does not need ``unrar``; the open target gates on it so CI
    and local runs without RARLAB unrar skip rather than thrashing open paths
    that are only fully meaningful with the data backend available.
    """
    return rar_available() and unrar_available()


def rar_header_one(data: bytes) -> None:
    try:
        parse_rar_archive(io.BytesIO(data), max_members=_MAX_MEMBERS)
    except ArchiveyError:
        return


def rar_open_one(data: bytes) -> None:
    """List a RAR archive and read the first files through the external decoder.

    Header parse does not start ``unrar``. The read is the glue around it: solid
    copies, passwords, and whatever exception the decoder's failure becomes.
    """
    try:
        with open_archive(
            io.BytesIO(data),
            format=ArchiveFormat.RAR,
            config=_FUZZ_CONFIG,
            password=_PASSWORD_CANDIDATES,
        ) as arc:
            _sample_seekable(
                arc, max_reads=_MAX_MEMBER_READS, max_bytes=_MAX_ZIP_READ_BYTES
            )
    except ArchiveyError:
        return


def _sample_seekable(arc: ArchiveReader, *, max_reads: int, max_bytes: int) -> None:
    """List up to ``_MAX_MEMBERS`` and read the first file members."""
    reads = 0
    for i, member in enumerate(arc):
        if i >= _MAX_MEMBERS:
            break
        _ = member.name
        if reads >= max_reads or not member.is_file:
            continue
        try:
            with arc.open(member) as stream:
                _ = stream.read(max_bytes)
            reads += 1
        except ArchiveyError:
            # One damaged member does not end the listing.
            continue


def _sample_forward(
    arc: ForwardArchiveReader, *, max_reads: int, max_bytes: int
) -> None:
    """The streaming pass: members arrive with their data, and ``open`` does not exist."""
    reads = 0
    for i, (member, stream) in enumerate(arc.stream_members()):
        if i >= _MAX_MEMBERS:
            break
        _ = member.name
        if stream is None or reads >= max_reads or not member.is_file:
            continue
        try:
            stream.read(max_bytes)
        except ArchiveyError:
            pass
        reads += 1


def _exercise_hit_validators(data: bytes) -> None:
    def peek_more(n: int) -> bytes:
        return data[:n]

    known = len(data)
    for remaining in (known, None):
        validate_zip_local_header(peek_more, remaining)
        validate_rar_main_header(peek_more, remaining)
        validate_sevenzip_signature_header(peek_more, remaining)


# Containers that can be read from a pipe. 7z, RAR and ISO refuse one.
_PIPE_CONTAINERS = frozenset(
    {ContainerFormat.ZIP, ContainerFormat.TAR, ContainerFormat.RAW_STREAM}
)


def open_detected_one(data: bytes) -> None:
    """Open whatever ``detect_format`` names, then read a few members.

    Forced ``format=`` starts at byte 0, so a stub in front of an archive never
    reaches the payload. Leaving format unset is the SFX path. A compressed tar
    is also opened as the single-file stream around it: detection reports the
    tar, and that reader is a different module from the codec target.
    """
    from archivey.detection_cost import BALANCED_BUDGET

    config = ArchiveyConfig(
        detection_budget=BALANCED_BUDGET,
        always_probe_content=True,
        use_rapidgzip=AcceleratorMode.OFF,
        use_indexed_bzip2=AcceleratorMode.OFF,
        decoder_limits=_FUZZ_DECODER_LIMITS,
    )
    try:
        info = detect_format(io.BytesIO(data), config=config)
    except ArchiveyError:
        return
    container = info.format.container
    if container in (ContainerFormat.UNKNOWN, ContainerFormat.DIRECTORY):
        return
    password = (
        _PASSWORD_CANDIDATES
        if container
        in (ContainerFormat.ZIP, ContainerFormat.SEVEN_Z, ContainerFormat.RAR)
        else None
    )
    _open_sampled(io.BytesIO(data), streaming=False, config=config, password=password)
    if container in _PIPE_CONTAINERS:
        _open_sampled(
            NonSeekableBytesIO(data), streaming=True, config=config, password=password
        )
    if (
        container is ContainerFormat.TAR
        and info.format.stream is not StreamFormat.UNCOMPRESSED
    ):
        single = ArchiveFormat(ContainerFormat.RAW_STREAM, info.format.stream)
        _open_sampled(
            io.BytesIO(data),
            streaming=False,
            config=config,
            password=None,
            format=single,
        )


def _open_sampled(
    source: io.RawIOBase | io.BytesIO,
    *,
    streaming: bool,
    config: ArchiveyConfig,
    password: list[str | bytes] | None,
    format: ArchiveFormat | None = None,
) -> None:
    try:
        with open_archive(
            source,
            format=format,
            streaming=streaming,
            config=config,
            password=password,
        ) as arc:
            _sample_forward(
                arc, max_reads=_MAX_MEMBER_READS, max_bytes=_MAX_ZIP_READ_BYTES
            )
    except ArchiveyError:
        return


# liblzma branch filters whose start offset of 0 it accepts. ARM64 and RISC-V are
# separate: Python's lzma refuses those ids, and the decoders here are archivey's.
_LIBLZMA_BRANCHES = (
    lzma.FILTER_X86,
    lzma.FILTER_POWERPC,
    lzma.FILTER_IA64,
    lzma.FILTER_ARM,
    lzma.FILTER_ARMTHUMB,
    lzma.FILTER_SPARC,
)
# Byte 0 of a filter input selects one of these: BCJ2, ARM64, Delta, each liblzma
# branch, then RISC-V. ``filter_seeds`` builds one seed per value. RISC-V is last so
# the kinds before it keep the numbers existing corpora use.
_RISCV_KIND = 3 + len(_LIBLZMA_BRANCHES)
FILTER_KIND_COUNT = _RISCV_KIND + 1


def filters_one(data: bytes) -> None:
    """Run one filter decoder. Byte 0 picks which.

    A 7z mutation does not assemble a BCJ2 folder or an ARM64 or RISC-V coder, so
    those decoders stay dark unless a seed already has them. This target feeds
    them hostile payloads directly.
    """
    if not data:
        return
    kind = data[0] % FILTER_KIND_COUNT
    body = data[1:]
    try:
        if kind == 0:
            _fuzz_bcj2(body)
        elif kind == 1:
            pc = int.from_bytes(body[:4], "little") & ~3
            arm64_decode(body[4 : 4 + _MAX_FILTER_BYTES], pc)
            _fuzz_filter_stream(body[4:], {"id": FILTER_ARM64, "start_offset": pc})
        elif kind == _RISCV_KIND:
            pc = int.from_bytes(body[:4], "little") & ~1
            riscv_decode(body[4 : 4 + _MAX_FILTER_BYTES], pc)
            _fuzz_filter_stream(body[4:], {"id": FILTER_RISCV, "start_offset": pc})
        elif kind == 2:
            dist = 1 + (body[0] % 256 if body else 0)
            _fuzz_filter_stream(body[1:], {"id": lzma.FILTER_DELTA, "dist": dist})
        else:
            _fuzz_filter_stream(
                body, {"id": _LIBLZMA_BRANCHES[kind - 3], "start_offset": 0}
            )
    except ArchiveyError:
        return


def _fuzz_bcj2(body: bytes) -> None:
    if len(body) < 12:
        return
    weights = [int.from_bytes(body[i : i + 2], "little") for i in range(0, 8, 2)]
    unpack = int.from_bytes(body[8:12], "little") % (_MAX_FILTER_BYTES + 1)
    parts = _split4(body[12 : 12 + _MAX_FILTER_BYTES], weights)
    decoder = Bcj2DecoderStream(
        *(io.BytesIO(part) for part in parts), unpack_size=unpack
    )
    try:
        decoder.read(min(4096, unpack))
        if unpack and decoder.seekable():
            decoder.seek(0)
            decoder.read(128)
    finally:
        decoder.close()


def _split4(data: bytes, weights: list[int]) -> list[bytes]:
    if not data:
        return [b"", b"", b"", b""]
    usable = list(weights)
    if sum(usable) == 0:
        usable = [1, 1, 1, 1]
    total = sum(usable)
    bounds: list[int] = []
    acc = 0
    for weight in usable[:-1]:
        acc += weight
        bounds.append(len(data) * acc // total)
    parts: list[bytes] = []
    prev = 0
    for bound in bounds:
        parts.append(data[prev:bound])
        prev = bound
    parts.append(data[prev:])
    return parts


def _fuzz_filter_stream(payload: bytes, lzma_filter: dict[str, int]) -> None:
    payload = payload[:_MAX_FILTER_BYTES]
    unpack = min(len(payload) + 16, _MAX_FILTER_BYTES)
    with FilterStream(
        io.BytesIO(payload),
        lzma_filter=lzma_filter,
        unpack_size=unpack,
        seekable=True,
    ) as stream:
        got = stream.read(4096)
        if not stream.seekable():
            return
        try:
            stream.seek(0)
            stream.read(1024)
            if got:
                stream.seek(len(got) // 2)
                stream.read(1024)
        except (OSError, io.UnsupportedOperation, ArchiveyError):
            return


def iso_per_input_timeout() -> float:
    raw = os.environ.get("ARCHIVEY_FUZZ_ISO_INPUT_TIMEOUT", "2.0")
    try:
        return max(0.1, float(raw))
    except ValueError:
        return 2.0


def stream_per_input_timeout() -> float:
    """Per-input kill for hang-prone codecs (LZW / xz / bzip2, …)."""
    raw = os.environ.get("ARCHIVEY_FUZZ_STREAM_INPUT_TIMEOUT", "2.0")
    try:
        return max(0.1, float(raw))
    except ValueError:
        return 2.0


def accel_libfuzzer_args() -> list[str]:
    """libFuzzer sandbox flags for the accelerator targets.

    ``-timeout`` is a C-level alarm that kills the process even while the main thread is
    inside native code; ``-rss_limit_mb`` is checked from a libFuzzer thread. Either breach
    saves the input under the artifact prefix and fails the run.
    Env: ``ARCHIVEY_FUZZ_ACCEL_INPUT_TIMEOUT`` (whole seconds), ``ARCHIVEY_FUZZ_ACCEL_RSS_MB``.
    """
    timeout = os.environ.get("ARCHIVEY_FUZZ_ACCEL_INPUT_TIMEOUT", "10")
    rss_mb = os.environ.get("ARCHIVEY_FUZZ_ACCEL_RSS_MB", "2048")
    return [f"-timeout={int(timeout)}", f"-rss_limit_mb={int(rss_mb)}"]


def make_codec_one(codec: Codec) -> Callable[[bytes], None]:
    """Build an ``open_codec_stream`` target for ``codec`` (seekable, accelerators off)."""

    def codec_one(data: bytes) -> None:
        try:
            with open_codec_stream(
                codec, io.BytesIO(data), config=_STREAM_CONFIG
            ) as stream:
                _ = stream.read(_MAX_STREAM_READ_BYTES)
                # Hit seek-index / CLEAR paths when the backend exposes them.
                if stream.seekable():
                    try:
                        stream.seek(0)
                        _ = stream.read(min(4096, _MAX_STREAM_READ_BYTES))
                    except (OSError, io.UnsupportedOperation, ArchiveyError):
                        pass
        except ArchiveyError:
            return

    codec_one.__name__ = f"{codec.value}_one"
    codec_one.__qualname__ = f"{codec.value}_one"
    return codec_one


def _codec_available(codec: Codec) -> Callable[[], bool]:
    def _check() -> bool:
        return is_codec_available(codec)

    _check.__name__ = f"{codec.value}_available"
    return _check


# Declared-size prefix on zlib / raw DEFLATE accelerator inputs (see ``split_declared_size``).
ACCEL_SIZE_PREFIX = 4
# Bytes read after each seek in an accelerator target.
_ACCEL_SEEK_READ = 4096


def split_declared_size(data: bytes) -> tuple[int, bytes]:
    """``(declared decompressed size, compressed bytes)`` for a zlib / raw DEFLATE input.

    AUTO engages rapidgzip on zlib and raw DEFLATE only with a container-declared
    decompressed size (``StreamConfig.expected_decompressed_size``), the way a ZIP member
    or a 7z coder opens. The first four bytes (little-endian, capped at twice the read
    cap) are that declaration, so the fuzzer can make it lie.
    """
    size = int.from_bytes(data[:ACCEL_SIZE_PREFIX], "little")
    return size % (2 * _MAX_STREAM_READ_BYTES + 1), data[ACCEL_SIZE_PREFIX:]


def _drain(stream: io.IOBase, cap: int) -> tuple[bytes, ArchiveyError | None]:
    """Read up to ``cap`` bytes; return them and the typed error that stopped the read."""
    out = bytearray()
    try:
        while len(out) < cap:
            chunk = stream.read(min(64 * 1024, cap - len(out)))
            if not chunk:
                break
            out += chunk
    except ArchiveyError as exc:
        return bytes(out), exc
    return bytes(out), None


def _read_reference(
    codec: Codec, data: bytes, config: StreamConfig
) -> tuple[bytes, ArchiveyError | None]:
    """The accelerators-off decode of ``data``: the oracle for the accelerated one."""
    try:
        with open_codec_stream(codec, io.BytesIO(data), config=config) as stream:
            return _drain(stream, _MAX_STREAM_READ_BYTES)
    except ArchiveyError as exc:
        return b"", exc


def _check_against_reference(what: str, got: bytes, ref: bytes, *, at: int = 0) -> None:
    """Bytes the accelerated stream returned at ``at`` must match the reference there."""
    end = min(at + len(got), len(ref))
    if at < end and got[: end - at] != ref[at:end]:
        raise AssertionError(
            f"{what}: accelerated bytes at {at}..{end} differ from the "
            "accelerators-off decode"
        )


def _gzip_ignoring_lengths(data: bytes) -> bytes | None:
    """The content of a concatenated gzip ``data`` whose ISIZE may be wrong where the
    spec accepts that, or ``None`` when it fails on anything else, or is a single member.

    rapidgzip checks each member's CRC-32, and the spec accepts a wrong ISIZE over data
    the CRC-32 confirms in a file of several members: a malformed trailer, not damaged
    data. That is a member another member follows. The last member's is checked by the
    backstop, against the end of the output, whatever comes before it, so a wrong ISIZE
    there is never excused, nor in a file of one member, with or without padding or other
    bytes after it.
    zlib checks the CRC-32 before the length, so a member that fails only "incorrect
    length check" has its data confirmed. Fed a byte at a time so the output before that
    error is kept and the member's end is known; only called on the rare input where the
    two decodes disagree that way.
    """
    out = bytearray()
    pos = 0
    members: list[bool] = []  # whether each failed the length check
    while pos < len(data):
        if not any(data[pos:]):
            break  # zero padding after the last member, as GzipFile skips it
        decoder = zlib.decompressobj(31)
        bad_length = False
        while True:
            if pos >= len(data):
                return None  # cut inside a member
            try:
                out += decoder.decompress(data[pos : pos + 1])
            except zlib.error as exc:
                if "incorrect length check" not in str(exc):
                    return None
                pos += 1
                bad_length = True
                break
            pos += 1
            if decoder.eof:
                break
        members.append(bad_length)
    if len(members) < 2 or members[-1]:
        return None
    return bytes(out)


def make_accel_codec_one(codec: Codec, *, sized: bool) -> Callable[[bytes], None]:
    """Build a differential target for ``codec`` with its accelerator forced on.

    Contract on top of the codec targets' (typed error or success): every byte the
    accelerated stream returns, before and after seeks, matches the accelerators-off
    decode at the same offset; and the accelerated stream never reaches a clean end of
    data where the accelerators-off decode raised, which would be damaged input accepted
    silently. ``sized`` inputs carry a declared decompressed size (``split_declared_size``)
    that both decodes get.
    """

    def accel_one(data: bytes) -> None:
        on_config, off_config = _ACCEL_ON_CONFIG, _STREAM_CONFIG
        if sized:
            size, data = split_declared_size(data)
            on_config = replace(on_config, expected_decompressed_size=size)
            off_config = replace(off_config, expected_decompressed_size=size)
        ref, ref_error = _read_reference(codec, data, off_config)
        try:
            with open_codec_stream(codec, io.BytesIO(data), config=on_config) as stream:
                got, error = _drain(stream, _MAX_STREAM_READ_BYTES)
                _check_against_reference("first read", got, ref)
                if (
                    error is None
                    and ref_error is not None
                    and len(got) < _MAX_STREAM_READ_BYTES
                    and not (
                        codec is Codec.GZIP
                        and "incorrect length check" in str(ref_error)
                        and _gzip_ignoring_lengths(data) == got
                    )
                ):
                    raise AssertionError(
                        f"accelerated read ended cleanly after {len(got)} bytes; "
                        f"accelerators off raised {type(ref_error).__name__}: {ref_error}"
                    )
                if not stream.seekable():
                    return
                # Backward seeks after a read go through the accelerator's index and its
                # resume points; seek 0 through a re-arm. Positions come from the data
                # read, so the fuzzer steers them.
                for target in (len(got) // 2, 0, max(0, len(got) - 1)):
                    try:
                        stream.seek(target)
                        after = stream.read(_ACCEL_SEEK_READ)
                    except (io.UnsupportedOperation, ArchiveyError):
                        continue
                    _check_against_reference(
                        f"read after seek({target})", after, ref, at=target
                    )
        except ArchiveyError:
            return

    name = f"{codec.value}_accel_one"
    accel_one.__name__ = name
    accel_one.__qualname__ = name
    return accel_one


def accelerator_available(codec: Codec) -> Callable[[], bool]:
    """Whether ``codec``'s accelerator can run here (rapidgzip installed, child spawnable)."""

    def _check() -> bool:
        from archivey.internal.streams.codecs.bzip2_codec import _bzip2_uses_accelerator
        from archivey.internal.streams.codecs.rapidgzip_child import (
            rapidgzip_child_unavailable_reason,
        )
        from archivey.internal.streams.codecs.rapidgzip_select import (
            _deflate_family_uses_accelerator,
        )

        if codec is Codec.BZIP2:
            return _bzip2_uses_accelerator(_ACCEL_ON_CONFIG)
        return (
            _deflate_family_uses_accelerator(_ACCEL_ON_CONFIG)
            and rapidgzip_child_unavailable_reason() is None
        )

    _check.__name__ = f"{codec.value}_accel_available"
    return _check


TargetSpec = tuple[str, Callable[[bytes], None], Callable[[], list[bytes]], dict]


def iter_target_specs() -> list[dict]:
    """Descriptor dicts consumed by ``__main__`` / the CI runner."""
    stream_timeout = stream_per_input_timeout()
    specs: list[dict] = [
        {
            "name": "sevenzip_header",
            "fn": sevenzip_header_one,
            "seeds": sevenzip_seeds,
            "fixup": fixup_sevenzip_header_crcs,
            "per_input_timeout": None,
        },
        {
            "name": "sevenzip_open",
            "fn": sevenzip_open_one,
            "seeds": sevenzip_seeds,
            "fixup": fixup_sevenzip_header_crcs,
            # Member decode (LZMA, BCJ2) can spin. The header target has no read.
            "per_input_timeout": stream_timeout,
        },
        {
            "name": "detect_format",
            "fn": detect_format_one,
            "seeds": detect_format_seeds,
            "fixup": None,
            "per_input_timeout": None,
        },
        {
            "name": "zip",
            "fn": zip_open_one,
            "seeds": zip_seeds,
            "fixup": None,  # CRC fixup applied inside zip_open_one
            # Seekable and pipe opens both decode members. A spin there has to
            # die inside the slice, the same as the other read targets.
            "per_input_timeout": stream_timeout,
        },
        {
            "name": "tar",
            "fn": tar_open_one,
            "seeds": tar_seeds,
            "fixup": fixup_tar_header_checksums,
            "per_input_timeout": stream_timeout,
        },
        {
            "name": "iso",
            "fn": iso_open_one,
            "seeds": iso_seeds,
            "fixup": None,
            "per_input_timeout": iso_per_input_timeout(),
        },
        {
            "name": "rar_header",
            "fn": rar_header_one,
            "seeds": rar_seeds,
            "fixup": fixup_rar_header_crcs,
            "per_input_timeout": None,
            "skip_unless": rar_available,
        },
        {
            "name": "rar",
            "fn": rar_open_one,
            "seeds": rar_seeds,
            "fixup": fixup_rar_header_crcs,
            # unrar on a mutated solid archive is the hang class here.
            "per_input_timeout": stream_timeout,
            "skip_unless": rar_open_available,
        },
        {
            "name": "open_detected",
            "fn": open_detected_one,
            "seeds": open_detected_seeds,
            "fixup": None,
            "per_input_timeout": stream_timeout,
        },
        {
            "name": "filters",
            "fn": filters_one,
            "seeds": filter_seeds,
            "fixup": None,
            "per_input_timeout": stream_timeout,
        },
    ]

    # Required standalone stream/codec targets (always registered).
    required_streams: list[tuple[str, Codec, Callable[[], list[bytes]]]] = [
        ("unix_compress", Codec.UNIX_COMPRESS, unix_compress_seeds),
        ("xz", Codec.XZ, xz_seeds),
        ("lzip", Codec.LZIP, lzip_seeds),
        ("gzip", Codec.GZIP, gzip_seeds),
        ("bzip2", Codec.BZIP2, bzip2_seeds),
        ("lzma_alone", Codec.LZMA_ALONE, lzma_alone_seeds),
        ("zlib", Codec.ZLIB, zlib_seeds),
    ]
    for name, codec, seeds_fn in required_streams:
        specs.append(
            {
                "name": name,
                "fn": make_codec_one(codec),
                "seeds": seeds_fn,
                "fixup": None,
                "per_input_timeout": stream_timeout,
            }
        )

    # Optional extras — skip-clean when the backend is absent.
    optional_streams: list[tuple[str, Codec, Callable[[], list[bytes]]]] = [
        ("zstd", Codec.ZSTD, zstd_seeds),
        ("brotli", Codec.BROTLI, brotli_seeds),
        ("lz4", Codec.LZ4, lz4_seeds),
        ("deflate64", Codec.DEFLATE64, deflate64_seeds),
    ]
    for name, codec, seeds_fn in optional_streams:
        specs.append(
            {
                "name": name,
                "fn": make_codec_one(codec),
                "seeds": seeds_fn,
                "fixup": None,
                "per_input_timeout": stream_timeout,
                "skip_unless": _codec_available(codec),
            }
        )

    # Accelerator differential targets. A native busy loop or a runaway allocation in the
    # accelerator is out of reach of a Python alarm, so these use libFuzzer's own per-input
    # timeout and RSS cap (signal-level, and the run fails with the input saved); the
    # gzip-family decoder runs in a child process, the bzip2 one in this process.
    accel_streams: list[tuple[str, Codec, Callable[[], list[bytes]], bool]] = [
        ("gzip_accel", Codec.GZIP, accel_gzip_seeds, False),
        ("zlib_accel", Codec.ZLIB, accel_zlib_seeds, True),
        ("deflate_accel", Codec.DEFLATE, accel_deflate_seeds, True),
        ("bzip2_accel", Codec.BZIP2, accel_bzip2_seeds, False),
    ]
    for name, codec, seeds_fn, sized in accel_streams:
        specs.append(
            {
                "name": name,
                "fn": make_accel_codec_one(codec, sized=sized),
                "seeds": seeds_fn,
                "fixup": None,
                "per_input_timeout": None,
                "libfuzzer_args": accel_libfuzzer_args(),
                "skip_unless": accelerator_available(codec),
            }
        )

    return specs
