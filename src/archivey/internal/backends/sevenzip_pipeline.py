"""7z folder decode pipeline — registry-driven trees of linear coder chains.

A *folder* is a coder graph over one or more packed streams. This module accepts a
**tree of linear chains**: every coder has one output, every coder but BCJ2 has one
input, and each input is either a pack stream or bound to one coder's output. A plain
folder is a single chain over pack stream 0; a BCJ2 folder is a BCJ2 coder fed by four
chains, one per pack stream.

Decode order within a chain (packed → unpacked)::

    AES? → (COPY skipped) → SINGLE codecs | LZMA-family run

``MethodKind.LZMA_FAMILY`` means “participates in a liblzma / BCJ staging run”,
not “is LZMA”: Delta and BCJ are batched with LZMA1/2 here.

- LZMA2 then Delta/BCJ (decode order) → one stdlib ``lzma`` raw filter chain, except
  ARM64 and RISC-V: stdlib ``lzma`` will not build them, so such a filter and every
  filter decoded after it in the run are each their own stage
- LZMA1 then Delta → one capped chain; a BCJ after LZMA1 is its own stage
  (BPO-21872 truncation)
- A Delta/BCJ decoded before any LZMA1/LZMA2 → one filter stage per coder (a liblzma
  raw chain must end in LZMA1/LZMA2 in encode order, so that codec decodes first)
- Several LZMA1/LZMA2 coders in one run → one chain each
- BCJ2 (``0x0303011B``) → the source of its chain: four branch chains, each capped at
  its declared size, feed :class:`~archivey.internal.streams.codecs.bcj2_filter.Bcj2DecoderStream`

Two phases: :func:`plan_folder` resolves stages (pure — no I/O); then
:func:`open_folder_pipeline` / :func:`_execute_stage` fold stages onto the packed
sources. Encoded-header decode also lives here (parser stays structure-only); the
archive-open flow that uses it is ``load_sevenzip_archive`` in ``sevenzip_reader``.
The encoded header stays linear-only: no writer puts BCJ2 there.
"""

from __future__ import annotations

import io
import lzma
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    EncryptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.sevenzip_aes import SevenZipKeyCache
from archivey.internal.backends.sevenzip_methods import (
    METHOD_DELTA,
    METHOD_LZMA,
    METHOD_LZMA2,
    MethodKind,
    _method_hex,
    is_bcj,
    is_lzma_family,
    lookup,
    require,
)
from archivey.internal.backends.sevenzip_parser import (
    MAX_NEXT_HEADER_SIZE,
    EncodedHeader,
    FolderGraph,
    SevenZipCoder,
    SevenZipFolder,
    check_bind_pairs,
    check_packed_indices,
    encoded_header_slice,
    folder_is_encrypted,
)
from archivey.internal.config import (
    DEFAULT_STREAM_CONFIG,
    StreamConfig,
    check_decoder_memory,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.codecs import (
    LZMA_DICTIONARY_FILTERS,
    Codec,
    CodecParams,
    decode_lzma_filter_properties,
    open_codec_stream,
    parse_ppmd_var_h_properties,
)
from archivey.internal.streams.codecs.arm64_filter import FILTER_ARM64
from archivey.internal.streams.codecs.bcj2_filter import Bcj2DecoderStream
from archivey.internal.streams.codecs.isolated import IN_PROCESS, natives_for
from archivey.internal.streams.codecs.lzma_filter_decoder import FilterStream
from archivey.internal.streams.codecs.riscv_filter import FILTER_RISCV
from archivey.internal.streams.codecs.zstd_framing import (
    MAX_FRAME_HEADER_SIZE,
    frame_window_size,
)
from archivey.internal.streams.crypto import open_aes_decrypt_stream
from archivey.internal.streams.decompressor_stream import DataAfterEndError
from archivey.internal.streams.resume import ask_resume_offset
from archivey.internal.streams.streamtools import SlicingStream, read_exact
from archivey.internal.streams.streamtools.base import DelegatingStream
from archivey.internal.streams.streamtools.binaryio import (
    read_blocking,
    readinto_via_read,
    try_readinto,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

# The most filters one liblzma chain holds (``LZMA_FILTERS_MAX`` in lzma/filter.h).
_LIBLZMA_MAX_FILTERS = 4


# A folder's coder chain is decoded in two phases: `plan_folder` resolves it into an
# ordered list of these concrete stages (pure — no streams opened), then
# `_execute_stage` / `open_folder_pipeline` fold each stage onto the packed source.
# Keeping the branchy LZMA1+BCJ staging in the planner makes the decode flow
# inspectable and keeps I/O out of the decision.


@dataclass
class _AesStage:
    """AES-256 decryption of the stream."""

    coder: SevenZipCoder


@dataclass
class _CodecStage:
    """A single self-contained codec (Deflate, BZip2, Zstd, PPMd, …).

    ``unpack_size`` is the coder's output length from the folder header. It is passed
    through for codecs that need a bound (PPMd7 has no end mark). The codecs in
    :data:`_CODEC_LABELS` end their own stream, so their output is checked against
    this size instead (:class:`_DecodedPastSizeCheck`).

    ``pack_size`` is the coder's *input* length — the output of the preceding coder in
    its chain, or a BCJ2 source's declared output (``None`` when this coder consumes
    the packed slice directly, whose length ``open_codec_stream`` recovers from the
    sized source). The codec's input is cut at it, as 7-Zip reads it: a byte of
    that span the codec leaves after its end is refused (``StreamConfig.refuse_input_after_end``),
    and an AES stage's block padding, past the span, is not in it. PPMd also uses it
    to gate post-eof recovery on full pack delivery, and the rapidgzip accelerators
    to bound their own input.
    """

    codec: Codec
    properties: bytes | None
    unpack_size: int | None = None
    pack_size: int | None = None


@dataclass
class _LzmaChainStage:
    """One liblzma raw-filter chain (LZMA1/LZMA2 with any Delta/BCJ filters).

    ``cap_size`` bounds the decoded output (the codec's ``unpack_size``); it is set
    for every LZMA1 chain, because 7-Zip writes LZMA1 without an end marker and a
    reader past the declared size (a BCJ look-ahead, BPO-21872, or a following codec)
    would otherwise ask for input that is not there. ``None`` means no cap. The
    following ``_FilterStage`` must close the capped stream (``owns_inner=True``) —
    DecompressorStream does not close a passed-in stream by default. The capped
    output is checked too (:class:`_DecodedPastSizeCheck`): its read past the size
    is where the codec reports input left after the stream's end.

    ``end_check_size`` is set for an LZMA2 chain instead: the declared output size,
    past which a decoded byte is corruption (:class:`_DecodedPastSizeCheck`).

    ``pack_size`` is the chain's input length, as for :class:`_CodecStage`: the codec
    reads no further, so AES padding is outside the span in which input after an end
    marker is corruption.
    """

    codec: Codec
    filters: list[dict]
    cap_size: int | None
    end_check_size: int | None = None
    pack_size: int | None = None


@dataclass
class _FilterStage:
    """One filter-only coder staged on its own, outside any liblzma chain: a BCJ after
    LZMA1, a Delta/BCJ decoded before any LZMA1/LZMA2 in its run or past liblzma's
    filter limit, or ARM64 / RISC-V and any filter decoded after it.

    ``lzma_filter`` is the liblzma filter dict with its options (BCJ
    ``start_offset``, Delta ``dist``). :class:`FilterStream` picks the decoder by
    filter id: ``PythonBranchFilterDecoder`` decodes ARM64 and RISC-V in Python, and
    ``FilterDecoder`` runs every other filter through liblzma over its own LZMA2
    framing.
    """

    lzma_filter: dict
    unpack_size: int


@dataclass
class _CopyStage:
    """A COPY coder reading a pack stream: output past its declared size is refused.

    A COPY coder anywhere else passes its input through unchanged, and needs no stage:
    the planner has already checked that its size equals its input coder's.
    """

    unpack_size: int


_Stage = _AesStage | _CodecStage | _LzmaChainStage | _FilterStage | _CopyStage


@dataclass
class _Bcj2Stage:
    """A BCJ2 coder: the source of a chain, fed by four chains of its own.

    ``branches`` are ``main``, ``call``, ``jump`` and ``rc``, in the coder's input order.
    """

    branches: list[_Chain]
    unpack_size: int


@dataclass
class _Chain:
    """Linear stages over one source: a pack stream, or a BCJ2 coder's output.

    ``source`` is the pack stream's position in the folder's ``packed_indices``
    (0 for a linear folder), or the :class:`_Bcj2Stage` whose output the stages read.
    ``stages`` are in decode order.
    """

    source: int | _Bcj2Stage
    stages: list[_Stage]
    # The declared size of the chain's output: its top coder's unpack size. ``None``
    # for a bare pack stream, whose view is already sized.
    unpack_size: int | None = None

    def has_bcj2(self) -> bool:
        return isinstance(self.source, _Bcj2Stage)

    def pack_count(self) -> int:
        """How many pack streams this chain reads, counting every BCJ2 branch."""
        if isinstance(self.source, _Bcj2Stage):
            return sum(branch.pack_count() for branch in self.source.branches)
        return 1


def plan_folder(folder: SevenZipFolder) -> _Chain:
    """Resolve a folder's coder graph into decode stages, opening no streams.

    The graph must be a tree of linear chains. Every coder has one output; the only
    coder with more than one input is BCJ2, with four. Each input is either a pack
    stream or bound to exactly one coder's output. The root is the coder whose output
    no bind pair consumes, and the plan is read from the root down (design D1 of the
    ``sevenzip-bcj2-decode`` change).

    A graph that cannot be a valid folder (no coders, a coder with no input or no
    output, a cycle, an input that is neither packed nor bound) is
    :class:`CorruptionError`. A valid shape this planner does not run (a
    coder with several outputs, a multi-input coder other than BCJ2) is
    :class:`UnsupportedFeatureError`. A linear folder plans to one chain over pack
    stream 0, as it always has.
    """
    coders = folder.coders
    if not coders:
        raise CorruptionError("7z folder has no coders")
    for coder in coders:
        if coder.num_out_streams == 0:
            raise CorruptionError(
                f"7z coder {_method_hex(coder.method)} has no out-stream"
            )
        if coder.num_in_streams == 0:
            raise CorruptionError(
                f"7z coder {_method_hex(coder.method)} has no in-stream"
            )
        if coder.num_out_streams != 1:
            raise UnsupportedFeatureError(
                "7z folders with multi-output coders are not supported"
            )
        method = lookup(coder.method)
        is_bcj2 = method is not None and method.kind is MethodKind.BCJ2
        if coder.num_in_streams != 1 and not (is_bcj2 and coder.num_in_streams == 4):
            raise UnsupportedFeatureError(
                f"7z coder {_method_hex(coder.method)} with "
                f"{coder.num_in_streams} inputs is not supported"
            )
    # The two checks leave every in-stream either bound to a coder's output (so
    # ``graph.producer`` names that coder) or packed: an in-stream with no producer
    # is in ``packed_indices``, which the two ``.index`` calls below rely on.
    graph = FolderGraph.of(folder)
    check_bind_pairs(folder.bind_pairs, graph.total_in, graph.total_out)
    check_packed_indices(folder.packed_indices, set(graph.bound), graph.total_in)
    roots = graph.roots()
    if not roots:
        raise CorruptionError("7z folder coder graph has a cycle and no output")
    if len(roots) > 1:
        raise UnsupportedFeatureError(
            "7z folders with several outputs are not supported"
        )
    if len(folder.unpack_sizes) < len(coders):
        raise CorruptionError("7z folder has fewer unpack sizes than coders")

    visited: set[int] = set()

    def input_chain(in_index: int) -> _Chain:
        producer = graph.producer(in_index)
        if producer is not None:
            return chain_ending_at(producer)
        return _Chain(folder.packed_indices.index(in_index), [])

    def chain_ending_at(top: int) -> _Chain:
        run: list[int] = []  # top first; reversed into decode order below
        coder_index = top
        while True:
            if coder_index in visited:
                raise CorruptionError("7z folder coder graph has a cycle")
            visited.add(coder_index)
            # Four inputs means BCJ2: the check at the top refused every other coder
            # with more than one input. Relaxing that check must change this test too.
            if coders[coder_index].num_in_streams == 4:
                source: int | _Bcj2Stage = _Bcj2Stage(
                    [input_chain(in_index) for in_index in graph.inputs[coder_index]],
                    folder.unpack_sizes[coder_index],
                )
                break
            run.append(coder_index)
            (in_index,) = graph.inputs[coder_index]
            producer = graph.producer(in_index)
            if producer is None:
                source = folder.packed_indices.index(in_index)
                break
            coder_index = producer
        run.reverse()
        return _Chain(source, _plan_run(folder, run, source), folder.unpack_sizes[top])

    chain = chain_ending_at(roots[0])
    if len(visited) != len(coders):
        # Every output but the root's is bound, so a coder the root never reaches
        # feeds a loop of coders.
        raise CorruptionError("7z folder coder graph has a cycle")
    return chain


def _plan_run(
    folder: SevenZipFolder, run: list[int], source: int | _Bcj2Stage
) -> list[_Stage]:
    """Plan one linear run of 1-in coders, given as coder indices in decode order.

    "The preceding coder" is the previous coder *in this run*, not in the folder's
    coder list: in a BCJ2 folder the previous coder in the list is usually a sibling
    branch's. The first coder's input is the source: a pack stream, whose length the
    sized view carries, or a BCJ2 stage, whose output size the folder declares.
    """
    coders = folder.coders
    source_size = source.unpack_size if isinstance(source, _Bcj2Stage) else None
    _check_size_preserving_coders(folder, run, source_size)
    stages: list[_Stage] = []
    position = 0
    while position < len(run):
        index = run[position]
        method = require(coders[index].method)
        if method.kind is MethodKind.COPY:
            if position == 0 and source_size is None:
                # Over a pack stream, whose length the folder does not carry: the
                # check is on the output, as for a codec.
                stages.append(_CopyStage(folder.unpack_sizes[index]))
            position += 1
            continue
        if method.kind is MethodKind.BCJ2:
            # Only reachable with a BCJ2 coder declared with one input.
            raise UnsupportedFeatureError("7z BCJ2 coder must have four inputs")
        if method.kind is MethodKind.AES:
            stages.append(_AesStage(coders[index]))
            position += 1
            continue
        if method.kind is MethodKind.SINGLE:
            assert method.codec is not None
            input_size = (
                folder.unpack_sizes[run[position - 1]] if position > 0 else source_size
            )
            stages.append(
                _CodecStage(
                    method.codec,
                    coders[index].properties,
                    unpack_size=folder.unpack_sizes[index],
                    pack_size=input_size,
                )
            )
            position += 1
            continue
        # LZMA_FAMILY (LZMA1/LZMA2/Delta/BCJ): batch the contiguous run, then plan it.
        run_input_size = (
            folder.unpack_sizes[run[position - 1]] if position > 0 else source_size
        )
        lzma_run: list[SevenZipCoder] = []
        sizes: list[int] = []
        while position < len(run) and is_lzma_family(coders[run[position]].method):
            lzma_run.append(coders[run[position]])
            sizes.append(folder.unpack_sizes[run[position]])
            position += 1
        stages.extend(_plan_lzma_family(lzma_run, sizes, run_input_size))
    return stages


def _check_size_preserving_coders(
    folder: SevenZipFolder, run: list[int], source_size: int | None
) -> None:
    """Refuse a COPY, Delta or BCJ coder whose size differs from its input's.

    These coders output exactly as many bytes as they read, so in a valid folder each
    one's unpack size equals its input's: the preceding coder's unpack size, or a BCJ2
    source's. (An AES coder declares its output without the block padding, so this
    holds after AES too.) 7-Zip decodes every coder to its own size and reports a
    mismatch as a data error. Without this check a filter's size would go unchecked
    inside a liblzma chain, whose output is checked only at the chain's last size: an
    LZMA2 coder could decode past its own size in front of a Delta that declares more.
    A coder over a pack stream has no declared input size here; a COPY there gets a
    :class:`_CopyStage`.
    """
    for position, index in enumerate(run):
        coder = folder.coders[index]
        method = require(coder.method)
        if method.kind is not MethodKind.COPY and not method.is_filter:
            continue
        input_size = (
            folder.unpack_sizes[run[position - 1]] if position > 0 else source_size
        )
        if input_size is not None and input_size != folder.unpack_sizes[index]:
            raise CorruptionError(
                f"7z coder {_method_hex(coder.method)} declares "
                f"{folder.unpack_sizes[index]} bytes of output from "
                f"{input_size} bytes of input"
            )


def _is_lzma_codec(coder: SevenZipCoder) -> bool:
    method = lookup(coder.method)
    return method is METHOD_LZMA or method is METHOD_LZMA2


def _in_liblzma_chain(coder: SevenZipCoder) -> bool:
    method = lookup(coder.method)
    return method is not None and method.in_liblzma_chain


def _plan_lzma_family(
    run: list[SevenZipCoder], unpack_sizes: list[int], input_size: int | None = None
) -> list[_Stage]:
    """Plan a run of LZMA1/LZMA2/Delta/BCJ coders, given in decode order.

    A liblzma raw chain is written in encode order and must end in its one LZMA1 or
    LZMA2 filter, so in decode order that codec comes first and only filters follow
    it. The run is therefore cut into segments, each an LZMA1/LZMA2 coder and the
    filters decoded after it, up to liblzma's filter limit. A filter decoded before
    any codec of its segment (``7z a -m0=LZMA2 -m1=BCJ`` stores BCJ first in decode
    order), or past the limit, runs as its own stage. So does a filter Python's
    ``lzma`` will not build (ARM64, RISC-V), and every filter decoded after it in its
    segment.

    ``input_size`` is the run's input length (``None`` over a pack stream); each
    chain's input is the output of the coder before it.
    """
    if len(run) != len(unpack_sizes):
        raise CorruptionError("7z LZMA-family run length does not match unpack sizes")
    stages: list[_Stage] = []
    index = 0
    while index < len(run):
        if not _is_lzma_codec(run[index]):
            # liblzma will not build a raw chain without an LZMA1/LZMA2 terminator.
            stages.append(_filter_stage(run[index], unpack_sizes[index]))
            index += 1
            continue
        end = index + 1
        while (
            end < len(run)
            and end - index < _LIBLZMA_MAX_FILTERS
            and not _is_lzma_codec(run[end])
            and _in_liblzma_chain(run[end])
        ):
            end += 1
        if lookup(run[index].method) is METHOD_LZMA:
            # liblzma can silently truncate BCJ look-ahead when LZMA1 lacks EOS
            # (BPO-21872). The LZMA1 chain stops before the first BCJ, and is capped
            # at its declared output size: 7-Zip writes LZMA1 without an end marker,
            # so reading past that size would ask for input that is not there. Each
            # BCJ, and each filter after one, runs as its own stage. The filters are
            # size-preserving and checked against the codec's size by the planner,
            # so the chain's last size is the LZMA1 coder's own.
            chain_end = index + 1
            while chain_end < end and not is_bcj(run[chain_end].method):
                chain_end += 1
            stages.append(
                _lzma_chain_stage(
                    run[index:chain_end],
                    cap_size=unpack_sizes[chain_end - 1],
                    pack_size=unpack_sizes[index - 1] if index > 0 else input_size,
                )
            )
            stages.extend(
                _filter_stage(coder, size)
                for coder, size in zip(
                    run[chain_end:end], unpack_sizes[chain_end:end], strict=True
                )
            )
        else:
            # LZMA2 ± Delta ± BCJ: one chain. LZMA2 has an end marker, so it is not
            # capped; its declared size is checked against what it decodes instead.
            # As above, the chain's last size is the LZMA2 coder's own.
            stages.append(
                _lzma_chain_stage(
                    run[index:end],
                    cap_size=None,
                    end_check_size=unpack_sizes[end - 1],
                    pack_size=unpack_sizes[index - 1] if index > 0 else input_size,
                )
            )
        index = end
    return stages


def _decode_lzma_properties(coder: SevenZipCoder, filter_id: int) -> dict:
    if coder.properties is None:
        return {"id": filter_id}
    return decode_lzma_filter_properties(
        filter_id, coder.properties, what=f"7z LZMA coder {_method_hex(coder.method)}"
    )


def _lzma_filter(coder: SevenZipCoder) -> dict:
    method = require(coder.method)
    if method is METHOD_LZMA or method is METHOD_LZMA2:
        assert method.lzma_filter_id is not None
        return _decode_lzma_properties(coder, method.lzma_filter_id)
    if method is METHOD_DELTA:
        if coder.properties is None:
            return {"id": lzma.FILTER_DELTA}
        if len(coder.properties) != 1:
            raise CorruptionError("Malformed 7z Delta coder properties")
        return {"id": lzma.FILTER_DELTA, "dist": coder.properties[0] + 1}
    if method.lzma_filter_id is not None and method.is_branch_filter:
        return _bcj_filter(coder, method.lzma_filter_id)
    raise UnsupportedFeatureError(
        f"Unsupported 7z LZMA-family coder {_method_hex(coder.method)}"
    )


# The start-offset alignment 7-Zip requires of the branch filters decoded in Python:
# its ``REGISTER_FILTER_E_BRANCH`` alignment masks (3 for ARM64, 1 for RISC-V) plus one.
_PYTHON_FILTER_ALIGNMENT = {FILTER_ARM64: 4, FILTER_RISCV: 2}


def _bcj_filter(coder: SevenZipCoder, filter_id: int) -> dict:
    """liblzma dict for a 7z BCJ coder, carrying its start offset when it has one.

    7z BCJ properties are absent or a 4-byte little-endian start offset. Writers
    almost always omit it or write zero; a non-zero value shifts the addresses the
    filter converts, so dropping it would decode a well-formed archive wrongly.

    The property is read as liblzma's ``start_offset`` (7-Zip's branch coders seed
    their position from it the same way liblzma seeds ``now_pos``). For the filters
    liblzma decodes, that equivalence is from reading both sources: the 7-Zip CLI
    cannot write a non-zero offset for them, so no 7-Zip-written archive checks it,
    and the tests encode their fixtures with liblzma. ARM64 and RISC-V are the
    exceptions: ``7z a -m0=ARM64:<n>`` and ``-m0=RISCV:<n>`` write an offset, and
    ``tests/test_sevenzip_arm64.py`` and ``tests/test_sevenzip_riscv.py`` check it
    against the bytes 7-Zip stores.
    """
    if not coder.properties:
        return {"id": filter_id}
    if len(coder.properties) != 4:
        raise CorruptionError(
            f"Malformed 7z BCJ coder properties for {_method_hex(coder.method)}"
        )
    start_offset = int.from_bytes(coder.properties, "little")
    if start_offset == 0:
        return {"id": filter_id}
    lzma_filter = {"id": filter_id, "start_offset": start_offset}
    alignment = _PYTHON_FILTER_ALIGNMENT.get(filter_id)
    if alignment is not None:
        # Decoded in Python (Python's lzma refuses the id). 7-Zip refuses an offset
        # that is not a multiple of the instruction alignment (E_NOTIMPL), and so
        # does liblzma.
        if start_offset % alignment:
            raise _unsupported_start_offset(
                coder, start_offset, f"it must be a multiple of {alignment}"
            )
        return lzma_filter
    try:
        # liblzma rejects an offset the architecture's alignment forbids (ARM needs
        # 4, IA64 16); find that at plan time, not on the first read. This only
        # builds the filter and decodes nothing, so it stays in this process under
        # every ``process_isolation``.
        IN_PROCESS.lzma_decompressor(
            lzma.FORMAT_RAW, filters=[lzma_filter, {"id": lzma.FILTER_LZMA2}]
        )
    except lzma.LZMAError:
        raise _unsupported_start_offset(
            coder, start_offset, "liblzma refuses it for this filter"
        ) from None
    return lzma_filter


def _unsupported_start_offset(
    coder: SevenZipCoder, start_offset: int, reason: str
) -> UnsupportedFeatureError:
    return UnsupportedFeatureError(
        f"7z BCJ coder {_method_hex(coder.method)} start offset {start_offset} "
        f"is not supported: {reason}"
    )


def _open_aes_stage(
    source: BinaryIO,
    coder: SevenZipCoder,
    *,
    password: bytes | None,
    key_cache: SevenZipKeyCache,
) -> BinaryIO:
    if password is None:
        raise EncryptionError("Password required to decrypt this 7z folder")
    if coder.properties is None:
        raise CorruptionError("7z AES coder is missing properties")
    try:
        params = key_cache.aes_params_from_properties(password, coder.properties)
    except ValueError as exc:
        raise CorruptionError(f"Malformed 7z AES properties: {exc}") from exc
    return open_aes_decrypt_stream(source, params)


def _filter_stage(coder: SevenZipCoder, unpack_size: int) -> _FilterStage:
    method = require(coder.method)
    if not method.is_filter:
        raise UnsupportedFeatureError(
            f"Unsupported 7z filter-only coder {_method_hex(coder.method)}"
        )
    return _FilterStage(_lzma_filter(coder), unpack_size)


def _lzma_chain_stage(
    run: list[SevenZipCoder],
    *,
    cap_size: int | None,
    end_check_size: int | None = None,
    pack_size: int | None = None,
) -> _LzmaChainStage:
    has_lzma1 = any(lookup(c.method) is METHOD_LZMA for c in run)
    has_lzma2 = any(lookup(c.method) is METHOD_LZMA2 for c in run)
    if not has_lzma1 and not has_lzma2:
        # liblzma's FORMAT_RAW needs the chain to end in LZMA1/LZMA2; a filter-only
        # chain fails two layers down as "Invalid or unsupported options". The
        # planner routes filter-only runs to _FilterStage, so this is a planner bug.
        raise UnsupportedFeatureError(
            "7z filter-only coder run cannot be a liblzma chain: "
            + ", ".join(_method_hex(c.method) for c in run)
        )
    # Decode order is outer-first; liblzma wants encode order → reversed(run).
    filters = [_lzma_filter(coder) for coder in reversed(run)]
    codec = Codec.LZMA if has_lzma1 and not has_lzma2 else Codec.LZMA2
    return _LzmaChainStage(codec, filters, cap_size, end_check_size, pack_size)


# The codecs whose output _DecodedPastSizeCheck checks, with 7-Zip's name for each.
# This is an allowlist. Most codecs here end their own stream, so output past the
# declared size is surplus and not data. LZMA1 and PPMd stop at the declared size
# themselves and check there that their input ends too; the check's one read past the
# size is what reaches that verdict (:class:`DataAfterEndError`), since every reader
# above stops at the size. A codec that relied on the declared size to stop and did
# not stop there itself would fail valid archives here.
_CODEC_LABELS = {
    Codec.LZMA: "LZMA",
    Codec.PPMD: "PPMD",
    Codec.LZMA2: "LZMA2",
    Codec.DEFLATE: "Deflate",
    Codec.DEFLATE64: "Deflate64",
    Codec.BZIP2: "BZip2",
    Codec.ZSTD: "Zstd",
    Codec.LZ4: "LZ4",
    Codec.BROTLI: "Brotli",
}


class _DecodedPastSizeCheck(DelegatingStream):
    """Refuse a coder that decodes more than its declared unpack size.

    It wraps the output of every codec in :data:`_CODEC_LABELS`: an LZMA1 or LZMA2
    chain, and PPMd, Deflate, Deflate64, BZip2, Zstd, LZ4 and Brotli. LZMA1 and PPMd
    have no end marker in 7z, so they stop at their size themselves and decode
    nothing past it; for them the read past the size finds only whether their input
    ended there too (:class:`DataAfterEndError`).
    It also wraps a COPY coder that reads a pack stream (:class:`_CopyStage`): pack
    bytes past the COPY coder's size would otherwise reach the coder after it.

    Every reader above this one stops at the declared size (the member slice, a BCJ2
    branch slice, the filter after the codec), so surplus output would otherwise pass
    unseen. 7-Zip reports such a folder as a data error. When the output reaches the
    declared size, this reads **one** more byte of output from the decoder. Only
    decoded bytes count, so a further stream in the same coder (a second BZip2
    stream, a second Zstd or LZ4 frame) is surplus when it decodes to one byte or
    more.

    The probe is one read of output, not a second decode, but its input cost is not
    one read. To produce that byte, the decoder consumes as much input as it needs,
    up to the end of the coder's packed slice: a tail of streams that decode to
    nothing is read to its end. That cost is linear in the archive's own size, the
    same bound as decoding the folder, so it is accepted rather than bounded here.
    Bounding it would need a counter on the codec's input, outside this wrapper.

    AES padding in the codec's input is not output, so it is never surplus: every
    codec reads only its ``pack_size`` span, which excludes the pad. So a decoder
    error on the probe read is not surplus output either, with one exception: input
    left in the coder's span after its stream's end (:class:`DataAfterEndError`),
    which 7-Zip reports as a data error, for every codec. Discarding the other
    errors is safe because every codec wrapped here verifies its data
    before or together with delivering it (the BZip2 block CRC, the Zstd and LZ4
    content checksums), so a failed check of the declared data raises on the read
    that delivers that data, before the probe: only input after the stream reaches
    the probe read. A codec that verifies only after
    its last byte must not be added to :data:`_CODEC_LABELS` without revisiting this.
    """

    def __init__(self, inner: BinaryIO, *, size: int, label: str) -> None:
        super().__init__(inner)
        self._size = size
        self._label = label
        self._position = 0
        self._checked = False

    def read(self, n: int = -1, /) -> bytes:
        if n == 0:
            return b""
        data = read_blocking(self._inner, n)
        self._count(len(data))
        return data

    def readinto(self, b: WriteableBuffer, /) -> int:
        n = try_readinto(self._inner, b)
        if n is None:
            return readinto_via_read(self, b)  # read() counts
        self._count(n)
        return n

    def _count(self, n: int) -> None:
        self._position += n
        if self._position > self._size:
            self._raise_surplus()
        if self._position == self._size and not self._checked:
            self._checked = True
            try:
                surplus = self._inner.read(1)
            except DataAfterEndError:
                # Input after the stream's end inside the coder's span: 7-Zip's
                # data error. The span excludes AES padding (``pack_size``).
                raise
            except (ArchiveyError, lzma.LZMAError, EOFError):
                surplus = b""
            if surplus:
                self._raise_surplus()

    def _raise_surplus(self) -> None:
        raise CorruptionError(
            f"7z {self._label} coder decodes past its declared unpack size of "
            f"{self._size} bytes"
        )

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        self._position = self._inner.seek(offset, whence)
        self._checked = False
        return self._position

    def nearest_resume_offset(self, target: int) -> int | None:
        return ask_resume_offset(self._inner, target)


def _execute_stage(
    stream: BinaryIO,
    stage: _Stage,
    *,
    password: bytes | None,
    key_cache: SevenZipKeyCache,
    stream_config: StreamConfig,
    collector: DiagnosticCollector | None,
    seekable: bool,
    owns_input: bool,
) -> BinaryIO:
    """Open one planned stage on top of ``stream``. The only stream-opening code.

    ``owns_input`` is consumed only by ``_FilterStage`` (``owns_inner``): True when
    ``stream`` is a private earlier output rather than a borrowed pack view. Other
    stages ignore it: the raw LZMA decoder stream does not close a passed-in
    fileobj, so ``[AES, LZMA]`` still leaves the AES decrypt stream to GC.
    ``AesDecryptStream`` borrows the pack view (``owns_inner`` default).
    """
    if isinstance(stage, _AesStage):
        return _open_aes_stage(
            stream, stage.coder, password=password, key_cache=key_cache
        )
    if isinstance(stage, _CodecStage):
        if stage.pack_size is not None:
            # The coder's input span, which excludes an AES stage's padding. The slice
            # does not clamp to its source's size: a short source raises its own error.
            stream = SlicingStream(
                stream,
                length=stage.pack_size,
                owns_inner=False,
                probe_source_size=False,
            )
        decoded = open_codec_stream(
            stage.codec,
            stream,
            config=stream_config,
            params=CodecParams(
                properties=stage.properties,
                unpack_size=stage.unpack_size,
                pack_size=stage.pack_size,
                # A bzip2 coder's data is one stream, as 7-Zip reads it: it ends at
                # its first end-of-stream marker. No other codec stage reads the
                # flag, and Zstd and LZ4 keep counting concatenated frames together
                # (format-7z), so it is set for BZip2 only.
                single_stream=stage.codec is Codec.BZIP2,
            ),
            collector=collector,
            seekable=seekable,
        )
        label = _CODEC_LABELS.get(stage.codec)
        if label is None:
            return decoded
        # The planner always sets unpack_size; None is only the dataclass default.
        assert stage.unpack_size is not None
        return _DecodedPastSizeCheck(decoded, size=stage.unpack_size, label=label)
    if isinstance(stage, _LzmaChainStage):
        out = open_codec_stream(
            stage.codec,
            stream,
            config=stream_config,
            # An LZMA1 chain stops at its size in the codec (``unpack_size``),
            # which also checks that its input ends there.
            params=CodecParams(
                filters=stage.filters,
                unpack_size=stage.cap_size,
                pack_size=stage.pack_size,
            ),
            collector=collector,
            seekable=seekable,
        )
        size = stage.end_check_size
        if size is None:
            size = stage.cap_size
        if size is not None:
            out = _DecodedPastSizeCheck(
                out, size=size, label=_CODEC_LABELS[stage.codec]
            )
        return out
    if isinstance(stage, _CopyStage):
        return _DecodedPastSizeCheck(stream, size=stage.unpack_size, label="Copy")
    return FilterStream(
        stream,
        lzma_filter=stage.lzma_filter,
        unpack_size=stage.unpack_size,
        seekable=seekable,
        owns_inner=owns_input,
        natives=natives_for(stream_config.process_isolation),
    )


def open_folder_pipeline(
    sources: Sequence[BinaryIO],
    folder: SevenZipFolder,
    *,
    password: bytes | None,
    key_cache: SevenZipKeyCache,
    stream_config: StreamConfig | None = None,
    collector: DiagnosticCollector | None = None,
    seekable: bool = False,
) -> BinaryIO:
    """Compose a folder's coder graph into a single pull stream (plan, then fold).

    ``sources`` are borrowed pack views, one per pack stream, in the order of the
    folder's ``packed_indices``. Each stage wraps the previous output.
    Only a ``_FilterStage`` takes ``owns_inner``: True when it is not first in its
    chain, so it closes the previous stage's output — the LZMA1 cap slice, or an
    ``AesDecryptStream`` on ``[AES, BCJ]``. Other follow-on stages do not close
    their input: ``[AES, LZMA]`` (the common encrypted shape) still leaves the AES
    stream unclosed, because the raw LZMA decoder stream does not close a passed-in
    fileobj. The AES stream borrows the pack view (``owns_inner`` default) and holds no OS
    handle. Wiring codec stages to close it is a follow-up; seek does not depend on it.

    In a BCJ2 folder, ``seekable`` also applies to every branch, because the
    :class:`Bcj2DecoderStream` seeks backward by rewinding its four inputs. It owns and
    closes the branch outputs.
    """
    config = stream_config if stream_config is not None else DEFAULT_STREAM_CONFIG
    plan = plan_folder(folder)
    if len(sources) != plan.pack_count():
        raise CorruptionError(
            f"7z folder reads {plan.pack_count()} packed streams, "
            f"but {len(sources)} were given"
        )

    # Every decoder of a folder runs at once: the stages of a chain are stacked
    # streams, and a BCJ2 folder's branches (main, call, jump; rc too, when it is not
    # a bare pack stream) run side by side. Each declares its own memory and is
    # checked on its own when it opens; the folder's total is checked here, before
    # any of them is built. One decoder alone is left to its own check, whose
    # message names the field.
    declared = _declared_decoder_memory(plan, sources)
    if len(declared) > 1:
        folder_kind = "7z BCJ2 folder" if plan.has_bcj2() else "7z folder"
        check_decoder_memory(
            sum(declared),
            limits=config.decoder_limits,
            what=f"the sum over a {folder_kind}'s decoders "
            "(LZMA dictionaries, PPMd memory, zstd windows)",
            usage=config.usage,
        )

    def open_chain(chain: _Chain, *, seekable: bool) -> BinaryIO:
        stream: BinaryIO
        if isinstance(chain.source, _Bcj2Stage):
            branches: list[BinaryIO] = []
            try:
                for branch in chain.source.branches:
                    branch_stream = open_chain(branch, seekable=seekable)
                    if branch.unpack_size is not None:
                        # A branch ends at its declared size. 7-Zip's LZMA branches
                        # have no end marker, and BCJ2 reads its inputs in blocks,
                        # so an uncapped LZMA1 decoder would read past its data.
                        branch_stream = SlicingStream(
                            branch_stream,
                            length=branch.unpack_size,
                            owns_inner=_opens_streams(branch),
                        )
                    branches.append(branch_stream)
            except BaseException:
                for opened, branch in zip(branches, chain.source.branches):
                    if branch.unpack_size is not None:
                        opened.close()
                raise
            main, call, jump, rc = branches
            stream = Bcj2DecoderStream(
                main,
                call,
                jump,
                rc,
                unpack_size=chain.source.unpack_size,
                # A bare pack-stream branch is a borrowed view (``rc``, usually);
                # every other branch is wrapped in a private slice.
                owns_inputs=[b.unpack_size is not None for b in chain.source.branches],
            )
            owns_input = True
        else:
            stream = sources[chain.source]
            owns_input = False
        for stage in chain.stages:
            stream = _execute_stage(
                stream,
                stage,
                password=password,
                key_cache=key_cache,
                stream_config=config,
                collector=collector,
                seekable=seekable,
                owns_input=owns_input,
            )
            owns_input = True
        return stream

    return open_chain(plan, seekable=seekable)


def _declared_decoder_memory(chain: _Chain, sources: Sequence[BinaryIO]) -> list[int]:
    """The decoder memory each decoder of a chain declares, over every BCJ2 branch.

    Counts what ``max_decoder_memory`` bounds per decoder: LZMA1/LZMA2 dictionary
    sizes, the PPMd memory size and the zstd window. Every other stage declares none
    here, and ``max_decoder_memory`` does not count it. The compressors among them still
    hold working memory, which their formats bound: 32 KiB to 64 KiB for Deflate and
    Deflate64, about 4 MiB for BZip2 and an LZ4 frame, and up to 16 MiB for a Brotli
    window. PPMd properties that do not parse count as 0 here; the PPMd stage refuses
    them itself when it opens.

    A zstd window is declared in the frame header, not in the coder properties, so it
    is read from the pack stream when the zstd coder reads one directly (the layout
    7-Zip ZS writes): the first frame's window counts. A zstd coder behind another
    coder (AES, say) counts as 0, and so do later frames; each frame's window is still
    held to ``max_decoder_memory`` on its own when the frame starts.
    """
    declared: list[int] = []
    if isinstance(chain.source, _Bcj2Stage):
        for branch in chain.source.branches:
            declared.extend(_declared_decoder_memory(branch, sources))
    elif (
        chain.stages
        and isinstance(chain.stages[0], _CodecStage)
        and chain.stages[0].codec is Codec.ZSTD
    ):
        window = _zstd_first_frame_window(sources[chain.source])
        if window:
            declared.append(window)
    for stage in chain.stages:
        if isinstance(stage, _LzmaChainStage):
            declared.extend(
                spec.get("dict_size", 0)
                for spec in stage.filters
                if spec.get("id") in LZMA_DICTIONARY_FILTERS
            )
        elif isinstance(stage, _CodecStage) and stage.codec is Codec.PPMD:
            try:
                declared.append(parse_ppmd_var_h_properties(stage.properties)[1])
            except ValueError:
                declared.append(0)
    return declared


def _zstd_first_frame_window(source: BinaryIO) -> int | None:
    """The window of the zstd frame at the start of a pack view, which is left as found."""
    if not source.seekable():
        return None
    position = source.tell()
    try:
        source.seek(0)
        header = source.read(MAX_FRAME_HEADER_SIZE)
    finally:
        source.seek(position)
    return frame_window_size(header)


def _opens_streams(chain: _Chain) -> bool:
    """Whether opening ``chain`` creates a stream, rather than returning a pack view."""
    return bool(chain.stages) or chain.has_bcj2()


def decode_folder_to_bytes(
    source: BinaryIO,
    folder: SevenZipFolder,
    *,
    compressed_size: int,
    uncompressed_size: int,
    password: bytes | None,
    key_cache: SevenZipKeyCache,
    stream_config: StreamConfig | None = None,
    collector: DiagnosticCollector | None = None,
) -> bytes:
    """Fully decode one folder's packed stream into memory and CRC-check it."""
    stream = open_folder_pipeline(
        [SlicingStream(source, 0, compressed_size)],
        folder,
        password=password,
        key_cache=key_cache,
        stream_config=stream_config,
        collector=collector,
    )
    try:
        decoded = read_exact(stream, uncompressed_size)
        if len(decoded) != uncompressed_size:
            raise TruncatedError("7z folder is truncated after decoding")
        if (
            folder.digest_defined
            and folder.crc is not None
            and zlib.crc32(decoded) & 0xFFFFFFFF != folder.crc & 0xFFFFFFFF
        ):
            raise CorruptionError("Decoded 7z folder CRC mismatch")
        return decoded
    finally:
        stream.close()


def decode_encoded_header(
    archive_fp: BinaryIO,
    encoded: EncodedHeader,
    *,
    password: bytes | None,
    key_cache: SevenZipKeyCache,
    stream_config: StreamConfig | None = None,
    collector: DiagnosticCollector | None = None,
) -> bytes:
    """Materialize an ENCODED_HEADER's one packed folder to plaintext header bytes."""
    folder, absolute_offset, compressed_size, uncompressed_size = encoded_header_slice(
        encoded
    )
    # Hostile archives can claim a multi-EiB folder unpack size. Cap it before
    # ``read_exact`` / codec buffers allocate (Atheris: raw MemoryError).
    if uncompressed_size > MAX_NEXT_HEADER_SIZE:
        raise CorruptionError(
            f"Encoded 7z header unpack size {uncompressed_size} exceeds the "
            f"{MAX_NEXT_HEADER_SIZE}-byte parser limit"
        )
    return decode_folder_to_bytes(
        SlicingStream(archive_fp, absolute_offset, compressed_size),
        folder,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        password=password,
        key_cache=key_cache,
        stream_config=stream_config,
        collector=collector,
    )


def encoded_header_needs_password(encoded: EncodedHeader) -> bool:
    folders = encoded.streams.folders or []
    return any(folder_is_encrypted(folder) for folder in folders)
