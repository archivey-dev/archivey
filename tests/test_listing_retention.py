"""Closed listings must not wait for cyclic GC to release their reader."""

import gc
import io
import platform
import weakref
import zipfile

import pytest

import archivey

_requires_reference_counting = pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="Immediate reclamation without cyclic GC relies on reference counting",
)


def _zip(payload: bytes = b"content") -> bytes:
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as writer:
        writer.writestr("member.txt", payload)
    return source.getvalue()


@_requires_reference_counting
def test_a_closed_reader_is_released_while_its_members_are_kept() -> None:
    source = _zip()
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        with archivey.open_archive(io.BytesIO(source)) as reader:
            members = list(reader.members())
        reader_ref = weakref.ref(reader)
        del reader
        assert reader_ref() is None
        assert [member.name for member in members] == ["member.txt"]
    finally:
        if was_enabled:
            gc.enable()


@_requires_reference_counting
def test_a_descendant_retains_its_closed_root() -> None:
    source = _zip()
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        with archivey.open_archive(io.BytesIO(source)) as root:
            child = archivey.open_archive(io.BytesIO(source), parent=root)
        root_ref = weakref.ref(root)
        del root
        try:
            assert root_ref() is not None
            with child.open(next(iter(child.members()))) as stream:
                assert stream.read() == b"content"
            del stream
        finally:
            child.close()
        del child
        assert root_ref() is None
    finally:
        if was_enabled:
            gc.enable()


def test_streams_keep_the_nest_ratio_after_readers_are_dropped() -> None:
    source = _zip(b"x" * 4096)
    config = archivey.ArchiveyConfig(
        decoder_limits=archivey.config.DecoderLimits(
            max_ratio=1.2, ratio_activation_threshold=0
        )
    )
    root = archivey.open_archive(io.BytesIO(source), config=config)
    child = archivey.open_archive(io.BytesIO(source), parent=root)
    first = root.open(next(iter(root.members())))
    second = child.open(next(iter(child.members())))
    root_ref = weakref.ref(root)
    child_ref = weakref.ref(child)
    was_enabled = gc.isenabled()
    gc.disable()
    del root, child
    try:
        gc.collect()
        assert root_ref() is not None
        assert first.read() == b"x" * 4096
        with pytest.raises(
            archivey.ResourceLimitError, match="Nest decompression ratio"
        ):
            second.read()
    finally:
        first.close()
        second.close()
        if (held_child := child_ref()) is not None:
            held_child.close()
        if (held_root := root_ref()) is not None:
            held_root.close()
        if was_enabled:
            gc.enable()
