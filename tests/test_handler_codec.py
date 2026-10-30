"""The registry entry ``builtin_codec`` builds for a built-in :class:`CodecHandler`:
the defaults a handler with no private hooks gets, and which hooks the entry has."""

from __future__ import annotations

import pytest

from archivey.formats import CodecCall, Decompressor, Magic
from archivey.internal.config import DEFAULT_STREAM_CONFIG
from archivey.internal.streams.codecs.base import Codec, CodecParams, StreamCodec
from archivey.internal.streams.codecs.framed_decoder import StreamStart
from archivey.internal.streams.codecs.handler_codec import (
    BuiltinCodecHandler,
    builtin_call,
    builtin_codec,
)
from archivey.types import ArchiveFormat, ContainerFormat, MagicSignature, StreamFormat


class PlainHandler(BuiltinCodecHandler):
    """No private hook overridden."""

    codec = Codec.ZSTD
    stream_format = StreamFormat.ZSTD
    magic = (Magic(0, b"AB"),)

    def decompressor(self, call: CodecCall) -> Decompressor:
        raise NotImplementedError


_PARAMS = CodecParams()


def _start(handler: BuiltinCodecHandler, params: CodecParams = _PARAMS) -> StreamStart:
    return handler._stream_start(builtin_call(params, DEFAULT_STREAM_CONFIG))


def test_a_further_stream_starts_with_the_offset_0_magic() -> None:
    start = _start(PlainHandler())
    assert start(b"AB rest") is True
    assert start(b"A") is None
    assert start(b"XY") is False


def test_a_single_stream_coder_takes_no_further_stream() -> None:
    assert _start(PlainHandler(), CodecParams(single_stream=True))(b"AB") is False


def test_a_codec_that_is_not_concatenated_takes_no_further_stream() -> None:
    class Once(PlainHandler):
        concatenated = False

    assert _start(Once())(b"AB") is False


def test_the_entry_takes_the_magic_as_the_raw_stream_format() -> None:
    entry = builtin_codec(PlainHandler)()
    fmt = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.ZSTD)
    assert list(entry.magic) == [MagicSignature(0, b"AB", fmt)]


def test_the_entry_has_only_the_detection_hooks_the_handler_overrides() -> None:
    plain = builtin_codec(PlainHandler)
    assert plain.magic_behind_prefix is StreamCodec.magic_behind_prefix
    assert plain.content_probe is StreamCodec.content_probe

    class Probing(PlainHandler):
        def _magic_behind_prefix(self, prefix: bytes) -> bool:
            return prefix.endswith(b"AB")

        def _content_probe(self, entry, prefix, **kwargs) -> bool:
            return prefix == b"yes"

    probing = builtin_codec(Probing)()
    assert probing.magic_behind_prefix(b"..AB")
    assert probing.content_probe(b"yes")
    assert not probing.content_probe(b"no")


def test_a_container_only_codec_has_no_magic() -> None:
    class Container(BuiltinCodecHandler):
        codec = Codec.SHRINK

        def decompressor(self, call: CodecCall) -> Decompressor:
            raise NotImplementedError

    entry = builtin_codec(Container)()
    assert entry.stream_format is None
    assert entry.magic == ()


def test_the_entry_is_named_like_the_modules_alias() -> None:
    entry = builtin_codec(PlainHandler)
    assert entry.__name__ == entry.__qualname__ == "PlainCodec"
    assert entry.__module__ == __name__


def test_codec_name_names_the_stream_everywhere() -> None:
    class Renamed(PlainHandler):
        codec_name = "renamed"

    entry = builtin_codec(Renamed)()
    warning = entry.rewind_warning(DEFAULT_STREAM_CONFIG)
    assert warning is not None and warning.codec_name == "renamed"


@pytest.mark.parametrize(
    ("field", "value"),
    [("requires", ("somelib",)), ("install_hint", "pip"), ("probe", bool)],
)
def test_a_plugins_dependency_or_probe_field_is_refused(
    field: str, value: object
) -> None:
    handler = type("Odd", (PlainHandler,), {field: value})
    with pytest.raises(AssertionError, match="a built-in uses"):
        builtin_codec(handler)
