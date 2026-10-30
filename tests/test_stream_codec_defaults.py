"""What :class:`StreamCodec` gives a codec that decodes through :meth:`decompressor`,
a plugin's included: how a further stream starts, the stream's name, and the package
an exclusion names; and that every registered codec's magic names its own format."""

from __future__ import annotations

from archivey.formats import CodecCall, CodecHandler, Decompressor, Magic
from archivey.internal.codec_adapter import codec_class
from archivey.internal.config import DEFAULT_STREAM_CONFIG, StreamConfig
from archivey.internal.streams.codecs.base import Codec, CodecParams, StreamCodec
from archivey.internal.streams.codecs.registry import stream_codecs
from archivey.types import (
    ArchiveFormat,
    MagicSignature,
    MissingComponent,
    OptionalLibrary,
    PluginStream,
    StreamFormat,
)


class PlainCodec(StreamCodec):
    """Nothing overridden but the decoder."""

    codec = Codec.ZSTD
    stream_format = StreamFormat.ZSTD
    magic = (MagicSignature(0, b"AB", ArchiveFormat.ZST),)

    def decompressor(self, params: CodecParams, config: StreamConfig) -> Decompressor:
        raise NotImplementedError


def test_a_further_stream_starts_with_the_offset_0_magic() -> None:
    start = PlainCodec().stream_start(CodecParams())
    assert start(b"AB rest") is True
    assert start(b"A") is None
    assert start(b"XY") is False


def test_a_single_stream_coder_takes_no_further_stream() -> None:
    assert PlainCodec().stream_start(CodecParams(single_stream=True))(b"AB") is False


def test_a_codec_that_is_not_concatenated_takes_no_further_stream() -> None:
    class Once(PlainCodec):
        concatenated = False

    assert Once().stream_start(CodecParams())(b"AB") is False


def test_a_container_only_codec_takes_no_further_stream() -> None:
    class Container(PlainCodec):
        stream_format = None
        magic = ()

    assert Container().stream_start(CodecParams())(b"AB") is False


def test_codec_name_names_the_stream() -> None:
    class Renamed(PlainCodec):
        codec_name = "renamed"

    codec = Renamed()
    assert codec.stream_name == "renamed"
    warning = codec.rewind_warning(DEFAULT_STREAM_CONFIG)
    assert warning is not None and warning.codec_name == "renamed"


def test_an_exclusion_names_the_package_in_use() -> None:
    # zstd's case: ``requirement`` names the backport, the standard library's module
    # decodes on 3.14+.
    class InUse(PlainCodec):
        requirement = MissingComponent(
            OptionalLibrary.BACKPORTS_ZSTD, "pip install it", ("zstd",)
        )

        def _library(self) -> OptionalLibrary:
            return OptionalLibrary.COMPRESSION_ZSTD

    codec = InUse()
    excluded = frozenset({OptionalLibrary.COMPRESSION_ZSTD})
    assert codec.excluded_by(excluded)
    requirement = codec.requirement_under(excluded)
    assert requirement is not None and requirement.name == "compression.zstd"
    assert not codec.excluded_by(frozenset({OptionalLibrary.BACKPORTS_ZSTD}))


def test_a_plugin_codec_starts_a_further_stream_by_the_same_rule() -> None:
    # The plugin entry inherits stream_start. No caller opens a plugin codec as a
    # one-stream coder today (``single_stream`` is set for bzip2 only), but if one
    # does, the plugin reads one stream as a built-in would.
    class Stream(PluginStream):
        DEFAULTS = "defaultsx"

    class Handler(CodecHandler):
        stream_format = Stream.DEFAULTS
        magic = (Magic(0, b"AB"),)

        def decompressor(self, call: CodecCall) -> Decompressor:
            raise NotImplementedError

    entry = codec_class(Handler)()
    assert entry.stream_start(CodecParams())(b"AB") is True
    assert entry.stream_start(CodecParams(single_stream=True))(b"AB") is False

    class Once(Handler):
        concatenated = False

    assert codec_class(Once)().stream_start(CodecParams())(b"AB") is False


def test_every_codec_magic_names_the_codec_own_format() -> None:
    # Each codec writes its magic's format by hand: a wrong one would make the detector
    # report another format for the file.
    for codec in stream_codecs():
        if codec.stream_format is None:
            assert not codec.magic, codec
        for signature in codec.magic:
            assert signature.format == codec.single_file_format, codec
