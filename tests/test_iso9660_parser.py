"""The native ISO 9660 / Joliet / Rock Ridge parser (``internal/backends/iso9660.py``).

Two kinds of test. The differential ones parse images that ``pycdlib``, ``xorriso`` and
``genisoimage`` write, and require the same trees ``pycdlib`` parses: every record's
identifier, kind and extent, and its Rock Ridge name, mode and owner and link target.
pycdlib is the parser this one replaces, so on an image both open the two must agree.
The others pin how the parser handles damage, which is where it departs from pycdlib on
purpose: a cut image, a malformed System Use entry, padding, loops, and records that
share an identifier.
"""

from __future__ import annotations

import io
import random
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
)
from archivey.internal.backends.iso9660 import (
    JOLIET_TREE,
    PRIMARY_TREE,
    IsoEntry,
    IsoVolume,
    RawDate,
    date_is_invalid,
    date_value,
    iter_tree,
)
from tests.conftest import requires, requires_binary

pytestmark = requires("pycdlib")

_Tree = dict[str, list[tuple[Any, ...]]]


def _volume(data: bytes, **kwargs: Any) -> IsoVolume:
    return IsoVolume(
        lambda offset, n: data[offset : offset + n],
        len(data),
        archive_name=None,
        budget=kwargs.pop("budget", None),
        **kwargs,
    )


# --- the two parsers' trees, in one shape ----------------------------------------


def _pycdlib_tree(root: Any, rock_ridge: bool) -> _Tree:
    """Every record under ``root`` as pycdlib parsed it, per directory path, sorted."""
    out: _Tree = {}
    seen = {root.extent_location()}
    stack: list[tuple[str, Any]] = [("", root)]
    while stack:
        path, directory = stack.pop()
        records: list[tuple[Any, ...]] = []
        for child in directory.children:
            if child is None or child.is_dot() or child.is_dotdot():
                continue
            item: tuple[Any, ...] = (
                bytes(child.file_ident),
                child.is_dir(),
                child.orig_extent_loc,
            )
            rr = child.rock_ridge if rock_ridge else None
            if rr is not None:
                groups = [rr.dr_entries] + ([rr.ce_entries] if rr.ce_entries else [])
                px = next(
                    (
                        (
                            g.px_record.posix_file_mode,
                            g.px_record.posix_user_id,
                            g.px_record.posix_group_id,
                        )
                        for g in groups
                        if g.px_record is not None
                    ),
                    None,
                )
                has_nm = any(g.nm_records for g in groups)
                target = bytes(rr.symlink_path()) if rr.is_symlink() else None
                item += (bytes(rr.name()) if has_nm else None, px, target)
            records.append(item)
            cl = rr is not None and rr.child_link_record_exists()
            if child.is_dir() and not cl and child.extent_location() not in seen:
                seen.add(child.extent_location())
                stack.append((f"{path}/{bytes(child.file_ident)!r}", child))
        out[path] = sorted(records, key=repr)
    return out


def _native_tree(root: IsoEntry, rock_ridge: bool) -> _Tree:
    """The same records as the native parser joined them into entries."""
    out: _Tree = {}
    stack: list[tuple[str, IsoEntry]] = [("", root)]
    while stack:
        path, directory = stack.pop()
        records: list[tuple[Any, ...]] = []
        for child in directory.children or ():
            for block, _ in child.extents:
                item: tuple[Any, ...] = (child.ident, child.is_dir, block)
                rr = child.rr if rock_ridge else None
                if rr is not None:
                    px = None if rr.mode is None else (rr.mode, rr.uid, rr.gid)
                    target = rr.symlink if rr.is_symlink else None
                    item += (rr.name, px, target)
                records.append(item)
            if child.is_dir and child.children is not None:
                stack.append((f"{path}/{child.ident!r}", child))
        out[path] = sorted(records, key=repr)
    return out


def _assert_same_trees(data: bytes) -> IsoVolume:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(data))
    try:
        volume = _volume(data)
        rock_ridge = bool(iso.has_rock_ridge())
        assert volume.rock_ridge == rock_ridge
        assert (volume.joliet is not None) == bool(iso.has_joliet())
        assert _native_tree(volume.primary.root, rock_ridge) == _pycdlib_tree(
            iso.get_record(iso_path="/"), rock_ridge
        )
        if volume.joliet is not None:
            assert _native_tree(volume.joliet.root, False) == _pycdlib_tree(
                iso.get_record(joliet_path="/"), False
            )
        assert volume.block_size == iso.logical_block_size
        assert volume.volume_identifier == iso.pvd.volume_identifier
    finally:
        iso.close()
    return volume


# --- images ----------------------------------------------------------------------


def _pycdlib_image(*, rock_ridge: bool, joliet: bool, deep: int = 0) -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    kwargs: dict[str, Any] = {}
    if rock_ridge:
        kwargs["rock_ridge"] = "1.09"
    if joliet:
        kwargs["joliet"] = 3
    iso.new(interchange_level=3, **kwargs)

    def names(rr: str, jo: str) -> dict[str, str]:
        out = {}
        if rock_ridge:
            out["rr_name"] = rr
        if joliet:
            out["joliet_path"] = jo
        return out

    iso.add_fp(io.BytesIO(b"hello"), 5, "/FILE.TXT;1", **names("file.txt", "/file.txt"))
    iso.add_fp(io.BytesIO(b""), 0, "/EMPTY.TXT;1", **names("empty.txt", "/empty.txt"))
    iso.add_directory("/DIR", **names("subdir", "/subdir"))
    iso.add_fp(
        io.BytesIO(b"n" * 5000), 5000, "/DIR/N.TXT;1", **names("n.txt", "/subdir/n.txt")
    )
    if rock_ridge:
        iso.add_symlink("/SYM.TXT;1", "sym", "subdir/n.txt")
        path = ""
        for depth in range(deep):
            path += f"/D{depth}"
            iso.add_directory(path, rr_name=f"dir{depth}")
        if deep:
            iso.add_fp(io.BytesIO(b"deep"), 4, path + "/F.;1", rr_name="f.txt")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _populate(root: Path, *, long_link: bool) -> None:
    """A source tree with the shapes writers handle: long and non-ASCII names,
    symlinks, nesting deeper than ISO 9660's eight levels, and an empty file. With
    ``long_link``, a symlink whose target is long enough that genisoimage 1.1.11 wraps
    its ``SL`` length (xorriso 1.5.6 aborts on it)."""
    (root / "a long file name that plain ISO 9660 cannot hold.txt").write_text("x" * 99)
    (root / "café.txt").write_text("café")
    (root / "empty").write_bytes(b"")
    deep = root
    for depth in range(10):
        deep = deep / f"level{depth}"
    deep.mkdir(parents=True)
    (deep / "bottom.txt").write_text("bottom")
    (root / "link").symlink_to("café.txt")
    (root / "dangling").symlink_to("../../outside/" + "x" * (400 if long_link else 100))


def _tool_image(tmp_path: Path, command: list[str], *, long_link: bool) -> bytes:
    src = tmp_path / "src"
    src.mkdir()
    _populate(src, long_link=long_link)
    out = tmp_path / "out.iso"
    subprocess.run(
        [*command, "-o", str(out), str(src)], check=True, capture_output=True
    )
    return out.read_bytes()


@pytest.mark.parametrize(
    ("rock_ridge", "joliet"),
    [(False, False), (False, True), (True, False), (True, True)],
)
def test_pycdlib_images_parse_as_pycdlib_parses_them(
    rock_ridge: bool, joliet: bool
) -> None:
    _assert_same_trees(_pycdlib_image(rock_ridge=rock_ridge, joliet=joliet))


def test_relocated_deep_directories_parse_as_pycdlib_parses_them() -> None:
    volume = _assert_same_trees(_pycdlib_image(rock_ridge=True, joliet=True, deep=12))
    root = volume.primary.root
    assert root.children is not None
    moved = next(c for c in root.children if c.ident == b"RR_MOVED")
    assert moved.children
    # Each directory under rr_moved has a "..", that points back with a PL entry.
    assert all(child.parent_linked for child in moved.children)
    placeholders = [
        entry
        for _, entry in iter_tree(root)
        if entry.rr is not None and entry.rr.child_link is not None
    ]
    assert placeholders
    assert all(entry.children is None for entry in placeholders)


@requires_binary("xorriso")
def test_xorriso_images_parse_as_pycdlib_parses_them(tmp_path: Path) -> None:
    _assert_same_trees(
        _tool_image(
            tmp_path,
            ["xorriso", "-as", "mkisofs", "-R", "-J", "-joliet-long"],
            long_link=False,
        )
    )


@requires_binary("genisoimage")
def test_genisoimage_images_parse_as_pycdlib_parses_them(tmp_path: Path) -> None:
    _assert_same_trees(
        _tool_image(
            tmp_path,
            ["genisoimage", "-quiet", "-R", "-J", "-input-charset", "utf-8"],
            long_link=False,
        )
    )


@requires_binary("genisoimage")
def test_a_wrapped_symlink_entry_ends_only_its_records_area(tmp_path: Path) -> None:
    """genisoimage 1.1.11 writes a long symlink target with an ``SL`` length that
    wraps past 255; the entries after it are not read, the record says why, and the
    rest of the tree parses. (pycdlib refuses the whole image.)"""
    volume = _volume(
        _tool_image(
            tmp_path,
            ["genisoimage", "-quiet", "-R", "-J", "-input-charset", "utf-8"],
            long_link=True,
        )
    )
    entries = {e.rr.name: e for _, e in iter_tree(volume.primary.root) if e.rr}
    dangling = entries[b"dangling"].rr
    assert dangling is not None and dangling.is_symlink
    assert dangling.dropped is not None
    link = entries[b"link"].rr
    assert link is not None and link.symlink == "café.txt".encode()
    assert link.dropped is None


@requires_binary("genisoimage", "mkzftree")
def test_zisofs_entries_are_read(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.txt").write_bytes(b"compressible " * 20000)
    packed = tmp_path / "packed"
    subprocess.run(["mkzftree", str(src), str(packed)], check=True)
    out = tmp_path / "z.iso"
    subprocess.run(
        ["genisoimage", "-quiet", "-R", "-z", "-o", str(out), str(packed)], check=True
    )
    volume = _volume(out.read_bytes())
    big = next(
        e for _, e in iter_tree(volume.primary.root) if e.ident.startswith(b"BIG")
    )
    assert big.rr is not None and big.rr.zisofs is not None
    assert big.rr.zisofs.tag == b"ZF"
    assert big.rr.zisofs.algorithm == b"pz"
    assert big.rr.zisofs.uncompressed_size == 13 * 20000


def test_bit_flips_never_crash_and_never_refuse_what_pycdlib_opens() -> None:
    """Flipped bits in the descriptors and directories: the parser raises only
    archivey's own errors, and it opens every image pycdlib opens, with the same trees
    whenever the System Use skip count is untouched (pycdlib ignores that count; this
    parser follows it, as Linux does). The one refusal pycdlib lacks is an identifier
    longer than its record, which Linux refuses too."""
    import pycdlib

    base = _pycdlib_image(rock_ridge=True, joliet=True, deep=10)
    rng = random.Random(20261120)
    for _ in range(300):
        buf = bytearray(base)
        for _ in range(rng.randint(1, 3)):
            buf[rng.randrange(16 * 2048, 40 * 2048)] ^= 1 << rng.randrange(8)
        data = bytes(buf)
        try:
            iso = pycdlib.PyCdlib()
            iso.open_fp(io.BytesIO(data))
        except Exception:  # noqa: BLE001 - pycdlib refuses in many ways
            try:
                _volume(data)
            except ArchiveyError:
                pass
            continue
        iso.close()
        try:
            _volume(data)
        except CorruptionError as exc:
            # pycdlib cuts such an identifier short; Linux and this parser refuse it.
            assert "its identifier declares" in str(exc)


# --- damage ----------------------------------------------------------------------


def test_an_image_cut_inside_a_directory_is_truncated() -> None:
    data = _pycdlib_image(rock_ridge=True, joliet=True)
    root = struct.unpack_from("<I", data, 16 * 2048 + 156 + 2)[0] * 2048
    with pytest.raises(TruncatedError, match="directory is cut short"):
        _volume(data[: root + 100])


def test_an_image_cut_inside_its_descriptors_is_truncated() -> None:
    data = _pycdlib_image(rock_ridge=False, joliet=False)
    with pytest.raises(TruncatedError, match="volume descriptor"):
        _volume(data[: 17 * 2048 + 10])


def test_a_root_past_a_full_length_image_is_corruption() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=False, joliet=False))
    at = 16 * 2048 + 156 + 2
    struct.pack_into("<I", data, at, 10**6)
    struct.pack_into(">I", data, at + 4, 10**6)
    with pytest.raises(CorruptionError, match="lies past|holds 0"):
        _volume(bytes(data))


def _root_records(data: bytes) -> tuple[int, int]:
    """The root directory's image offset and its length."""
    vd = 16 * 2048
    return (
        struct.unpack_from("<I", data, vd + 156 + 2)[0] * 2048,
        struct.unpack_from("<I", data, vd + 156 + 10)[0],
    )


def _record_offset(data: bytes, directory: int, ident: bytes) -> int:
    offset = directory
    while data[offset] and data[offset + 33 : offset + 33 + data[offset + 32]] != ident:
        offset += data[offset]
    assert data[offset], f"{ident!r} not found"
    return offset


def test_non_zero_padding_is_noted_and_skipped() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=False, joliet=False))
    root, length = _root_records(data)
    data[root + length - 1] = 0x55
    volume = _volume(bytes(data))
    assert volume.padding == [root + length - 1]
    names = {e.ident for _, e in iter_tree(volume.primary.root)}
    assert b"FILE.TXT;1" in names


def test_a_malformed_system_use_entry_ends_that_records_area_only() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=True, joliet=False))
    root, _ = _root_records(data)
    record = _record_offset(data, root, b"FILE.TXT;1")
    area = record + 33 + data[record + 32] + 1
    tf = data.index(b"TF", area)
    data[tf + 3] = 99  # version
    volume = _volume(bytes(data))
    entries = {e.ident: e for _, e in iter_tree(volume.primary.root)}
    damaged = entries[b"FILE.TXT;1"].rr
    assert damaged is not None
    assert damaged.dropped is not None and "version 99" in damaged.dropped
    assert damaged.mode is not None  # PX came before TF
    others = [e.rr for ident, e in entries.items() if ident != b"FILE.TXT;1"]
    assert all(rr is None or rr.dropped is None for rr in others)


def test_a_continuation_area_past_its_block_is_dropped_not_refused() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=True, joliet=False))
    root, _ = _root_records(data)
    # The root's "." record carries the ER entry in a continuation area (pycdlib
    # writes one); push that area's length past its block.
    ce = data.index(b"CE\x1c\x01", root)
    struct.pack_into("<I", data, ce + 20, 8 * 1024 * 1024)
    struct.pack_into(">I", data, ce + 24, 8 * 1024 * 1024)
    volume = _volume(bytes(data))
    # The ER entry was in the area that was not read: Rock Ridge is not recognized.
    assert not volume.rock_ridge


def test_a_directory_loop_is_refused() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=False, joliet=False))
    root, _ = _root_records(data)
    record = _record_offset(data, root, b"DIR")
    root_block = root // 2048
    struct.pack_into("<I", data, record + 2, root_block)
    struct.pack_into(">I", data, record + 6, root_block)
    with pytest.raises(CorruptionError, match="forms a loop"):
        _volume(bytes(data))


def test_a_directory_and_a_file_with_one_identifier_are_two_entries() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=False, joliet=False))
    root, _ = _root_records(data)
    record = _record_offset(data, root, b"FILE.TXT;1")
    length = data[record + 32]
    ident = b"DIR" + b"\0" * (length - 3)
    # Rename FILE.TXT;1 to DIR (padded with NULs to keep the record's length), then
    # shorten its identifier length so the identifier reads "DIR".
    data[record + 33 : record + 33 + length] = ident
    data[record + 32] = 3
    volume = _volume(bytes(data))
    root_entry = volume.primary.root
    assert root_entry.children is not None
    dirs = [c for c in root_entry.children if c.ident == b"DIR"]
    assert sorted(c.is_dir for c in dirs) == [False, True]


def test_multi_extent_records_join_into_one_entry() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=False, joliet=False))
    root, _ = _root_records(data)
    record = _record_offset(data, root, b"FILE.TXT;1")
    size = data[record]
    original = bytes(data[record : record + size])
    first = bytearray(original)
    first[25] |= 0x80
    second = bytearray(original)
    struct.pack_into("<I", second, 2, 999)
    struct.pack_into(">I", second, 6, 999)
    third = bytearray(original)  # no flag on the second: a separate file
    rest = bytes(data[record + size : root + 2048])
    data[record : root + 2048] = (bytes(first) + bytes(second) + bytes(third) + rest)[
        : root + 2048 - record
    ]
    volume = _volume(bytes(data))
    assert volume.primary.root.children is not None
    files = [c for c in volume.primary.root.children if c.ident == b"FILE.TXT;1"]
    assert [c.extents for c in files] == [
        ((struct.unpack_from("<I", original, 2)[0], 5), (999, 5)),
        ((struct.unpack_from("<I", original, 2)[0], 5),),
    ]
    assert files[0].data_length == 10


def test_an_image_cut_after_its_primary_descriptor_names_the_volume_space() -> None:
    """A cut inside a later descriptor is measured against the volume space the
    primary descriptor declares, not against the descriptor that is cut."""
    data = _pycdlib_image(rock_ridge=False, joliet=True)
    space = struct.unpack_from("<I", data, 16 * 2048 + 80)[0] * 2048
    with pytest.raises(TruncatedError, match=f"it declares {space} bytes"):
        _volume(data[: 17 * 2048 + 10])


def test_an_identifier_longer_than_its_record_is_refused() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=False, joliet=False))
    root, _ = _root_records(data)
    record = _record_offset(data, root, b"FILE.TXT;1")
    data[record + 32] = 200
    with pytest.raises(CorruptionError, match="its identifier declares 200"):
        _volume(bytes(data))


def test_a_symlink_component_longer_than_its_entry_ends_the_area() -> None:
    data = bytearray(_pycdlib_image(rock_ridge=True, joliet=False))
    root, _ = _root_records(data)
    record = _record_offset(data, root, b"SYM.TXT;1")
    sl = data.index(b"SL", record + 33)
    # The first component's length byte: past the end of the entry.
    data[sl + 6] = 0xF0
    volume = _volume(bytes(data))
    entries = {e.ident: e for _, e in iter_tree(volume.primary.root)}
    rr = entries[b"SYM.TXT;1"].rr
    assert rr is not None and rr.dropped is not None
    assert "has a component cut short" in rr.dropped
    assert rr.symlink is None


def test_the_root_skip_count_applies_before_the_rock_ridge_test() -> None:
    """With a non-zero ``SP`` skip count, every other System Use area starts with
    that many bytes before its first entry."""
    volume = _volume(_pycdlib_image(rock_ridge=True, joliet=False))
    volume._sp_skip = 4
    rr = volume._system_use(b"\xff" * 4 + b"NM\x08\x01\x00abc", 1, root_dot=False)
    assert rr is not None and rr.dropped is None
    assert rr.name == b"abc"


def test_a_name_cut_before_its_last_part_names_nothing() -> None:
    """An ``NM`` that says it continues, in an area that then ends at a malformed
    entry, is a name cut short: ``None``, so the reader falls back to the ISO 9660
    identifier rather than list a prefix."""
    volume = _volume(_pycdlib_image(rock_ridge=True, joliet=False))
    rr = volume._system_use(b"NM\x08\x01\x01abcTF\x05\x63\x00", 1, root_dot=False)
    assert rr is not None and rr.dropped is not None
    assert rr.name is None


class _Budget:
    def __init__(self) -> None:
        self.bytes = 0
        self.members = {PRIMARY_TREE: 0, JOLIET_TREE: 0}

    def add_iso_bytes(self, nbytes: int) -> None:
        self.bytes += nbytes

    def add_iso_member(self, tree: int) -> None:
        self.members[tree] += 1


def test_every_record_is_weighed_per_tree() -> None:
    budget = _Budget()
    _volume(_pycdlib_image(rock_ridge=True, joliet=True), budget=budget)
    # file.txt, empty.txt, subdir, sym.txt and subdir/n.txt; sym has no Joliet record.
    assert budget.members == {PRIMARY_TREE: 5, JOLIET_TREE: 4}
    assert budget.bytes > 0


class _Capped:
    """A budget that refuses past ``limit`` bytes, as ``ListingLimits`` does."""

    def __init__(self, limit: int) -> None:
        self.bytes = 0
        self.limit = limit

    def add_iso_bytes(self, nbytes: int) -> None:
        self.bytes += nbytes
        if self.bytes > self.limit:
            raise ResourceLimitError("over budget")

    def add_iso_member(self, tree: int) -> None:
        pass


def _directories_image(count: int, *, joliet: bool = False) -> bytes:
    """An image whose root holds ``count`` empty directories ``D0``, ``D1``..."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, **({"joliet": 3} if joliet else {}))
    for index in range(count):
        iso.add_directory(
            f"/D{index}", **({"joliet_path": f"/d{index}"} if joliet else {})
        )
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def test_directories_that_claim_more_than_the_image_are_refused_unread() -> None:
    """Directories that each claim the rest of the image are refused before they
    are read: K of them would read K times the image, while their records weigh next
    to nothing."""
    data = bytearray(_directories_image(8))
    data += bytes(4 * 2**20 - len(data))
    root, _ = _root_records(data)
    for index in range(8):
        record = _record_offset(data, root, f"D{index}".encode())
        (extent,) = struct.unpack_from("<I", data, record + 2)
        length = len(data) - extent * 2048
        struct.pack_into("<I", data, record + 10, length)
        struct.pack_into(">I", data, record + 14, length)
    image = bytes(data)
    reads: list[int] = []

    def read_at(offset: int, n: int) -> bytes:
        reads.append(n)
        return image[offset : offset + n]

    with pytest.raises(CorruptionError, match="more than the 4194304-byte image"):
        IsoVolume(read_at, len(image), archive_name=None, budget=None)
    assert sum(reads) < 2 * len(image)


def test_a_large_directory_is_read_a_chunk_at_a_time() -> None:
    """Each record is weighed before more of its directory is read, so a budget
    refuses a large directory without reading it whole."""
    data = bytearray(_directories_image(2000))
    _, length = _root_records(data)
    assert length > 64 * 1024
    image = bytes(data)
    reads: list[int] = []

    def read_at(offset: int, n: int) -> bytes:
        reads.append(n)
        return image[offset : offset + n]

    with pytest.raises(ResourceLimitError):
        IsoVolume(read_at, len(image), archive_name=None, budget=_Capped(2**14))
    assert max(reads) <= 64 * 1024
    assert sum(reads) < length


def test_directories_weigh_what_their_records_hold() -> None:
    """Small directories weigh their records, not the whole blocks they take."""
    count = 500
    budget = _Capped(2**30)
    data = _directories_image(count, joliet=True)
    _volume(data, budget=budget)
    # Each directory: its record in the root and its own ``.`` and ``..``, about
    # 150 bytes, twice (the ISO 9660 and Joliet trees). A block is 2048.
    assert budget.bytes < count * 400


# --- dates -----------------------------------------------------------------------


def test_short_and_long_dates() -> None:
    short = RawDate(bytes((120, 11, 20, 15, 59, 10, 4)), long=False)
    value = date_value(short)
    assert value is not None
    assert (value.year, value.month, value.hour, value.utcoffset()) == (
        2020,
        11,
        15,
        value.utcoffset(),
    )
    assert value.utcoffset() is not None and value.utcoffset().total_seconds() == 3600
    long = RawDate(b"2026112015591042" + bytes((252,)), long=True)
    value = date_value(long)
    assert value is not None
    assert value.microsecond == 420_000
    assert value.utcoffset() is not None and value.utcoffset().total_seconds() == -3600
    assert date_value(RawDate(bytes(7), long=False)) is None
    assert not date_is_invalid(RawDate(bytes(7), long=False))
    bad = RawDate(bytes((120, 13, 1, 0, 0, 0, 0)), long=False)
    assert date_value(bad) is None and date_is_invalid(bad)
    # A long form whose digits are not a date reads as not specified.
    assert not date_is_invalid(RawDate(b"20261320000000000", long=True))


def test_rock_ridge_times_are_read_in_rrip_order() -> None:
    """TF flag bit 1 is the modification time and bit 2 the access time."""
    data = bytearray(_pycdlib_image(rock_ridge=True, joliet=False))
    root, _ = _root_records(data)
    record = _record_offset(data, root, b"FILE.TXT;1")
    tf = data.index(b"TF", record)
    flags = data[tf + 4]
    volume = _volume(bytes(data))
    entry = next(
        e for _, e in iter_tree(volume.primary.root) if e.ident == b"FILE.TXT;1"
    )
    assert entry.rr is not None
    expected = {"modified"} if flags & 2 else set()
    expected |= {"accessed"} if flags & 4 else set()
    expected |= {"attribute"} if flags & 8 else set()
    expected |= {"created"} if flags & 1 else set()
    assert set(entry.rr.times) == expected
