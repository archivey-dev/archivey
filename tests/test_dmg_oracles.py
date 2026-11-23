"""The DMG reader against two other readers: dpp-py (Rust) and libyal (C).

7-Zip is the main oracle (``test_dmg.py``, ``test_dmg_apfs.py``); these two add a second
and third opinion on the same images, the ``hdiutil`` fixtures and the builder images.
Each runs in a subprocess (``tests/dmg_oracle_dump.py``). Every file, symlink and
directory archivey lists must be listed the same way by the other reader, and the other
reader may list nothing archivey does not, except the gaps below, which are the other
reader's (checked by hand against the macOS listing in
``fixtures/external/dmg_hdiutil/`` and the builder's own tree). Each gap is pinned: when
a reader stops getting it wrong, the test fails and asks for the pin to go, so the
comparison grows with the reader.

- Both list the HFS+ private folders that a mount hides, and list a FIFO as an empty
  file.
- dpp reads every path of an HFS+ file hard link as an empty file (its README: hard
  links are not supported), refuses ADC runs, reads decmpfs type 12 as an error, gives
  APFS plain-key (case-sensitive) volumes no entries, and reads the builder's sparse
  APFS file wrongly.
- libyal has no xz runs, fails on some bzip2 runs (``invalid run length`` / ``invalid
  origin pointer``), reads no file or symlink of the bzip2 HFS+ fixture (only its
  directories), and refuses the builder's sparse APFS file and decmpfs type 12.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

from archivey import MemberType, open_archive
from tests import apfs_build as a, dmg_build as d
from tests.conftest import requires

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "dmg_hdiutil"
_DUMP = Path(__file__).parent / "dmg_oracle_dump.py"

_ORACLES = {
    "dpp": requires("dpp"),
    "libyal": requires("pymodi", "pyfshfs", "pyfsapfs"),
}

# Entries a mount hides and archivey hides too; both other readers list them.
_HIDDEN = (
    "\x00\x00\x00\x00HFS+ Private Data",
    "␀␀␀␀HFS+ Private Data",
    ".HFS+ Private Directory Data\r",
)

# Whole images the other reader cannot read: (reader, image id) -> its error, matched.
_REFUSED = {
    ("dpp", "hfs-UDCO.dmg"): "ADC",
    **{
        ("dpp", f"hfs-builder-{layout}-adc"): "ADC" for layout in ("gpt", "apm", "none")
    },
    ("libyal", "hfs-ULMO.dmg"): "LZMA",
    ("libyal", "apfs-ULMO.dmg"): "LZMA",
    ("libyal", "apfs-UDBZ.dmg"): "bzip",
    **{
        ("libyal", f"hfs-builder-{layout}-{codec}"): err
        for layout in ("gpt", "apm", "none")
        for codec, err in (("xz", "LZMA"), ("bzip2", "bzip"))
    },
}

# Members the other reader gets wrong or cannot read: (reader, image id prefix) ->
# names.
_HFS_BUILDER_LINKS = {"sub dir/first.txt", "other/second.txt"}
_WRONG = {
    ("dpp", "hfs-U"): {"hello.txt", "sub dir/hardlink.txt"},
    ("dpp", "hfs-builder"): _HFS_BUILDER_LINKS | {"comp/t12.txt", "comp/big12.bin"},
    ("dpp", "apfs-builder"): {"sparse.bin", "comp/t12.txt"},
    ("libyal", "apfs-builder"): {"sparse.bin", "comp/t12.txt"},
}
# Images where the other reader lists the directories but reads no file or symlink.
_NO_MEMBER_DATA = {("libyal", "hfs-UDBZ.dmg")}
# Images where the other reader lists nothing and reports no error: (reader, prefix).
_LISTS_NOTHING = {("dpp", "apfs-builder-plain")}

_HDIUTIL = (
    "hfs-UDZO.dmg",
    "hfs-UDBZ.dmg",
    "hfs-ULFO.dmg",
    "hfs-ULMO.dmg",
    "hfs-UDRO.dmg",
    "hfs-UDCO.dmg",
    "apfs-UDZO.dmg",
    "apfs-UDBZ.dmg",
    "apfs-ULFO.dmg",
    "apfs-ULMO.dmg",
    "apfs-UDRO.dmg",
)
_CODECS = {
    "raw": d.RAW,
    "zlib": d.ZLIB,
    "bzip2": d.BZIP2,
    "xz": d.LZMA,
    "adc": d.ADC,
    "lzfse": d.LZFSE,
}
_LAYOUTS = ("gpt", "apm", "none")
# Builder images: id -> (layout, codec name) for HFS+, id -> (layout, hashed keys) for
# APFS.
_HFS_BUILDER = {
    f"hfs-builder-{layout}-{codec}": (layout, codec)
    for layout in _LAYOUTS
    for codec in _CODECS
}
_APFS_BUILDER = {
    f"apfs-builder-{kind}-{layout}": (layout, kind == "hashed")
    for layout in _LAYOUTS
    for kind in ("hashed", "plain")
}
_IMAGES = sorted({*_HDIUTIL, *_HFS_BUILDER, *_APFS_BUILDER})


def _image_bytes(image_id: str) -> bytes:
    if image_id in _HFS_BUILDER:
        from tests.test_dmg import _image

        layout, codec = _HFS_BUILDER[image_id]
        return _image(layout=layout, codec=_CODECS[codec])
    if image_id in _APFS_BUILDER:
        from tests.test_dmg_apfs import _container

        layout, hashed = _APFS_BUILDER[image_id]
        return a.apfs_dmg(_container(hashed=hashed).container, layout=layout)
    return (_FIXTURES / image_id).read_bytes()


def _ours(image: bytes) -> dict[str, list[str]]:
    """archivey's entries in the dump's shape; a hard link has its target's data."""
    entries: dict[str, list[str]] = {}
    links: dict[str, str] = {}
    with open_archive(io.BytesIO(image)) as reader:
        for member in reader.members():
            name = unicodedata.normalize("NFC", member.name.rstrip("/"))
            if member.type is MemberType.FILE:
                entries[name] = [
                    "file",
                    hashlib.sha256(reader.read(member)).hexdigest(),
                ]
            elif member.type is MemberType.DIRECTORY:
                entries[name] = ["dir"]
            elif member.type is MemberType.SYMLINK:
                entries[name] = ["symlink", member.link_target or ""]
            elif member.type is MemberType.HARDLINK:
                links[name] = unicodedata.normalize("NFC", member.link_target or "")
            else:  # a FIFO, device or socket: both other readers list it as a file
                entries[name] = ["other"]
    for name, target in links.items():
        entries[name] = entries[target]
    return entries


def _theirs(tmp_path: Path, reader: str, image: bytes) -> dict:
    path = tmp_path / "image.dmg"
    path.write_bytes(image)
    done = subprocess.run(
        [sys.executable, str(_DUMP), reader, str(path)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout)


def _hidden(name: str) -> bool:
    return name.startswith(_HIDDEN)


@pytest.mark.parametrize("image_id", _IMAGES)
@pytest.mark.parametrize(
    "reader", [pytest.param(r, marks=m) for r, m in _ORACLES.items()]
)
def test_other_readers_agree_with_archivey(
    tmp_path: Path, reader: str, image_id: str
) -> None:
    image = _image_bytes(image_id)
    theirs = _theirs(tmp_path, reader, image)
    refused = _REFUSED.get((reader, image_id))
    if refused is not None:
        assert not theirs["ok"], f"{reader} now reads {image_id}: drop it from _REFUSED"
        assert refused in theirs["error"]
        pytest.skip(f"{reader} cannot read {image_id}: {theirs['error'][:120]}")
    assert theirs["ok"], theirs["error"]
    ours = _ours(image)
    got = {n: v for n, v in theirs["entries"].items() if not _hidden(n)}
    if any(r == reader and image_id.startswith(p) for r, p in _LISTS_NOTHING):
        assert not got, f"{reader} now lists {image_id}: drop it from _LISTS_NOTHING"
        pytest.skip(f"{reader} lists nothing in {image_id}")
    if (reader, image_id) in _NO_MEMBER_DATA:
        for name, entry in ours.items():
            if entry[0] == "dir":
                assert got.get(name) == entry, (name, got.get(name))
            elif entry != ["other"]:
                assert got.get(name, [""])[0] == "error", (
                    f"{reader} now reads {name} in {image_id}: drop it from"
                    " _NO_MEMBER_DATA"
                )
        pytest.skip(f"{reader} reads no file or symlink of {image_id}")
    wrong: set[str] = set()
    for (who, prefix), names in _WRONG.items():
        if who == reader and image_id.startswith(prefix):
            wrong |= names
    for name in wrong:
        assert name in ours, f"{name} is not in {image_id}: drop it from _WRONG"
        assert got.get(name) != ours[name], (
            f"{reader} now reads {name} in {image_id}: drop it from _WRONG"
        )
    for name, entry in ours.items():
        if name in wrong or entry == ["other"]:
            continue
        assert got.get(name) == entry, (name, entry, got.get(name))
    assert set(got) <= set(ours), sorted(set(got) - set(ours))
