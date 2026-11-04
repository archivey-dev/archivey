"""Field survey for the Brotli content-probe investigation — run it, send back the JSON.

Supporting `dev-docs/investigations/brotli-content-probe-results.md`. That investigation
was measured on one Linux container, and three of its conclusions rest on corpora too
small or too uniform to be sure of:

1. **Which executable-header rule is safe.** The results doc recommends keeping
   `e_lfanew` -> `PE\\0\\0` and *not* narrowing to DOS-header fields, because a Linux EFI
   kernel image breaks every field-based rule. That rests on 100 binaries, almost all
   cross-compiled or MSVC library artifacts — no installers, packers, signed EXEs, or
   16-bit/OS-2 binaries. **The `e_lfanew` maximum (280 here) is the single number most
   likely to be wrong.**
2. **What WBITS real Brotli streams use.** Two `.br` files and twelve WOFF2 fonts is not a
   sample. The doc rejects WBITS whitelisting partly on that evidence.
3. **Whether the probe has real-world false positives.** Zero were found in 950 repo files
   and 1200 system binaries, but high-entropy headerless blobs scored 1.5-2.6%.

This script collects exactly that, on whatever machine you run it on.

**It is read-only.** It opens files, reads at most the first 64 KiB of each, and writes one
JSON report where you tell it to. It never modifies, moves, deletes, or uploads anything.

**Zero dependencies** — stdlib only, Python 3.8+. It runs on a bare system interpreter, so
you do not need the archivey venv (or archivey at all) on the machines you survey. If the
`brotli` module happens to be importable it is used as a cross-check, and skipped if not.

Usage::

    python3 brotli_probe_field_survey.py                    # default system roots
    python3 brotli_probe_field_survey.py ~/Downloads /opt    # plus your own paths
    python3 brotli_probe_field_survey.py --self-test         # verify the parser first
    python3 brotli_probe_field_survey.py --out report.json

Privacy: by default the report contains **file basenames only** — no directory paths, no
usernames, no file contents beyond header fields that are format constants (magic numbers,
`e_lfanew`, and the like). Use ``--no-names`` to replace names with content hashes, or
``--full-paths`` if you are surveying a machine where paths are not sensitive. The script
prints a summary of what it collected before writing, and the JSON is plain text you can
read and edit before sending it anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import struct
import sys
import time
from collections import Counter
from datetime import datetime, timezone

SCHEMA = "archivey-brotli-probe-survey/1"

# How much of each file to read. The header parsers need a few hundred bytes; the
# Brotli chain walk seeks, so it does not need the file resident.
HEAD_BYTES = 65536
# The archivey probe feeds this many bytes to the decoder (`_PROBE_PREFIX`).
PROBE_PREFIX = 256
# archivey's detection window (`DETECTION_LIMIT`), for the "would detection see it" flag.
DETECTION_LIMIT = 4096

# ---------------------------------------------------------------------------------------
# RFC 7932 meta-block header parser (the investigation's `hdr.py`, trimmed)
#
# Parses only the layer that decides a stream's fate before any Huffman table is read:
# WBITS, then a meta-block header. Bit order is LSB-first within each byte (RFC 7932 §1.5).
# ---------------------------------------------------------------------------------------

INVALID_WBITS = "invalid_wbits"
EMPTY_LAST = "empty_last"
BAD_PAD_LAST = "bad_pad_last"
EXUBERANT_NIBBLE = "exuberant_nibble"
METADATA = "metadata"
METADATA_BAD = "metadata_bad"
UNCOMPRESSED = "uncompressed"
BAD_PAD_UNCOMP = "bad_pad_uncomp"
COMPRESSED = "compressed"
SHORT = "short"

# Outcomes the reference decoder rejects outright (measured: 0% acceptance each).
FATAL = frozenset(
    {INVALID_WBITS, BAD_PAD_LAST, EXUBERANT_NIBBLE, METADATA_BAD, BAD_PAD_UNCOMP}
)
# Outcomes that declare a length and so survive a bounded prefix.
DECLARING = frozenset({UNCOMPRESSED, METADATA})


class _Bits:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        v = 0
        for i in range(n):
            byte_i, bit_i = divmod(self.pos, 8)
            if byte_i >= len(self.data):
                raise EOFError
            v |= ((self.data[byte_i] >> bit_i) & 1) << i
            self.pos += 1
        return v


def _wbits(br, r):
    if br.take(1) == 0:
        r["wbits"] = 16
        return True
    n = br.take(3)
    if n != 0:
        r["wbits"] = 17 + n
        return True
    m = br.take(3)
    if m == 1:  # reserved for the large-window extension; invalid in RFC 7932
        r["outcome"] = INVALID_WBITS
        return False
    r["wbits"] = 17 if m == 0 else 8 + m
    return True


def _metablock(br, r):
    islast = br.take(1)
    r["islast"] = islast
    if islast and br.take(1):  # ISLASTEMPTY
        pad = (-br.pos) % 8
        ok = pad == 0 or br.take(pad) == 0
        r["outcome"] = EMPTY_LAST if ok else BAD_PAD_LAST
        r["consumed"] = (br.pos + 7) // 8
        return r

    code = br.take(2)
    if code == 3:  # metadata meta-block (MNIBBLES == 0); may carry ISLAST
        if br.take(1) != 0:  # reserved bit
            r["outcome"] = METADATA_BAD
            return r
        nbytes = br.take(2)
        if nbytes == 0:
            skip = 0
        else:
            skip = br.take(nbytes * 8)
            if nbytes > 1 and (skip >> ((nbytes - 1) * 8)) == 0:
                r["outcome"] = METADATA_BAD
                return r
            skip += 1
        pad = (-br.pos) % 8
        if pad and br.take(pad) != 0:
            r["outcome"] = METADATA_BAD
            return r
        r["mlen"] = skip
        r["outcome"] = METADATA
        r["consumed"] = br.pos // 8
        return r

    nibbles = 4 + code
    mlen = 0
    for i in range(nibbles):
        nib = br.take(4)
        if i + 1 == nibbles and nibbles > 4 and nib == 0:
            r["outcome"] = EXUBERANT_NIBBLE
            return r
        mlen |= nib << (4 * i)
    r["mlen"] = mlen + 1

    if not islast and br.take(1):  # ISUNCOMPRESSED
        pad = (-br.pos) % 8
        if pad and br.take(pad) != 0:
            r["outcome"] = BAD_PAD_UNCOMP
            return r
        r["outcome"] = UNCOMPRESSED
        r["consumed"] = br.pos // 8
        return r
    r["outcome"] = COMPRESSED
    return r


def parse_brotli(data, first=True):
    """Classify a prefix as RFC 7932 sees it. ``first=False`` skips the WBITS field."""
    r = {"outcome": None, "wbits": None, "mlen": None, "islast": None, "consumed": None}
    br = _Bits(data)
    try:
        if first and not _wbits(br, r):
            return r
        return _metablock(br, r)
    except EOFError:
        r["outcome"] = SHORT
        return r


def probe_would_accept(outcome):
    """Whether archivey's probe is likely to accept, from the header class alone.

    Calibrated on 200 000 random blobs: UNCOMPRESSED 99.8%, METADATA 51%, COMPRESSED
    0.02%, everything else 0%. Exact only when the real decoder is available.
    """
    return outcome in DECLARING


def framing_fits(info, file_size):
    """The proposed gate: a declared meta-block must fit inside the file."""
    if info["outcome"] not in DECLARING:
        return None
    return info["consumed"] + info["mlen"] <= file_size


def chain_walk(fh, file_size, max_links=64):
    """Follow byte-aligned self-describing meta-blocks as far as framing allows.

    Returns (verdict, links). ``verdict`` is False only when the file provably cannot be
    a complete Brotli stream. Stops at the first compressed meta-block, whose length is
    knowable only by Huffman-decoding it.
    """
    off = 0
    for link in range(max_links):
        try:
            fh.seek(off)
            chunk = fh.read(24)
        except OSError:
            return True, link
        if not chunk:
            return False, link
        info = parse_brotli(chunk, first=(off == 0))
        outcome = info["outcome"]
        if outcome in FATAL:
            return False, link
        if outcome in (COMPRESSED, SHORT):
            return True, link
        if outcome == EMPTY_LAST:
            return off + info["consumed"] == file_size, link
        nxt = off + info["consumed"] + info["mlen"]
        if nxt > file_size:
            return False, link
        if info["islast"]:
            return nxt == file_size, link
        off = nxt
    return True, max_links


# ---------------------------------------------------------------------------------------
# Executable headers
# ---------------------------------------------------------------------------------------

MACHO_MAGICS = {
    0xFEEDFACE: "macho32",
    0xFEEDFACF: "macho64",
    0xCEFAEDFE: "macho32-swapped",
    0xCFFAEDFE: "macho64-swapped",
    0xCAFEBABE: "fat-or-java",  # Mach-O universal binary *and* Java .class share this
    0xBEBAFECA: "fat-swapped",
}
PE_SIGNATURES = (b"PE\x00\x00", b"NE", b"LE", b"LX", b"LC")


def analyse_pe(head, file_size=None, fh=None):
    """DOS/PE header fields, plus every candidate cue rule's verdict.

    ``e_lfanew`` is bounded against the *file*, not against the head buffer: a stub big
    enough to push the PE header past ``HEAD_BYTES`` is exactly the installer/packer case
    this script exists to measure, and bounding against the buffer would silently drop it
    from the maximum. When the signature sits past the head buffer, seek for it.
    """
    if len(head) < 0x40:
        return {"truncated": True}
    e_cblp, e_cp = struct.unpack_from("<HH", head, 2)
    (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
    limit = (file_size if file_size is not None else len(head)) - 4
    in_bounds = 0x40 <= e_lfanew <= limit
    sig = b""
    beyond_head = False
    if in_bounds:
        if e_lfanew + 4 <= len(head):
            sig = head[e_lfanew : e_lfanew + 4]
        elif fh is not None:
            beyond_head = True
            try:
                fh.seek(e_lfanew)
                sig = fh.read(4)
            except OSError:
                sig = b""
    sig2 = sig[:2]
    return {
        "bytes_0_3": head[:4].hex(" "),
        "e_cblp": e_cblp,
        "e_cp": e_cp,
        "e_lfanew": e_lfanew,
        "e_lfanew_in_bounds": in_bounds,
        "e_lfanew_beyond_head": beyond_head,
        "e_lfanew_align8": e_lfanew % 8 == 0,
        "e_lfanew_align4": e_lfanew % 4 == 0,
        "signature": sig.hex(" ") if sig else None,
        "signature_ascii": (
            sig.decode("ascii", "replace").replace("\x00", ".") if sig else None
        ),
        # The candidate STRONG rules the results doc compares (§7).
        "rule_e_cblp_le_512": e_cblp <= 512,
        "rule_bytes23_9000": head[2:4] == b"\x90\x00",
        "rule_pe_sig": sig == b"PE\x00\x00",
        "rule_pe_ne_le_lx": sig2 in (b"PE", b"NE", b"LE", b"LX"),
        "rule_lfanew_le_1024": in_bounds and e_lfanew <= 1024,
    }


def analyse_elf(head):
    if len(head) < 16:
        return {"truncated": True}
    ei_class, ei_data, ei_version, ei_osabi = head[4], head[5], head[6], head[7]
    return {
        "ei_class": ei_class,
        "ei_data": ei_data,
        "ei_version": ei_version,
        "ei_osabi": ei_osabi,
        # archivey's STRONG ELF cue: a structurally valid identification block.
        "ident_valid": ei_class in (1, 2) and ei_data in (1, 2) and ei_version == 1,
    }


def analyse_macho(head):
    if len(head) < 8:
        return {"truncated": True}
    (be,) = struct.unpack_from(">I", head, 0)
    kind = MACHO_MAGICS.get(be)
    out = {"magic_be": "0x%08x" % be, "kind": kind}
    if be == 0xCAFEBABE:
        # Java class files share this magic. Both put a small number in bytes 4-7, so
        # "is it small?" does not separate them: a Java 8 class reads 0x00000034 = 52.
        # Split on the field layout instead — Java has minor_version then major_version,
        # and major has been >= 45 since JDK 1.1; Mach-O has a single nfat_arch count.
        minor, major = struct.unpack_from(">HH", head, 4)
        (nfat,) = struct.unpack_from(">I", head, 4)
        out["next_u32"] = nfat
        out["java_major"] = major
        if minor in (0, 0xFFFF) and 45 <= major <= 80:
            out["likely"] = "java-class"
        elif 1 <= nfat <= 32:
            out["likely"] = "macho-fat"
        else:
            out["likely"] = "unknown"
    return out


def classify(head):
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if len(head) >= 4 and struct.unpack_from(">I", head, 0)[0] in MACHO_MAGICS:
        return "macho"
    if head[:4] == b"wOF2":
        return "woff2"
    if head[:4] == b"wOFF":
        return "woff"
    return "other"


# ---------------------------------------------------------------------------------------
# WOFF2: locate the embedded raw Brotli stream
# ---------------------------------------------------------------------------------------


def woff2_stream_offset(fh, head):
    """Byte offset of the raw Brotli stream inside a WOFF2 file, or None.

    The table directory is variable-length, so the offset is found by scanning for the
    first position at which ``totalCompressedSize`` bytes parse as a Brotli header that
    is not immediately invalid. Cheap and good enough for a WBITS census.
    """
    if len(head) < 48:
        return None, None
    try:
        (total_comp,) = struct.unpack_from(">I", head, 20)
    except struct.error:
        return None, None
    for off in range(48, min(len(head), 4096)):
        info = parse_brotli(head[off : off + 64])
        if info["outcome"] in FATAL or info["outcome"] == SHORT:
            continue
        # A real stream's first meta-block is essentially always compressed.
        if info["outcome"] == COMPRESSED:
            return off, total_comp
    return None, total_comp


# ---------------------------------------------------------------------------------------
# Walking
# ---------------------------------------------------------------------------------------

SKIP_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/private/var/vm",
    "/System/Volumes",
    "/.Spotlight-V100",
    "/.fseventsd",
    "/net",
    "/Network",
}
SKIP_NAMES = {".git", "node_modules", "__pycache__", ".svn", ".hg"}


def default_roots():
    system = platform.system()
    home = os.path.expanduser("~")
    if system == "Windows":
        roots = [
            os.environ.get("SystemRoot", r"C:\Windows"),
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.path.join(home, "Downloads"),
        ]
    elif system == "Darwin":
        roots = [
            "/bin",
            "/usr/bin",
            "/usr/lib",
            "/usr/libexec",
            "/usr/local",
            "/Applications",
            "/System/Library/CoreServices",
            os.path.join(home, "Downloads"),
        ]
    else:
        roots = [
            "/bin",
            "/usr/bin",
            "/usr/lib",
            "/usr/libexec",
            "/usr/local",
            "/opt",
            os.path.join(home, "Downloads"),
        ]
    return [r for r in roots if r and os.path.exists(r)]


def iter_files(roots, max_files, deadline, errors):
    seen_dirs = set()
    yielded = 0
    for root in roots:
        if os.path.isfile(root):
            yield root
            yielded += 1
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if time.time() > deadline or yielded >= max_files:
                return
            if any(dirpath.startswith(s) for s in SKIP_DIRS):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_NAMES]
            # Key on the resolved path, not st_ino: Windows reports st_ino == 0 on some
            # filesystems, which would collapse every such directory into one "seen"
            # entry and silently truncate the scan.
            try:
                key = os.path.normcase(os.path.realpath(dirpath))
            except OSError as exc:
                errors[type(exc).__name__] += 1
                continue
            if key in seen_dirs:
                dirnames[:] = []
                continue
            seen_dirs.add(key)
            for name in filenames:
                if yielded >= max_files or time.time() > deadline:
                    return
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    continue
                yield path
                yielded += 1


# ---------------------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------------------


def analyse_file(path, real_probe):
    """Return a record dict, or None if the file is uninteresting/unreadable."""
    try:
        size = os.path.getsize(path)
        if size < 8:
            return None
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
            kind = classify(head)
            ext = os.path.splitext(path)[1].lower()

            rec = {
                "name": os.path.basename(path),
                "path": path,
                "ext": ext,
                "size": size,
                "kind": kind,
                "sha256_head12": hashlib.sha256(head[:8192]).hexdigest()[:12],
            }

            if kind == "pe":
                rec["pe"] = analyse_pe(head, size, fh)
            elif kind == "elf":
                rec["elf"] = analyse_elf(head)
            elif kind == "macho":
                rec["macho"] = analyse_macho(head)

            # --- the Brotli question, for every file ---
            info = parse_brotli(head[:DETECTION_LIMIT])
            rec["brotli"] = {
                "outcome": info["outcome"],
                "wbits": info["wbits"],
                "mlen": info["mlen"],
                "consumed": info["consumed"],
                "islast": info["islast"],
                "header_accepts": probe_would_accept(info["outcome"]),
                "framing_fits": framing_fits(info, size),
            }
            if probe_would_accept(info["outcome"]):
                verdict, links = chain_walk(fh, size)
                rec["brotli"]["chain_ok"] = verdict
                rec["brotli"]["chain_links"] = links
                rec["brotli"]["head_hex"] = head[:16].hex(" ")

            if real_probe is not None:
                rec["brotli"]["decoder_accepts"] = real_probe(head[:PROBE_PREFIX])

            # --- real Brotli streams: .br files and WOFF2 payloads ---
            if ext == ".br":
                rec["brotli_stream"] = {
                    "source": "br-file",
                    "offset": 0,
                    "wbits": info["wbits"],
                    "first_metablock": info["outcome"],
                }
            elif kind == "woff2":
                off, total = woff2_stream_offset(fh, head)
                if off is not None:
                    sub = parse_brotli(head[off : off + 64])
                    rec["brotli_stream"] = {
                        "source": "woff2",
                        "offset": off,
                        "compressed_size": total,
                        "wbits": sub["wbits"],
                        "first_metablock": sub["outcome"],
                    }
            return rec
    except OSError:
        return None
    except (struct.error, ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------------------


def hist(counter, limit=40):
    items = counter.most_common(limit)
    return {str(k): v for k, v in items}


def summarise(records):
    kinds = Counter(r["kind"] for r in records)
    pes = [r for r in records if r["kind"] == "pe" and "truncated" not in r["pe"]]
    elves = [r for r in records if r["kind"] == "elf"]
    acheron = [r for r in records if r["kind"] == "macho"]

    pe_summary = {}
    if pes:
        lfa = [r["pe"]["e_lfanew"] for r in pes if r["pe"]["e_lfanew_in_bounds"]]
        rules = [
            "rule_e_cblp_le_512",
            "rule_bytes23_9000",
            "rule_pe_sig",
            "rule_pe_ne_le_lx",
            "rule_lfanew_le_1024",
        ]
        pe_summary = {
            "count": len(pes),
            "bytes_2_3": hist(Counter(r["pe"]["bytes_0_3"][6:] for r in pes)),
            "e_cblp": hist(Counter(r["pe"]["e_cblp"] for r in pes)),
            "e_cp": hist(Counter(r["pe"]["e_cp"] for r in pes)),
            "e_lfanew": hist(Counter(r["pe"]["e_lfanew"] for r in pes)),
            "e_lfanew_min": min(lfa) if lfa else None,
            "e_lfanew_max": max(lfa) if lfa else None,
            "e_lfanew_out_of_bounds": sum(
                1 for r in pes if not r["pe"]["e_lfanew_in_bounds"]
            ),
            "e_lfanew_unaligned8": sum(
                1 for r in pes if not r["pe"]["e_lfanew_align8"]
            ),
            "e_lfanew_unaligned4": sum(
                1 for r in pes if not r["pe"]["e_lfanew_align4"]
            ),
            "signatures": hist(Counter(str(r["pe"]["signature_ascii"]) for r in pes)),
            "rule_pass_counts": {k: sum(1 for r in pes if r["pe"][k]) for k in rules},
            # The binaries that decide which cue rule is safe. Named here rather than
            # left to the detail cap, where a flood of probe hits can crowd them out.
            "outliers": [
                {
                    "name": r.get("name"),
                    "path": r.get("path"),
                    "bytes_0_3": r["pe"]["bytes_0_3"],
                    "e_cblp": r["pe"]["e_cblp"],
                    "e_cp": r["pe"]["e_cp"],
                    "e_lfanew": r["pe"]["e_lfanew"],
                    "signature": r["pe"]["signature_ascii"],
                    "size": r["size"],
                    "fails": [k for k in rules if not r["pe"][k]]
                    + ([] if r["pe"]["e_lfanew_align8"] else ["align8"]),
                }
                for r in sorted(
                    (
                        r
                        for r in pes
                        if r["pe"]["e_lfanew"] > 512
                        or not all(r["pe"][k] for k in rules)
                        or not r["pe"]["e_lfanew_align8"]
                    ),
                    key=lambda r: -r["pe"]["e_lfanew"],
                )[:25]
            ],
        }

    streams = [r for r in records if "brotli_stream" in r]
    hits = [r for r in records if r["brotli"]["header_accepts"]]

    return {
        "kinds": hist(kinds),
        "pe": pe_summary,
        "elf": {
            "count": len(elves),
            "ident_valid": sum(1 for r in elves if r["elf"].get("ident_valid")),
        },
        "macho": {
            "count": len(acheron),
            "kinds": hist(Counter(str(r["macho"].get("kind")) for r in acheron)),
            "likely": hist(Counter(str(r["macho"].get("likely")) for r in acheron)),
        },
        "brotli_streams": {
            "count": len(streams),
            "wbits": hist(Counter(str(r["brotli_stream"]["wbits"]) for r in streams)),
            "by_source": hist(Counter(r["brotli_stream"]["source"] for r in streams)),
            "first_metablock": hist(
                Counter(r["brotli_stream"]["first_metablock"] for r in streams)
            ),
        },
        "probe": {
            "scanned": len(records),
            "header_accepts": len(hits),
            "header_outcomes": hist(Counter(r["brotli"]["outcome"] for r in records)),
            "hits_by_ext": hist(Counter(r["ext"] or "<none>" for r in hits)),
            "hits_by_kind": hist(Counter(r["kind"] for r in hits)),
            "framing_gate_would_reject": sum(
                1 for r in hits if r["brotli"]["framing_fits"] is False
            ),
            "chain_walk_would_reject": sum(
                1 for r in hits if r["brotli"].get("chain_ok") is False
            ),
            "survives_both_gates": sum(
                1
                for r in hits
                if r["brotli"]["framing_fits"] is not False
                and r["brotli"].get("chain_ok") is not False
            ),
        },
    }


def interesting(records):
    """The records worth shipping in full, rarest first.

    Ordered rather than left in walk order: the detail list is capped, and a large
    false-positive set would otherwise crowd out the PE rule-violators and real Brotli
    streams that the survey exists to collect. Probe hits are the most numerous and the
    least individually informative, so they go last — and the gate-surviving ones go
    before the rest, since those are the residual worth naming.
    """
    scored = []
    for r in records:
        pe = r.get("pe") or {}
        odd_pe = r["kind"] == "pe" and (
            not pe.get("rule_e_cblp_le_512", True)
            or not pe.get("rule_bytes23_9000", True)
            or not pe.get("rule_pe_sig", True)
            or not pe.get("e_lfanew_align8", True)
            or not pe.get("e_lfanew_in_bounds", True)
            or (pe.get("e_lfanew") or 0) > 512
        )
        hit = r["brotli"]["header_accepts"]
        survives = hit and r["brotli"].get("chain_ok") is not False
        if odd_pe:
            rank = 0
        elif "brotli_stream" in r:
            rank = 1
        elif survives:
            rank = 2
        elif hit:
            rank = 3
        else:
            continue
        scored.append((rank, r))
    scored.sort(key=lambda pair: pair[0])
    return [r for _rank, r in scored]


SELF_TEST_VECTORS = [
    (b"MZ" + b"\x90" * 254, UNCOMPRESSED, 23, 2171061),
    (b"MZ" + b"\x00" * 254, EXUBERANT_NIBBLE, 23, None),
    (b"MZ" + b"A" * 254, COMPRESSED, 23, 8553141),
    (b"\x7fELF" + b"\x00" * 60, BAD_PAD_LAST, 24, None),
    (b"\x06" + b"\x00" * 60, EMPTY_LAST, 16, None),
    (b"MZ\x90\x00" + b"\x90" * 252, EXUBERANT_NIBBLE, 23, None),
]


def self_test():
    ok = True
    print("RFC 7932 header parser self-test")
    for data, want_outcome, want_wbits, want_mlen in SELF_TEST_VECTORS:
        got = parse_brotli(data)
        good = got["outcome"] == want_outcome and got["wbits"] == want_wbits
        if want_mlen is not None:
            good = good and got["mlen"] == want_mlen
        ok = ok and good
        print(
            "  %-5s %-22s outcome=%-17s wbits=%-5s mlen=%s"
            % (
                "ok" if good else "FAIL",
                repr(data[:6])[1:],
                got["outcome"],
                got["wbits"],
                got["mlen"],
            )
        )
    try:
        import brotli  # noqa: F401

        print("  brotli module present — decoder cross-check will be included")
    except ImportError:
        print("  brotli module absent — header classification only (this is fine)")
    print("PASS" if ok else "FAIL — please report this")
    return 0 if ok else 1


def load_real_probe():
    """archivey's actual probe, if the `brotli` module is importable here."""
    try:
        import brotli
    except ImportError:
        return None

    def probe(prefix):
        try:
            brotli.Decompressor().process(prefix)
        except brotli.error:
            return False
        return True

    return probe


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Survey executables and Brotli streams for the archivey "
        "brotli-content-probe investigation.",
        epilog="Read-only. Writes one JSON report; uploads nothing.",
    )
    ap.add_argument(
        "roots", nargs="*", help="files/directories to scan (default: system)"
    )
    ap.add_argument("--out", default=None, help="JSON report path")
    ap.add_argument("--max-files", type=int, default=40000)
    ap.add_argument("--time-limit", type=float, default=600.0, help="seconds")
    ap.add_argument("--max-detail", type=int, default=400, help="max detailed records")
    ap.add_argument("--full-paths", action="store_true", help="include directory paths")
    ap.add_argument("--no-names", action="store_true", help="drop names, keep hashes")
    ap.add_argument(
        "--self-test", action="store_true", help="verify the parser and exit"
    )
    ap.add_argument(
        "--emit-json",
        action="store_true",
        help="also print the report to stdout (for CI logs, where artifacts are awkward)",
    )
    args = ap.parse_args(argv)

    # Filenames are arbitrary bytes; a Windows console defaulting to cp1252 would raise
    # UnicodeEncodeError part-way through the summary and lose the whole run.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass

    if args.self_test:
        return self_test()

    roots = args.roots or default_roots()
    if not roots:
        print("no scan roots found; pass some paths explicitly", file=sys.stderr)
        return 2

    real_probe = load_real_probe()
    deadline = time.time() + args.time_limit
    errors = Counter()
    records = []
    started = time.time()

    print(
        "scanning %d root(s), max %d files, %.0fs budget"
        % (len(roots), args.max_files, args.time_limit)
    )
    for path in iter_files(roots, args.max_files, deadline, errors):
        rec = analyse_file(path, real_probe)
        if rec is not None:
            records.append(rec)
        if len(records) % 5000 == 0 and records:
            print("  ... %d files" % len(records))

    summary = summarise(records)
    detail = interesting(records)[: args.max_detail]

    for rec in detail:
        if args.no_names:
            rec.pop("name", None)
            rec.pop("path", None)
        elif not args.full_paths:
            rec.pop("path", None)

    report = {
        "schema": SCHEMA,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": round(time.time() - started, 1),
        "environment": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "decoder_cross_check": real_probe is not None,
        },
        "options": {
            "roots": roots
            if args.full_paths
            else [os.path.basename(r) or r for r in roots],
            "max_files": args.max_files,
            "full_paths": args.full_paths,
            "no_names": args.no_names,
        },
        "summary": summary,
        "detail": detail,
        "walk_errors": hist(errors),
    }

    out = args.out or "brotli-survey-%s-%s.json" % (
        platform.system().lower(),
        datetime.now().strftime("%Y%m%d-%H%M%S"),
    )
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, sort_keys=True)

    # JSON first, human summary last: in a CI log the summary is what gets read, and a
    # 60-line tail should reach it however big the report grew.
    if args.emit_json:
        print("\n----- BEGIN REPORT JSON -----")
        print(json.dumps(report, indent=1, sort_keys=True))
        print("----- END REPORT JSON -----")
    print_summary(report, out)
    return 0


def print_summary(report, out):
    s = report["summary"]
    print("\n" + "=" * 72)
    print(
        "scanned %d files in %ss on %s/%s"
        % (
            s["probe"]["scanned"],
            report["elapsed_s"],
            report["environment"]["system"],
            report["environment"]["machine"],
        )
    )
    print("file kinds: %s" % s["kinds"])

    if s["pe"]:
        pe = s["pe"]
        print("\nPE/DOS headers (%d binaries)" % pe["count"])
        print("  bytes 2-3:  %s" % pe["bytes_2_3"])
        print("  e_cblp:     %s" % pe["e_cblp"])
        print("  e_lfanew:   %s" % pe["e_lfanew"])
        print(
            "  e_lfanew range %s..%s   unaligned(8): %d   out of bounds: %d"
            % (
                pe["e_lfanew_min"],
                pe["e_lfanew_max"],
                pe["e_lfanew_unaligned8"],
                pe["e_lfanew_out_of_bounds"],
            )
        )
        print("  signatures: %s" % pe["signatures"])
        print("  candidate cue rules, binaries accepted out of %d:" % pe["count"])
        for k, v in sorted(pe["rule_pass_counts"].items()):
            flag = "" if v == pe["count"] else "   <-- rejects real binaries"
            print("    %-22s %5d%s" % (k, v, flag))
        if pe.get("outliers"):
            print("  binaries that decide the ranking (largest e_lfanew first):")
            for o in pe["outliers"][:12]:
                print(
                    "    e_lfanew=%-6d %s e_cblp=%-5d %s"
                    % (o["e_lfanew"], o["bytes_0_3"], o["e_cblp"], ",".join(o["fails"]))
                )
                print("      %s" % (o.get("path") or o.get("name")))

    if s["macho"]["count"]:
        print("\nMach-O: %d  %s" % (s["macho"]["count"], s["macho"]["likely"]))
        print(
            "  (archivey's executable cue handles MZ and ELF only — these get no cue)"
        )

    st = s["brotli_streams"]
    if st["count"]:
        print("\nreal Brotli streams found: %d  %s" % (st["count"], st["by_source"]))
        print("  WBITS: %s" % st["wbits"])

    p = s["probe"]
    print("\nBrotli content probe")
    print("  header would accept: %d / %d files" % (p["header_accepts"], p["scanned"]))
    if p["header_accepts"]:
        print("  by extension: %s" % p["hits_by_ext"])
        print("  framing gate would reject: %d" % p["framing_gate_would_reject"])
        print("  chain walk would reject:   %d" % p["chain_walk_would_reject"])
        print("  survives both gates:       %d" % p["survives_both_gates"])

    print("\nwrote %s (%d detailed records)" % (out, len(report["detail"])))
    print(
        "Please review it — it is plain JSON — and send it back. Nothing was uploaded."
    )
    print("=" * 72)


if __name__ == "__main__":
    sys.exit(main())
