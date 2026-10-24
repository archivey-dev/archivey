# Recipes

Each recipe on this page is a complete script for one common job. The first group is for data
pipelines that download and unpack datasets. The second is for servers that check archives
uploaded by users. The pages they link to explain the options in full.

## Data pipelines

### Download a dataset and extract it

This replaces `tarfile.extractall`, `shutil.unpack_archive` and helpers such as torchvision's
`download_and_extract_archive`:

```python
import hashlib
import shutil
import urllib.request

import archivey

URL = "https://example.com/dataset.tar.gz"
# The checksum published with the dataset
SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

with urllib.request.urlopen(URL) as response, open("dataset.tar.gz", "wb") as f:
    shutil.copyfileobj(response, f)

with open("dataset.tar.gz", "rb") as f:
    if hashlib.file_digest(f, "sha256").hexdigest() != SHA256:
        raise RuntimeError("dataset.tar.gz does not match its published checksum")

with archivey.open_archive("dataset.tar.gz") as archive:
    report = archive.extract_all(
        "data/",
        overwrite="replace",
        abort_on=["blocked_member"],
    )

extracted = [r for r in report if r.status is archivey.ExtractionStatus.EXTRACTED]
print(len(extracted), "members extracted")
```

The same code works for a ZIP, 7z or RAR download, because `open_archive` identifies the format
from the file's contents. `overwrite="replace"` lets the script run again over an earlier run's
files. Without it, the first file that's already there stops the extraction. With
`abort_on=["blocked_member"]`, a member that would land outside `data/`, such as `../evil.txt`,
stops the extraction with an exception. Without it, that member is skipped and the report lists it
as `ExtractionStatus.BLOCKED`. [Extracting](extracting.md#options) explains both options.

By default, an extraction raises `ResourceLimitError` once it has written 2 GiB or 262,144 entries,
or when data expands more than 1000 times. A sparse TAR member, such as a disk image, can expand
that much on its own. Listing an archive also raises `ResourceLimitError` past 262,144 members, or
past 64 MiB of text kept for names, comments and link targets. A larger dataset from a source you
trust needs higher limits:

```python
import archivey

config = archivey.ArchiveyConfig(listing_limits=archivey.ListingLimits.UNLIMITED)

with archivey.open_archive("dataset.tar.gz", config=config) as archive:
    archive.extract_all("data/", limits=archivey.ExtractionLimits.UNLIMITED)
```

`ExtractionLimits.UNLIMITED` turns off all three extraction limits, the expansion check included,
and `ListingLimits.UNLIMITED` turns off both listing limits. Listing still costs about 1.5 KiB of
memory per member. To keep some protection, raise single fields instead, such as
`ListingLimits(max_members=5_000_000, max_metadata_bytes=2**30)`.
[Hardening](security.md#hardening) lists each limit with its default and what it costs.

### Extract while downloading

An HTTP response can't seek, so it opens with `streaming=True`. Nothing is saved apart from the
extracted files:

```python
import urllib.request

import archivey

URL = "https://example.com/dataset.tar.gz"

with urllib.request.urlopen(URL) as response:
    with archivey.open_archive(response, streaming=True) as archive:
        archive.extract_all("data/", overwrite="replace")
```

This works for TAR and ZIP archives and single compressed files. 7z, RAR and ISO archives need a
source that can seek, so for them `open_archive` raises `StreamNotSeekableError`, and the download
needs to be saved first, as in the previous recipe.

If the download stops partway, the call raises `TruncatedError` or another `CorruptionError`. From
a TAR, the members written before then stay in `data/`. A ZIP keeps its index at the end, so its
members are put in place only once the whole download has arrived, and a download that stops
earlier leaves nothing in `data/`. [Reading once](reading.md#reading-once) has the details.

### Read members without extracting

A member stream is a binary file object, so `json`, `csv` and most other readers take it as is:

```python
import csv
import io
import json

import archivey

with archivey.open_archive("dataset.zip") as archive:
    with archive.open("data/meta.json") as stream:
        meta = json.load(stream)
    with archive.open("data/train.csv") as stream:
        text = io.TextIOWrapper(stream, encoding="utf-8", newline="")
        rows = list(csv.DictReader(text))

print(meta, len(rows))
```

If you use pandas, `read_csv` takes the stream the same way:

```python
import archivey
import pandas as pd

with archivey.open_archive("dataset.zip") as archive:
    with archive.open("data/train.csv") as stream:
        df = pd.read_csv(stream)

print(df.shape)
```

Member streams don't seek by default. A reader that needs to seek, such as one for Parquet files,
needs `seekable_members=True` ([Seeking inside a member](reading.md#seeking-inside-a-member)). On
a `.tar.gz` or a solid 7z archive, opening members one by one decompresses the data before each of
them again, and the next recipe avoids that.

### Read every member of a large archive once

```python
import csv
import io

import archivey


def is_csv(member):
    return member.name.endswith(".csv")


row_counts = {}
with archivey.open_archive("dataset.tar.gz", streaming=True) as archive:
    for member, stream in archive.stream_members(is_csv):
        if not member.is_file or stream is None:
            continue
        text = io.TextIOWrapper(stream, encoding="utf-8", newline="")
        row_counts[member.name] = sum(1 for _ in csv.reader(text))

print(row_counts)
```

`stream_members` decompresses the archive once, from start to end, and gives you each member with
a stream of its contents. The function passed to it chooses the members, and the others are skipped
without being handed to you. Each stream works only until the loop moves on. With
`streaming=True`, the same loop also reads from an HTTP response, as in [Extract while
downloading](#extract-while-downloading). [Read everything in one
pass](index.md#read-everything-in-one-pass) explains the loop.

## Checking uploaded archives

An archive uploaded by a user can be built to harm the server that opens it. The recipes in this
group read uploads with lower limits than the defaults, run decoders in child processes, and treat
anything unusual as a reason to refuse the upload. [Security](security.md) explains what archivey
protects against and where that stops.

### List, hash and test an upload

```python
import hashlib

import archivey

CONFIG = archivey.ArchiveyConfig(
    listing_limits=archivey.ListingLimits(
        max_members=10_000,
        max_metadata_bytes=4 * 2**20,
    ),
    decoder_limits=archivey.DecoderLimits(max_decoder_memory=256 * 2**20),
    process_isolation=archivey.ProcessIsolation.NATIVE_DECODERS,
    diagnostic_policy=archivey.DiagnosticPolicy.STRICT,
)
MAX_TOTAL_BYTES = 1 * 2**30


class UploadTooLarge(Exception):
    pass


def scan_upload(path):
    entries = []
    total = 0
    with archivey.open_archive(path, streaming=True, config=CONFIG) as archive:
        for member, stream in archive.stream_members():
            sha256 = None
            if member.is_file and stream is not None:
                digest = hashlib.sha256()
                while chunk := stream.read(2**20):
                    total += len(chunk)
                    if total > MAX_TOTAL_BYTES:
                        raise UploadTooLarge(path)
                    digest.update(chunk)
                sha256 = digest.hexdigest()
            entries.append((member.name, member.type.value, member.size, sha256))
    return entries


for entry in scan_upload("upload.zip"):
    print(entry)
```

Reading each member to its end also tests it: where the format stores a checksum, the read that
reaches the end raises if the data is damaged. No password is given, so an encrypted member raises
`EncryptionError`.

Each setting in `CONFIG` does one job:

- `listing_limits` caps how many members the archive may list and how much text their names,
  comments and link targets may take.
- `decoder_limits` caps the memory the archive can ask a decoder for. Lower it to what one upload
  may use on your server.
- `ProcessIsolation.NATIVE_DECODERS` runs every native decoder, such as zlib, bz2 and lzma, in a
  child process, so a crash in one raises `CorruptionError` for that member instead of ending your
  server. AES decryption and checksums still run in your process. A large stream reads about
  1.05 to 6 times slower depending on the compression, and each member with its own decoder adds
  about 1 ms (2 ms for PPMd), which is most of the cost for an archive of many small members
  ([Decoders in a child process](security.md#decoders-in-a-child-process)).
- `DiagnosticPolicy.STRICT` raises `DiagnosticRaisedError` when the archive itself is unusual, such
  as a name that displays as a different one, bytes after the end of the archive, or a TAR that ends
  without its end marker
  ([Raising or quieting a diagnostic](errors-and-diagnostics.md#raising-or-quieting-a-diagnostic)).

`ExtractionLimits` covers only what `extract_all` writes, so a loop that reads member data keeps
its own count. [Where the guarantees stop](security.md#where-the-guarantees-stop) says which limits
apply to a read, and [Hardening](security.md#hardening) lists every limit.

### Refuse an upload with a reason

Every problem with the archive raises a subclass of `ArchiveyError`. A server can turn each one into
a reason for the user. `CONFIG` and the byte count are the ones from the previous recipe:

```python
import zipfile

import archivey

CONFIG = archivey.ArchiveyConfig(
    listing_limits=archivey.ListingLimits(
        max_members=10_000,
        max_metadata_bytes=4 * 2**20,
    ),
    decoder_limits=archivey.DecoderLimits(max_decoder_memory=256 * 2**20),
    process_isolation=archivey.ProcessIsolation.NATIVE_DECODERS,
    diagnostic_policy=archivey.DiagnosticPolicy.STRICT,
)
MAX_TOTAL_BYTES = 1 * 2**30


class UploadTooLarge(Exception):
    pass


def check_upload(path):
    total = 0
    try:
        with archivey.open_archive(path, streaming=True, config=CONFIG) as archive:
            for member, stream in archive.stream_members():
                if stream is not None:
                    while chunk := stream.read(2**20):
                        total += len(chunk)
                        if total > MAX_TOTAL_BYTES:
                            raise UploadTooLarge(path)
    except UploadTooLarge:
        return "the archive is too large"
    except archivey.FormatDetectionError:
        return "not an archive"
    except archivey.EncryptionError:
        return "encrypted archives are not accepted"
    except archivey.CorruptionError:
        return "the archive is damaged"
    except archivey.ResourceUnavailableError:
        return "the server is short of memory; try again later"
    except archivey.ResourceLimitError:
        return "the archive is too large"
    except archivey.DiagnosticRaisedError as e:
        return f"the archive looks unusual ({e.diagnostic.code.value})"
    except archivey.UnsupportedFeatureError:
        return "the archive uses a feature that is not supported"
    except archivey.ArchiveyError:
        return "the archive could not be read"
    return "accepted"


with zipfile.ZipFile("upload.zip", "w") as zf:
    zf.writestr("report.txt", "hello")
print(check_upload("upload.zip"))

with open("damaged.zip", "wb") as f:
    f.write(open("upload.zip", "rb").read()[:-30])
print(check_upload("damaged.zip"))
```

What each exception means for an upload:

- **`FormatDetectionError`**: the file isn't in a format archivey reads.
- **`EncryptionError`**: a member needs a password. 7z archives and old ZIP encryption can't tell
  damage from a wrong password, so damage in an encrypted member raises this too.
- **`CorruptionError`**, with its subclass `TruncatedError`: the data is damaged or ends early.
- **`ResourceLimitError`**: the archive went over a limit. Its subclass `ResourceUnavailableError`
  means the machine ran short instead: a decoder's child process was killed from outside, most
  often by the out-of-memory killer, or no child process could start. Retrying with more memory
  may work; raising a limit won't.
- **`DiagnosticRaisedError`**: `DiagnosticPolicy.STRICT` raised a diagnostic. `e.diagnostic.code`
  says which one.
- **`UnsupportedFeatureError`**: the format is recognized, but the archive uses something archivey
  can't handle, such as an unknown compression method. A damaged header can look like this.
- **`PackageNotInstalledError`**: reading the archive needs an optional package or program that
  your server doesn't have, such as `unrar`. That's worth logging as your problem, not the user's.

Some errors aren't about the archive, so `except archivey.ArchiveyError` doesn't catch them.
`ArchiveyUsageError` means a mistake in the calling code, `OSError` a problem with your own disk,
and `MemoryError` that your process ran out of memory. Any other exception type from inside archivey
is a bug. [Errors and diagnostics](errors-and-diagnostics.md#exceptions) has the full hierarchy.

### Stop a scan that takes too long

The limits cap bytes, entries and password-hashing work, not time. For a hard time limit, run the
scan in a worker process and kill it when the time runs out:

```python
import multiprocessing
import zipfile

import archivey

CONFIG = archivey.ArchiveyConfig(
    listing_limits=archivey.ListingLimits(
        max_members=10_000,
        max_metadata_bytes=4 * 2**20,
    ),
    decoder_limits=archivey.DecoderLimits(max_decoder_memory=256 * 2**20),
    process_isolation=archivey.ProcessIsolation.NATIVE_DECODERS,
    diagnostic_policy=archivey.DiagnosticPolicy.STRICT,
)


def list_upload(path):
    with archivey.open_archive(path, streaming=True, config=CONFIG) as archive:
        return [member.name for member in archive]


def list_with_timeout(path, seconds):
    with multiprocessing.get_context("spawn").Pool(1) as pool:
        return pool.apply_async(list_upload, (path,)).get(timeout=seconds)


if __name__ == "__main__":
    with zipfile.ZipFile("upload.zip", "w") as zf:
        zf.writestr("report.txt", "hello")
    try:
        print(list_with_timeout("upload.zip", 30))
    except multiprocessing.TimeoutError:
        print("the scan took too long")
```

Leaving the `with` block terminates the worker, also when the time ran out in the middle of a
decoder. An `ArchiveyError` raised in the worker reaches the caller with its details, since
archivey's exceptions can be pickled. The worker can be any function, such as `scan_upload` from
the first recipe in this group, as long as it's defined at the top level of a module.

If you only need to know whether the archive passed, and not data from it, the command line in a
subprocess with a timeout is simpler. [Where the guarantees stop](security.md#where-the-guarantees-stop)
shows it.

### Extract an upload

```python
import tempfile

import archivey

CONFIG = archivey.ArchiveyConfig(
    listing_limits=archivey.ListingLimits(
        max_members=10_000,
        max_metadata_bytes=4 * 2**20,
    ),
    decoder_limits=archivey.DecoderLimits(max_decoder_memory=256 * 2**20),
    process_isolation=archivey.ProcessIsolation.NATIVE_DECODERS,
    diagnostic_policy=archivey.DiagnosticPolicy.STRICT,
)

with archivey.open_archive("upload.zip", config=CONFIG) as archive:
    dest = tempfile.mkdtemp(prefix="upload-")
    report = archive.extract_all(
        dest,
        abort_on=["blocked_member", "name_collision"],
        limits=archivey.ExtractionLimits(
            max_extracted_bytes=500 * 2**20,
            max_entries=10_000,
        ),
    )

print(dest, len(report))
```

`CONFIG` is the one from [List, hash and test an upload](#list-hash-and-test-an-upload). A new,
empty folder for each upload means nothing else can be in the way, and you can check what
came out before moving it anywhere else. The default `policy="strict"` refuses or rewrites every
kind of unsafe member archivey knows of, and `abort_on` turns a refused member, or two members that
would be written to the same path, into an exception that ends the extraction. Files written before
then stay in `dest`. [What each policy does with unusual
members](extracting.md#what-each-policy-does-with-unusual-members) lists the cases.

### Archives inside the upload

The limits apply to each archive separately. A small upload can hold archives that each expand up
to the limit, and those can hold more. The simplest choice is to refuse an upload that contains an
archive. `detect_format` tells whether a member is one, when it's given the whole member, and
`always_probe_content=True` in `CONFIG` makes it also try decoding the start of the member:

```python
import io
import tempfile
import zipfile

import archivey

CONFIG = archivey.ArchiveyConfig(
    listing_limits=archivey.ListingLimits(
        max_members=10_000,
        max_metadata_bytes=4 * 2**20,
    ),
    decoder_limits=archivey.DecoderLimits(max_decoder_memory=256 * 2**20),
    process_isolation=archivey.ProcessIsolation.NATIVE_DECODERS,
    diagnostic_policy=archivey.DiagnosticPolicy.STRICT,
    always_probe_content=True,
)
MAX_TOTAL_BYTES = 1 * 2**30


def contains_archive(path):
    total = 0
    with archivey.open_archive(path, streaming=True, config=CONFIG) as archive:
        for member, stream in archive.stream_members():
            if not member.is_file or stream is None:
                continue
            with tempfile.TemporaryFile() as copy:
                while chunk := stream.read(2**20):
                    total += len(chunk)
                    if total > MAX_TOTAL_BYTES:
                        raise RuntimeError("the upload expands too much")
                    copy.write(chunk)
                copy.seek(0)
                try:
                    archivey.detect_format(copy, config=CONFIG)
                except archivey.FormatDetectionError:
                    continue
                return True
    return False


inner = io.BytesIO()
with zipfile.ZipFile(inner, "w") as zf:
    zf.writestr("payload.txt", "x" * 1000)
with zipfile.ZipFile("upload.zip", "w") as zf:
    zf.writestr("report.txt", "hello")
    zf.writestr("more.zip", inner.getvalue())

print(contains_archive("upload.zip"))
```

The member is copied to a temporary file because its first bytes aren't always enough. An ISO keeps
its signature 32 KiB into the file, and a self-extracting archive starts with a program, so the
archive may start far into the member. A check of the first few KiB alone is only a fast first
filter, and a member it lets through still needs the full check.

zlib, Brotli and `.lzma` data start with nothing that identifies them, and the copy has no file name
to go by. Without `always_probe_content=True`, `detect_format` misses them, though `open_archive`
reads the same bytes saved under a name ending in `.zz`, `.br` or `.lzma`. With it, the occasional
file that only happens to decode as one of them also counts as an archive, which errs on the side
of refusing.

Even so, the check finds only what archivey recognizes. Other tools can find more: `unzip` and
7-Zip also find a ZIP behind arbitrary leading bytes, which archivey doesn't.

A compressed file such as `notes.txt.gz` or `data.zz` counts as an archive here, since it can expand
as much as one. So do Office documents, JAR files and wheels, which are ZIP archives.

If you need to look inside, keep one budget for the bytes read at every level, and refuse the
upload when archives are nested more deeply than you allow:

```python
import io
import tempfile
import zipfile

import archivey

CONFIG = archivey.ArchiveyConfig(
    listing_limits=archivey.ListingLimits(
        max_members=10_000,
        max_metadata_bytes=4 * 2**20,
    ),
    decoder_limits=archivey.DecoderLimits(max_decoder_memory=256 * 2**20),
    process_isolation=archivey.ProcessIsolation.NATIVE_DECODERS,
    diagnostic_policy=archivey.DiagnosticPolicy.STRICT,
    always_probe_content=True,
)
# Archives up to 2 levels inside the upload are scanned. A third level is refused.
MAX_DEPTH = 2


class Budget:
    def __init__(self, max_bytes):
        self.left = max_bytes

    def take(self, n):
        self.left -= n
        if self.left < 0:
            raise RuntimeError("the upload expands too much")


def scan(source, budget, depth=0):
    names = []
    with archivey.open_archive(source, streaming=True, config=CONFIG) as archive:
        for member, stream in archive.stream_members():
            names.append("  " * depth + member.name)
            if not member.is_file or stream is None:
                continue
            with tempfile.TemporaryFile() as copy:
                while chunk := stream.read(2**20):
                    budget.take(len(chunk))
                    copy.write(chunk)
                copy.seek(0)
                try:
                    archivey.detect_format(copy, config=CONFIG)
                except archivey.FormatDetectionError:
                    continue
                if depth + 1 > MAX_DEPTH:
                    raise RuntimeError("archives are nested too deeply")
                copy.seek(0)
                names += scan(copy, budget, depth + 1)
    return names


inner = io.BytesIO()
with zipfile.ZipFile(inner, "w") as zf:
    zf.writestr("payload.txt", "x" * 1000)
with zipfile.ZipFile("upload.zip", "w") as zf:
    zf.writestr("report.txt", "hello")
    zf.writestr("more.zip", inner.getvalue())

print("\n".join(scan("upload.zip", Budget(100 * 2**20))))
```

Each member is copied to a temporary file, which can seek, so an inner 7z, RAR or ISO archive opens
too. The copy counts against the budget before anything is opened from it, so a nested archive
can't use more than what's left. The temporary files take disk space up to the budget at each level.
