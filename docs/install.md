# Install

Archivey is on PyPI as `archivey`. It needs Python 3.11 or later and has no dependencies of its own.
Optional packages, grouped as extras, add the rest:

```bash
pip install archivey                 # no dependencies
pip install "archivey[recommended]"  # every format and compression method that installs everywhere
pip install "archivey[seekable]"     # faster seeking and reading in large gzip, bzip2 and DEFLATE data
pip install "archivey[all]"          # recommended and seekable together
```

If you only want the `archivey` command, `uvx archivey-cli` runs it with everything
`[recommended]` adds, without installing anything for good, and `pipx install archivey-cli`
installs it. `archivey-cli` is a separate package that holds no code: it depends on
`archivey[recommended]` at the same version. `uvx archivey` works too, but it runs the base
package only, because an extra must be named to be installed.

If you use a free-threaded Python build, [Free-threaded Python](#free-threaded-python) has the extra
to use instead. There's no extra per format, because ZIP, 7z and TAR share their compression
methods.

| You install | It reads |
| --- | --- |
| `archivey` | ZIP, TAR and 7z with their common compression methods, and directories. gzip, bzip2, xz, LZMA, zlib, lzip and `.Z` files, alone or inside a TAR, and Zstandard too on Python 3.14 and later. RAR archives can be listed, and their uncompressed, unencrypted files read. |
| `[recommended]` adds | ISO images, and LZ4, Brotli and Zstandard files (Zstandard only before Python 3.14). PPMd, Deflate64 and Zstandard inside 7z and ZIP, and Brotli and LZ4 inside 7z. AES decryption for 7z, RAR and WinZip AES ZIP files. Progress bars in the command-line tool. |
| `[seekable]` adds | No new format. Faster seeking inside large gzip, zlib and bzip2 data, and large DEFLATE members in ZIP and 7z, when you open with `seekable_members=True`. On Linux and macOS, also faster reading of large DEFLATE data that compresses 3:1 or less, without that option. |

Compressed RAR files, and a few encrypted ones, also need an outside program, which no extra can
install. The next section covers it.

## RAR needs an outside program

RAR is a proprietary format, and there's no self-contained Python decoder for it, so archivey reads
compressed RAR members with an outside program. It lists RAR archives and reads stored
(uncompressed) members itself, encrypted ones too when `cryptography` is installed and the member is
in one part.

The preferred program is RARLAB's `unrar` (or `rar`), version 6.0 or later. Archivey also supports
`unar` 1.10 or later, from The Unarchiver, but it has some limitations. Archivey uses `unar` when it
finds no usable `unrar`, and then passes an encrypted archive's password on `unar`'s command line,
where other users on the same machine can see it while it runs. Some `unar` packages in Debian and
Ubuntu have a bug that drops some files; archivey tests the `unar` it finds and won't use one that
has it. If you want to choose the program yourself, set `rar_decompressor` in `ArchiveyConfig` to
`"unrar"`, `"unar"`, `"none"` or `"auto"` (the default). With `"unrar"`, archivey never runs `unar`.

### Getting `unrar`

On Debian and Ubuntu, `sudo apt install unrar` installs RARLAB's program. It's in the non-free
(Debian) or multiverse (Ubuntu) section, and the `unrar-free` package is a different program that
archivey doesn't use. Other Linux distributions have a package of RARLAB's UnRAR under a similar
name.

On Windows, download the command-line UnRAR from [RARLAB](https://www.rarlab.com/rar_add.htm) and
put `UnRAR.exe` on your `PATH`.

On macOS, Homebrew no longer ships `unrar`. You can install it from an unofficial Homebrew tap,
which builds or downloads RARLAB's program:

```bash
brew install gromgit/new-life/unrar
```

If you'd rather not trust that tap, download the UnRAR source from
[RARLAB](https://www.rarlab.com/rar_add.htm) and build it with Xcode's command-line tools:

```bash
tar xf unrarsrc-*.tar.gz
cd unrar
make
cp unrar ~/.local/bin/   # or any folder on your PATH
```

Running `unrar` with no arguments prints its version, so you can check it's 6.0 or later.

### Getting `unar`

On macOS, `brew install unar` installs a version archivey accepts. On Debian and Ubuntu, the
packaged `unar` may have the bug described above; if archivey won't use it, either install `unrar`
or build `unar` 1.10.8 from [The Unarchiver's source](https://github.com/MacPaw/XADMaster).

## Checking what an install can read

If your program needs to know at run time which formats work with what's installed,
[`format_availability()`](api.md#archivey.format_availability) says whether a format is fully
supported, partly supported (it opens, but some members need a missing package) or not available,
and which packages would add the rest. RAR counts as partly supported without RARLAB's `unrar`, even
when `unar` is installed. To find out, it runs each `unrar` or `rar` on your `PATH` once to read its
version, whatever `rar_decompressor` says; pass `check_programs=False` to run nothing. `cryptography`
isn't counted, because only encrypted members need it.

## Python versions and platforms

Archivey needs Python 3.11 or later. Every change is tested on Linux with CPython 3.11 to 3.14
and PyPy 3.11, and on macOS and Windows with CPython 3.11 and 3.14. Other platforms aren't
tested, and PyPy has some limits ([PyPy](#pypy) lists them). [How it is built](how-it-is-built.md) has the full test
setup.

## Free-threaded Python

On a free-threaded build (3.13t and later), importing a compiled package that doesn't declare
free-threading support turns the GIL back on for the rest of the process. If you use `pip install
"archivey[free-threaded]"`, you get only the optional packages that keep it off: ISO, LZ4 and
Zstandard support, and CLI progress bars, plus AES decryption from 3.14t. On 3.13t, `[recommended]`
doesn't install at all, because `cryptography` can't be installed there yet, and neither does
`archivey-cli`, which depends on it. Use `[free-threaded]` there instead.

Other optional packages can still be installed. Archivey imports each one only when a file needs it,
so the GIL comes back the first time you read PPMd, Deflate64 or Brotli data. Free-threaded builds
are tested on Linux only.

## PyPy

archivey works on PyPy 3.11, with the limits below. Every change to the main branch runs the whole
test suite on PyPy 3.11, with and without the optional packages, and it has to pass there.

Under PyPy, archivey doesn't use rapidgzip, lz4, pyppmd or inflate64, even when they are
installed, because there they misread data or crash the interpreter. It reads as if they weren't
installed:

- LZ4 files, including `.tar.lz4`, and LZ4 members of 7z archives can't be read.
- PPMd members of ZIP and 7z archives can't be read.
- Deflate64 members of ZIP and 7z archives can't be read.
- The accelerator behind `[seekable]` is off, so seeking backwards in gzip, zlib or bzip2 data, or
  in a DEFLATE member of a ZIP or 7z archive, decompresses more of it again.

If you read data that needs lz4, pyppmd or inflate64, the error says why archivey doesn't use the
package, in place of an install hint, and so do `format_availability()` and
`archivey --version -v`. rapidgzip only speeds things up, so neither lists it, and you see its
reason only if you ask for it outright by setting `use_rapidgzip` or `use_indexed_bzip2` to
`AcceleratorMode.ON`.

If you use PyPy, close member streams and passes yourself, with a `with` block or `close()`. On
CPython, one that nothing refers to any more is closed at once. PyPy closes it only at a later
garbage collection, and until then it still holds the archive. When a call finds the archive held,
archivey runs a garbage collection and tries once more, so a stream or pass you dropped doesn't
block it. One you still refer to does: unless you opened the archive with
`concurrent_operations=True`, the next `open` raises `ArchiveyUsageError` because a member stream
is already open, and an unfinished `stream_members` pass makes the archive's other calls raise. A
RAR member read through `unrar` also keeps its `unrar` process running until the collection, and
so does a decoder's child process where one is in use
([Decoders in a child process](security.md#decoders-in-a-child-process)). Closing an XZ or LZMA
stream also frees its decoder's dictionary at once. Dropped unclosed, the dictionary, as large as
the data declares, stays allocated until that collection.
[Reading once](reading.md#reading-once) shows the `with` form for a pass.
