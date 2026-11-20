# archivey-cli

The [`archivey`](https://pypi.org/project/archivey/) command-line tool, installed together
with archivey's recommended optional packages: ISO images, LZ4, Brotli and Zstandard,
PPMd and Deflate64 inside 7z and ZIP, AES decryption, and progress bars. Where they
install from a ready-made wheel, it also brings `.bz3` support and parallel decoding of
large gzip, bzip2 and DEFLATE data. It also brings `fsspec` and `aiohttp`, so the
command reads archives from HTTP and HTTPS URLs. `archivey --version -v` lists what this
install reads, and how to add anything missing.

```bash
uvx archivey-cli photos.zip          # run it once, without installing
pipx install archivey-cli            # or install the `archivey` command
archivey extract photos.zip
```

This package holds no code of its own. It depends on `archivey[recommended]` at the same
version, plus `fsspec` and `aiohttp`, and `bzip3` and `rapidgzip` where they have
wheels, and installs the `archivey` command (and `archivey-cli`, the same command under
the package's name, which is what `uvx archivey-cli` runs). If you use archivey as a
library, install `archivey[recommended]` instead. Both packages declare the `archivey`
command, but they share one script file, and uninstalling archivey-cli deletes it:
archivey stays installed without its `archivey` command. A plain `pip install archivey`
then reports it as already installed and writes nothing, so reinstall it to get the
command back (`pip install --force-reinstall archivey`).

The [command-line guide](https://archivey-dev.github.io/archivey/cli/) lists every command and
option. Compressed RAR archives also need an outside program, which no Python package can
install; the [install page](https://archivey-dev.github.io/archivey/install/) explains how to get
one.
