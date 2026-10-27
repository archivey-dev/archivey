# Command line

The `archivey` command lists, checks and extracts archives, and prints members to the terminal. It
comes with the base package. Progress bars need `tqdm`, which `[recommended]` installs; without it
the command works the same, just without the bars.

To run the command without setting up a project, use `uvx archivey-cli` (for example,
`uvx archivey-cli extract photos.zip`), or `pipx install archivey-cli` to keep it. The
`archivey-cli` package brings `[recommended]` with it, so the command reads every format that
installs everywhere. [Install](install.md) has the details.

```bash
archivey photos.zip                 # list the members (same as archivey list)
archivey test photos.zip            # read every member and check its checksum
archivey extract photos.zip         # extract safely, into ./photos/
archivey info photos.zip            # the format, and what reading it costs
archivey cat photos.zip notes.txt   # write one member to stdout
```

`list`, `test`, `extract` and `info` also answer to `l`, `t`, `x` and `i`. `archivey <command>
--help` lists every option.

## Listing and inspecting

`archivey list` prints one line per member: its type, permissions, size, modification time and
name. Three options add more:

- `--long` adds columns for the compressed size, the space saved, the compression method and the
  CRC-32 checksum.
- `--details` prints everything archivey knows about each member, as `key: value` lines.
- `--digests` adds the checksums the archive stores, such as `[crc32=363a3020]`, without reading
  the members' data.

`--long` and `--details` can't be used together.

`archivey info` describes the archive instead of its members: its format and how archivey
recognised it, whether it's encrypted, solid or split into volumes, how many members it has, and
what reading it costs. For a `.tar.gz`, it says that listing means decompressing the whole archive,
and that reading one member may mean decoding the ones before it.

`archivey --version -v` prints the version, then each format and whether this install can read it
fully, partly or not at all. [Install](install.md#checking-what-an-install-can-read) explains what
each one needs.

## Checking an archive

`archivey test` reads every member to the end and compares it with the checksum the archive
stores, without writing anything. It prints how many members passed and failed, and `-v` adds a
line for each member.

It exits with `1` when a member fails, and also when a member couldn't be tested or its checksum
couldn't be checked, even if nothing failed. That happens, for example, when the members after a
damaged spot can't be reached, or when a gzip file's checksum sits past the point where archivey
stops looking for it. The warning printed for each one says why. A member whose format stores no
checksum at all, such as a Brotli or `.Z` file, passes once it reads to the end without an error.

`--outer` checks only the compression layer, as `gzip -t` does. For a `.tar.gz`, archivey reads the
whole decompressed tar and checks gzip's own checksum, without looking at the members inside. gzip,
lzip, bzip2 and zlib always carry that checksum, xz does unless it was written with `--check=none`,
zstd and LZ4 only when the program that wrote the file added one, and Brotli and `.Z` never do. A
ZIP, 7z, RAR, ISO or plain tar has no compression layer, so `--outer` refuses it.

## Extracting

`archivey extract photos.zip` puts the members in a new folder named after the archive, `photos/`,
so an archive with many top-level entries doesn't spread them over the current directory. If the
archive holds a single top-level folder, that folder lands in the current directory instead. The
new folder is always new: if something named `photos` is already there, archivey uses `photos (1)`.
To choose the folder yourself, pass `-d out/`, or `-d .` for the current directory.

??? note "When does a single folder stay inside `photos/`?"
    Without `-d`, archivey never replaces or deletes anything in the current directory. If a name it
    needs is already taken, the default `--overwrite rename` gives the new entry a free name, such
    as `notes (1).txt`; with `error`, `skip` or `replace`, the folder stays in `photos/` instead.

    For an archive that doesn't list its members up front, such as a TAR, archivey extracts into
    `photos/` first and moves the folder out at the end. It leaves the folder in `photos/`, and
    prints why, if the move could change what a link points to (the folder is a symlink, or holds
    one that leads outside it), or if part of it couldn't be listed.

Extraction uses the `strict` policy by default: a member that would land outside the destination,
or a link that points outside it, is refused and reported, and the rest are still extracted.
`--policy standard` and `--policy trusted` relax it, as
[What each policy does](extracting.md#what-each-policy-does-with-unusual-members) describes.

Two defaults differ from the library's `extract_all()`, because a command is expected to finish and
report instead of stopping at the first problem:

| When | `archivey extract` | `extract_all()` |
| --- | --- | --- |
| A file with the member's name is already there | writes the member as `photo (1).jpg` | raises an error |
| A member fails | reports it, carries on, and exits with `1` at the end | raises an error at once |

`--overwrite error --stop-on-error` makes the command behave like the library. `--overwrite` also
takes `skip` (keep the file that's there) and `replace` (write over it).

`--stop-on-error` stops at the first member that fails, but refused members are still only
reported. To stop on those too, pass `--abort-on blocked-member`, which is the safest choice for an
archive you don't trust. `--abort-on name-collision` stops when two members land on the same name,
and `--abort-on name-sanitized` when a name had to be changed to be written. `--abort-on` can be
given more than once. Files written before the stop stay on disk.

`--dry-run` runs every check and reads every member, but writes nothing. It prints the same report
and exits with the same code as a real extraction into an empty folder. Before the summary it
adds one line, `peak use of the reader limits:`. It gives the largest decoder allocation
archivey checked and what it was for, the bytes spooled to a temporary file at their peak, and
two totals: the key-derivation rounds and the listing's members and metadata bytes. These are
the numbers to compare with [`DecoderLimits`, `SpoolLimits` and `ListingLimits`](security.md)
before you open an untrusted archive with tighter limits. A part that is zero is left out, and
when every part is zero there is no line. A run that stops before its summary, such as a limit
refusal or `--abort-on`, prints no line either. Decoder memory counts only the allocations
archivey checks itself: xz, LZMA Alone and zstd leave that check to their library.

`--outer` removes only the compression layer: `archivey extract data.tgz --outer` writes
`data.tar` and keeps the original, as `gunzip -k` does.

## Writing members to stdout

`archivey cat` writes the selected members to stdout, one after another in archive order, as
`unzip -p` and `tar -xO` do. Directories and links are skipped, and with `-v` each member's name
goes to stderr.

```bash
archivey cat config.zip settings.ini     # one member
archivey cat logs.tar.zst '**/*.log'     # every .log file, at any depth
curl -s URL | archivey cat - '*.txt'     # - reads the archive from stdin
curl -s URL | archivey cat - --outer | tar t
```

With `--outer`, `cat` writes what's inside the compression layer unchanged: the tar inside a
`.tar.gz`, the file inside a `.gz`.

Data reaches stdout as it's decoded, so if a member's checksum fails at the end, its data is
already written. `cat` then prints the error and exits with `1`, as `zcat` does, so check the exit
code before you trust the output.

## Choosing members

`list`, `test`, `extract` and `cat` take patterns after the archive name, and work on the members
that match:

- `*` matches within one folder: `'*.md'` matches `README.md` at the top level, not
  `docs/guide.md`.
- `**` matches any number of folders: `'**/*.md'` matches every `.md` file.
- A folder brings its contents: `docs` and `docs/` both match `docs/` and everything in it, but not
  `docs.txt`.

`--exclude PATTERN` leaves out the members it matches, even ones a pattern selected, and can be
given more than once. On Windows, `\` works in place of `/`. Quote patterns, so the shell doesn't
expand them first.

If a pattern matches nothing, archivey says so. `test`, `extract` and `cat` then exit with `1`, as
they do when `--exclude` leaves nothing; `list` exits with `0`. From Python, the same matching is
`members=match_glob(pattern, with_contents=True)` from `archivey.paths`.

## Passwords

When an archive needs a password and stdin is a terminal, archivey asks for it without showing what
you type. With no terminal, as in a pipe or a cron job, it doesn't ask, and the encrypted members
fail as if no password had been given.

`--password` passes it on the command line instead. If you use it, other users of the machine can
see the password in the process list, and your shell may keep it in its history.

## Reading from a pipe

`archivey cat -` reads the archive from stdin. The other commands take a path, and a pipe can
still reach them as `/dev/stdin` on Linux and macOS:

```bash
cat backup.tar.gz | archivey list /dev/stdin
```

A pipe can only be read once, from start to end, so archivey reads it in a single pass. That works
for TAR (compressed or not), ZIP and single compressed files such as `.gz`. 7z, RAR and ISO
archives need to jump around in the file, so from a pipe they fail with exit `1` and a message to
copy the input to a file first. `extract --outer` and `test --outer` also need a file; for a pipe,
use `archivey cat - --outer`. A redirect from a file, as in `archivey cat - < backup.7z`, isn't a
pipe, so every format works that way.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | The command failed: a member failed, a pattern matched nothing, `test` couldn't check everything, or an extraction stopped early. |
| `2` | The command line was wrong. |
| `3` | `extract` finished, with every member written or refused, and at least one refused. |
| `130` | Interrupted with Ctrl-C. |
| `141` | The output was closed early, as with `archivey test -v big.zip 2>&1 \| head -1`. For `test`, that means you don't have the result. |

## File names and shared options

The first word after `archivey` is read as a command when it is one, so `archivey x a.zip`
extracts. A file named `x` is reached as `archivey ./x` or `archivey list x`. A file whose name
starts with `-` goes after `--`: `archivey -- -weird.zip`. An empty name is an error, not the
current directory; write `.` for that.

Options shared by every command can go before or after the command; a command's own options,
such as `-d` or `--exclude`, go after it. Besides `--password` and `-v`, the shared ones are:

- `--hide-progress` turns off progress bars.
- `--track-io` reports how many bytes archivey decompressed and read, and how often it seeked.
- `--probe-content` recognises a raw LZMA, zlib or Brotli stream whatever the file is named. These
  have no signature at their start, so archivey normally knows them only by their extension
  (`.lzma`, `.zz`, `.br` and the like). With this option it tries decoding the start of the file
  instead. It's off by default because some unrelated files pass the trial. `--outer` always tries
  decoding, so it doesn't need this option.
