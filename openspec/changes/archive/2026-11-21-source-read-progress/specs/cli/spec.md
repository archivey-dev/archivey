## ADDED Requirements

### Requirement: The CLI shows the reads of the archive's file

Every verb that opens an archive (`list`, `info`, `test`, `extract` and `cat`) SHALL set
`ArchiveyConfig.on_source_read` when it would show a progress bar: `tqdm` is installed,
`--hide-progress` is not given, and stderr (or the process's own stderr) is a terminal.
It SHALL show one line on stderr, and only the reads of the file the user named
(`nest_level` 0).

Before the first member's data is read, and in `list`, `info` and `cat`, the line SHALL
be a status line: where in the file the latest read ended, against the file's size,
shown only once the reads have gone on for 0.5 seconds and cleared, not left, when
they end. It SHALL be cleared before the CLI prints a line to stderr, and `cat` SHALL
clear it for good before it writes the first byte to stdout. In `test` and `extract`
the member bar SHALL replace it at the first member's data. That bar SHALL count output
bytes against the selected members' total when the total is known, and otherwise the
position in the file against the file's size, so a `.tar.xz` shows a percentage. For a
URL the line SHALL also show the range requests so far and the bytes they fetched.

#### Scenario: a large .tar.xz is tested

- **WHEN** `archivey test big.tar.xz` runs on a terminal with `tqdm` installed
- **THEN** the bar shows how far the file has been read as a percentage of its size

#### Scenario: a URL is listed

- **WHEN** `archivey list https://host/big.zip` takes longer than half a second
- **THEN** a status line shows the position, the request count and the bytes fetched,
  and it is gone before the first member line is printed

#### Scenario: progress is hidden

- **WHEN** `--hide-progress` is given, or stderr is not a terminal
- **THEN** no line is shown and `on_source_read` is not set
