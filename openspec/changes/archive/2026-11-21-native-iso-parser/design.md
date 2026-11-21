## Context

`iso_reader.py` is 3,600 lines; about half adapts pycdlib. `udf.py` (merged in 0.5.0)
showed the shape of a native parser for one tree: a class that parses at construction
through the source's `read_at`, weighs what it keeps against a budget protocol, and
raises archivey's own `TruncatedError`/`CorruptionError`.

## Decisions

### One module per tree family, parsed eagerly

`IsoVolume` parses the primary tree and the Joliet tree at construction, as
`UdfVolume` does for UDF. The listing budget and cut detection then act before any
member is listed, and listing reads nothing more, as today. Lazily parsing only the
listed tree would save reads on remote sources, but the other-trees report compares
every tree; that optimisation is a later, measured change.

### Keep the model close to the disc

An `IsoEntry` is one entry of a directory: its first record's offset (its identity),
identifier, flags, date and Rock Ridge entries, plus every record's `(block, declared
length)`. Directories keep their entries in on-disc order. Nothing is clamped or
reordered at parse time; the reader decides at read time what is present. That removes
the raw re-parse the pycdlib reader needed to undo clamping and reordering, and gives
salvage the offsets it needs to tell trees and sessions apart by data location.

### What the parser checks, and what it does not

Kept from pycdlib, because each guards a field archivey follows: the primary and Joliet
descriptors' version, zero fields and both-endian copies; a logical block size of 512,
1024 or 2048; a terminator; a directory record's minimum length, its extent and volume
sequence number agreeing in both byte orders; a directory loop.

Added, following Linux's isofs: a directory record whose identifier is longer than the
record refuses the image (`do_isofs_readdir` reports a corrupted directory entry).
pycdlib cut the identifier short and listed the record under that name. One tree's
directories may together declare no more than the image holds: they do not overlap, so
an honest image always passes, and a crafted one cannot have each directory claim the
rest of the image and read it once per directory.

Changed in the reader, following Linux's isofs: a Rock Ridge `CL` is followed to the
directory at its extent for its contents and attributes, and the member keeps the
placeholder's own `NM` name. pycdlib's `list_children` took the first entry of that
directory's parent with the placeholder's name, so two deep directories of one name
(`a/.../x`, `b/.../x`) both listed the first one's files, and the second's were lost.

Dropped, following Linux's isofs and 7-Zip:

- Path tables are not read to list. Readers that walk directories ignore them; pycdlib
  refused an image whose two path tables disagreed or ran past the end. They are read
  only to hint a remote source where the directories are, and then never raise.
- A second primary or Joliet descriptor is ignored rather than compared.
- Records that share an identifier are separate entries unless the multi-extent flag
  joins them; pycdlib refused a directory after a file of the same name.
- A System Use entry that does not parse (wrong length for `PX`, a both-endian field
  that disagrees, an `SL` component with bad flags, a `TF` shorter than its flags, a
  `CE` whose area runs past its block or past a full-length image) ends that record's
  area, with the reason kept for the reader's `MEMBER_HEADER_RECORD_SKIPPED`. Before, a
  hook filtered only malformed headers, and pycdlib refused the image on the rest.

### Rock Ridge detection and the SUSP skip

A tree is Rock Ridge when some record carries SUSP entries and some record carries an
`ER` entry naming RRIP (`RRIP_1991A` or `IEEE_P1282`), as pycdlib decided. The skip
count of the root's `SP` entry is applied to every other System Use area, as SUSP and
Linux apply it; pycdlib ignored it. Writers record 0, so no real image changes.

### Data length and the image end

A record's data length is read little-endian only, as every reader does. A file whose
extent runs past the end of the image keeps its declared length; the reader lists that
size and reads what is there, so the adapter's size check turns the cut into a
`TruncatedError` at the offset it happens. The trailing-data check still takes the
volume to end at the furthest file data inside the image when the volume space size
says less (pycdlib grew the space size that way; Office XP images need it).

## Risks

- pycdlib was a second reader of odd producers. The differential tests run pycdlib,
  xorriso and genisoimage images and a bit-flip campaign; the reader's existing ISO
  suite (about 230 tests) runs unchanged where behaviour is unchanged.
- The UDF and cue/raw-sector paths are untouched; the reader keeps calling them.
