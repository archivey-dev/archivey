## MODIFIED Requirements

### Requirement: Return a named member's own bytes when its mask selects others

`unrar p` with an include mask emits every payload member the mask selects, in archive
order and with no headers between them. The system SHALL build the mask from the name as
`unrar` reads it from the header, SHALL compute which members that mask selects the way
`unrar` 7 does, and SHALL return only the target's bytes: it SHALL skip the unpacked size
of the selected members before the target and SHALL stop at the target's size. This
covers members with the same name, names `unrar` reads as the same text, a mask that
names a directory prefix of another member, and a RAR5 name that is not valid UTF-8,
which `unrar` reads only up to its first invalid byte.

The system MUST NOT return another member's bytes for a member. When the selection is not
known, the system SHALL raise `UnsupportedFeatureError` naming
`rar_decompressor='unar'` before `unrar` is spawned and before a stream source is
copied. That is the case when `unrar` reads the name as empty or as a path with no name,
when the name `unrar` reads cannot be passed back to it in argv, when the mask would not
select the target, and when an earlier member's name cannot be read the way `unrar`
reads it on this host. A stored name that contains a NUL SHALL be refused the same way.

A mask with no `*` or `?` that selects earlier members costs `unrar` the same decode of
those members as a glob, and SHALL be refused like one by default (`Refuse a member name
whose mask also selects earlier members`); with `rar_allow_glob_member_concatenation`, or
when `auto` reads it with `unar`, the read SHALL return the target's own bytes as above.

#### Scenario: shared mask matrix

| Case | Expected |
| --- | --- |
| Two or three members with the same name, solid or not, with `rar_allow_glob_member_concatenation` | Each read returns its own bytes |
| The same names, default config, `rar_decompressor='unrar'` | The first reads; a later one is refused like a glob name |
| RAR5 `ab\xffcd.txt` after members `unrar` reads as `ab`, with the flag | Its own bytes; the earlier ones are skipped |
| RAR5 name `\xff` beside a sibling named U+FFFD, no stored digest | `UnsupportedFeatureError`; never the sibling's bytes |
| A name `unrar` reads as empty (`\xc0\x80x`) | `UnsupportedFeatureError` |
| Earlier 8-bit RAR 1.5-4 name and no UTF-8 locale for `unrar` | A later member's read raises `UnsupportedFeatureError` |

### Requirement: Refuse a glob member name whose mask also matches earlier members

A RAR member's stored name may contain `*` or `?`. Because `unrar` is addressed by an
include mask, such a name can match other members, and `unrar` decompresses every match
and emits them concatenated ahead of the target. A name with no `*` or `?` does the same
when its mask selects other members: a duplicate name, or two names `unrar` reads as the
same text.

When the mask built from a member's stored name, glob or not, also selects **earlier**
payload members holding data, the system SHALL raise `UnsupportedFeatureError` rather
than read the member.
The error SHALL name the configuration flag that allows the read. On a non-solid
archive it SHALL also name the number of bytes of earlier matching members that
`unrar` would decompress first. On a solid archive those members are already inside
the solid prefix the read pays, so the error SHALL NOT describe that count as an
avoidable extra decode.

`ArchiveyConfig.rar_allow_glob_member_concatenation` SHALL default to `False`. When set
to `True` the read SHALL proceed and return the member's own bytes, skipping the earlier
matches as before. The flag SHALL govern only whether the read is attempted; it SHALL
NOT change what a successful read returns.

A name whose mask selects **no** earlier member SHALL be unaffected and SHALL read
without the flag; so is the first of several members with the same name. The flag keeps
its name for a non-glob name: it governs every mask that selects earlier members. On
POSIX a RAR 1.5-4 UTF-16 name sends each surrogate unit as `?` (`Decode RAR member
names`), and that mask falls under this requirement like a stored glob.

A call site that builds no include mask SHALL be unaffected, whatever the member names
are. In particular a solid `stream_members()` pass uses one unnamed `unrar p` pipe
demultiplexed by size, so it SHALL read glob-named members without the flag.

The refusal exists because names like this are almost always constructed. On a
non-solid archive the extra decode is also unbounded and unreported: it is not
covered by `ExtractionLimits`, which do not reach `open()` / `read()`. On a solid
archive `AccessCost.SOLID` already advertises the prefix; the names are still
refused.

#### Scenario: glob member matrix

| Case | Expected |
| --- | --- |
| `a*.txt` with an earlier `subdir/aY.txt` match, default config, non-solid | `UnsupportedFeatureError` naming the byte count and the flag |
| The same member on a solid archive, default config | `UnsupportedFeatureError` naming the flag, not an avoidable extra decode |
| The same read with `rar_allow_glob_member_concatenation=True` | The member's own bytes, earlier matches skipped |
| `only*.dat`, whose mask matches nothing else, default config | Reads normally; no refusal |
| Solid `stream_members()` over glob-named members, default config | All members read; no mask is built |
| A name with no `*` or `?` shared with an earlier member, default config, `rar_decompressor='unrar'` | `UnsupportedFeatureError` naming the flag (and, non-solid, the byte count) |
| The same read with the flag | The member's own bytes |
| A name with no `*` or `?` that selects nothing earlier | Not refused |
| POSIX: `hi` U+D800 `.txt` after `hiX.txt`, default config | `UnsupportedFeatureError` naming the flag; with the flag, the member's own bytes |

### Requirement: Under auto, read a member unrar cannot name with unar

`unar` selects members by index, so a name `unrar` cannot be given, or a name whose
mask also selects earlier members, glob or not, costs it nothing. When
`ArchiveyConfig.rar_decompressor` is `auto` and resolved to `unrar`, a read that the
two requirements above would refuse SHALL instead be served by `unar -i <index>`, when
all of these hold: an accepted `unar` is installed (the same check `auto` uses), the
read needs no password (see "A spawn gets a password only when the read needs one";
`unar` takes it on its command line), the source
is a file with nothing before the RAR (`unar` would otherwise need its own copy: a
prefix has no open-time cost note under `unrar`, and a stream source would be copied a
second time against the same `SpoolLimits` budget; a file is linked into `unar`'s
private directory, copied only where the system allows no link), and `unar` itself would not refuse the member
or the archive (`Read RAR member data with unar`). Otherwise the `unrar` refusal SHALL be
raised unchanged. The dictionary memory check SHALL use `unar`'s rule for that read.
Every other member SHALL still be read with `unrar`. With `rar_decompressor='unrar'`
the refusals SHALL stand.

#### Scenario: auto routes unnameable members to unar

| Case | Expected |
| --- | --- |
| `a*.txt` with an earlier `subdir/aY.txt`, non-solid, `auto`, accepted `unar` installed | The member's own bytes, read with `unar`; other members read with `unrar` |
| `d*/x.txt` (glob in a directory component), `auto`, accepted `unar` installed | The member's own bytes, read with `unar` |
| A duplicate name after an earlier entry with data, non-solid, `auto`, accepted `unar` installed | The member's own bytes, read with `unar` |
| The same reads with no accepted `unar` | The `unrar` refusals, unchanged |
| The same reads with `rar_decompressor='unrar'` | The `unrar` refusals, unchanged |
| RAR5 solid archive with data after a directory (`unar` refuses it) | The `unrar` refusal, unchanged |
| A read that needs a password, or a stream source, or a prefix before the RAR | The `unrar` refusal, unchanged; nothing is written to disk |
| A plaintext member of a non-solid archive whose last member is encrypted | Read with `unar`, which gets no password |

### Requirement: Count the RAR dictionary against the decoder memory cap

The reader SHALL refuse a member read with `ResourceLimitError` when the dictionary
memory the decompressing program would use is over
`DecoderLimits.max_decoder_memory`. The refusal SHALL come before `unrar` or `unar` is
spawned and before a stream source is copied to disk. The count SHALL follow the
program that will run, so under `rar_decompressor="auto"` it is the rule of the program
`auto` picked:

- `unar`: the largest dictionary declared in the member's solid stream, up to and
  including the member.
- `unrar`, nonsolid: for the member and for every earlier member its include mask also
  selects, the smaller of that member's declared dictionary and its unpacked size; the
  largest of these.
- `unrar`, solid: the smaller of the largest dictionary declared up to and including the
  member and the unpacked size of those members. "Solid" here is the MAIN header's solid
  flag, which is what `unrar` decides by; a member's own solid flag does not.

A stored member, a directory and a RAR5 redirect add nothing to either count. Under
`unar` and in a nonsolid archive they SHALL count 0; under `unrar` in a solid archive
they SHALL count the `unrar` solid count of the members before them, because `unrar`
decodes those members to reach them. A `stream_members()` pass that runs one process
over the archive SHALL count, for each member, the largest count of any member up to
and including it, and SHALL check it on that member's first read, so a pass that lists
or skips a member is not refused for it. The message SHALL name the member whose header
declared the dictionary behind the count when the member read does not declare it, and
SHALL give the declared size when the count is smaller.

#### Scenario: dictionary cap matrix

| Case | Expected |
| --- | --- |
| `unar`, a small member declaring 4 GiB, default cap | `ResourceLimitError`; `unar` not spawned |
| `unrar`, a small nonsolid member declaring 4 GiB, default cap | Reads |
| `unrar`, a nonsolid member declaring 4 GiB and 3 GiB unpacked, default cap | `ResourceLimitError` naming 3 GiB and the declared 4 GiB; `unrar` not spawned |
| `unrar`, a solid member behind a member declaring 4 GiB and 3 GiB unpacked | `ResourceLimitError`, for a named read and in a `stream_members()` pass |
| `unrar`, a stored solid member behind a member declaring 4 GiB and 3 GiB unpacked | `ResourceLimitError` naming the earlier member; `unar` counts it 0 |
| `unrar` with `rar_allow_glob_member_concatenation`, a duplicate name whose earlier entry declares 4 GiB and 3 GiB unpacked | `ResourceLimitError` when the later, small entry is read |
| `rar_decompressor="auto"` | The count of the program `auto` picked |
