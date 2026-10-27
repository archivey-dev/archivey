# Philosophy

Python can already open archives, but each format has its own library, its own API and its own
gotchas. Archivey aims to put them all behind one interface that behaves the same way for every
format, does what you'd expect, and helps you avoid footguns. Simple tasks stay simple, but the data
and options are there if you need more control.

## What archivey is for

Archivey reads archives. It opens ZIP, TAR (plain or compressed), 7z, RAR and ISO files, as well as
single compressed files such as `.gz` or `.xz`, all through one interface. Code that lists or reads
a ZIP works unchanged on a 7z. It's built for working with an archive's contents from your code:
you can list the members, read one into memory, or go through all of them in one pass, without
extracting anything to disk first. It can also extract to disk, with checks that stop a hostile
archive from writing outside the folder you chose. It doesn't write archives yet.

Each member carries every field its format records: times, permissions, owner, link targets,
comments, stored checksums, and the format's own extras. When formats record the same thing,
archivey puts it in the same field. When they record it differently, the difference stays visible.
A TAR modification time is in UTC, so `modified` carries a time zone. A ZIP that has only the old
DOS time stores local time with no zone, so its `modified` has none. Permissions are set only when
the format stores them, and otherwise `mode` is `None`, rather than a guess.

## No surprises

Archivey tries to make the easy way to use it also the right one, so that problems show up while
you write your code, not later on a file you hadn't tried. Where an operation can quietly cost far
more than it looks, such as seeking inside a compressed member, the default refuses it until you
ask for it. Where refusing would get in the way of ordinary use, such as reading a solid archive
out of order, it's allowed, and [Choosing how to read](reading.md#why-these-arent-on-by-default)
explains the cost. If the data is damaged or cut short, reading it through raises an error instead
of handing back short data as if it were complete, and you still get what archivey could read
before the damage. A strict default can be relaxed later without breaking anyone's code, but a
permissive one can't be tightened.

## Safe with untrusted archives

Archivey is meant to be safe on archives from anyone, such as files uploaded to a server.
Extraction never writes outside the folder you chose, and listing, decompression and extraction
have limits on memory and size, so a hostile archive raises an error instead of exhausting the
machine. If you trust your archives, you can relax the limits and the checks on names and
permissions, but not the check that keeps extraction inside the folder.
[Extracting](extracting.md#archives-you-trust) and [Security](security.md) have the details.

[VISION.md](https://github.com/archivey-dev/archivey/blob/main/VISION.md) explains these principles in more
depth, and the [design rules](https://github.com/archivey-dev/archivey/blob/main/dev-docs/design-rules.md)
show how they settle specific cases.
