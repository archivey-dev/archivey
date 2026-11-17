"""External command-line decompressors, independent of any one archive format.

- :mod:`.cli` — find a program on ``PATH``, identify it once by its banner (with a
  timeout), cache that answer per binary, and stop a child process.
- :mod:`.unar` — ``unar`` from The Unarchiver's XADMaster library: identification,
  the argv archivey builds, and the stdout wrapper that owns the child process.

A backend decides *whether* a program may serve a read (the format-specific refusals
live next to the backend, e.g. :mod:`archivey.internal.backends.rar_unar`). This package
only knows how to run the program safely and how to read its result. RARLAB ``unrar``
keeps its own finder, in :mod:`archivey.internal.backends.rar_unrar`.
"""
