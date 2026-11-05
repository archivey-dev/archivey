# Tasks

- [x] 1.1 `FileCopySources` counts copies per source; `copy_reached()` and `advance()`
      let a source go after its last copy.
- [x] 1.2 The solid pass calls them from its per-member open, after the driver has
      closed the previous stream.
- [x] 1.3 Tests: two sources with room in the spool for one keep both in turn with one
      decompressor run; a released memory source frees its room.
