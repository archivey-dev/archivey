# program-resource-archives — stop warning about the program bytes after an archive stored as a resource

**Status:** Implemented in one pull request. Depends on `pe-aware-sfx-location` (archived). Not breaking: one warning goes away on one kind of installer.

**Why it matters:** Squirrel, the installer Electron apps use on Windows (GitHub Desktop, Slack, Discord), keeps its ZIP as a resource inside the setup program's `.rsrc` section. Icons, version strings, `.reloc` and the signature follow it. Archivey opens the ZIP but warns that data follows it, and `STRICT` refuses the file, although those bytes are the program's own.

**What it does:** When the archive ends inside one resource's data, the trailing-data check stops at that resource's end. Bytes past it are the rest of the program and are not reported. Junk inside the resource, after the archive, still is. ZIP, 7z and RAR do this; LHA is left as it is.

**Decided:** A rule about resources, not a Squirrel special case. Read lazily: nothing is read unless a reader already found a non-zero byte after its archive. The same answer for auto-detect and a forced `format=`, because the resource table comes from the program's headers, not from where detection found the archive.

**Your call later:** None.

**Bottom line:** Squirrel installers open under `STRICT`, at no cost to any other file.
