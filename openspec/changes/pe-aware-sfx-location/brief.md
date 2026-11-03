# pe-aware-sfx-location — find archives in Windows installers from the executable's own layout

**Status:** Ready to implement. Depends on nothing. Blocks nothing. Not breaking: one narrow change of answer, and signed installers stop warning about their own signature. Effort: medium to large, in three pull requests.

**Why it matters:** The IRPF 2026 installer carries a ZIP thirty-five megabytes in, past the two mebibyte scan window, so detection refuses a file that opening it as ZIP reads fine. The earlier tail probe was struck because it would have read the end of every file. A Windows executable's header says, for free, whether anything was appended to it at all, and where its signature starts.

**What it does:** First, readers learn where a signed installer's signature starts, so they stop warning about it and the ZIP reader searches for its end record before it. Then, when a large executable has appended data and the forward scan found nothing, detection looks for a ZIP end record just before the signature. Last, it checks for an archive exactly where the appended data starts, before scanning.

**Decided:** Gate on the executable's layout, not on a list of installer brands, and add no budget setting. A ZIP found from its end reports the start its end record implies, which never cuts a member off and costs no extra read. A new yes-or-no field says whether the archive had a prefix, instead of testing the offset. The signature's start is reported too and passed to the readers, which never read before their own start. A known signature no longer raises a trailing-data warning. A valid archive at the start of the appended data wins over any other match, in every reader that scans. ZIP64 end records are declined for now, and Linux and macOS executables are out of scope.

**Your call later:** None. The design is settled.

**Bottom line:** A bounded fix for a real missed file, plus quieter signed installers and a decoy-proof path for classic self-extractors. Not urgent.
