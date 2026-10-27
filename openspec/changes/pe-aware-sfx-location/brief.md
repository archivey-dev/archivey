# pe-aware-sfx-location — find archives in Windows installers from the executable's own layout

**Status:** Ready to implement, with one small choice left open. Depends on nothing. Blocks nothing. Not breaking, with one narrow change of answer. Effort: medium, in two pull requests.

**Why it matters:** The IRPF 2026 installer carries a ZIP thirty-five megabytes in, past the two mebibyte scan window, so detection refuses a file that opening it as ZIP reads fine. The earlier tail probe was struck because it would have read the end of every file. A Windows executable's header says, for free, whether anything was appended to it at all.

**What it does:** It reads where the program's sections end and where its code signature sits. When a large executable has appended data and the forward scan found nothing, it looks for a ZIP end record just before the signature, and confirms it before answering. Separately, it checks for a RAR, 7z or ZIP archive exactly where the appended data starts, before scanning, which is where the 7-Zip and WinRAR installers put theirs.

**Decided:** Gate on the executable's layout, not on a list of installer brands. Ordinary programs never pay for a tail read. No new budget setting. The answer is still reported as an SFX scan hit, and the tail read gets its own tier name for the records. A valid archive at the start of the appended data wins over an earlier match inside the program, and the RAR and 7z readers follow the same rule. ZIP64 end records are declined for now. Linux and macOS executables are out of scope.

**Your call later:** Which offset to report for a ZIP found from its end. The recommendation is the first entry's local header.

**Bottom line:** A small, well-bounded fix for a real missed file, plus a cheaper and decoy-proof path for classic self-extractors. Not urgent.
