# name-encoding-auto — an opt-in guess for Japanese, Chinese and Korean member names

**Status:** Design draft for review. Implementation can start once the design is
accepted. It depends on nothing and blocks nothing. Not breaking. Effort: medium.

**Why it matters:** Archives made by older tools store names in a local code page and
don't say which one. A caller who doesn't know the code page gets garbled names for
every Japanese, Chinese or Korean archive.

**What it does:** Passing encoding equals auto asks archivey to guess the code page of
names that are not valid UTF-8. The guess picks among Shift JIS, EUC-JP, GBK, Big5 and
the Korean code page. It uses small built-in character-frequency tables, about twelve
kilobytes, and needs no new dependency. When no code page wins clearly, it abstains, and
the name decodes exactly as it does today.

**Decided:** Latin code pages are never guessed, because every guesser tested was often
wrong where the default was right. Each name is guessed from the legacy names met so
far, in archive order, and the guess freezes after the first 256. Each stored name, and
each directory path, decodes once per reader, so a folder and its children always stay
one tree. A folder waits for the next entry that is not a folder before it is decoded.
So every path comes out right in 76-100% of single-folder archives, against 15-91%
without the wait and 90-100% for a whole-archive guess. The wait reads only headers, at
most 64 entries ahead, and never past a listing limit. Streaming and random access give
the same names, with no member data buffered on TAR streams. The exceptions are a ZIP
whose central directory is in another order than its local headers, a ZIP with damaged
local headers, and the folders just before a listing limit raises. A symbolic link among
the first few names that points forward may not resolve, which is accepted and tested.
Link targets and comments never change the guess, and an archive comment is never
guessed, so it reads the same whenever it is read. Plugins decode member names with
decode name, other text with a new decode text, and LHA's name-and-target field with a
new decode name and target. ISO takes the Joliet name before guessing. Every guessed
name reports the existing inferred-encoding diagnostic, and the strict policy refuses
it. Cyrillic, Greek and Hebrew need the chardet library and wait for a later change.

**Your call later:** None. The design is settled. The frequency tables come from
Wikipedia titles, as measured, and names that happen to be valid UTF-8 stay out of the
guess.

**Bottom line:** A small, well-measured feature, with the hard consistency question
settled in the design. It is ready once the review agrees.
