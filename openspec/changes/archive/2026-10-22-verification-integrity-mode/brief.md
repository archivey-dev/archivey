<!--
The "coffee brief": a spoken-word-friendly summary of this change, readable (or
read aloud) in under a minute. Prose only — NO tables, NO code blocks, minimal
symbols — so text-to-speech reads cleanly. Aim for ~200–280 words. Derive it from
proposal.md / design.md / tasks.md; do not introduce new decisions here.
-->

# verification-integrity-mode — A strict opt-in for content verification

**Status:** Closed, not implemented (2026-10-22): the verification level replaced it. Earlier: parked, not part of 0.2.0 (2026-10-07). The questions below were never answered, and no longer need to be.

**Why it matters:** Content verification is verify-as-you-go. Read a member fully and you get a verdict; read part of it, or seek, or read then close, and verification is quietly abandoned. That is deliberate, it is what keeps verification inside the performance budget, and decision fourteen settled it as the contract. What is missing is the way out of that bargain. Someone extracting an untrusted archive wants to demand verification however they read, and there is no way to ask. For an encrypted member the gap is sharper, because the authentication tag sits at the end: a partial read hands back plaintext that nobody has authenticated, with no error and no signal. The caller who most needs the guarantee is the one who cannot get it.

**What already happened:** This proposal had two halves and the first one shipped. Pull request three hundred and fifty removed the WinZip AES close-time drain, so the default is now uniform across checksummed and encrypted members, and two of the four original questions went with it.

**What it does:** It adds one opt-in mode, strict, that guarantees a verdict no matter how you read. A partial read forces a bounded verifying pass. A seek either verifies ahead or fails, never silently drops the check. Close completes verification. Strict can force a full decompress or decrypt in advance, so it knowingly breaks the performance budget, and it is never selected implicitly.

**Why it is not scheduled:** The maintainer asked that strict and the separate idea of verification state as data, a verified level on a stream plus an on-demand verify method, be designed as one question rather than two. Both run through the same verifier class, and a mode flag designed alone would later have to be reconciled with a level model covering the same ground.

**Your call, when it comes up:** the names, and whether a strict seek verifies ahead or fails.
