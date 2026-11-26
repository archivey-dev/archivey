# Direction reviews, November 2026

Four agents from different providers each wrote a high-level direction review of archivey
on 2026-11-23 and 2026-11-24: what is missing, what is too complicated in the API and the
internals, and whether the project has gone too far. None of them read the others. They
were not bug hunts. The assessment compares them, checks their claims against the code,
and turns them into a ranked trim plan, followed by the decisions the maintainer took.

| File | Written by | Original PR |
|------|------------|-------------|
| [assessment.md](assessment.md) | Claude, comparing the four | not a PR |
| [openai-codex.md](openai-codex.md) | OpenAI Codex | [#1821](https://github.com/archivey-dev/archivey/pull/1821) |
| [cursor.md](cursor.md) | Cursor cloud agent | [#1822](https://github.com/archivey-dev/archivey/pull/1822) |
| [google-gemini.md](google-gemini.md) | Google Gemini | [#1823](https://github.com/archivey-dev/archivey/pull/1823) |
| [anthropic-claude.md](anthropic-claude.md) | Anthropic Claude (Claude Code) | [#1824](https://github.com/archivey-dev/archivey/pull/1824) |

Each review file is its PR's documents joined into one file, otherwise unchanged. The
reviews describe `main` as it was on 2026-11-23, so some of their claims were already out
of date then; the assessment lists those. Read the assessment first.
