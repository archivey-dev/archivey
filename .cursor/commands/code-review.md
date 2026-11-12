# Code review

Review the relevant code with a code review mindset. The process lives in the skill:
[`.claude/skills/code-review-skill/SKILL.md`](../../.claude/skills/code-review-skill/SKILL.md)
— read it first, then the one doc its §1 names for what you are reviewing. This file is
the Cursor entrypoint. It routes and binds the Cursor-specific facts; it is not a second
copy of the rules, and a rule change should never need an edit here.

## Priorities (Cursor `/code-review` defaults)

Keep these as the primary lens, on top of the skill's process:

1. **Bugs** and correctness errors
2. **Behavioral regressions**
3. **Security / safety** issues
4. **Missing tests** (especially red–green for bug fixes)

**Findings must be the primary focus**, ordered by severity. Do **not** make code changes
unless the user explicitly asks for them.

## Cursor-specific facts

- **Your finding-ID prefix is `C`** — `C1`, `C2`, … The rule those IDs follow, and what
  happens to them across rounds, is `SKILL.md` §6.
- **Use only Cursor's included models: Grok 4.7 or later**, for the review and for every
  subagent it starts. Where the skill says Sonnet (or any Claude, GPT or Gemini model),
  use Grok instead: third-party models bill to paid credit, not the included usage.
- **Cursor posts under its own `cursor[bot]` identity**; still end what you post with
  your own attribution footer (`AGENTS.md` §Review workflow).

## Scope

- Default: current branch vs `main` (`git diff main...HEAD` and/or `@Branch`), plus any paths
  or PR the user named. Uncommitted work? Include the working-tree diff.
- **Re-reviewing?** The scope is narrower than the whole PR — `reference/fix-round.md`.
- Skip formatting and lint nits that `ruff` and the type-checkers already own.

The implementing agent then works through it with `/address-review`
([`.claude/skills/address-review-findings/`](../../.claude/skills/address-review-findings/SKILL.md)).
