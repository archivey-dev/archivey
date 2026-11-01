---
name: write-user-docs
description: |
  Write or rewrite a user-facing docs page with the maintainer, one agreed paragraph
  at a time: build the pile of facts, verify each by running code, offer options per
  paragraph, show the final text before committing. Merges five writing skills into one
  voice where "sounds like a person" outranks Simplified Technical English.
  Use when: writing or rewriting a user docs page, "write the next docs page", drafting
  user documentation with the maintainer, editing user docs prose, or when the user
  invokes /write-user-docs.
---

# Write user docs

How user docs pages are written here. Pages written to sentence rules alone came out too
flat, too prescriptive and too detailed, so this process works in small agreed steps and
puts "reads as if a person wrote it" above the sentence rules, below only being true
and being impossible to misread.

This skill sets the voice for **all user docs prose**: `docs/`, the README and the
release's `CHANGELOG.md` entry. Its loop
is for writing or rewriting a page with the maintainer. For a one-sentence fix, use the
Voice and Shaping sections without the loop. Chat, PR comments and briefs still use
[`unslop`](../unslop/SKILL.md). Code comments and exception messages still use
[`asd-ste100`](../asd-ste100/SKILL.md) in strict mode ([`AGENTS.md`](../../../AGENTS.md)
§Writing English).

## The loop

1. **Build the pile first.** List the facts a user needs, mined from `docs/`, the code and
   the tests, and sort them into tiers: the first page, concept pages, and reference. Write
   down who the reader is walking in (writes Python, knows what a ZIP is, has never heard
   of a solid archive) and what they don't know yet. Keep the pile in a notes file, not in
   the PR.
2. **Agree the order.** At site level, each page is one step in the reader's journey and
   says what it grounds for later pages. At page level, propose the sections and their
   order and let the maintainer reorder. The order can change later, so start writing once
   it's roughly right.
3. **One paragraph at a time.** For each paragraph or block, offer two or three options,
   labelled a, b, c. Each option is the actual draft text or a one-line description of
   it, and your recommendation comes first with one line of why. Also argue the format:
   prose, a list, a table, or a code block.
4. **Show the final text before committing it.** Once the maintainer picks and edits,
   post the paragraph as it will appear, and commit only after they accept it. If you
   committed early, say so and post it anyway for edits. Don't roll back.
5. **Treat the maintainer's questions as fact checks.** "Are you sure about opening vs
   seeking?" changed a page. Answer by running code, not from memory, and say what you
   ran.
6. **Commit each agreed section** to the page's draft PR, so the PR always holds only
   agreed text. Read the maintainer's inline PR comments too. Reply on each thread, fix
   it, and resolve it.
7. **When a page is done**, ask for a review (the `review` label) for fresh eyes, merge
   it, and start the next pages in a new PR.

## Verify every behaviour claim by running it

Docstrings and old docs drift. During #523, the `extract_all` docstring still described
the filter order from before a merged change, and several first guesses were wrong:
Windows reserved names such as `CON` are refused under `strict` and `standard` rather than
renamed (`trusted` keeps them, and `sanitize_names` renames them), and refusing `..` or a
link pointing outside happens under every policy, not only some. So:

- Build a tiny archive with the unusual case in it and run it through the API under each
  option. Use `uv run python`, not bare `python3`. Keep the scratch script outside the
  repo, and delete any files it drops in the working tree.
- When a table states behaviour per option, every cell comes from a run.
- When a merged PR changes behaviour the page describes, rerun the checks and update the
  page. If the source has drifted too, fix it in the same docs PR.

## Voice

Precedence when rules disagree, settled from the maintainer's choices in #523:

**true > can't be misread > sounds like a person > grounding > Diátaxis > sentence rules >
STE.**

When two rules still pull different ways on a paragraph, offer the options and let the
maintainer pick. The maintainer settles which rule applies; nothing licenses an
inaccurate sentence.

1. **True, and no bigger than true.** A sentence that isn't quite accurate gets cut, not
   reworded around ("just remove it"). Scope claims to what holds: "whenever possible",
   not "most". Don't imply the opposite case is unsafe ("even for untrusted archives"
   suggests trusted ones aren't safe). Don't sell what every library already does, and
   don't gloat ("helps you" was too much). Be honest about what a workaround can't do:
   "be careful with archives inside archives", not "bound the total yourself" when the
   user can't bound the ratio. Say "best effort" when something is: `on_progress` can stop
   an extraction, but only between chunks.
2. **Can't be misread.** STE's rules were dropped, but its goal stayed. Read each word as
   a stranger would. "Calls" read as "decisions". "RAR archives list" makes the archive do
   the listing ("can be listed"). Archives, members and files never read, list or open
   themselves: write "archivey reads X", "X is read" or "X is supported", never "X
   members read". "Limits apply to one archive at a time" reads as
   concurrency ("apply to each archive separately"). "Works out" became "identifies".
3. **Sounds like a person.** Within the first two, natural wins over rule-following.

Rulings from the maintainer in #523's thread:

- Describe behaviour, don't command facts. Imperatives belong only in real step-by-step
  procedures. Write "each stream works only until the loop moves on", not "read each
  stream inside the loop".
- No imperative-as-conditional. Write "If you use X, Y happens", never "Use X and Y
  happens".
- Never use a term before the page defines it. Don't name a mechanism the reader hasn't
  met: instead of "checksum", write "damage may go unnoticed"; instead of "its block",
  say what the reader sees.
- Vague about how, specific about what happens. A first page can skip the mechanism and
  link to it, but it names the consequence: "reading a member may require decompressing
  all other members before it, which is slow", not "on some archives this is slow".
- Headings name the topic plainly ("Extracting", not "Safe extraction").

## Shaping a page

- **One Diátaxis mode per page.** Don't mix modes on a page; split and link. Grounding
  still wins over the mode on a usage page (see below).

  | Mode | When | Voice |
  | --- | --- | --- |
  | Tutorial | Learning by doing | "we"; every step shows a result |
  | How-to | Goal-directed steps for a competent reader | Imperatives; no teaching digressions |
  | Reference | Lookup facts | Dry, complete, no persuasion |
  | Explanation | Why and trade-offs | Opinion allowed; one bounded topic |

- **Code and tables before prose.** "The code is immediately understandable, more than a
  paragraph." Give an example for each form an argument takes (a list, a function), the
  values and effects of each option, and examples when behaviour depends on the input.
  Use a table only when it fits a 390 px phone screen, which in practice means three
  columns or fewer; otherwise write the same facts as a list, one item per value or input.
- **Follow the user's choices.** Start with the call the reader makes, then the arguments
  they choose, then what each choice does. Every argument of the call appears on the
  page, and each section says which argument it explains.
- **Answer the reader's "why" and "what if".** Find the objection a reader will have and
  answer it on the page: "why don't you just let me do everything", "why refuse reads
  that would be cheap", "will I be left with half a file". Give the reason in terms of
  what it saves the user, such as surprises in production instead of during development.
- **Link, don't list.** Don't repeat fields the code example already shows. Link to the
  reference for the full list.
- **One subject per paragraph.** When one point carries much more detail than the others,
  the change of subject is jarring: split the paragraph and put the lighter point first.
  When a section outgrows its page, move it to its own page and leave a one-line pointer.
  Don't link to a page that doesn't exist yet.
- **Sound current.** Name tools the reader actually uses (uv alongside pip), and lead
  with the fact that matters (the PyPI name). Describe the core first, then what an
  extra adds.

Mechanics:

- No em dashes or en dashes. Use commas or full stops. A colon introduces a list, an
  example, or what the claim before it means ("It's safe by default: nothing lands outside
  `out/`"). It never joins two separate thoughts. Parentheses only as a whole grammatical
  unit. Hyphens in words and ranges ("2-3") are fine.
- Never put a bidi control character in a doc or a chat message. Describe it in words,
  because a real one reverses the rest of the line where it's displayed.
- Show defaults in a code block with one short comment per argument, then explain the
  values.
- Mention that string options are enum values once, where the options are introduced.
- Mix sentence lengths. A short paragraph is fine.

## What the five source skills each contribute

The process merges five external skills. None of them is vendored here. This section is
what was kept from each.

| Source | Kind | Kept |
|---|---|---|
| mattpocock `writing-beats` | process | Grow the text one agreed move at a time, chosen from 2-3 candidates, at site level (page order) |
| mattpocock `writing-shape` | process | The same loop per paragraph, including the argument about format. Grounding: no block leans on an idea the reader hasn't met |
| blader `humanizer` | style | The top goal: the result must sound like a person. Its tell catalogue, ranked by strength |
| pstack `unslop` | style | Cuts puffery, throat-clearing and ornaments. Already in this repo as [`unslop`](../unslop/SKILL.md) |
| pstack `technical-writing` | style | Pick a Diátaxis mode per page (the table in Shaping a page), short everyday words, conditions before instructions |

Where they conflicted, this is how it was settled:

- **Diátaxis vs grounding.** On a usage page, grounding wins. A first page may explain a
  concept in a clause, or stay vague and link out, rather than lean on an undefined term.
- **Punctuation.** `unslop` bans dashes, parentheses and mid-sentence colons, while
  `humanizer` offers colons and parentheses as the replacement for dashes. The rule in
  Mechanics above is the result.
- **STE strictness.** STE's caps (one instruction per sentence, word limits, avoid -ing)
  are a check for real procedures and warnings only. Applied to whole pages they produced
  the flat docs this process replaced.
- **The pile.** Both process skills assume the exploring is done. Here it wasn't, which is
  why step 1 builds the pile before any writing starts.
