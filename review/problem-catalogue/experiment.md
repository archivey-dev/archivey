# `experiment.md` — the fresh-design comparison

The catalogue's second consumer. Written now because writing it now is what keeps the
schema honest ([`brief.md`](brief.md) §The experiment); **running it is a later, separate
exercise** and this document does not claim it has been run.

> **Status: not run.** No results section exists yet. When the experiment is run, its
> output goes in `results/<date>-<model>/` beside this file, and the divergence table's
> "not considered" rows become findings filed against the review that owns each area.

## What it is for

The catalogue was built by reading archivey's own documents, so it inherits archivey's
priors. The experiment is the only check available on whether the problem *set* is the
real problem set: hand the forces to a designer with no exposure to this library, see what
they build, and sort the differences.

It is not a competition and it is not a validation. It has exactly one valuable output:
**problems archivey never considered, or considered and resolved on reasoning that does not
survive a second framing.** Everything else is noise, and §Grading is written to keep it
out.

## The one thing that invalidates it

If a problem in [`catalogue-neutral.md`](catalogue-neutral.md) is phrased in archivey's
vocabulary, the model is being asked a leading question and its agreement proves nothing.
That is a defect in the catalogue, not in the experiment
([`brief.md`](brief.md) §The neutrality rule).

Two mechanical guards exist, both in `scripts/tests/test_review_problem_catalogue.py`:

- `catalogue-neutral.md` is **derived** from `catalogue.md` by
  `scripts/review/derive_neutral_catalogue.py`, and the test fails if the committed file is
  stale. Redaction is therefore not a step anyone can forget at experiment time.
- No entry's fields 1–3 may name an archivey type, module or config field.

Neither guard checks *voice*, which is the part that matters and is a human review pass.
Before running, spot-check a sample against §Pre-flight.

## Inputs

| Input | Value | Why |
|---|---|---|
| The problems | `catalogue-neutral.md`, **whole file, verbatim** | Fields 1–3 only. Never `catalogue.md` |
| The goals | `VISION.md`, **whole file** | The experiment asks for a design against archivey's *goals*, so a divergence is about means, not ends. Withholding the goals produces a design for a different library and nothing is comparable |
| Nothing else | — | No `docs/`, no `openspec/`, no `src/`, no repository access, no ADRs, no mention of the library's name |

`VISION.md` names archivey. That is unavoidable and acceptable: it states goals, not
mechanisms. Do **not** substitute a paraphrase — a hand-written version of the goals is an
unrecorded variable.

## Procedure

Run each arm in a **fresh session with no history**. The model must not see another arm's
output, and must not see any grading.

### 1. Set up

```bash
cd "$(git rev-parse --show-toplevel)"
python scripts/review/derive_neutral_catalogue.py --check   # must exit 0
git rev-parse --short HEAD                           # record as the catalogue revision
```

Record, in `results/<date>-<model>/manifest.md`: the catalogue revision, the model
identifier and version, the exact prompt, and the number of entries
(`grep -c '^### ' review/problem-catalogue/catalogue-neutral.md`).

### 2. Arm A — design from the problems (the experiment)

Prompt, verbatim:

> Below are two documents. The first states the goals of a library for reading archive
> files. The second is a list of problems that such a library must contend with — properties
> of archive formats, defects in the libraries and tools available to implement it,
> platform behaviour, hostile input, and usage patterns. Each problem states what happens
> in the world, what someone observes, and the evidence that it is real. None of them
> describes a solution.
>
> Design the library. Produce:
>
> 1. The public interface: the operations a caller performs, and their signatures.
> 2. The internal structure: the components, what each owns, and how they compose.
> 3. For each of the numbered problems, which part of your design addresses it — or an
>    explicit statement that your design does not address it, and why you chose not to.
> 4. The three design decisions you are least confident about, and what evidence would
>    settle each.
>
> Do not describe an implementation plan or write code. Do not assume any existing
> library's structure.
>
> --- GOALS ---
> [contents of VISION.md]
>
> --- PROBLEMS ---
> [contents of catalogue-neutral.md]

Item 3 is what makes the result gradeable — without it, an omission cannot be told from a
disagreement. Item 4 is where the honest uncertainty lives, and is often the most useful
part of the output.

### 3. Arm B — the control (run this, it is cheap and it is the whole basis for reading Arm A)

Same session discipline, **goals only, no problems**:

> Below are the goals of a library for reading archive files. Design the library, with the
> same four deliverables …
>
> --- GOALS ---
> [contents of VISION.md]

Arm B measures how much of Arm A's output came from the catalogue rather than from what the
model already knew about archive libraries. Anything Arm B produces unprompted is **shared
prior knowledge, not a finding** — a convergence with archivey there tells us nothing, and a
divergence there is the model's own priors, not a response to our problems. Without Arm B
every convergence in Arm A is uninterpretable.

### 4. Arm C — optional, the coverage probe

Goals only, and ask for the *problems* rather than a design:

> … list the non-obvious problems a library meeting these goals will have to solve. For
> each, state what happens in the world and what someone observes.

Then diff against `catalogue-neutral.md`. Arm C is the only arm that can find a problem the
catalogue *missed* — Arms A and B cannot, because they are graded against a design. Its
output is candidate entries: each needs evidence before it may enter the catalogue, and
unevidenced ones go on the unverified list, never in it
([`brief.md`](brief.md) §Hard constraints).

### 5. Grade

Grade **with `catalogue.md` open** — field 4 is exactly the material grading needs, and is
the reason it is a separate field rather than a separate document.

Do not let the model grade itself, and do not show it archivey's design. If a second model
is used as a grader, give it the same inputs a human grader gets, and record that it was
used.

## Grading

For every point where the produced design differs from archivey's, fill one row:

| Column | Values |
|---|---|
| Entry id(s) | `FQ-06`, … — or `—` if the divergence is not about a catalogued problem |
| Divergence | One sentence: what they do, what we do |
| Bucket | `already-considered` · `not-considered` · `prior` · `out-of-scope` |
| Citation | For `already-considered`: the ADR / change / finding from field 4 |
| Does the reasoning still hold? | For `already-considered` only: `yes` / `weakened` / `no`, with why |
| Action | For `not-considered` and `weakened`/`no`: the review that owns the area |

### The four buckets

- **`already-considered`** — field 4 cites a decision that weighed this. The value is not
  "we were right"; it is a **re-test**: does the recorded reasoning still hold under the
  model's framing? A `weakened` or `no` here is as much a finding as a `not-considered`,
  and is easier to miss because the row starts out looking like a win.
- **`not-considered`** — no decision covers it. **This is the output of the experiment.**
- **`prior`** — Arm B produced it too, so it is shared prior knowledge rather than a
  response to the catalogue. Record and set aside; do not count it either way.
- **`out-of-scope`** — the design targets something `VISION.md` excludes (writing, async,
  a different language). Not a finding.

### Reading the result

**Convergence is weak evidence; divergence is the signal.** A model trained on
archive-handling libraries shares our priors, so agreement proves little — the same caveat
`#208` and Topic 9's two-pass round already recorded, and the reason both were run isolated
rather than in conversation ([`brief.md`](brief.md) §The experiment).

Concretely:

- A convergence that Arm B **also** produced is worth nothing. Bucket it `prior`.
- A convergence that Arm B did **not** produce is worth a little: the catalogue entry
  carried enough of the force to lead an independent designer to the same place.
- **A `not-considered` divergence is worth the whole exercise**, even one, even a small one.
- A model *failing* to address a catalogued problem is **not** evidence the problem is
  unimportant. It is one design session against work that took months. Never use Arm A's
  silence to argue for removing a guard — that inversion is the most likely way for this
  experiment to do harm.

### Reporting

`results/<date>-<model>/`:

| File | Contents |
|---|---|
| `manifest.md` | Catalogue revision, model + version, prompts verbatim, entry count, who graded |
| `arm-a.md`, `arm-b.md`, `arm-c.md` | Raw output, unedited |
| `divergences.md` | The table above, one row per divergence |
| `findings.md` | The `not-considered` rows and the `weakened`/`no` rows, each addressed to the review that owns the area |

`findings.md` is the deliverable. **File its rows as findings; do not act on them here** —
Topic 10 makes no fixes, no refactors and no spec changes
([`brief.md`](brief.md) §Hard constraints), and a catalogue that starts changing the design
it catalogues stops being a record of the problems.

## Pre-flight

Before spending the run:

- [ ] `python scripts/review/derive_neutral_catalogue.py --check` exits 0.
- [ ] `uv run --no-sync pytest scripts/tests/test_review_problem_catalogue.py -q` passes.
- [ ] Sample ten entries at random and read fields 1–3 as a stranger would. Each states
      what the world does, not what a library does. Rewrite any that fail; a bad entry
      costs a whole run.
- [ ] `catalogue.md` is **not** in the input set. Check the actual bytes being sent.
- [ ] Arm B is scheduled. Arm A alone is not interpretable.
- [ ] The manifest records the catalogue revision, so a later run is comparable.

## Cheaper variants, if a full run is not warranted

The full protocol costs three sessions and a grading pass. Two subsets are worth running on
their own:

- **Arm C alone** — the coverage probe. Answers "what is the catalogue missing?", needs no
  design, and its output is candidate entries rather than findings. The cheapest useful
  thing in this document.
- **A single-category Arm A** — hand over one category's entries (say every `SEC-*`) and
  ask for that area's design. Narrower, much cheaper to grade, and enough to test whether
  the catalogue's voice carries at all. A good first run before committing to the whole
  thing.
