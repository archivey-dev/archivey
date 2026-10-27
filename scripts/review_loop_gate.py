#!/usr/bin/env python3
"""Decide whether a review round runs, and write the comment that closes it.

A round starts when someone adds the ``review`` label to a pull request, and the round
takes the label off again as it starts, so the label can be added for the next one.
`.github/workflows/review-loop.yml` is the wiring; this is the part worth testing.
Stdlib only, no GitHub access: the workflow collects the facts and this makes the
decisions.

Two modes, each reading one JSON object on stdin and writing one on stdout.

**Decide** (the default)::

    {"labels": ["review", ...], "markers": ["<!-- archivey-review-round n=1 ... -->"],
     "head_sha": "abc...", "sender_type": "Bot", "sender_login": "claude[bot]",
     "label_since": "2026-09-23T01:00:00Z",
     "label_events": [{"at": "2026-09-23T01:00:00Z", "actor": "claude[bot]",
                       "app": "claude"}],
     "repository": "archivey-dev/archivey"}
    -> {"run": true, "round": 2, "final": false, "person": false, "reason": "...",
        "comment": "", "max_rounds": 5}

``markers`` are the first lines of the workflow's own earlier comments on the pull
request (`ROUND_MARKER` and `ATTEMPT_MARKER`). They are the only state: which rounds ran,
what each one's verdict was, and which commits a review already failed on.
``label_events`` are the pull request's ``review`` labeled events, with the slug of
the app each was ``performed_via_github_app`` (empty for none), and ``label_since`` is
the pull request's ``updated_at`` in the webhook, which labelling bumps; see
`is_person`.

**Finish** (``--finish``)::

    {"round": 3, "final": false, "head_sha": "abc...", "live_head_sha": "def...",
     "repository": "...",
     "verdict": {"verdict": "findings", "summary": "...", "question": ""}}
    -> {"verdict": "findings", "stop": false, "counted": true,
        "comment": "...", "reason": "...", "label": "changes-requested",
        "unlabel": ["approved", "approved-with-fixes", "needs-decision"]}

``verdict`` is the file the reviewing agent wrote, or ``null`` when it wrote none.
``head_sha`` is the commit the round checked out and read; ``live_head_sha`` is the
branch's head when the round closed, and when the two differ the comment says which
commits the review did not see.
The comment says what happened and what the implementer does next, and it carries
the marker that makes the round count. ``label`` is the outcome label the workflow puts
on, taking the ``unlabel`` ones off; see `OUTCOME_LABELS`.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

#: The label that asks for a round. Adding it is the whole trigger.
REVIEW_LABEL = "review"

#: The label that keeps a pull request out of review for good. The review hub carries
#: it: its base is an orphan branch, so its diff is the whole repository, and one
#: `review` label there would review everything.
NO_REVIEW_LABEL = "no-review"

#: How many rounds an agent can ask for before the pull request is a person's.
#:
#: Five (davitf, 2026-09-21): the cap is the backstop that stops two agents going back
#: and forth on one pull request, not the mechanism that ends a review. A round whose
#: verdict does not ask to see the fix already says "no further round" (`VERDICT_STOPS`).
MAX_ROUNDS = 5

#: The round past which nothing runs, whoever asks.
#:
#: A person can buy rounds past `MAX_ROUNDS`, and telling a person from an agent rests
#: on one field GitHub records (`is_person`). This ceiling keeps the bound if that field
#: is ever misread: three spare rounds, as the loop this replaced had (davitf,
#: 2026-09-21).
MAX_FORCED_ROUNDS = MAX_ROUNDS + 3

#: How much older than the webhook's ``updated_at`` this run's labeled event may be.
#: The two are written by the same action and usually agree to the second. The
#: workflow's retry check spells the same number out; a test holds them together.
LABEL_EVENT_SKEW = timedelta(seconds=30)

#: The first line of a closing comment for a round that ran, and what the count counts.
#:
#: The workflow reads only comments by ``github-actions[bot]``, so a person quoting a
#: marker cannot change the count.
ROUND_MARKER = "<!-- archivey-review-round"

#: The first line of a closing comment for a review that stopped before its verdict.
#: Not a round, but the commit it failed on is remembered (see `decide`).
ATTEMPT_MARKER = "<!-- archivey-review-attempt"

_FIELD = re.compile(r"(\w+)=(\S+)")

#: What a round's verdict says about whether another round is wanted.
#:
#: The reviewer decides this, per `code-review-skill` §4: a plain approval,
#: a conditional approval whose open findings have an obvious fix, and a comment all
#: mean "I do not need to see the result". Only "request changes" asks for another
#: look. In the two weeks to 2026-09-19 every 🔴 in this repository was raised in
#: round 1 or 2, and late rounds found almost only wording, so a round the reviewer
#: did not ask for is the back-and-forth the cap exists to bound.
#:
#: A verdict this does not recognise counts as `findings`: a reviewer whose verdict
#: cannot be read has not said it is finished, and the cap still bounds what that costs.
#:
#: This decides what the closing comment asks for, and nothing more. An agent's label
#: after a round that asked for none still runs: a nit or a maintainer question can
#: grow into a larger change that warrants a full review, and the implementer is
#: trusted to judge that (davitf, 2026-09-23).
VERDICT_STOPS = {
    # Nothing was found at all.
    "clean": True,
    # ✅ Approve, with nothing to fix beyond 💡/📚/🎉 annotations.
    "approved": True,
    # ✅ Approve conditional on the listed fixes, or 💬 Comment: findings were posted,
    # and the reviewer does not need to see them fixed. They are still fixed; what ends
    # is the re-reading.
    "conditional": True,
    # 🔄 Request Changes: the next round is the implementer's to ask for.
    "findings": False,
    # A maintainer decision. Once it is answered and acted on, the implementer asks for
    # the next round; the workflow cannot tell an answered question from an open one.
    "decision": False,
}

#: What an unreadable or unrecognised verdict is treated as. See `VERDICT_STOPS`.
DEFAULT_VERDICT = "findings"

#: The label a finished round leaves on the pull request, so its standing shows in the
#: pull request list. A round puts its own on and takes the others off.
#:
#: These only report. Nothing here reads them, and nothing may: a status label that
#: steered the rounds is what went wrong with the ``loop:round-N`` labels this workflow
#: replaced, and the round markers stay the only state (davitf asked for the labels,
#: 2026-09-23). A round that did not finish, or did not run, leaves them as they were,
#: and one left on after later pushes goes stale; the marker names the commit reviewed.
OUTCOME_LABELS = {
    "clean": "approved",
    "approved": "approved",
    "conditional": "approved-with-fixes",
    "findings": "changes-requested",
    "decision": "needs-decision",
}


def _footer(repository: str) -> str:
    # A relative link does not resolve from an issue comment, so spell the URL out.
    doc = f"https://github.com/{repository}/blob/main/dev-docs/review-loop.md"
    return (
        f"\n\n---\n_Posted by the [review workflow]({doc}). "
        "[Claude Code](https://claude.ai/code) wrote the review; "
        "this comment is bookkeeping._\n"
    )


# --- what the earlier comments say ----------------------------------------------------


@dataclass(frozen=True)
class History:
    #: Rounds that reached a verdict.
    rounds: int
    #: Commits a review stopped on before reaching a verdict.
    failed_shas: frozenset[str]


def read_history(markers: object) -> History:
    """What the workflow's own earlier comments record, from their first lines."""
    rounds = 0
    failed: set[str] = set()
    for line in markers if isinstance(markers, list) else []:
        if not isinstance(line, str):
            continue
        fields = dict(_FIELD.findall(line))
        if line.startswith(ROUND_MARKER + " "):
            rounds += 1
        elif line.startswith(ATTEMPT_MARKER + " ") and fields.get("sha"):
            failed.add(fields["sha"])
    return History(rounds, frozenset(failed))


def _when(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def label_event(event: dict) -> dict | None:
    """The labeled event this run is for, or None when it cannot be found.

    The latest ``review`` event on the pull request is not enough on its own: the
    events API can lag the webhook by a few seconds, and then the latest listed event
    is an earlier label, perhaps a person's click. So only an event by this run's
    sender, no older than the webhook's ``updated_at`` less `LABEL_EVENT_SKEW`, is
    taken. The workflow retries the fetch a few times before giving up.
    """
    since = _when(event.get("label_since"))
    if since is None:
        return None
    earliest = since - LABEL_EVENT_SKEW
    sender = event.get("sender_login")
    found = []
    for item in event.get("label_events") or []:
        if not isinstance(item, dict) or item.get("actor") != sender:
            continue
        at = _when(item.get("at"))
        if at is not None and at >= earliest:
            found.append((at, item))
    return max(found, key=lambda pair: pair[0])[1] if found else None


def is_person(event: dict) -> bool:
    """Did a person add the label, rather than an agent?

    ``sender.type`` alone is not enough. An agent working from a Claude Code project
    thread sometimes lands its label as ``davitf``, type ``User``: #384's events show
    one at 2026-09-21T01:57:37Z, with ``performed_via_github_app: claude``, while the
    same route landed as ``claude[bot]`` on #392 and #399. What separates the two is
    that app field, which is empty only when someone acted without an app, in GitHub's
    own interface. An event that cannot be found (`label_event`) counts as an agent:
    that can only refuse a person, and a second click fixes it.
    """
    found = label_event(event)
    return (
        event.get("sender_type") == "User"
        and found is not None
        and found.get("app") == ""
    )


# --- deciding whether a round runs ----------------------------------------------------


@dataclass(frozen=True)
class Decision:
    run: bool
    round: int
    reason: str
    #: The round about to run is the last one an agent can ask for.
    final: bool = False
    #: A person asked, so the agent-only refusals did not apply.
    person: bool = False
    #: What to post when no round runs and the reason is worth announcing, else empty.
    comment: str = ""
    #: The cap, so the workflow's prompt has one source for it.
    max_rounds: int = MAX_ROUNDS


def decide(event: dict) -> Decision:
    """Should adding the label run a round now, and which round is it?"""
    labels = list(event.get("labels") or [])
    history = read_history(event.get("markers"))
    done = history.rounds
    nxt = done + 1
    person = is_person(event)
    footer = _footer(str(event.get("repository") or ""))
    label = f"`{REVIEW_LABEL}`"

    def refuse(reason: str, comment: str) -> Decision:
        return Decision(False, done, reason, person=person, comment=comment + footer)

    if REVIEW_LABEL not in labels:
        # The label was on the pull request when the event fired and is gone now: a
        # round that started meanwhile took it, or a person changed their mind. Either
        # way nobody is asking any more.
        return Decision(False, done, f"the {REVIEW_LABEL!r} label is no longer set")

    if NO_REVIEW_LABEL in labels:
        return refuse(
            f"{NO_REVIEW_LABEL!r} is set",
            f"**Not reviewed: this pull request carries `{NO_REVIEW_LABEL}`.** "
            "Nothing reviews it while that label is on.",
        )

    if nxt > MAX_FORCED_ROUNDS:
        return refuse(
            "the ceiling is spent",
            f"**Not reviewed: {MAX_FORCED_ROUNDS} rounds have run, which is the most "
            "this workflow runs on one pull request.** Review the rest by hand.",
        )

    if not person:
        if nxt > MAX_ROUNDS:
            return refuse(
                "round cap spent, and an agent asked",
                f"**Not reviewed: all {MAX_ROUNDS} rounds an agent can ask for are "
                "spent.** This pull request needs a person now. A person adding the "
                f"{label} label still buys another round.",
            )
        head_sha = str(event.get("head_sha") or "")
        if head_sha and head_sha in history.failed_shas:
            return refuse(
                "a review already failed at this commit, and an agent asked",
                "**Not retried: a review already stopped before its verdict at this "
                "commit.** Retrying the same commit usually fails the same way. If it "
                "stopped within seconds, the likely cause is that this branch's copy "
                "of the review workflow differs from `main`'s: merge `main` and add "
                f"the {label} label again. A person adding the label retries as is.",
            )

    return Decision(
        True,
        nxt,
        "requested by a person" if person else "requested by an agent",
        final=nxt >= MAX_ROUNDS,
        person=person,
    )


# --- finishing a round -----------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """What the round's own verdict file says, once it has been made safe to act on."""

    verdict: str
    #: The reviewer does not need another round.
    stop: bool
    summary: str
    #: Only a `decision` carries one; anything else is dropped rather than shown.
    question: str
    reason: str


def read_verdict(payload: object) -> Verdict:
    """The reviewer's verdict file, normalised.

    The reviewing agent writes this file, so it is the one input that is prose rather
    than GitHub state. Every answer names what it read, so a spelling nobody expected
    shows up in the run summary instead of quietly becoming another round.
    """
    if not isinstance(payload, dict):
        return Verdict(
            DEFAULT_VERDICT, False, "", "", "the verdict file is not a JSON object"
        )

    raw = payload.get("verdict")
    name = raw.strip().lower() if isinstance(raw, str) else ""
    summary = payload.get("summary")
    summary = summary.strip() if isinstance(summary, str) else ""
    question = payload.get("question")

    if name not in VERDICT_STOPS:
        return Verdict(
            DEFAULT_VERDICT,
            False,
            summary,
            "",
            f"verdict {raw!r} is not one this loop knows; treating it as "
            f"{DEFAULT_VERDICT!r}",
        )

    return Verdict(
        name,
        VERDICT_STOPS[name],
        summary,
        # A question on any other verdict would read as though something waits on the
        # maintainer, on a pull request where nothing does.
        question.strip() if name == "decision" and isinstance(question, str) else "",
        f"verdict {name!r}",
    )


@dataclass(frozen=True)
class Finish:
    verdict: str
    stop: bool
    #: The comment carries `ROUND_MARKER`, so this round counts towards the cap.
    counted: bool
    comment: str
    reason: str
    #: The outcome label to put on (`OUTCOME_LABELS`), or empty to leave them alone.
    label: str = ""
    #: The other outcome labels, to take off when `label` goes on.
    unlabel: tuple[str, ...] = ()


def finish(event: dict) -> Finish:
    """The comment that closes a round: what the review said and what happens next."""
    rnd = int(event.get("round") or 0)
    final = bool(event.get("final"))
    sha = str(event.get("head_sha") or "")
    footer = _footer(str(event.get("repository") or ""))
    label = f"`{REVIEW_LABEL}`"

    if event.get("verdict") is None:
        # Not a round: the review did not reach a verdict, and one that died early (one
        # on #352 did, 481 ms in) has not spent the reviewer's time. The attempt marker
        # records the commit, so an agent cannot retry it into a loop (`decide`).
        marker = f"{ATTEMPT_MARKER} n={rnd}{f' sha={sha}' if sha else ''} -->"
        return Finish(
            DEFAULT_VERDICT,
            False,
            False,
            f"{marker}\n\n**Round {rnd} did not finish.** The review stopped before it "
            "reached a verdict, so the round was not counted. If it stopped within "
            "seconds, the likely cause is that this branch's copy of the review "
            "workflow differs from `main`'s: merge `main`, then add the "
            f"{label} label again. An agent's retry at this same commit is refused; "
            "a person's is not." + footer,
            "no verdict file",
        )

    v = read_verdict(event.get("verdict"))
    summary = f" {v.summary}" if v.summary else ""
    live = str(event.get("live_head_sha") or "")
    unseen = (
        f"\n\n**Pushed during the round.** The review read `{sha[:8]}`; the branch is "
        f"now at `{live[:8]}`, and nothing reviewed the commits in between."
        if sha and live and live != sha
        else ""
    )

    def again(sentence: str) -> str:
        """How another round starts, which the cap and the ceiling can change."""
        if rnd >= MAX_FORCED_ROUNDS:
            return (
                "This was the last round this workflow runs on this pull request, so "
                "review anything further by hand."
            )
        if final:
            return (
                f"All {MAX_ROUNDS} rounds an agent can ask for are spent, so only a "
                f"person adding the {label} label starts another."
            )
        return sentence

    if v.verdict == "decision":
        body = (
            f"**Round {rnd} stopped for a decision.**{summary}\n\n"
            f"**The question:** {v.question or 'see the review above.'}\n\n"
            "The options, and what each one costs, are in the review above. "
            + again(f"Once it is answered, add the {label} label again to carry on.")
        )
    elif v.verdict == "clean":
        body = (
            f"**Round {rnd} found nothing to fix.**{summary}\n\n"
            "This is ready for a person to look at and merge."
        )
    elif v.stop:
        # Not "the review approved it": this covers ✅ Approve, the conditional
        # approval and 💬 Comment, and SKILL.md §4 is explicit that a comment is not
        # an approval.
        body = (
            f"**Round {rnd}: the review does not need to see the result.**{summary}\n\n"
            "Work through any findings it posted with `address-review-findings`. No "
            "further round is needed. "
            + again(
                "If the fixes grow into a larger change that needs a fresh look, add "
                f"the {label} label again."
            )
        )
    elif rnd >= MAX_FORCED_ROUNDS:
        body = (
            f"**Round {rnd} posted findings, and that was the last round this workflow "
            f"runs on this pull request.**{summary}\n\n"
            "Work through them with `address-review-findings`, and review the result "
            "by hand."
        )
    elif final:
        body = (
            f"**Round {rnd} posted findings, and that was the last round an agent can "
            f"ask for.**{summary}\n\n"
            "Work through them with `address-review-findings`. Nothing reviews the "
            f"result unless a person adds the {label} label."
        )
    else:
        body = (
            f"**Round {rnd} posted findings and wants to see the fixes.**{summary}\n\n"
            "Work through them with `address-review-findings`, push, and then add the "
            f"{label} label again for round {rnd + 1}. Up to {MAX_ROUNDS} rounds run "
            "this way."
        )

    marker = (
        f"{ROUND_MARKER} n={rnd}{f' sha={sha}' if sha else ''} verdict={v.verdict} -->"
    )
    outcome = OUTCOME_LABELS[v.verdict]
    return Finish(
        v.verdict,
        v.stop,
        True,
        f"{marker}\n\n{body}{unseen}{footer}",
        v.reason,
        outcome,
        tuple(sorted({other for other in OUTCOME_LABELS.values() if other != outcome})),
    )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        payload = {"_error": str(exc)}

    if "--finish" in sys.argv[1:]:
        # Never an error exit: the findings are already on the pull request, and the
        # round still has to say so and take its label off.
        if "_error" in payload:
            answer = asdict(
                Finish(DEFAULT_VERDICT, False, False, "", payload["_error"])
            )
        else:
            answer = asdict(finish(payload))
    else:
        answer = asdict(decide(payload if isinstance(payload, dict) else {}))

    json.dump(answer, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
