## MODIFIED Requirements

### Requirement: Confirm candidates when a weak check permits retries

When a format's password check can admit wrong values, a candidate SHALL NOT be
accepted or added to known-good on that weak check alone if another distinct
candidate may be tried.

**Confirmation is a rejection filter, not a proof.** Its job is to stop a wrong
candidate from shadowing a correct one; the authoritative digest still runs on the
caller's own stream. Confirmation SHALL therefore be bounded, and SHALL obey "Bounded
implicit temporary storage" — no plaintext buffering proportional to unit size, and no
decode work proportional to unit size where a cheaper signal decides the same question.

A confirmation step SHALL yield one of three verdicts:

| Verdict | Meaning |
| --- | --- |
| `REJECTED` | this candidate is wrong; try the next |
| `CONFIRMED` | a signal of at least 2⁻³² strength matched; accept |
| `INCONCLUSIVE` | the candidate survived its budget without reaching a deciding signal |

The budget has **two** halves, and a spec that names only the first does not bound the
work. The plaintext half is `PASSWORD_CONFIRM_PREFIX_BYTES` (64 KiB of decoded output):
not one byte, and not `DetectionBudget.max_prefix_bytes`, since confirm measures
decompressed output where detection measures source peeks. The compressed half is a cap
on how much input may be consumed to produce that output, and it SHALL be stated too.

A block-transform codec emits nothing until it has consumed a whole block, so an
output-only bound does not constrain it: decoding 64 KiB of output from a bzip2 stream
consumes 905 KB of input (13.8× the bound), against 1.1× for LZMA2. The inner-TAR
content probe already carries a cap sized for exactly this
(`_INNER_TAR_MAX_PROBE_BYTES`, 1 MiB, chosen for bzip2's worst-case block), and confirm
SHALL use a bound of that shape rather than re-derive one.

Backends SHALL apply the strongest signal reachable, in this order:

1. **Cheap key check** — an O(1) test that confirms the *key* without decoding payload
   data. Confirms only at ≥ 2⁻³²; SHALL NOT reject on its own where a format permits
   writers to vary the bytes it inspects.
2. **Integrity anchor** — a stored checksum over a decodable prefix of the unit. The
   **earliest sufficient** anchor SHALL be used, and a plan SHALL stop once
   checksum-verified bytes reach 4; a shorter verified prefix carries less than 32 bits
   and SHALL NOT terminate the plan on its own. If that anchor sits **inside** the
   budget, decode to it and stop. If it sits **past** the budget: a chain with a
   rejecting codec SHALL NOT walk it (rung 3 settles a wrong key without reading the
   unit); a chain with no rejecting codec SHALL walk it anyway (nothing else can tell a
   wrong key from a right one).
3. **Codec rejection** — a chain *rejects* iff it contains a decompressor measured to
   fail on random input. Surviving a bounded prefix yields `INCONCLUSIVE`, not
   `CONFIRMED`. Filters (Delta, BCJ) never reject. A codec not yet measured is treated
   as non-rejecting until a test says otherwise.

**When no digest exists anywhere in the unit**, the backend SHALL NOT invent an
unbounded decode to discover that. A rejecting chain uses the prefix (`INCONCLUSIVE` on
survive); a non-rejecting chain stops at the budget and the caller's read-time digest is
authoritative. Candidate ambiguity does not change this: an unbounded multi-candidate
pass exists to find whose output matches a stored checksum, and there is none to match.

**When a digest exists but sits past the budget**, rung 2 governs, and the unbounded
pass a non-rejecting chain runs there is per candidate when the set is ambiguous.

**Resolving several candidates.** A `CONFIRMED` candidate SHALL be accepted at once, and
no later candidate SHALL be probed for that unit. A `REJECTED` candidate SHALL be
skipped. An `INCONCLUSIVE` candidate SHALL NOT be accepted while static candidates
remain to probe: every remaining static candidate SHALL be probed with the same bounded
plan. Then:

- one survivor SHALL be accepted, `INCONCLUSIVE`, when no provider can be asked for the
  unit, or when the unit has no full check (it is read once, or a plugin gave no
  `full_check`): the provider is then not asked first. When a provider can be asked and
  there is a full check, the survivor SHALL run it as several do, and a `REJECTED`
  result SHALL lead to the provider: the survivor may be a known-good
  password from another unit, and the provider may hold this unit's own. With no
  provider, a lone survivor means every other static candidate was rejected, so the
  read's own check reports a wrong one and the unit is decoded once;
- several survivors SHALL each, in candidate order, run the **full check**: the plan
  that walks to the unit's end anchor whatever the codec. The first survivor it confirms
  SHALL be accepted. When the unit has no anchor to walk to, the first survivor SHALL be
  accepted, `INCONCLUSIVE`. When the full check rejects every survivor, the provider, if
  any, SHALL be consulted as if no static candidate had survived;
- provider answers SHALL NOT be gathered this way: the provider stays lazy, and is
  asked one answer at a time. An `INCONCLUSIVE` answer SHALL run the full check first
  when the unit has one, and a `REJECTED` result SHALL lead to the next provider call;
  the first answer that neither the bounded plan nor the full check rejects SHALL be
  accepted. The rule is the same for the built-in readers and for a format plugin's
  `NeedsPassword` request (`format-plugins`).

**A unit read once** (a ZIP member from a pipe) has no second walk for the full check.
There the backend SHALL run each candidate's bounded plan on a kept prefix of the unit's
input, at most `PASSWORD_CONFIRM_MAX_INPUT_BYTES` and its encryption header, replayed to
the accepted candidate. A plan that would walk past the kept prefix ends there
`INCONCLUSIVE`. Several survivors SHALL NOT run the full check: the first SHALL be
accepted, `INCONCLUSIVE`, and its read-time digest decides, as for one candidate. This
is a choice that MAY change: spooling the whole unit would allow the full check.

The full check is proportional to the unit's size, and it SHALL run only for candidates
that survived the bounded plan when more than one did, for a lone survivor while a
provider can still be asked for the unit, and for an `INCONCLUSIVE` provider answer.

A `CONFIRMED` candidate SHALL be added to known-good. An `INCONCLUSIVE` candidate
SHALL be added to known-good only when the candidate set is unambiguous. The
candidate loop remains `_PasswordCandidates.attempt`; confirmation supplies the
bounded probe and the full check. A format plugin's `NeedsPassword` request SHALL run
through the same loop, which also tries the request's saved winner first, leaves the
provider out of a replacement open, and lets go of the plugin's guards around each
provider call. A second driver SHALL NOT be introduced.

Accepting an `INCONCLUSIVE` candidate SHALL emit `ENCRYPTED_MEMBER_UNVERIFIED` if the
caller then abandons the member's stream before its declared digest is reached.

After confirmation, backend MAY re-open/re-decode the accepted candidate for the
caller's stream. Returned stream SHALL keep ordinary read-time integrity checking.

"Another candidate may be tried" includes ≥2 distinct known-good/static values and
a provider that can return another answer. Provider stays lazy (no advance
enumeration). Duplicates are not distinct. Provider-raised `EncryptionError` is
provider failure — propagate unchanged, not as candidate exhaustion.

If confirmation fails and candidates are exhausted, report the irreducible ambiguity
(wrong password **or** corrupt unit). This holds whenever at least one candidate was
rejected only by the unit's data checksum (the full check), even when other candidates
were rejected earlier by a stronger check: rejecting a different key is no evidence
against the one the checksum rejected. MAY use `EncryptionError`. SHALL NOT return an
unvalidated candidate. A single distinct static candidate MAY keep the format's normal
lazy streaming path.

#### Scenario: weak-check confirmation matrix

| Case | Expected |
| --- | --- |
| Wrong candidate passes weak check first of two | Reject via confirmation; stream from correct candidate |
| Large member, many candidates, at most one survives the bounded plan | Confirmation bounded — not proportional to member size |
| Rejecting codec, CRC past budget, two candidates survive the prefix | Each survivor in order walks to the CRC; the one it matches wins and joins known-good |
| Rejecting codec, CRC past budget, the right candidate after a wrong one | Wrong one `REJECTED` or settled by the full check; the right one is served |
| First candidate `CONFIRMED` | Later candidates are not probed |
| Provider answer fails confirmation | Request next answer without pre-enumerating; accept only after confirm |
| Anchor reachable within budget | Decode to the anchor only, never past it |
| Unit carries both an early per-item checksum and a whole-unit checksum | The earlier one decides |
| Checksum-verified prefix shorter than 4 bytes | Plan continues to the next anchor |
| Rejecting codec, CRC past budget | Prefix only; wrong key `REJECTED`; survivor `INCONCLUSIVE` |
| Block-transform codec (bzip2), 64 KiB output requested | Input consumed stays within the compressed cap, not 64 KiB |
| Non-rejecting codec, CRC past budget | Walk to the CRC |
| Unit read once, two candidates survive the kept prefix | First survivor read, `INCONCLUSIVE`; its digest at the end decides |
| Unit read once, non-rejecting codec, CRC past the kept prefix | No walk; survivor `INCONCLUSIVE` |
| Rejecting codec, no digest at all | Prefix; survivor `INCONCLUSIVE`; no unbounded decode |
| Non-rejecting codec, no digest, one distinct candidate | Stop at budget; caller's digest is authoritative |
| Non-rejecting codec, no digest, several candidates | First candidate; `DIGEST_UNVERIFIABLE`; no unbounded decode |
| Non-rejecting codec, CRC at end, several candidates | Unbounded pass; the matching checksum wins |
| Cheap key check matches for one candidate at full strength | `CONFIRMED` with no payload decode |
| Cheap key check matches no candidate | Ladder continues with every candidate; no candidate dropped |
| `INCONCLUSIVE` accepted, another candidate may still be tried | Not added to known-good |
| Confirmation fails, then provider raises `EncryptionError` | Provider exception propagates unchanged |
| All candidates fail confirmation | Ambiguity message; no candidate bytes returned |
| One distinct static value (incl. duplicates) | No eager consume for disambiguation; ordinary read-time errors |
