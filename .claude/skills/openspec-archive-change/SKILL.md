---
name: openspec-archive-change
description: Archive a completed change in the experimental workflow. Use when the user wants to finalize and archive a change after implementation is complete.
license: MIT
compatibility: Requires openspec CLI.
metadata:
  author: openspec
  version: "1.0"
  generatedBy: "1.4.1"
---

Archive a completed change in the experimental workflow.

**Input**: Optionally specify a change name. If omitted, check if it can be inferred from conversation context. If vague or ambiguous you MUST prompt for available changes.

**Steps**

1. **If no change name provided, prompt for selection**

   Run `openspec list --json` to get available changes. Use the **AskUserQuestion tool** to let the user select.

   Show only active changes (not already archived).
   Include the schema used for each change if available.

   **IMPORTANT**: Do NOT guess or auto-select a change. Always let the user choose.

2. **Check artifact completion status**

   Run `openspec status --change "<name>" --json` to check artifact completion.

   Parse the JSON to understand:
   - `schemaName`: The workflow being used
   - `planningHome`, `changeRoot`, `artifactPaths`, and `actionContext`: path and scope context
   - `artifacts`: List of artifacts with their status (`done` or other)

   If status reports `actionContext.mode: "workspace-planning"`, explain that workspace archive is not supported in this slice and STOP. Do not move workspace changes into repo-local archives or edit linked repos.

   **If any artifacts are not `done`:**
   - Display warning listing incomplete artifacts
   - Use **AskUserQuestion tool** to confirm user wants to proceed
   - Proceed if user confirms

3. **Check task completion status**

   Read the tasks file (typically `tasks.md`) to check for incomplete tasks.

   Count tasks marked with `- [ ]` (incomplete) vs `- [x]` (complete).

   **If incomplete tasks found:**
   - Display warning showing count of incomplete tasks
   - Use **AskUserQuestion tool** to confirm user wants to proceed
   - Proceed if user confirms

   **If no tasks file exists:** Proceed without task-related warning.

4. **Preview the delta specs**

   Use `artifactPaths.specs.existingOutputPaths` from status JSON to check for delta specs. If none exist, go to step 5.

   **If delta specs exist:**
   - Compare each delta spec with its corresponding main spec at `openspec/specs/<capability>/spec.md`
   - Determine what the archive will apply (adds, modifications, removals, renames)
   - Show a combined summary, then use **AskUserQuestion tool** to confirm: "Archive and apply these deltas", "Cancel"

   If a main spec already contains a delta's changes (for example, `openspec-sync-specs` ran earlier), say so in the summary: the archive applies the deltas again. For a non-trivial delta, `CONTRIBUTING.md` §"Archiving an OpenSpec change" says how to check it with a dry-run archive first.

5. **Perform the archive**

   ```bash
   openspec archive "<name>" --yes
   ```

   The CLI applies the deltas to `openspec/specs/` and moves the change into the archive. If it fails, report its output and stop. Do not move the directory by hand: a change archived without its deltas leaves `openspec/specs/` wrong, and CI checks for that (`CONTRIBUTING.md` §"Archiving an OpenSpec change").

   Commit the resulting `openspec/specs/` updates together with the moved change.

6. **Display summary**

   Show archive completion summary including:
   - Change name
   - Schema that was used
   - Archive location
   - Which specs the archive updated (if any)
   - Note about any warnings (incomplete artifacts/tasks)

**Output On Success**

```
## Archive Complete

**Change:** <change-name>
**Schema:** <schema-name>
**Archived to:** the archive path derived from `planningHome.changesDir`/YYYY-MM-DD-<name>/
**Specs:** ✓ Deltas applied to main specs (or "No delta specs")

All artifacts complete. All tasks complete.
```

**Guardrails**
- Always prompt for change selection if not provided
- Use artifact graph (openspec status --json) for completion checking
- Don't block archive on warnings - just inform and confirm
- Archive only through `openspec archive "<name>" --yes`, never by moving the directory
- Show clear summary of what happened
- If delta specs exist, always show the combined summary before prompting
