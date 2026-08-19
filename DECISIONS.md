# pipewatch — DECISIONS.md

Seeded from the gossamer-suite integration audit (Aug 2026), same process
as tokenwatch's. No prior `DECISIONS.md` existed for pipewatch before this
— this is the first version. As of this entry, only Section 0 (inventory)
and a narrow slice of Section 2 (CLI contract) have been run against real
execution; this file will grow as the rest of the checklist gets worked
through, same as tokenwatch's did incrementally rather than in one pass.

## Inventory (Section 0)

- No prior `DECISIONS.md`, no test suite in the repo at clone time.
- Packaging is present and plausible: `pyproject.toml`, `LICENSE`,
  `README.md`. `license = "CC-BY-4.0"` in `pyproject.toml` — flagged for
  the license-audit step, since the suite standard split (per tokenwatch's
  own relicense) is Apache 2.0 *code* / CC BY 4.0 *docs*, and pipewatch's
  code itself (`pipewatch.py`) carrying a docs license is worth confirming
  is deliberate rather than copy-paste from the README's licensing, not
  yet resolved either way.
- `pip install -e .` succeeds cleanly; console script `pipewatch` resolves
  on PATH, matching `registry.py`'s `ToolSpec` expectations.
- Single-file implementation (`pipewatch.py`, ~1200 lines) — no package
  subfolder, unlike tokenwatch's `tokenwatch/` layout. `pyproject.toml`
  declares it via `[tool.setuptools] py-modules = ["pipewatch"]` rather
  than a package `packages =` entry. Not a defect, just a structurally
  different distribution shape to keep in mind for later sections. **See
  Addendum 3**: this changed — `pipewatch_verify.py` was added as a
  second, deliberately isolated module, and `py-modules` now lists both.

## Known open item: `--json` doesn't protect the baseline-missing path

`cmd_audit()` calls `load_baseline(repo, args.baseline)` **before** any
`--json`-conditional branching. When no baseline has been set (`pipewatch
baseline` never run), this exits via a plain `sys.exit("error: no baseline
set. Run \`pipewatch baseline\` first.")` — a bare string to stderr, exit
code 1 — regardless of whether `--json` was passed on the command line.

Verified directly, not inferred: ran `pipewatch audit --json .` against a
fresh git repo with no baseline. Got exit 1, the string error on stderr,
**empty stdout** (not malformed JSON, just nothing).

This matters for gossamer-suite specifically: `aggregate.py`'s
`run_tool()` treats any non-JSON stdout as a tool error and records it in
`errors` — which is technically correct behavior on `aggregate.py`'s part
(pipewatch really did fail to produce its envelope), but it means every
`gossamer audit` run against a repo that hasn't had `pipewatch baseline`
run first will silently list pipewatch under `errors` with a fairly
generic `"non-JSON output (exit 1)"` reason, rather than something a CI
consumer could act on programmatically (e.g. "run `pipewatch baseline`
first" as a structured, actionable field). Whether that's worth fixing
(making the baseline-missing case still emit a minimal JSON envelope
under `--json`, schema-conformant, with a category/severity that flags
"no baseline configured" as its own condition) or left as legitimate
tool-level error reporting is an open design question, not yet decided —
noted here rather than fixed silently, per audit process. **RESOLVED in
Addendum 4 — the envelope option was chosen.**

## Section 1 — schema conformance: CLOSED (see Addenda 1 and 2)

Original findings (real fixture run, `jsonschema.Draft202012Validator`
against the actual `finding-envelope.schema.json`):

- **Missing `schema_version`** — fixed in Addendum 1.
- **Category taxonomy drift** — every multi-word category used
  underscores, none matched `categories.json`'s registered slugs. Fully
  resolved in Addendum 2 (six renames, three new registrations, one
  registration correction in this session — see below).
- `summary` was already schema-conformant.
- `id` scheme was already correct (`PW-` prefix, correct pattern).

**Full resolution is documented in Addenda 1 and 2 below. Section 1 is
CLOSED as of this file's most recent update**, verified against the
controller's own current `categories.json` and `finding-envelope.schema.json`.

## Known open items (not yet audited — logged, not assumed clean)

- ~~Section 3 (network boundary)~~ — **CLOSED, see Addendum 3.**
- Section 5 (`gossamer audit` integration) not yet run end-to-end with a
  properly baselined fixture.
- Section 6 (real-repo true/false positive) not yet run.
- ~~License field (`CC-BY-4.0` on the code itself)~~ — **RESOLVED, see Addendum 5.**
- Section 2 (exit-code/CLI contract) not yet run as its own explicit pass
  — some incidental coverage exists (the baseline-missing exit-code
  behavior above, the `--verify-shas` failure-mode work in Addendum 3),
  but the checklist's own clean-fixture/non-zero-per-severity matrix
  hasn't been run.
- Section 4 (cache/state edge cases) not yet run.
- Section 7 (documentation gaps) not yet run as its own pass — though
  this file itself, and the fact that it wasn't committed to the repo
  until this point, is itself a Section 7 finding (see below).

---

## Addendum 1 (Aug 12 2026) — schema_version fix, verified

Root cause confirmed directly in source: `build_report()` (pipewatch.py,
~line 1007) constructed the envelope dict without a `schema_version` key
at all — not a regression, never added in the first place. Added
`"schema_version": "1.0"` as the first key.

Verified against real execution: fresh venv, `pip install -e .`, git repo
baselined clean, then the same `pull_request_target` + PR-head checkout +
write-permissions + unpinned-actions diff used in the original Section 1
audit. Real `pipewatch audit --json` run confirmed: exit 1 (findings
present), stdout parses as pure JSON, `schema_version: "1.0"` present as
first key, 9 findings, summary totals unchanged (6 HIGH / 3 MEDIUM).

**Follow-up fix, same addendum**: a static-type-checker complaint
surfaced (`Argument of type "Path" cannot be assigned to parameter "repo"
of type "str"`) — `build_report`'s signature declared `repo: str` but
`_repo(args.repo)` returns a `Path`; the function coerced it internally
with `str(repo)`, so this was a type-hint mismatch, not a runtime bug.
Fixed: `repo: "str | Path"`. Re-verified with a fresh install and a real
audit run: syntax valid, install succeeds, output unchanged
(`schema_version: "1.0"`, 9 findings, `repo` field still serializes as a
string).

---

## Addendum 2 (Aug 12 2026) — category reconciliation closed; pipeline-file-change fallback implemented

### Category renames — six applied, verified against real code and real runs

| Old (code) | New (code, now live) |
|---|---|
| `script_injection` | `script-injection` |
| `pull_request_target_misuse` | `pull-request-target` |
| `unpinned_dependency` | `mutable-pin` |
| `permissions` | `permission-misconfig` |
| `invalid_pinned_sha` | `invalid-pin` |
| `runner_environment` | `runner-drift` |

Applied via exact string-literal replacement, scoped to confirm zero
collision with `doc.get("permissions")`/`job_def.get("permissions")`
dict-key lookups elsewhere in the same file (5 category-arg occurrences of
`"permissions"` renamed; dict-key lookups untouched).

Two more renames, landing on new registrations:

| Old (code) | New (code, now live) | Registration |
|---|---|---|
| `step_fingerprint` | `workflow-step-tampering` | new |
| `self_hosted_runner` | `self-hosted-runner` | new |

**Correction discovered mid-session and resolved**: the original closed
decision table classified `pull_request_target_misuse` → `pull-request-target`
as an *existing* registered slug. Re-validation against the controller's
actually-uploaded `categories.json` showed `pull-request-target` was not
present at that time (only `workflow-chain`, a different concept, was).
The controller added it as a genuinely new registration. Final registry
state (confirmed by direct diff against the controller's re-uploaded
`categories.json`) now includes all four new slugs pipewatch needed:
`pull-request-target`, `workflow-step-tampering`, `self-hosted-runner`,
`pipeline-file-change`. All four fixture outputs from this session
validate with **zero unregistered categories** against that file.

`coverage-gap` and `workflow-chain` (registered, but not currently emitted
by pipewatch's code) remain reserved-but-unimplemented — not retired, not
force-fit onto anything pipewatch currently does.

### `pipeline-file-change` — fallback-only, implemented and verified

Previously fired unconditionally for every changed tracked pipeline file.
Reworked per the closed spec: fires only when a genuinely-changed file has
zero findings from any other pipewatch category referencing that file
this run.

**Implementation**: `explained_files` is built from the *raw*
per-detector outputs (`StepChange.path`, `PinningFinding.path`, and
`static_finding["location"].split("::", 1)[0]`) — deliberately not from
other findings' rendered `location` text, because
`_findings_from_pinning`'s grouped finding truncates its `location` to a
comma-list of at most 5 files. Building the explained-set from that
truncated string would silently under-count files 6+ and produce
false-positive `pipeline-file-change` findings on files that actually had
a real, specific pinning finding that just got grouped past the display
cutoff.

Severity fixed at `MEDIUM` in both sub-cases (unmatched-but-analyzable,
and couldn't-be-analyzed at all) — no auto-escalation. One category, two
description strings — no slug split.

**Parse-failure sub-case — real gap found and closed, not assumed already
wired**: before this change, YAML parse failures were caught and silently
swallowed (`except yaml.YAMLError: cur_doc = {}`) with no signal retained
anywhere. Fixed at the root: added `FileDiff.parse_failed: bool`, a real
YAML-parse attempt (`_yaml_parse_failed`) run against each file's current
content during `diff_pipeline_files` (Jenkinsfiles exempted — previewed
via regex, never YAML-parsed), threaded through both the "added" and
"modified" `FileDiff` construction paths.

**Follow-up gap, caught by the controller's own pressure-test, fixed in
the same session**: a previously-valid file that becomes unparseable
doesn't hit `pipeline-file-change`'s parse-failure branch at all — it gets
explained via `workflow-step-tampering` instead, because
`diff_fingerprints`'s own independent YAML-parse-failure handling
(`_fingerprints()`, separately swallowing `yaml.YAMLError` → `{}`) makes
all baseline steps read as "removed." Original description text for that
case was a flat "was removed since baseline" — indistinguishable from a
genuine deliberate edit, a real information-loss bug for any CI consumer
reading it. Fixed at the root: added `StepChange.parse_failed: bool`,
threaded through from the same parse attempt, and `_findings_from_steps`'
description now explicitly states when a "removed" reading is a
parse-failure artifact rather than a confirmed removal.

**Verified against real fixtures** (four distinct scenarios, re-confirmed
against a fresh GitHub clone, not just the local working copy that
produced the fix):

1. Original Section-1 fixture: file fully explained by 4 specific
   categories → `pipeline-file-change` correctly absent (9 findings → 8).
2. Step-content-only change, well-formed YAML: `workflow-step-tampering`
   explains it → `pipeline-file-change` correctly suppressed.
3. Top-level-only change (no job/step diff at all): fallback correctly
   fires, non-parse-failure description text.
4. Brand-new pipeline file, permanently unparseable YAML: fallback
   correctly fires with the parse-failure description branch.
5. (Follow-up) Baseline-valid file that becomes unparseable: now
   correctly states the parse-failure cause in `workflow-step-tampering`'s
   description, rather than reading as an unqualified removal.

---

## Addendum 3 (Aug 13 2026) — Section 3 (network boundary): closed

### Correction to a standing instruction, per controller

Originally told "no network-capable imports anywhere in pipewatch's own
code" as an absolute. Controller corrected this mid-session: the actual
suite-wide invariant is that the *registered, `gossamer audit`-invoked*
path is fully offline; a legitimate opt-in network tier is permitted if
it's structurally isolated into its own file so a static grep can exempt
it by name, documented, and never reachable via the registered
`audit_args` — same precedent as VSac's `refresh.py`/`digest.py` split.

### Extraction: `pipewatch_verify.py`

`_verify_commit_exists` and `verify_pinned_shas` (the `--verify-shas`
opt-in GitHub-API pin-verification feature) moved out of `pipewatch.py`
into a new sibling module, `pipewatch_verify.py`. `pipewatch.py` no longer
imports `urllib.error`/`urllib.request` at all — confirmed via a precise
import-statement grep (matches only lines starting with `import`/`from`,
not substring occurrences): **0 hits**, post-extraction.

`pipewatch_verify.py` is lazy-imported inside a new `_run_verify_shas`
helper in `pipewatch.py`, called only from the two CLI paths that accept
`--verify-shas` — never at module load time, never on the default
registered path. Confirmed against `registry.py`: pipewatch's registered
`audit_args = ("audit", "--json")` — no `--verify-shas`, no `--token`.

### Real bug found and fixed: silent failure on network unavailability

`_verify_commit_exists`'s original exception handling swallowed *any*
non-HTTPError failure (blocked socket, DNS failure, timeout) and returned
`True` — "commit confirmed to exist" — meaning an offline environment or a
genuine outage would silently produce a clean-looking scan instead of
surfacing that verification never ran. Fixed at the root:
`pipewatch_verify.py` now defines `VerifyNetworkError`, raised for any
network-layer failure (everything except a confirmed HTTP 404, the real
"pin doesn't exist" finding). `pipewatch.py`'s `_run_verify_shas` catches
it once at the CLI boundary and exits with a clear, specific stderr
message rather than returning findings.

### Real packaging gap found and fixed

`py-modules = ["pipewatch"]` in `pyproject.toml` only listed the original
file. Confirmed this actually mattered via a real, non-editable
`pip install .` into a clean venv: `pipewatch_verify.py` was omitted
entirely until fixed. Corrected to
`py-modules = ["pipewatch", "pipewatch_verify"]`, re-verified with a fresh
non-editable install — `pipewatch_verify.py` now present in site-packages
with a real hash-verified `RECORD` entry.

### Runtime verification — real, not simulated

- **Default registered path (`pipewatch audit --json`, no flags) under a
  `sitecustomize.py`-injected hard socket block**: output byte-for-byte
  identical to a network-available run on the same fixture (timestamp
  excluded), same exit code, no stderr noise.
- **`--verify-shas` with a real SHA-pinned action, same socket block**:
  fails loudly — empty stdout, clear stderr, exit 1.
- **Same fixture, real network, unauthenticated and rate-limited (GitHub
  API returned HTTP 403)**: also failed loudly via the same
  `VerifyNetworkError` path — independent confirmation the fix isn't an
  artifact of the synthetic block.

### Static-grep precision note

Precise import-statement match found 1 real hit pre-extraction (the
`import urllib.request` itself), 0 post-extraction. A naive substring
match over-counted at 3 hits for the same pre-extraction code — the extra
2 were usage lines (`urllib.request.Request(...)`,
`urllib.request.urlopen(...)`), not additional imports. Confirms the
precision requirement wasn't precautionary.

### Status

All four checklist items for Section 3 covered on real evidence, re-run
and reconfirmed against a fresh GitHub clone after the controller
independently re-uploaded/verified state. Two real bugs found and fixed
in the course of doing this properly: the silent-failure
network-unavailability bug, and the packaging omission.

---

## Section 7 note (added during Addendum 3 discussion, not yet a full pass)

This file did not exist in the actual `pipewatch` repo until this
consolidated version was committed — everything above lived only in
session/project history until now. Flagging this explicitly as a process
gap this consolidation closes, not something to let recur: future audit
work on this tool should treat this file, at this path, as the ledger —
not chat history, not a project-only document.
---

## Addendum 4 (Aug 19 2026) — baseline-missing path emits a coverage-gap envelope

### Decision

The open item above (Section 0 / open-item section) is resolved: the
envelope option was chosen. Under `--json`, a missing baseline no longer
exits via a bare stderr string — pipewatch emits a schema-conformant
finding envelope and exits 1.

The synthetic finding is a **coverage-gap** (registered controller
category, `used_by: ["vsac", "pipewatch"]` — its locked description
explicitly names "no baseline configured"):

- `id: PW-GAP-001`, `severity: INFO` (schema-required placeholder),
  `non_scored: true`, `location` = the repo path (the thing that was not
  evaluated), description tells the CI consumer to run `pipewatch
  baseline` and re-run.
- `non_scored` makes the controller's `gate_passed()` fail closed —
  an unevaluated repo can never pass the gate as "clean". This was the
  original motivation for the DECISIONS.md non_scored rule (see
  gossamer-suite DECISIONS.md); pipewatch now exercises it for real.

### Scope guard

Only the *missing* baseline takes this path. HMAC verification failures
and plain-text-with-key refusals still exit loudly in both modes —
tamper suspicion must never be demoted to a coverage-gap finding. The
`--baseline <sha>` override path is unchanged.

### Found-and-fixed along the way

- `build_report(..., baseline=None)` emitted `"baseline_commit": null`,
  which violates the envelope schema (`type: string`). This silently
  broke `pin-audit --json` and `static --json` envelopes. `baseline_commit`
  is now omitted when there is no baseline.
- `__version__` was `"0.5.0"` while the distribution was `0.6.0`; the
  envelope's `version` field now matches the distribution.

### Verified

Fresh git repo, no baseline: `audit --json .` → coverage-gap envelope,
exit 1, schema-valid; human mode keeps the original error message and
exit 1; `--baseline` override and post-`pipewatch baseline` runs
unchanged; `pin-audit --json` / `static --json` now schema-valid.

## Addendum 5 (Aug 19 2026) — relicense to Apache-2.0 (code) / CC BY 4.0 (docs)

Resolves the Section 0 inventory flag and the open item on the license
field: pipewatch's code was shipping under `CC-BY-4.0`, a docs license,
not the suite's code standard (Apache 2.0). Confirmed with the project
lead — it was carried over from the README's docs licensing, not a
deliberate choice. The suite is now consistent:

- **Code** (`pipewatch.py`, `pipewatch_verify.py`): Apache-2.0.
  `pyproject.toml` declares `license = "Apache-2.0"` with
  `license-files = ["LICENSE"]`; `LICENSE` carries the full Apache 2.0
  text (byte-identical to the other suite members').
- **Docs** (README, DECISIONS.md): CC BY 4.0, unchanged — that is the
  docs license across the suite.
- The relicense is retroactive: David Obi is the sole copyright holder,
  so no third-party rights are affected. Published PyPI releases
  0.2.0–0.6.0 keep their original metadata; any future release ships
  under the corrected terms.

### Verified

`LICENSE` identical to vsac/tokenwatch's Apache 2.0 text; wheel built
from a clean copy contains the LICENSE file and
`License-Expression: Apache-2.0` in METADATA; README license section
points at Apache 2.0.
