# pipewatch

**Integrity monitoring and static analysis for CI/CD pipelines.**

CI/CD pipelines are high-value targets: they run with elevated permissions, pull from external registries, and execute arbitrary code on every commit. A single injected step, mutable action pin, or misconfigured trigger is enough to exfiltrate secrets, backdoor build artifacts, or pivot into production infrastructure — and the attack surface is almost always left unmonitored.

`pipewatch` audits GitHub Actions workflows, GitLab CI, and Jenkinsfiles for exactly these risks. It combines commit-anchored baseline diffing, per-step SHA-256 fingerprinting, static misconfiguration analysis, and runner environment tracking into a single CLI tool. All commands exit non-zero on findings and emit structured JSON — suitable as a pipeline gate, a pre-merge check, or a periodic audit job.

---

## What It Detects

| Check | What it catches |
|---|---|
| **Baseline diff** | Pipeline files modified, added, or deleted since a known-good commit |
| **Step fingerprinting** | Individual steps injected, removed, or silently modified between commits |
| **`pull_request_target` misuse** | Workflows that check out and execute PR head code with base-branch write permissions — the pattern behind numerous CI poisoning attacks |
| **Script injection** | `run:` blocks and `env:` blocks that route user-controlled context values (`github.event.pull_request.title`, `github.event.comment.body`, etc.) into shell commands — both direct interpolation and the indirect `env: VAR: ${{ ctx }}` → `$VAR` pattern are detected |
| **Permission misconfiguration** | Missing `permissions:` blocks, `write-all` scopes, `secrets: inherit` |
| **Mutable action pins** | `uses:` references not locked to a full commit SHA — tags like `v3` can be silently overwritten by a supply-chain attacker |
| **Invalid pinned SHAs** | Pinned SHAs that do not exist in the upstream action repo (typos, deleted commits, fork SHAs) |
| **Unsafe `workflow_run` chains** | Write-permissioned workflows triggered indirectly by external pull requests or issues, creating a privilege escalation path |
| **Self-hosted runners** | Non-ephemeral runners that persist state between runs and are not managed by GitHub |
| **Runner environment drift** | Env var and tool version changes between CI runs that could indicate a compromised or modified runner |

Findings are severity-ranked (CRITICAL → HIGH → MEDIUM → LOW → INFO) and always include a location, description, and evidence field.

---

## Installation

```bash
git clone https://github.com/TheVoidThatConsumes/pipewatch.git
cd pipewatch
pip install pyyaml
```

Requires Python 3.12+. `pyyaml` is the only external dependency.

---

## Quick Start

```bash
# Record the current HEAD as known-good
pipewatch baseline

# Scan for changes and misconfigurations
pipewatch scan

# Full audit in one pass (scan + pin-audit + static)
pipewatch audit --verify-shas
```

---

## Commands

### `baseline`
Records the current (or a specified) commit as the integrity reference point. Set `PIPEWATCH_HMAC_KEY` to store a signed baseline — if the file is modified to suppress future findings, the HMAC check will fail and the tool will refuse to proceed.

```bash
pipewatch baseline [--repo PATH] [--commit SHA]
```

---

### `scan`
Diffs pipeline files and per-step fingerprints against the baseline commit. Detects both file-level changes (unified diff) and step-level tampering — a step whose `uses`, `run`, `with`, `env`, or `shell` fields change gets flagged even if the surrounding file diff looks innocuous.

```bash
pipewatch scan [--repo PATH] [--baseline SHA] [--verbose] [--json]
```

Covers GitHub Actions, GitLab CI, and Jenkinsfile stages.

---

### `static`
Static analysis with no baseline required. Audits all GitHub Actions workflow files in `.github/workflows/` for structural misconfigurations.

```bash
pipewatch static [--repo PATH] [--verbose] [--json]
```

Checks: `pull_request_target` misuse · script injection · missing/overpermissioned `permissions:` blocks · `secrets: inherit` · self-hosted runners · unsafe `workflow_run` trigger chains.

---

### `pin-audit`
Flags `uses:` references not pinned to a full 40- or 64-character commit SHA. With `--verify-shas`, makes live GitHub API calls to confirm each pinned SHA actually exists in its upstream repository.

```bash
pipewatch pin-audit [--repo PATH] [--verify-shas] [--token TOKEN] [--verbose] [--json]
```

Rate limit: 60 requests/hr unauthenticated, 5 000/hr with `--token` or `GITHUB_TOKEN`. API calls are deduplicated — the same `owner/repo@sha` is only verified once regardless of how many steps reference it. Findings are **not** deduplicated: if the same invalid SHA appears across multiple workflow files or jobs, each affected step produces its own finding so the full scope of a compromised action is visible in the report.

---

### `snapshot`
Captures the runner environment — environment variables and tool versions — to a JSON file for later comparison.

```bash
pipewatch snapshot [--output FILE]
```

Tracked tools: `python3`, `python`, `node`, `npm`, `pip`, `pip3`, `git`, `curl`, `wget`, `docker`, `kubectl`, `terraform`, `aws`, `gcloud`, `az`. Volatile per-run variables (`GITHUB_RUN_ID`, `RUNNER_TEMP`, etc.) are excluded to prevent noise on every comparison.

**Credential exclusion** — environment variables whose names contain `token`, `secret`, `key`, `password`, `passwd`, `pwd`, `auth`, `credential`, `private`, or `api_key` (case-insensitive) are never written to the snapshot file. This prevents secrets such as `GITHUB_TOKEN` or `PIPEWATCH_HMAC_KEY` from being persisted to disk or uploaded to the Actions cache. Note that a legitimately non-sensitive variable with one of these terms in its name will also be excluded; rename it if you need `env-diff` to track it.

Add the snapshot file to `.gitignore` to prevent it from being accidentally committed:

```
.pipewatch_env_snapshot.json
```

---

### `env-diff`
Diffs two runner environment snapshots. Detects new, removed, or changed environment variables and tool versions — useful for identifying runner poisoning or unexpected environment mutations between runs. If `--current-snapshot` is omitted, captures the live environment.

```bash
pipewatch env-diff BASELINE_SNAPSHOT [--current-snapshot FILE] [--repo PATH] [--verbose] [--json]
```

---

### `audit`
Full audit in one pass: `scan` + `pin-audit` + `static`. Exits non-zero if any findings exist.

```bash
pipewatch audit [--repo PATH] [--baseline SHA] [--verify-shas] [--token TOKEN] [--verbose] [--json]
```

---

### `init-runner`
Prints a ready-to-paste GitHub Actions step block that adds runner environment monitoring to any existing job.

```bash
pipewatch init-runner [--snapshot-path PATH]
```

---

## Finding IDs

| Prefix | Category | Default Severity |
|---|---|---|
| `PW-DIFF-NNN` | Pipeline file added / modified / deleted | HIGH / MEDIUM |
| `PW-STEP-NNN` | Step fingerprint changed / injected / removed | HIGH / MEDIUM |
| `PW-PRT-NNN` | `pull_request_target` misuse | HIGH |
| `PW-INJ-NNN` | Script injection risk | HIGH |
| `PW-PERM-NNN` | Permission misconfiguration | HIGH / MEDIUM |
| `PW-CHAIN-NNN` | Unsafe `workflow_run` chain | HIGH |
| `PW-PIN-NNN` | Unpinned action reference | MEDIUM |
| `PW-SHA-NNN` | Pinned SHA not found in upstream repo | HIGH |
| `PW-RUNNER-NNN` | Self-hosted runner | INFO |
| `PW-ENV-NNN` | Runner environment drift | MEDIUM / LOW |

---

## JSON Output

All commands accept `--json`:

```json
{
  "tool": "pipewatch",
  "version": "0.2.0",
  "timestamp": "2025-01-01T00:00:00+00:00",
  "repo": "/path/to/repo",
  "baseline_commit": "abc123...",
  "findings": [
    {
      "id": "PW-INJ-001",
      "severity": "HIGH",
      "category": "script_injection",
      "title": "Script injection risk: .github/workflows/ci.yml::build::step[2]",
      "description": "A run: block interpolates a user-controlled context value...",
      "location": ".github/workflows/ci.yml::build::step[2]",
      "evidence": "dangerous expressions found: ['github.event.pull_request.title']"
    }
  ],
  "summary": { "total": 1, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0 }
}
```

Gate on exit code, or filter with `jq`:

```bash
# fail the build on any HIGH or CRITICAL finding
pipewatch audit --json | jq -e '.summary.HIGH == 0 and .summary.CRITICAL == 0'

# list all finding titles
pipewatch audit --json | jq -r '.findings[].title'
```

---

## Tamper-Evident Baselines

Set `PIPEWATCH_HMAC_KEY` before running `baseline`. The baseline is stored as a signed JSON object:

```json
{
  "commit": "abc123...",
  "timestamp": "2025-01-01T00:00:00+00:00",
  "hmac": "<sha256-hmac-of-commit-and-timestamp>"
}
```

The HMAC is computed over both the commit SHA **and** the timestamp, bound together. This protects against two distinct attacks:

- **Tampering** — an attacker who modifies the `commit` field to point to an older known-good commit cannot produce a valid HMAC without the key.
- **Replay** — an attacker who reverts the baseline file to a previously-valid signed snapshot (to suppress findings introduced after that point) is also blocked, because the timestamp is part of the signed payload and the stored timestamp would no longer match the signature of any rewritten content.

On `scan` or `audit`, the HMAC is verified before the baseline commit is trusted. Any verification failure causes an immediate exit with an error.

**Format-downgrade protection** — if `PIPEWATCH_HMAC_KEY` is set and the baseline file is in plain-text format (a raw commit SHA rather than signed JSON), the tool refuses to proceed. An attacker cannot bypass signing by overwriting the file with an unsigned commit SHA. If you set `PIPEWATCH_HMAC_KEY` for the first time on a repo that already has an unsigned baseline, re-run `pipewatch baseline` to generate a signed one before your next scan.

Store the key in a CI secret (`PIPEWATCH_HMAC_KEY: ${{ secrets.PIPEWATCH_HMAC_KEY }}`).

---

## Pipeline Integration

```yaml
- name: pipewatch audit
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    PIPEWATCH_HMAC_KEY: ${{ secrets.PIPEWATCH_HMAC_KEY }}
  run: |
    pipewatch audit --verify-shas --json | tee pw-report.json
    jq -e '.summary.HIGH == 0 and .summary.CRITICAL == 0' pw-report.json
```

Use `init-runner` to add runner environment monitoring alongside the audit step.

---

## Design Decisions

**HMAC-signed baselines** — tamper-evident storage for the known-good commit reference. The HMAC covers both the commit SHA and the timestamp, so an attacker who can write to the repo but wants to suppress findings would need to forge the HMAC — not just overwrite the file or revert it to an older signed state. Attempting to downgrade a signed baseline to unsigned plain text is also refused when `PIPEWATCH_HMAC_KEY` is set.

**Volatile variable exclusion** — `snapshot` strips run-specific GitHub variables so that `env-diff` doesn't generate noise on every comparison. Only structurally stable variables that could indicate environment manipulation are tracked. Variables whose names suggest credentials (containing `token`, `secret`, `key`, `password`, etc.) are also excluded so secrets are never written to the snapshot file or the Actions cache.

**Conservative SHA verification** — `--verify-shas` treats network failures as non-findings. A flaky connection or GitHub API outage should not produce spurious HIGH alerts.

**Stdlib-first** — `pyyaml` is the only dependency. The tool audits supply-chain risk; its own footprint is minimal by design.

---

## Platform Support

| Platform | Coverage |
|---|---|
| GitHub Actions (`.github/workflows/*.yml`) | Full — file diff, step fingerprinting, static analysis, pin audit |
| GitLab CI (`.gitlab-ci.yml`) | File diff + `before_script` / `script` / `after_script` fingerprinting |
| Jenkins (`Jenkinsfile`) | File diff + best-effort stage / `sh` / `bat` fingerprinting (regex-based — not a Groovy parser) |

---

## License

GPLv2. See [LICENSE](LICENSE).