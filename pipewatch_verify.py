"""
Opt-in, network-dependent SHA verification for pipewatch.

This is the ONE deliberate, structurally-isolated exception to pipewatch's
otherwise fully-offline invariant. Extracted from pipewatch.py specifically
so a static import grep can exempt it by filename rather than trying to
prove a flag-gate (`--verify-shas`) is airtight by reading control flow --
same pattern established by VSac's refresh.py/digest.py split.

Not imported by pipewatch.py's module-level code, and never invoked by
`gossamer audit`'s registered audit_args for pipewatch (audit_args =
("audit", "--json") in registry.py -- verified, does not include
--verify-shas). Only reached if the person running pipewatch directly
passes --verify-shas on the command line.

Fails loudly, not silently, on network unavailability: this used to
swallow any non-HTTPError exception (including a blocked/unreachable
socket) and return True ("commit exists"), which meant a network outage
or a sandboxed/offline CI runner would silently report zero
invalid-pin findings instead of surfacing that verification couldn't
run at all. Fixed here: network-layer failures now raise
VerifyNetworkError, which the --verify-shas CLI path in pipewatch.py
catches and turns into a hard, visible error -- never a silent clean
result.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import yaml


class VerifyNetworkError(Exception):
    """Raised when SHA verification can't reach GitHub's API at all
    (blocked socket, DNS failure, timeout, etc.) -- distinct from a
    confirmed 404, which is a real finding, not a network problem."""


def _verify_commit_exists(owner: str, repo_name: str, sha: str, token: Optional[str], _version: str) -> bool:
    """Return False only if GitHub's API returns a confirmed 404 for this
    commit. Raises VerifyNetworkError for anything else that prevents a
    real answer (blocked socket, timeout, DNS failure, non-404 HTTP
    error) -- callers must not treat "couldn't check" as "verified
    clean"."""
    url = f"https://api.github.com/repos/{owner}/{repo_name}/git/commits/{sha}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"pipewatch/{_version}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise VerifyNetworkError(f"GitHub API returned HTTP {e.code} for {owner}/{repo_name}@{sha}") from e
    except Exception as e:
        raise VerifyNetworkError(
            f"could not reach GitHub API to verify {owner}/{repo_name}@{sha}: {e}"
        ) from e


def verify_pinned_shas(
    repo: Path,
    find_pipeline_files,
    is_sha_pinned,
    make_finding,
    token: Optional[str] = None,
    _version: str = "",
) -> list[dict]:
    """
    For each SHA-pinned action, verify the commit exists in that repo via
    GitHub API. Opt-in: pass --verify-shas. Rate limit: 60 req/hr
    unauthenticated, 5000 with --token.

    API calls are deduplicated (one call per unique owner/repo+SHA pair),
    but a finding is emitted for *every* affected step so callers see the
    full blast radius of a compromised or deleted commit.

    Dependency-injected (find_pipeline_files, is_sha_pinned, make_finding)
    rather than imported back from pipewatch.py at module scope, so this
    file's own import list stays exactly what it needs and nothing more --
    keeps the isolation the static grep relies on legible by inspection,
    not just by convention.

    Raises VerifyNetworkError if the network is unavailable -- does not
    catch it here, so the caller (pipewatch.py's --verify-shas CLI path)
    can fail loudly rather than silently emit a clean-looking envelope.
    """
    findings = []
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
                if ref.startswith("./") or "@" not in ref or not is_sha_pinned(ref):
                    continue
                action, _, sha = ref.rpartition("@")
                parts = action.split("/")
                if len(parts) < 2:
                    continue
                owner, repo_name = parts[0], parts[1]
                key = (f"{owner}/{repo_name}", sha)
                if key not in verified:
                    verified[key] = _verify_commit_exists(owner, repo_name, sha, token, _version)
                if not verified[key]:
                    findings.append(make_finding(
                        f"PW-SHA-{len(findings)+1:03d}", "HIGH",
                        "invalid-pin",
                        f"Pinned SHA not found in repo: {ref}",
                        f"Commit {sha[:8]}... does not exist in {owner}/{repo_name}. "
                        "This may be a typo, a SHA from a fork, or a deleted commit.",
                        f"{rel}::{job}::step[{idx}]",
                        f"checked: GET /repos/{owner}/{repo_name}/git/commits/{sha}",
                    ))
    return findings