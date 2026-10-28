"""Fixed normal Collection release identities; no scope or producer admission."""
from __future__ import annotations

import re

import workflow_control as control

RELEASE = control.RELEASE
APPROVAL_JOB = "Approve exact main promotion"

COLLECTIONS = {
    "ltn-it/ansible-collection-foundational": 1103405635,
    "ltn-it/ansible-collection-supplementary": 1103407173,
    "ltn-it/ansible-collection-rhel": 1103411913,
    "ltn-it/ansible-collection-ubuntu": 1268102957,
    "ltn-it/ansible-collection-ocp": 1103410706,
    "ltn-it/ansible-collection-cloud": 1318852819,
}
STABLE = re.compile(r"release/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def normal_release(pull, repository):
    """Recognize only a native same-repository stable release App PR to Main.

    This supplies neither a successful review nor publishing acceptance. The
    common executor must review the entire current revision and authenticate a
    genuine normal approval. Security's separately proven route stays separate.
    """
    identifier = COLLECTIONS.get(repository)
    if identifier is None:
        return False
    user = pull.get("user", {})
    base, head = pull.get("base", {}), pull.get("head", {})
    return (
        (user.get("login"), user.get("id"), user.get("type")) == RELEASE
        and base.get("ref") == "main"
        and type(head.get("ref")) is str
        and STABLE.fullmatch(head["ref"]) is not None
        and all(type((side.get("repo") or {}).get("id")) is int
                and (side.get("repo") or {}).get("id") == identifier
                and (side.get("repo") or {}).get("full_name") == repository for side in (base, head))
    )


def approval_purpose(pull, repository):
    """A public purpose marker is meaningful only in a real native User decision."""
    control.require(normal_release(pull, repository), "collection-release-identity-required")
    return "[collection-main-approval/v1 " + control.digest(control.binding(pull)) + "]"


def native_approval(api, repository, pull, source, run_id, *, allow_missing=False):
    """Authenticate a successful normal job and its explicitly scoped decision.

    Recovery shares the existing Environment. Its budget-only approval must
    never authorize a release, including during a verifier-only rerun. Bind the
    decision's first line to the complete current PR binding, and bind the
    successful normal job to its own attempt's protected operation artifact.
    """
    purpose = approval_purpose(pull, repository)
    expected = control.binding(pull)
    observed = api.call(f"repos/{repository}/actions/runs/{run_id}")
    control.require(observed.get("id") == run_id and control.native_required(observed, repository)
                    and observed.get("head_sha") == expected["head"]
                    and type(observed.get("run_attempt")) is int and observed["run_attempt"] > 0,
                    "collection-approval-native-run-required")
    history = api.call(f"repos/{repository}/actions/runs/{run_id}/approvals")
    control.require(type(history) is list, "native-approval-history-shape")
    control.require(not any(entry.get("state") == "rejected"
                    and any(environment.get("name") == "normal-release-promotion-approval"
                            for environment in entry.get("environments", [])) for entry in history),
                    "collection-main-approval-rejected")
    jobs = api.pages(f"repos/{repository}/actions/runs/{run_id}/jobs?filter=all", "jobs")
    normal = []
    bindings = {}
    for job in jobs:
        if job.get("name") != APPROVAL_JOB:
            continue
        attempt = job.get("run_attempt")
        control.require(job.get("run_id") == run_id and type(job.get("id")) is int and job["id"] > 0
                        and type(attempt) is int and 0 < attempt <= observed["run_attempt"],
                        "collection-approval-job-origin")
        if job.get("conclusion") == "skipped":
            continue  # A cancelled pre-classification attempt need not have an operation artifact.
        operation = control.operation_record(api, repository, observed | {"run_attempt": attempt}, source)
        if control.same_immutable_tuple(operation.get("binding", {}), expected):
            normal.append(job)
            bindings[job["id"]] = operation["binding"]
    latest_attempt = max((job["run_attempt"] for job in normal), default=0)
    latest = [job for job in normal if job["run_attempt"] == latest_attempt]
    control.require(len(latest) <= 1, "collection-approval-job-ambiguous")
    if not latest:
        control.require(allow_missing, "collection-normal-approval-job-required")
        return None
    control.require(latest[0].get("status") == "completed", "collection-normal-approval-pending")
    control.require(latest[0].get("conclusion") == "success", "collection-normal-approval-rejected")
    control.require(bindings[latest[0]["id"]] == expected, "collection-normal-approval-binding-changed")
    decisions = [entry for entry in history if entry.get("user", {}).get("type") == "User"
                 and type(entry["user"].get("id")) is int and entry["user"]["id"] > 0
                 and str(entry.get("comment") or "").split("\n", 1)[0].strip() == purpose
                 and any(environment.get("name") == "normal-release-promotion-approval"
                         for environment in entry.get("environments", []))]
    control.require(len(decisions) <= 1, "collection-main-approval-decision-ambiguous")
    if not decisions:
        control.require(allow_missing, "collection-main-approval-purpose-required")
        return None
    control.require(decisions[0].get("state") == "approved", "collection-main-approval-rejected")
    current_job = api.call(f"repos/{repository}/actions/jobs/{latest[0]['id']}")
    fields = ("id", "run_id", "run_attempt", "name", "status", "conclusion")
    control.require(all(current_job.get(key) == latest[0].get(key) for key in fields),
                    "collection-approval-job-drift")
    # This is the final native read: a job lookup can itself race a new attempt.
    current = api.call(f"repos/{repository}/actions/runs/{run_id}")
    generation = ("id", "run_attempt", "head_sha", "path", "workflow_id", "workflow_url")
    control.require(all(current.get(key) == observed.get(key) for key in generation),
                    "collection-approval-generation-drift")
    return decisions[0]
