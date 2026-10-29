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


def approval_purpose(pull, repository, run_id, attempt):
    """Scope the native User decision to one immutable operation and attempt."""
    control.require(normal_release(pull, repository), "collection-release-identity-required")
    control.require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
                    "collection-approval-attempt-required")
    return ("[collection-main-approval/v2 " + control.digest(control.binding(pull))
            + " " + str(run_id) + "/" + str(attempt) + "]")


def native_approval(api, repository, pull, source, run_id, *, expected_attempt=None):
    """Require a fresh normal approval in this executing native attempt.

    There is no historical approval reuse on the stable Collection route.
    An incomplete or verifier-only rerun must obtain a new normal gate through
    a complete execution; it cannot infer authority from skipped jobs/history.
    """
    expected = control.binding(pull)
    observed = api.call(f"repos/{repository}/actions/runs/{run_id}")
    control.require(observed.get("id") == run_id and control.native_required(observed, repository)
                    and observed.get("head_sha") == expected["head"]
                    and type(observed.get("run_attempt")) is int and observed["run_attempt"] > 0,
                    "collection-approval-native-run-required")
    attempt = observed["run_attempt"]
    control.require(expected_attempt is None or (type(expected_attempt) is int and expected_attempt == attempt),
                    "collection-approval-executing-attempt-drift")
    purpose = approval_purpose(pull, repository, run_id, attempt)
    artifacts = api.pages(f"repos/{repository}/actions/runs/{run_id}/artifacts", "artifacts")
    exact = [item for item in artifacts if item.get("name") == f"control-operation-{attempt}"
             and item.get("expired") is False]
    control.require(len(exact) == 1, "collection-current-operation-required")
    operation = control.operation_record(api, repository, observed, source)
    control.require(operation.get("binding") == expected, "collection-normal-approval-binding-changed")
    jobs = control.native_jobs(api, repository, observed)
    normal = [job for job in jobs if job.get("name") == APPROVAL_JOB]
    control.require(len(normal) == 1, "collection-current-normal-job-required")
    job = normal[0]
    control.require(type(job.get("id")) is int and job["id"] > 0 and job.get("run_attempt") == attempt,
                    "collection-approval-job-origin")
    control.require(job.get("status") == "completed" and job.get("conclusion") == "success",
                    "collection-current-normal-approval-not-successful")
    history = api.call(f"repos/{repository}/actions/runs/{run_id}/approvals")
    control.require(type(history) is list, "native-approval-history-shape")
    decisions = [entry for entry in history if entry.get("user", {}).get("type") == "User"
                 and type(entry["user"].get("id")) is int and entry["user"]["id"] > 0
                 and str(entry.get("comment") or "").split("\n", 1)[0] == purpose
                 and any(environment.get("name") == "normal-release-promotion-approval"
                         for environment in entry.get("environments", []))]
    control.require(len(decisions) == 1 and decisions[0].get("state") == "approved",
                    "collection-current-purpose-approval-required")
    control.live_pull(api, repository, pull["number"], expected)
    current_job = api.call(f"repos/{repository}/actions/jobs/{job['id']}")
    fields = ("id", "run_id", "run_attempt", "name", "status", "conclusion")
    control.require(all(current_job.get(key) == job.get(key) for key in fields),
                    "collection-approval-job-drift")
    current = api.call(f"repos/{repository}/actions/runs/{run_id}")
    generation = ("id", "run_attempt", "head_sha", "path", "workflow_id", "workflow_url")
    control.require(all(current.get(key) == observed.get(key) for key in generation),
                    "collection-approval-generation-drift")
    return decisions[0]
