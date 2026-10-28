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


def normal_job(api, repository, pull, source, run_id):
    """Read authenticated normal jobs; GitHub creation time orders serialized attempts."""
    expected = control.binding(pull)
    observed = api.call(f"repos/{repository}/actions/runs/{run_id}")
    control.require(observed.get("id") == run_id and control.native_required(observed, repository)
                    and observed.get("head_sha") == expected["head"]
                    and type(observed.get("run_attempt")) is int and observed["run_attempt"] > 0,
                    "collection-approval-native-run-required")
    jobs = api.pages(f"repos/{repository}/actions/runs/{run_id}/jobs?filter=all", "jobs")
    normal = []
    for job in jobs:
        if job.get("name") != APPROVAL_JOB:
            continue
        attempt = job.get("run_attempt")
        control.require(job.get("run_id") == run_id and type(job.get("id")) is int and job["id"] > 0
                        and type(attempt) is int and 0 < attempt <= observed["run_attempt"],
                        "collection-approval-job-origin")
        if job.get("conclusion") == "skipped":
            continue
        operation = control.operation_record(api, repository, observed | {"run_attempt": attempt}, source)
        if control.same_immutable_tuple(operation.get("binding", {}), expected):
            normal.append((job, operation["binding"]))
    latest_attempt = max((job["run_attempt"] for job, binding in normal), default=0)
    latest = [(job, binding) for job, binding in normal if job["run_attempt"] == latest_attempt]
    control.require(len(latest) <= 1, "collection-approval-job-ambiguous")
    if not latest:
        # A rejected gate can leave all normal jobs skipped. Preserve its
        # temporal barrier without treating a skipped job as positive authority.
        history = api.call(f"repos/{repository}/actions/runs/{run_id}/approvals")
        control.require(type(history) is list, "native-approval-history-shape")
        skipped = [job for job in jobs if job.get("name") == APPROVAL_JOB]
        rejected = any(entry.get("state") == "rejected" and any(
            env.get("name") == "normal-release-promotion-approval"
            for env in entry.get("environments", [])) for entry in history)
        if not rejected or not skipped:
            return None
        job = max(skipped, key=lambda item: item["run_attempt"])
        operation = control.operation_record(api, repository, observed, source)
        latest = [(job, operation["binding"])]
    job, binding = latest[0]
    created = job.get("created_at")
    control.require(type(created) is str and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created),
        "collection-approval-job-time-required")
    return observed, job, binding


def previous_approval(api, repository, pull, source, runs):
    """Run IDs are creation locators, never temporal decision ordering."""
    candidates = []
    for run in runs:
        facts = normal_job(api, repository, pull, source, run["id"])
        if facts is not None:
            candidates.append(facts)
    if not candidates:
        return None
    latest_time = max(job["created_at"] for observed, job, binding in candidates)
    latest = [facts for facts in candidates if facts[1]["created_at"] == latest_time]
    control.require(len(latest) == 1, "collection-approval-order-ambiguous")
    observed, job, binding = latest[0]
    if (job.get("status") != "completed" or job.get("conclusion") != "success"
            or binding != control.binding(pull)):
        return None
    decision = native_approval(api, repository, pull, source, observed["id"], allow_missing=True)
    return observed["id"] if decision is not None else None


def native_approval(api, repository, pull, source, run_id, *, allow_missing=False):
    """Authenticate the selected successful normal job and its exact attempt marker."""
    facts = normal_job(api, repository, pull, source, run_id)
    if facts is None:
        control.require(allow_missing, "collection-normal-approval-job-required")
        return None
    observed, job, binding = facts
    control.require(job.get("status") == "completed", "collection-normal-approval-pending")
    control.require(job.get("conclusion") == "success", "collection-normal-approval-rejected")
    control.require(binding == control.binding(pull), "collection-normal-approval-binding-changed")
    purpose = approval_purpose(pull, repository, run_id, job["run_attempt"])
    history = api.call(f"repos/{repository}/actions/runs/{run_id}/approvals")
    control.require(type(history) is list, "native-approval-history-shape")
    decisions = [entry for entry in history if entry.get("user", {}).get("type") == "User"
                 and type(entry["user"].get("id")) is int and entry["user"]["id"] > 0
                 and str(entry.get("comment") or "").split("\n", 1)[0] == purpose
                 and any(environment.get("name") == "normal-release-promotion-approval"
                         for environment in entry.get("environments", []))]
    control.require(len(decisions) <= 1, "collection-main-approval-decision-ambiguous")
    if not decisions:
        control.require(allow_missing, "collection-main-approval-purpose-required")
        return None
    control.require(decisions[0].get("state") == "approved", "collection-main-approval-rejected")
    current_job = api.call(f"repos/{repository}/actions/jobs/{job['id']}")
    fields = ("id", "run_id", "run_attempt", "name", "status", "conclusion", "created_at")
    control.require(all(current_job.get(key) == job.get(key) for key in fields),
                    "collection-approval-job-drift")
    current = api.call(f"repos/{repository}/actions/runs/{run_id}")
    generation = ("id", "run_attempt", "head_sha", "path", "workflow_id", "workflow_url")
    control.require(all(current.get(key) == observed.get(key) for key in generation),
                    "collection-approval-generation-drift")
    return decisions[0]
