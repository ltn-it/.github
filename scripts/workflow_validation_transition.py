"""Fixed Validation pre-admission history; never a Common seal or activation.

Old native schema-4 decisions retain their original route and issuer. New
integrations and the two existing Common integrations use the ordinary reader.
This module has no request, credential, mutation, or provider entry point.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from workflow_control import (
    RELEASE, check_native_control, check_renovate,
    digest, identity, native_jobs, native_required, require,
)
from workflow_subject import git

REPOSITORY = "ltn-it/modulix-validation"
REPOSITORY_ID = 1269461997
MAIN = "c2a251041b121e59809b06e158b52dc6df81a0a3"
BASELINE = "4af68360a5d5625f9407e3f91b0549b33994f5d3"
DESCRIPTOR = Path(__file__).resolve().parents[1] / ".lit/validation-historical-transition.json"
LEGACY_PATH = ".github/workflows/supplementary-current-revision-required.yml"
LEGACY_WORKFLOW = 338399472
QUALITY = {"quality": [
    {"workflow": ".github/workflows/repository-quality.yml", "job": "repository / quality"},
    {"workflow": ".github/workflows/validation-contracts.yml", "job": "validation / contracts"},
]}


def descriptor():
    value = json.loads(DESCRIPTOR.read_bytes())
    require(value.get("version") == 1 and value.get("repository") == REPOSITORY
            and type(value.get("repository_id")) is int
            and value["repository_id"] == REPOSITORY_ID
            and value.get("main") == MAIN and value.get("baseline") == BASELINE,
            "validation-transition-descriptor")
    rows = value.get("rows")
    require(type(rows) is list and len(rows) == 14
            and [r.get("pr") for r in rows] ==
            [409, 411, 413, 415, 416, 437, 439, 441, 444, 443, 451, 449, 452, 450]
            and len({r.get("merge") for r in rows}) == 14,
            "validation-transition-fixed-history")
    require(len(value.get("poc_authority", [])) == 1
            and value["poc_authority"][0].get("repository") == "ltn-it/.github"
            and value["poc_authority"][0].get("Main") == "8f3a6e96b9ddddbd5936f1120c2e5cdf1ac1038d"
            and value["poc_authority"][0].get("pull") == 914,
            "validation-transition-public-poc-authority")
    return value


def policy(api, repo, base, source_sha, pull):
    """Only the immutable pre-policy Main may use its exact adopted profile.

    The actual protected Main Git subject predates PR451's three-file adoption.
    This is a typed source-owned input; no missing-file exception or fallback.
    Ordinary policy_value still validates namespace, identity and source lineage.
    """
    if repo != REPOSITORY or base != MAIN:
        return None
    require(type(pull) is dict
            and pull.get("base", {}).get("sha") == MAIN
            and pull.get("base", {}).get("ref") == "main"
            and pull.get("head", {}).get("ref") == "develop"
            and identity(pull.get("user", {})) == RELEASE,
            "validation-transition-initial-policy-subject")
    current = api.call(f"repos/{REPOSITORY}")
    require(current.get("full_name") == REPOSITORY
            and type(current.get("id")) is int and current["id"] == REPOSITORY_ID
            and current.get("private") is False and current.get("archived") is False
            and current.get("disabled") is False,
            "validation-transition-initial-policy-identity")
    expected = descriptor()["initial_policy"]
    require(expected.get("path") == ".lit/workflow-control.json"
            and expected.get("ref") == BASELINE,
            "validation-transition-initial-policy-reference")
    raw = api.file(REPOSITORY, expected["path"], BASELINE)
    require(hashlib.sha256(raw).hexdigest() == expected["sha256"],
            "validation-transition-initial-policy-bytes")
    value = json.loads(raw)
    require(value == {"version": 1, "repository": "lightning-it/modulix-validation",
                     "mode": "reference", "quality": QUALITY["quality"],
                     "accepted_sources": [], "distribution_sources": [],
                     "artifact_publication": False},
            "validation-transition-initial-policy-profile")
    return value


def legacy_required(run):
    """Do not widen the ordinary Common native_required predicate."""
    return (run.get("workflow_id") == LEGACY_WORKFLOW
            and run.get("workflow_url") ==
            f"https://api.github.com/repos/{REPOSITORY}/actions/required_workflows/{LEGACY_WORKFLOW}"
            and run.get("path") == LEGACY_PATH)


def pull_matches(pull, row):
    require(pull.get("number") == row["pr"] and pull.get("merged") is True
            and pull.get("state") == "closed" and pull.get("draft") is False
            and pull.get("merge_commit_sha") == row["merge"]
            and identity(pull.get("user", {})) == tuple(row["author"]),
            "validation-transition-pull")
    for side in ("base", "head"):
        part = pull.get(side, {})
        repository = part.get("repo") or {}
        require(part.get("sha") == row[side]
                and repository.get("full_name") == REPOSITORY
                and type(repository.get("id")) is int
                and repository["id"] == REPOSITORY_ID,
                "validation-transition-pull-identity")
    require(pull["base"].get("ref") == "develop" and bool(pull.get("merged_at")),
            "validation-transition-merged-develop")


def successful_run(api, repository, run_id, *, head, path, before=None):
    run = api.call(f"repos/{repository}/actions/runs/{run_id}")
    require(run.get("id") == run_id and run.get("head_sha") == head
            and run.get("path") == path and run.get("status") == "completed"
            and run.get("conclusion") == "success" and run.get("run_attempt") == 1
            and run.get("repository", {}).get("full_name") == repository,
            "validation-transition-native-run")
    if before is not None:
        require(run.get("created_at", "~") < before,
                "validation-transition-postmerge-producer")
    return run


def unresolved_threads(api, number):
    # Fixed descriptor number, read-only GraphQL. More than100 is unqualified;
    # never silently truncate a larger or newly changed conversation.
    query = ('query { repository(owner:"ltn-it",name:"modulix-validation") {'
             f' pullRequest(number:{number}) {{ reviewThreads(first:100) {{'
             ' totalCount pageInfo { hasNextPage } nodes { isResolved } } } } }')
    result = api.call("graphql", method="POST", data={"query": query})
    require(not result.get("errors"), "validation-transition-conversation-read")
    thread = result.get("data", {}).get("repository", {}).get("pullRequest", {}).get("reviewThreads", {})
    nodes = thread.get("nodes")
    require(type(nodes) is list and thread.get("totalCount") == len(nodes)
            and thread.get("pageInfo", {}).get("hasNextPage") is False
            and all(item.get("isResolved") is True for item in nodes),
            "validation-transition-unresolved-conversation")


@dataclass
class Transition:
    api: object
    promotion: dict
    config: dict
    objects: Path
    value: dict
    observed: list = field(default_factory=list)

    def refs(self):
        for branch, expected in (("main", MAIN), ("develop", self.promotion["head"]["sha"])):
            record = self.api.call(f"repos/{REPOSITORY}/branches/{branch}")
            require(record.get("protected") is True
                    and record.get("commit", {}).get("sha") == expected,
                    "validation-transition-live-ref")

    def quality(self, pull, row):
        """Fixed pre-admission checks, not generic missing-association fallback.

        GitHub no longer returns the old PR associations. Require the frozen
        native job/check/suite and immutable integrated Git subject instead;
        every later ingress still uses ordinary check_quality through Common.
        """
        checks = self.api.pages(f"repos/{REPOSITORY}/commits/{row['head']}/check-runs?filter=latest", "check_runs")
        proof = []
        require(len(row["quality"]) == 2, "validation-transition-quality-inventory")
        for expected in row["quality"]:
            candidates = [c for c in checks if c.get("name") == expected["name"]
                          and c.get("app", {}).get("id") == 15368]
            require(candidates, "validation-transition-quality-missing")
            check = max(candidates, key=lambda c: c["id"])
            require(all(check.get(k) == v for k, v in expected.items())
                    and check.get("head_sha") == row["head"]
                    and check.get("status") == "completed" and check.get("conclusion") == "success"
                    and check.get("completed_at", "~") < pull["merged_at"],
                    "validation-transition-quality-check")
            match = re.fullmatch(r"https://github.com/(?:ltn-it|lightning-it)/modulix-validation/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)",
                                 check["details_url"])
            require(match is not None, "validation-transition-quality-origin")
            workflow = next((r["workflow"] for r in QUALITY["quality"] if r["job"] == check["name"]), None)
            run = successful_run(self.api, REPOSITORY, int(match[1]), head=row["head"],
                                 path=workflow, before=pull["merged_at"])
            require(run.get("repository", {}).get("id") == REPOSITORY_ID
                    and run.get("event") == "pull_request"
                    and run.get("check_suite_id") == check["check_suite"]["id"],
                    "validation-transition-quality-run")
            associated = run.get("pull_requests")
            require(type(associated) is list, "validation-transition-quality-association-drift")
            original_locator = not associated or (len(associated) == 1
                    and associated[0].get("number") == row["pr"]
                    and associated[0].get("base", {}).get("sha") == row["base"]
                    and associated[0].get("head", {}).get("sha") == row["head"])
            if not original_locator:
                # These two frozen Renovate ingresses reuse the same branch.
                # The later locator cannot replace any original check/run/job
                # proof above or below; authenticate only its branch alias.
                require(row["pr"] in {443, 449}, "validation-transition-quality-association-drift")
                from workflow_ingress import reused_branch_locator
                reused_branch_locator(self.api, REPOSITORY, pull, associated)
            jobs = native_jobs(self.api, REPOSITORY, run)
            require(any(j.get("id") == int(match[2]) and j.get("conclusion") == "success"
                        and j.get("completed_at", "~") < pull["merged_at"]
                        and j.get("check_run_url", "").endswith(f"/{check['id']}") for j in jobs),
                    "validation-transition-quality-job")
            proof.append({"check": check["id"], "run": run["id"], "attempt": run["run_attempt"],
                          "historical_base": row["base"], "head": row["head"]})
        return proof

    def legacy(self, pull, row):
        old = row["legacy"]
        run = successful_run(self.api, REPOSITORY, old["required_run"], head=row["head"],
                             path=LEGACY_PATH, before=pull["merged_at"])
        require(legacy_required(run) and run.get("event") == "pull_request_target"
                and run["run_attempt"] == old["attempt"] == 1,
                "validation-transition-native-legacy-origin")
        jobs = native_jobs(self.api, REPOSITORY, run)
        final = [j for j in jobs if j.get("name") == "Required current-revision workflow"]
        require(len(final) == 1 and final[0].get("conclusion") == "success"
                and final[0].get("completed_at", "~") < pull["merged_at"],
                "validation-transition-required-job")
        checks = self.api.pages(f"repos/{REPOSITORY}/commits/{row['head']}/check-runs?filter=latest", "check_runs")
        actual = {}
        for expected in old["checks"]:
            matches = [c for c in checks if c.get("id") == expected["id"]]
            require(len(matches) == 1, "validation-transition-legacy-check-missing")
            check = matches[0]
            require(check.get("head_sha") == row["head"]
                    and check.get("app", {}).get("id") == 15368
                    and check.get("status") == "completed" and check.get("conclusion") == "success"
                    and check.get("name") == expected["name"]
                    and check.get("external_id") == expected["external_id"]
                    and check.get("output") == expected["output"]
                    and check.get("completed_at", "~") < pull["merged_at"],
                    "validation-transition-legacy-check-drift")
            actual[check["name"]] = check
        gate = actual["Required current-revision workflow"]
        require(gate["id"] == final[0]["id"]
                and gate.get("check_suite", {}).get("id") == run.get("check_suite_id")
                and final[0].get("check_run_url", "").endswith(f"/{gate['id']}"),
                "validation-transition-legacy-job-correlation")
        summary = json.loads(actual["Current revision review"]["output"]["summary"])
        require(summary == old["schema4"] and summary.get("schema") == 4
                and summary.get("base_sha") == row["base"] and summary.get("head_sha") == row["head"]
                and summary.get("controller_sha") == row["base"]
                and summary.get("controller_ref") == "develop"
                and summary.get("head_repository") == "lightning-it/modulix-validation"
                and summary.get("pull_request_number") == row["pr"],
                "validation-transition-legacy-binding")
        verifier = actual["Protected current-revision verifier"]
        require(verifier["external_id"].startswith(
            f"rep60-required-workflow:v3:{run['id']}:{row['pr']}:{row['base']}:{row['head']}"),
            "validation-transition-independent-verifier")
        producer = self.api.call(f"repos/{REPOSITORY}/actions/runs/{summary['producer_run_id']}")
        expected_producer = old["producer"]
        require(producer.get("id") == summary["producer_run_id"]
                and producer.get("head_sha") == row["head"]
                and producer.get("repository", {}).get("id") == REPOSITORY_ID
                and producer.get("repository", {}).get("full_name") == REPOSITORY
                and all(producer.get(k) == v for k, v in expected_producer.items())
                and producer.get("path") == ".github/workflows/copilot-review.yml"
                and producer.get("run_attempt") == 1 and producer.get("status") == "completed"
                and producer.get("created_at", "~") < pull["merged_at"],
                "validation-transition-neutral-producer")
        # PR413's dispatcher failed after publication and before merge. Its
        # independent Required verifier succeeded; retain both actual results.
        require(producer.get("conclusion") == "success" or
                row["pr"] == 413 and producer.get("conclusion") == "failure",
                "validation-transition-producer-terminal")
        producer_jobs = native_jobs(self.api, REPOSITORY, producer)
        policy = [j for j in producer_jobs if j.get("name") == "Verify current revision policy"]
        require(len(policy) == 1 and policy[0].get("conclusion") == "success"
                and policy[0].get("completed_at", "~") < pull["merged_at"],
                "validation-transition-neutral-publication")
        failed = [j for j in producer_jobs if j.get("conclusion") == "failure"]
        require(not failed or row["pr"] == 413 and len(failed) == 1
                and failed[0].get("name") == "Dispatch protected managed-sync finalizer re-evaluation"
                and failed[0].get("started_at", "") > policy[0]["completed_at"],
                "validation-transition-producer-failure-scope")
        if "source_producer" in row:
            source = row["source_producer"]
            # The independent public native verifier already authenticated the
            # historical private producer. Reuse its exact retained statement;
            # never require private-source credentials in this public consumer.
            require(row["author"] == ["lightning-it-shared-assets-sync[bot]", 307342877, "Bot"]
                    and verifier["output"]["summary"].endswith(
                        f"producer https://github.com/lightning-it/shared-assets-lit/actions/runs/{source['id']}.")
                    and pull["head"]["ref"] ==
                    f"chore/sync-repository-quality-modulix-validation-{source['id']}-1",
                    "validation-transition-managed-provenance")
        if "review" in row:
            self.review(pull, row)
        if row["pr"] == 443:
            check_renovate(self.api, REPOSITORY, pull)
        if row["pr"] == 409:
            require(row["author"] == list(RELEASE)
                    and git(self.objects, "show", "-s", "--format=%P", row["head"]).split()
                        == [row["base"], MAIN]
                    and git(self.objects, "diff", "--name-only", row["base"], row["head"]).splitlines()
                        == [".lit/main-ancestry.json"],
                    "validation-transition-ancestry-exemption")
        return {"route": "validation-historical-legacy", "kind": summary["review_path"],
                "run": run["id"], "attempt": run["run_attempt"],
                "native_checks": [c["id"] for c in actual.values()], "binding_sha256": digest(summary),
                "producer_conclusion": producer["conclusion"],
                "adjacent_failed_jobs": [j["id"] for j in failed]}

    def review(self, pull, row):
        """Authenticate a frozen legacy publication without mutable PR locators."""
        reviews = self.api.pages(f"repos/{REPOSITORY}/pulls/{row['pr']}/reviews")
        current = [r for r in reviews if r.get("commit_id") == row["head"]
                   and r.get("user", {}).get("id") == 175728472
                   and r.get("user", {}).get("type") == "Bot"]
        require(len(current) == 1 and current[0].get("id") == row["review"]["id"],
                "validation-transition-historical-review")
        review = current[0]
        require(review.get("node_id") == row["legacy"]["schema4"]["review_id"]
                and review.get("state") in {"COMMENTED", "APPROVED"}
                and review.get("submitted_at", "~") < pull["merged_at"]
                and type(review.get("body")) is str
                and review["body"] == row["review"]["body"]
                and hashlib.sha256(review["body"].encode()).hexdigest() == row["review"]["body_sha256"],
                "validation-transition-review-body-drift")
        # Historical markup predates the current parser. Authenticate the exact
        # readable publication accepted by the independent old native verifier;
        # never make a generic parser fallback or infer a new current review.
        service = successful_run(self.api, REPOSITORY, row["review"]["service_run"],
                                 head=row["head"], path="dynamic/agents/copilot-pull-request-reviewer",
                                 before=pull["merged_at"])
        require(service.get("event") == "dynamic"
                and service.get("repository", {}).get("id") == REPOSITORY_ID
                and service.get("run_started_at", "~") <= review["submitted_at"],
                "validation-transition-review-service")
        associations = service.get("pull_requests")
        require(type(associations) is list and (not associations or len(associations) == 1
                and associations[0].get("number") == row["pr"]
                and associations[0].get("head", {}).get("sha") == row["head"]),
                "validation-transition-review-association-drift")
        runs = self.api.pages(f"repos/{REPOSITORY}/actions/runs?head_sha={row['head']}", "workflow_runs")
        require(not any(r.get("path") == service["path"] and r.get("id", 0) > service["id"] for r in runs),
                "validation-transition-new-review-generation")

    def poc(self, pull, row):
        require(row["pr"] == 451 and identity(pull.get("merged_by", {})) == tuple(row["author"]),
                "validation-transition-poc-actor")
        files = self.api.pages(f"repos/{REPOSITORY}/pulls/451/files")
        projection = [{k: f.get(k) for k in ("filename", "sha", "status", "additions", "deletions")} for f in files]
        require(projection == row["files"] and len(files) == 3
                and all(f.get("status") == "added" and not f.get("previous_filename") for f in files),
                "validation-transition-poc-exact-files")
        for authority in self.value["poc_authority"]:
            repository, number = authority["repository"], authority["pull"]
            accepted = self.api.call(f"repos/{repository}/pulls/{number}")
            require(accepted.get("merged") is True and accepted.get("base", {}).get("ref") == "main"
                    and accepted.get("merge_commit_sha") == authority["Main"]
                    and accepted.get("merged_at", "~") < pull["created_at"],
                    "validation-transition-poc-historical-authority")
            content = self.api.file(repository, "AGENTS.md", authority["Main"])
            require(hashlib.sha256(content).hexdigest() == authority["file_sha256"],
                    "validation-transition-poc-authority-bytes")
        return {"route": "validation-historical-poc", "kind": "exact-three-file-reference-adoption",
                "authority_sha256": digest(self.value["poc_authority"])}

    def fresh(self, pull, row):
        latest = self.api.call(f"repos/{REPOSITORY}/pulls/{row['pr']}")
        pull_matches(latest, row)
        require(latest.get("merged_at") == pull["merged_at"], "validation-transition-merge-drift")
        runs = self.api.pages(f"repos/{REPOSITORY}/actions/runs?head_sha={row['head']}", "workflow_runs")
        if row["kind"] == "legacy":
            producer = row["legacy"]["producer"]
            expected_id = row["legacy"]["schema4"]["producer_run_id"]
            require(not any(r.get("path") == ".github/workflows/copilot-review.yml"
                            and (type(r.get("id")) is not int
                                 or r["id"] > expected_id
                                 or r["id"] == expected_id
                                 and r.get("run_attempt") != producer["run_attempt"])
                            for r in runs),
                    "validation-transition-new-policy-generation")
            require(not any(native_required(r, REPOSITORY) or legacy_required(r)
                            and (r.get("id"), r.get("run_attempt")) !=
                            (row["legacy"]["required_run"], row["legacy"]["attempt"])
                            and r.get("id", 0) >= row["legacy"]["required_run"] for r in runs),
                    "validation-transition-new-native-generation")
        elif row["kind"] in {"poc", "renovate"}:
            require(not any(native_required(r, REPOSITORY) or legacy_required(r) for r in runs),
                    "validation-transition-unexpected-native-generation")
        self.refs()

    def control(self, ingress, commit):
        rows = [r for r in self.value["rows"] if r["merge"] == commit]
        if not rows:
            return None  # Every new integration retains ordinary Common admission.
        row, = rows
        pull_matches(ingress, row)
        if row["kind"] == "common":
            result = check_native_control(self.api, REPOSITORY, ingress, self.config)
            require(all(result.get(k) == v for k, v in row["common"].items()),
                    "validation-transition-common-original-proof")
            unresolved_threads(self.api, row["pr"])
            self.fresh(ingress, row)
            self.observed.append((ingress, row, result))
            return result
        quality = self.quality(ingress, row)
        if row["kind"] == "legacy":
            result = self.legacy(ingress, row)
        elif row["kind"] == "poc":
            result = self.poc(ingress, row)
        else:
            require(row["kind"] == "renovate" and row["pr"] == 449
                    and identity(ingress.get("user", {})) == ("renovate[bot]", 29139614, "Bot"),
                    "validation-transition-renovate-identity")
            result = {"route": "validation-historical-renovate",
                      "provenance": check_renovate(self.api, REPOSITORY, ingress)}
        unresolved_threads(self.api, row["pr"])
        self.fresh(ingress, row)
        result = result | {"head": row["head"], "quality": quality,
                           "descriptor_sha256": digest(self.value), "historical_only": True}
        self.observed.append((ingress, row, result))
        return result

    def finalize(self):
        """Refresh the full baseline after the last expensive history read."""
        require(len(self.observed) == 14, "validation-transition-incomplete-observation")
        for pull, row, result in self.observed:
            if row["kind"] == "common":
                require(check_native_control(self.api, REPOSITORY, pull, self.config) == result,
                        "validation-transition-common-generation-drift")
            else:
                quality = self.quality(pull, row)
                require(quality == result["quality"], "validation-transition-quality-generation-drift")
                if row["kind"] == "legacy":
                    self.legacy(pull, row)
                elif row["kind"] == "renovate":
                    check_renovate(self.api, REPOSITORY, pull)
                else:
                    self.poc(pull, row)
            unresolved_threads(self.api, row["pr"])
            self.fresh(pull, row)
        self.refs()


def prepare(api, repo, promotion, config, objects, commits):
    """Select only the fixed first Main; descriptor presence grants no scope."""
    if repo != REPOSITORY or promotion.get("base", {}).get("sha") != MAIN:
        return None
    value = descriptor()
    repository = api.call(f"repos/{repo}")
    require(repository.get("full_name") == REPOSITORY and type(repository.get("id")) is int
            and repository["id"] == REPOSITORY_ID and repository.get("archived") is False
            and repository.get("disabled") is False and repository.get("private") is False,
            "validation-transition-repository")
    require(promotion.get("head", {}).get("ref") == "develop"
            and promotion.get("base", {}).get("ref") == "main"
            and identity(promotion.get("user", {})) == RELEASE,
            "validation-transition-normal-promotion")
    prefix = [r["merge"] for r in value["rows"]]
    require(commits[:14] == prefix and git(objects, "merge-base", "--all", BASELINE,
            promotion["head"]["sha"]) == BASELINE, "validation-transition-history-prefix")
    for row in value["rows"]:
        require(git(objects, "show", "-s", "--format=%P", row["merge"]).split() == row["parents"]
                and row["parents"] == [row["base"], row["head"]]
                and git(objects, "show", "-s", "--format=%T", row["merge"]) == row["tree"],
                "validation-transition-immutable-graph")
    require(git(objects, "show", "-s", "--format=%T", BASELINE) == value["baseline_tree"],
            "validation-transition-baseline-tree")
    payload = git(objects, "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv",
                  f"{MAIN}^{{tree}}", BASELINE, binary=True)
    require(hashlib.sha256(payload).hexdigest() == value["baseline_diff_sha256"],
            "validation-transition-complete-diff")
    result = Transition(api, promotion, config, objects, value)
    result.refs()
    return result
