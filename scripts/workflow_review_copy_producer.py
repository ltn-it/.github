"""Prepare an inspectable private-copy CAS plan; applying it is a separate act.

No original workflow/artifact is recreated. The GitHub-signed copy commit and
the actual operator's locator have their own identities. This command never
starts a workflow, changes a source selector, requests AI or merges a PR.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import sys
from pathlib import Path

import workflow_review_copy as copy
import workflow_review_restore as archive
from workflow_control import API, AUTHORIZED_OPERATORS, SOURCE, binding, canonical, digest, identity, require, sha


def private_guard(api):
    repository = api.call(f"repos/{copy.CUSTODY}")
    require(type(repository.get("id")) is int and repository["id"] == copy.CUSTODY_ID
            and repository.get("full_name") == copy.CUSTODY and repository.get("private") is True
            and repository.get("archived") is False, "copy-producer-private-repository")
    rule = api.call(f"repos/{copy.CUSTODY}/rulesets/{copy.CUSTODY_RULE}")
    require(rule.get("id") == copy.CUSTODY_RULE and rule.get("enforcement") == "active"
            and rule.get("bypass_actors") == [] and rule.get("conditions") == {
                "ref_name": {"include": ["refs/heads/" + copy.CUSTODY_REF], "exclude": []}}
            and {x.get("type") for x in rule.get("rules", [])} == {"deletion", "non_fast_forward"},
            "copy-producer-private-ref-protection")


def prepare(api, original, copies, source, created_at):
    copy.original_scope(original)
    operator = identity(api.call("user"))
    require(operator in AUTHORIZED_OPERATORS, "copy-producer-authorized-operator")
    main = api.call(f"repos/{SOURCE}/git/ref/heads/main")
    require(main.get("object", {}).get("type") == "commit" and main["object"]["sha"] == sha(source),
            "copy-producer-protected-main-source")
    programs = copy.source_programs(api, source)
    instant = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    require(instant.tzinfo == timezone.utc and created_at.endswith("Z"), "copy-producer-plan-time")
    private_guard(api)
    base = copy.custody_ref(api)
    legacy_manifest = archive.decode(api.file(copy.CUSTODY, "manifest.json", base), archive.MAX_OPERATION_BYTES)
    require(type(legacy_manifest) is dict and type(legacy_manifest.get("schema")) is int
            and type(legacy_manifest.get("repository_id")) is int and legacy_manifest in [
        {"schema": 1, "repository": name, "repository_id": copy.CUSTODY_ID,
         "ref": "refs/heads/" + copy.CUSTODY_REF}
        for name in (copy.CUSTODY, "lightning-it/shared-assets-lit")
    ], "copy-producer-existing-manifest")
    pull = api.call(f"repos/{archive.REPOSITORY}/pulls/{copy.TARGET['number']}")
    require(copy.target(pull, archive.REPOSITORY), "copy-producer-target")
    comments = api.pages(f"repos/{archive.REPOSITORY}/issues/{pull['number']}/comments")
    require(not [x for x in comments if identity(x.get("user", {})) in AUTHORIZED_OPERATORS
                 and str(x.get("body") or "").startswith(copy.MARKER)], "copy-producer-locator-already-exists")
    report = archive.authenticate(api, original, copies)
    plan = {"schema": "cloud-review-copy-plan/v1", "operator": list(operator), "producer_source": source,
            "programs": programs, "created_at": created_at, "binding_sha256": digest(binding(pull)),
            "custody_base": base, "original": original, "report_sha256": digest(report)}
    return plan, report


def package_bytes(plan, report, copies):
    require(digest(report) == plan["report_sha256"], "copy-producer-report-drift")
    manifest = {"schema": "private-native-review-copy/v1", "plan": plan,
                "plan_sha256": digest(plan), "report": report}
    result = {"copy-manifest.json": canonical(manifest)}
    for name in ("operation", "receipt"):
        raw = archive.regular_file(copies / (name + ".zip"), archive.MAX_COPY_BYTES)
        expected = plan["original"]["artifacts"][name]
        require(len(raw) == expected["bytes"] and archive.sha256(raw) == expected["sha256"],
                "copy-producer-file-drift")
        result[name + ".zip"] = raw
    require(all(len(data) <= copy.FILES[name] for name, data in result.items()), "copy-producer-package-size")
    return result


def require_new_namespace(api, base, prefix):
    commit = api.call(f"repos/{copy.CUSTODY}/git/commits/{base}")
    root = sha(commit["tree"]["sha"])
    for part in prefix.split("/"):
        tree = api.call(f"repos/{copy.CUSTODY}/git/trees/{root}")
        require(tree.get("sha") == root and tree.get("truncated") is False
                and type(tree.get("tree")) is list, "copy-producer-existing-tree")
        matches = [x for x in tree["tree"] if x.get("path") == part]
        if not matches:
            return
        require(len(matches) == 1 and matches[0].get("type") == "tree"
                and matches[0].get("mode") == "040000", "copy-producer-namespace-conflict")
        root = sha(matches[0]["sha"])
    require(False, "copy-producer-namespace-already-exists")


def publish(api, plan, copies, expected_plan_sha256):
    """One CAS mutation, followed by an honestly separate locator write.

    Native transport errors/partial GraphQL results are terminal and must be
    observed by the coordinator. This function never retries a mutation.
    """
    require(digest(plan) == expected_plan_sha256, "copy-producer-explicit-plan-binding")
    private_guard(api)
    require(copy.custody_ref(api) == plan["custody_base"], "copy-producer-stale-saved-plan")
    current, report = prepare(api, plan["original"], copies, plan["producer_source"], plan["created_at"])
    require(current == plan, "copy-producer-stale-saved-plan")
    payloads = package_bytes(plan, report, copies)
    prefix = f"review-copies/cloud-276/{expected_plan_sha256}"
    # Reusing the protected existing branch does not revive its old controller:
    # only this new namespace is added; every old manifest/operation is retained.
    request = {
        "query": "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid parents(first:2){nodes{oid}}}}}",
        "variables": {"input": {
            "branch": {"repositoryNameWithOwner": copy.CUSTODY, "branchName": copy.CUSTODY_REF},
            "expectedHeadOid": plan["custody_base"],
            "message": {"headline": "Preserve Cloud review copy " + expected_plan_sha256},
            "fileChanges": {"additions": [
                {"path": prefix + "/" + name, "contents": base64.b64encode(data).decode()}
                for name, data in sorted(payloads.items())]},
        }},
    }
    require(len(canonical(request)) <= min(20_000_000, archive.resources.wire_limit()), "copy-producer-mutation-size")
    private_guard(api)
    require(copy.custody_ref(api) == plan["custody_base"], "copy-producer-before-cas-drift")
    require_new_namespace(api, plan["custody_base"], prefix)
    result = api.call("graphql", method="POST", data=request)
    require(type(result) is dict and not result.get("errors"), "copy-producer-cas-outcome-unknown")
    commit = result.get("data", {}).get("createCommitOnBranch", {}).get("commit", {})
    oid = sha(commit.get("oid"))
    require(oid != plan["custody_base"] and commit.get("parents", {}).get("nodes") == [{"oid": plan["custody_base"]}],
            "copy-producer-cas-parent")
    require(copy.custody_ref(api) == oid, "copy-producer-cas-readback-drift")
    actual = api.call(f"repos/{copy.CUSTODY}/commits/{oid}")
    require(actual.get("sha") == oid and identity(actual.get("author") or {}) == tuple(plan["operator"])
            and identity(actual.get("committer") or {}) == ("web-flow", 19864447, "User")
            and actual.get("commit", {}).get("verification", {}).get("verified") is True,
            "copy-producer-native-signed-identity")
    diff = api.call(f"repos/{copy.CUSTODY}/compare/{plan['custody_base']}...{oid}")
    require(diff.get("status") == "ahead" and diff.get("ahead_by") == 1 and diff.get("behind_by") == 0
            and diff.get("total_commits") == 1 and type(diff.get("files")) is list and len(diff["files"]) == 3
            and {x.get("filename") for x in diff["files"]} == {prefix + "/" + name for name in payloads}
            and all(x.get("status") == "added" for x in diff["files"]), "copy-producer-additions-only")
    for name, content in payloads.items():
        require(api.file(copy.CUSTODY, prefix + "/" + name, oid) == content, "copy-producer-committed-byte-drift")
    private_guard(api)
    pull = api.call(f"repos/{archive.REPOSITORY}/pulls/{copy.TARGET['number']}")
    require(copy.target(pull, archive.REPOSITORY) and digest(binding(pull)) == plan["binding_sha256"],
            "copy-producer-before-locator-drift")
    value = {"repository_id": archive.REPOSITORY_ID, "pull_request": pull["number"],
             "base": pull["base"]["sha"], "head": pull["head"]["sha"], "commit": oid,
             "manifest_sha256": archive.sha256(payloads["copy-manifest.json"]), "plan_sha256": expected_plan_sha256}
    body = copy.MARKER + canonical(value).decode()
    comment = api.call(f"repos/{archive.REPOSITORY}/issues/{pull['number']}/comments", method="POST", data={"body": body})
    require(identity(comment.get("user", {})) == tuple(plan["operator"]) and comment.get("body") == body
            and type(comment.get("id")) is int, "copy-producer-locator-outcome-unknown")
    require(api.call(f"repos/{archive.REPOSITORY}/issues/comments/{comment['id']}").get("body") == body,
            "copy-producer-locator-readback")
    return {"schema": "private-native-review-copy-produced/v1", "custody_commit": oid,
            "custody_repository_id": copy.CUSTODY_ID, "locator_comment": comment["id"],
            "plan_sha256": expected_plan_sha256, "manifest_sha256": value["manifest_sha256"],
            "original_artifacts_restored": False, "provider_requests_performed": 0, "current_gate_pass": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "publish"))
    parser.add_argument("--copies", type=Path, required=True)
    parser.add_argument("--original-manifest", type=Path)
    parser.add_argument("--producer-source")
    parser.add_argument("--created-at")
    parser.add_argument("--saved-plan", type=Path)
    parser.add_argument("--approved-plan-sha256")
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            require(args.original_manifest is not None and args.producer_source and args.created_at,
                    "copy-producer-prepare-arguments")
            original = archive.decode(archive.regular_file(args.original_manifest, archive.MAX_OPERATION_BYTES),
                                      archive.MAX_OPERATION_BYTES)
            plan, _report = prepare(API(), original, args.copies, args.producer_source, args.created_at)
            output = {"plan": plan, "plan_sha256": digest(plan), "execution_authorized": False}
        else:
            require(args.saved_plan is not None and args.approved_plan_sha256, "copy-producer-approval-required")
            saved = archive.decode(archive.regular_file(args.saved_plan, archive.MAX_OPERATION_BYTES), archive.MAX_OPERATION_BYTES)
            plan = saved["plan"]
            require(saved["plan_sha256"] == args.approved_plan_sha256, "copy-producer-saved-plan-digest")
            output = publish(API(), plan, args.copies, args.approved_plan_sha256)
    except Exception:
        print("Private review copy preparation or publication failed; observe native state before any retry.", file=sys.stderr)
        return 1
    print(canonical(output).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
