"""Read-only complete inventory and bounded current-content observation.

Only GH GET requests are implemented. Raw source text is held in memory and
never written to diagnostics or reports. Reports contain categories and hashes.
Run in a private context; an inventory includes private repository identities.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from collaboration_content import AdmissionError, policy_from, require, sha256, validate


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class GitHubReadOnly:
    def get(self, path):
        require(type(path) is str and re.match(r"^(?:orgs/ltn-it(?:[/?]|$)|repos/ltn-it/)", path)
                and ".." not in path and "\n" not in path, "read-path")
        try:
            result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET", path],
                                    capture_output=True, timeout=60, check=False)
            require(result.returncode == 0, "read-unavailable")
            require(0 < len(result.stdout) <= 16 * 1024 * 1024, "read-size")
            return json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
            raise AdmissionError("read-unavailable") from None


def pages(api, path, *, maximum=1000):
    """Require a terminal empty page, unique IDs and fully shaped list pages.

    A partial inventory is never returned on transport, shape or bound failure.
    A short page is not the terminator: the next page is still requested.
    """
    result, ids = [], set()
    separator = "&" if "?" in path else "?"
    for page in range(1, maximum + 1):
        block = api.get(f"{path}{separator}{urlencode({'per_page': 100, 'page': page})}")
        require(type(block) is list and len(block) <= 100, "pagination-shape")
        if not block:
            return result
        for row in block:
            require(type(row) is dict and type(row.get("id")) is int
                    and row["id"] > 0 and row["id"] not in ids, "pagination-identity")
            ids.add(row["id"])
            result.append(row)
    raise AdmissionError("pagination-bound")


def organization_inventory(api):
    started = utc_now()
    before = api.get("orgs/ltn-it")
    # Full organization visibility is required; a selected-installation token
    # or ordinary member's partial view cannot claim complete enumeration.
    membership = api.get("orgs/ltn-it/memberships/litroc")
    require(type(membership) is dict and membership.get("state") == "active"
            and membership.get("role") == "admin"
            and membership.get("organization", {}).get("login") == "ltn-it", "inventory-authority")
    rows = pages(api, "orgs/ltn-it/repos?type=all")
    after = api.get("orgs/ltn-it")
    for field in ("id", "login", "public_repos", "owned_private_repos"):
        require(type(before) is dict and type(after) is dict and field in before
                and before[field] == after.get(field), "inventory-generation")
    require(before["login"] == "ltn-it" and type(before["public_repos"]) is int
            and type(before["owned_private_repos"]) is int, "inventory-count")
    require(len(rows) == before["public_repos"] + before["owned_private_repos"]
            and sum(row.get("visibility") == "public" for row in rows) == before["public_repos"],
            "inventory-count")
    output = []
    for row in rows:
        require(type(row.get("owner")) is dict and row["owner"].get("login") == "ltn-it"
                and row.get("visibility") in ("public", "private", "internal")
                and type(row.get("private")) is bool
                and row["private"] is (row["visibility"] != "public")
                and type(row.get("archived")) is bool
                and type(row.get("full_name")) is str, "inventory-visibility")
        output.append({key: row[key] for key in ("id", "full_name", "visibility", "archived")})
    return {"version": 1, "organization": "ltn-it", "started_at": started, "finished_at": utc_now(),
            "complete": True, "repositories": sorted(output, key=lambda row: row["id"])}


def observe_open_issues(api, inventory, policy, repositories, *, state="open"):
    """Observe open issues and their current comments; explicitly exclude PRs.

    Preserve per-object read times. This is a bounded observation window, not
    an atomic organization snapshot or a promise about edits made afterward.
    """
    require(state in {"open", "all"}, "scope-state")
    results, counts = [], {"issues": 0, "comments": 0}
    known = {row["full_name"]: row for row in inventory["repositories"]}
    require(type(repositories) is list and repositories and len(set(repositories)) == len(repositories), "scope-shape")
    for repository in repositories:
        require(repository in known and known[repository]["visibility"] == "public", "scope-public-repository")
        validate({"kind": "comment", "repository": repository, "title": "", "body": ""}, inventory, policy)
        live = api.get(f"repos/{repository}")
        require(type(live) is dict and all(live.get(key) == known[repository][key]
                                         for key in ("id", "full_name", "visibility", "archived")), "scope-visibility-drift")
        issues = pages(api, f"repos/{repository}/issues?state={state}&sort=created&direction=asc")
        for issue in issues:
            if "pull_request" in issue:
                continue
            require(type(issue.get("number")) is int and issue["number"] > 0, "issue-number")
            number = issue["number"]
            current = api.get(f"repos/{repository}/issues/{number}")
            require(type(current) is dict and current.get("id") == issue["id"]
                    and current.get("number") == number
                    and current.get("state") in ({"open", "closed"} if state == "all" else {"open"})
                    and "pull_request" not in current,
                    "issue-binding")
            comments = pages(api, f"repos/{repository}/issues/{number}/comments")
            require(type(current.get("comments")) is int and len(comments) == current["comments"], "comment-count")
            objects = [("issue", current)] + [("comment", comment) for comment in comments]
            for kind, obj in objects:
                require(type(obj.get("body")) is str or obj.get("body") is None, "body-type")
                result = validate({"kind": kind, "repository": repository,
                                   "title": obj.get("title", "") if kind == "issue" else "",
                                   "body": obj.get("body") or ""}, inventory, policy)
                counts["issues" if kind == "issue" else "comments"] += 1
                # URLs, titles, author names, bodies, diffs and private values
                # do not cross this output boundary. The native opaque ID is
                # sufficient to resolve a target in the private remediation UI.
                results.append({"repository_id": known[repository]["id"], "kind": kind, "id": obj["id"],
                                "observed_at": utc_now(), "source_updated_at": obj.get("updated_at"),
                                "disposition": "admitted-current-content" if result["admitted"] else "owner-remediation-required",
                                "content_sha256": result["content_sha256"], "categories": result["categories"]})
            final = api.get(f"repos/{repository}/issues/{number}")
            require(type(final) is dict and final.get("id") == current["id"]
                    and all(final.get(field) == current.get(field) for field in ("state", "title", "body", "comments", "updated_at")),
                    "issue-observation-drift")
            repeated = pages(api, f"repos/{repository}/issues/{number}/comments")
            require(snapshot(comments, ("body", "updated_at")) == snapshot(repeated, ("body", "updated_at")),
                    "comment-observation-drift")
        latest = pages(api, f"repos/{repository}/issues?state={state}&sort=created&direction=asc")
        require([row["id"] for row in latest] == [row["id"] for row in issues], "scope-observation-drift")
        final_live = api.get(f"repos/{repository}")
        require(type(final_live) is dict and all(final_live.get(key) == known[repository][key]
                                                for key in ("id", "full_name", "visibility", "archived")),
                "scope-visibility-drift")
    excluded = ["closed-issues", "pull-requests", "reviews", "inline-comments", "edit-history",
                "attachments", "timeline", "releases", "wiki", "caches", "repository-files", "other-repositories"]
    if state == "all":
        excluded.remove("closed-issues")
    return {"version": 1, "scope": state + "-issue-titles-bodies-current-comments", "owner": policy["owner"],
            "started_at": inventory["started_at"], "finished_at": utc_now(),
            "repository_ids": [known[name]["id"] for name in repositories], "counts": counts,
            "clean": all(not row["categories"] for row in results), "objects": results, "excluded": excluded,
            "inventory_sha256": sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")))}


def snapshot(rows, fields):
    """An in-memory comparison only; source values never enter a receipt."""
    return [(row["id"], *(row.get(field) for field in fields)) for row in rows]


def observe_open_collaboration(api, inventory, policy, repositories, *, state="open"):
    """Explicitly extend the bounded open-issue scope with open PR content.

    Submitted reviews (including dismissed reviews), PR conversation comments
    and inline review comments are included. Pending review drafts and their
    comments are excluded. Re-enumeration detects observed drift; edits after
    the final read and cross-object races remain outside an atomic guarantee.
    """
    report = observe_open_issues(api, inventory, policy, repositories, state=state)
    report["scope"] = state + "-issues-and-pulls-current-comments-submitted-reviews-inline-comments"
    report["counts"].update({"pull_requests": 0, "pull_comments": 0, "reviews": 0, "inline_comments": 0})
    report["excluded"] = [item for item in report["excluded"]
                          if item not in ("pull-requests", "reviews", "inline-comments")]
    report["excluded"].extend((["closed-pull-requests"] if state == "open" else []) + ["pending-review-drafts"])
    report["pending_review_drafts_excluded"] = 0
    known = {row["full_name"]: row for row in inventory["repositories"]}
    for repository in repositories:
        path = f"repos/{repository}"
        enumeration = f"{path}/pulls?state={state}&sort=created&direction=asc"
        pulls = pages(api, enumeration)
        for listed in pulls:
            number = listed.get("number")
            require(type(number) is int and number > 0, "pull-number")
            target = f"{path}/pulls/{number}"
            current = api.get(target)
            require(type(current) is dict and current.get("id") == listed["id"]
                    and current.get("number") == number
                    and current.get("state") in ({"open", "closed"} if state == "all" else {"open"}), "pull-binding")
            comments_path = f"{path}/issues/{number}/comments"
            comments = pages(api, comments_path)
            reviews = pages(api, f"{target}/reviews")
            inline = pages(api, f"{target}/comments")
            require(type(current.get("comments")) is int and current["comments"] == len(comments)
                    and type(current.get("review_comments")) is int
                    and current["review_comments"] == len(inline), "pull-comment-count")
            require(all(row.get("state") in ("APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING")
                        for row in reviews), "review-state")
            review_ids = {row["id"] for row in reviews}
            pending = {row["id"] for row in reviews if row["state"] == "PENDING"}
            require(all(type(row.get("pull_request_review_id")) is int
                        and row["pull_request_review_id"] in review_ids for row in inline), "inline-review-binding")
            report["pending_review_drafts_excluded"] += len(pending)
            objects = [("pull_request", "pull_requests", current)]
            objects += [("comment", "pull_comments", row) for row in comments]
            objects += [("review", "reviews", row) for row in reviews if row["id"] not in pending]
            objects += [("review_comment", "inline_comments", row) for row in inline
                        if row["pull_request_review_id"] not in pending]
            for kind, counter, obj in objects:
                require(type(obj.get("body")) is str or obj.get("body") is None, "body-type")
                result = validate({"kind": kind, "repository": repository,
                                   "title": obj.get("title", "") if kind == "pull_request" else "",
                                   "body": obj.get("body") or ""}, inventory, policy)
                report["counts"][counter] += 1
                report["objects"].append({"repository_id": known[repository]["id"], "kind": kind, "id": obj["id"],
                                          "observed_at": utc_now(), "source_updated_at": obj.get("updated_at"),
                                          "disposition": "admitted-current-content" if result["admitted"] else "owner-remediation-required",
                                          "content_sha256": result["content_sha256"], "categories": result["categories"]})
            final = api.get(target)
            require(type(final) is dict and final.get("id") == current["id"]
                    and all(final.get(field) == current.get(field) for field in
                            ("number", "state", "title", "body", "comments", "review_comments", "updated_at", "head", "base")),
                    "pull-observation-drift")
            for suffix, initial, fields in (
                (comments_path, comments, ("body", "updated_at")),
                (f"{target}/reviews", reviews, ("body", "state", "submitted_at", "commit_id")),
                (f"{target}/comments", inline, ("body", "updated_at", "pull_request_review_id")),
            ):
                require(snapshot(initial, fields) == snapshot(pages(api, suffix), fields), "pull-content-drift")
        require([row["id"] for row in pages(api, enumeration)] == [row["id"] for row in pulls], "pull-scope-drift")
        final_live = api.get(path)
        require(type(final_live) is dict and all(final_live.get(key) == known[repository][key]
                                                for key in ("id", "full_name", "visibility", "archived")),
                "scope-visibility-drift")
    report["clean"] = all(not row["categories"] for row in report["objects"])
    report["finished_at"] = utc_now()
    return report


def private_write(path, value):
    # Never overwrite a receipt or follow a symlink. Caller selects a private
    # directory; a public Actions artifact is not a private remediation sink.
    parent = path.parent
    require(parent.is_dir() and not parent.is_symlink() and parent.stat().st_mode & 0o077 == 0,
            "private-report-directory")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--repository", action="append", required=True)
    parser.add_argument("--include-open-pulls", action="store_true",
                        help="Include open PRs, submitted reviews and current conversation/inline comments.")
    args = parser.parse_args()
    try:
        api = GitHubReadOnly()
        policy = policy_from(args.policy)
        inventory = organization_inventory(api)
        observe = observe_open_collaboration if args.include_open_pulls else observe_open_issues
        report = observe(api, inventory, policy, args.repository)
        private_write(args.report, {"inventory": inventory, "observation": report})
        print(json.dumps({"complete": True, "clean": report["clean"], "counts": report["counts"]}))
        return 0 if report["clean"] else 1
    except (AdmissionError, OSError) as error:
        category = str(error) if isinstance(error, AdmissionError) else "report-unavailable"
        print(json.dumps({"complete": False, "category": category}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
