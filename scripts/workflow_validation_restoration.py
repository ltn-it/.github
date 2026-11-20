"""Account for a single reverted integration in the Validation promotion.

Only the two later, normally reviewed integrations supply acceptance proofs.
The original failed run stays separately identifiable in the promotion archive.
"""
from workflow_control import RELEASE, identity, native_required, require
from workflow_ingress import FINAL_STEP, instant
from workflow_subject import git

REPOSITORY = "ltn-it/modulix-validation"
REPOSITORY_ID = 1269461997
MAIN = "eeb932bf8a2a064a78161925182a3141df489790"
PREVIOUS = "9e9280c1d3bf5d3f15d12cb5a79f2b97ac1a4062"
ORIGINAL = "472a8b39403d802c1f56c492bb2fc61e02ae2070"
FEATURE = "f5638e78231b6de7c86596098a1ccf675bc6844b"
INVERSE_HEAD = "fbee652cd239b978a2534db98933af03a9e46774"
FAILED_RUN = 44682671764
FAILED_JOB = 136110795976


def applies(repo, promotion, commit):
    return repo == REPOSITORY and promotion["base"]["sha"] == MAIN and commit == ORIGINAL


def merged_subject(pull, number, base, head, merge):
    require(pull.get("number") == number and pull.get("merged") is True
            and pull.get("state") == "closed" and pull.get("draft") is False
            and pull.get("merge_commit_sha") == merge and pull["base"]["ref"] == "develop"
            and pull["base"]["sha"] == base and pull["head"]["sha"] == head
            and all((pull[side]["repo"]["id"], pull[side]["repo"]["full_name"]) ==
                    (REPOSITORY_ID, REPOSITORY) for side in ("head", "base")),
            "validation-restoration-merged-subject")


def checked_review(api, pull, row):
    control = row["control"]
    require(control.get("route") == "copilot" and control["head"] == pull["head"]["sha"]
            and pull["number"] == row["pull"] and pull["merge_commit_sha"] == row["merge"],
            "validation-restoration-independent-review")
    job = api.call(f"repos/{REPOSITORY}/actions/jobs/{control['job']}")
    require(job.get("id") == control["job"] and job["run_id"] == control["run"]
            and job["run_attempt"] == control["attempt"] and job["head_sha"] == control["head"]
            and job["name"] == "Current revision review" and job["status"] == "completed"
            and job["conclusion"] == "success" and instant(job["completed_at"]) < instant(pull["merged_at"])
            and any(s["name"] == "Persist exact native acceptance proof" and s["conclusion"] == "success"
                    for s in job["steps"]), "validation-restoration-review-before-merge")


def verify(api, promotion, objects, commits, original_pull, references):
    """Called after every other integration has passed the normal control."""
    from workflow_control import classify
    require(classify(promotion, REPOSITORY) == "promotion" and identity(promotion["user"]) == RELEASE
            and promotion["base"]["sha"] == MAIN, "validation-restoration-promotion")
    merged_subject(original_pull, 477, PREVIOUS, FEATURE, ORIGINAL)
    require(original_pull["id"] == 5408425625 and commits.count(ORIGINAL) == 1
            and [r["merge"] for r in references] == [c for c in commits if c != ORIGINAL],
            "validation-restoration-complete-ingress")
    index = commits.index(ORIGINAL)
    successors = commits[index + 1:index + 3]
    require(len(successors) == 2, "validation-restoration-incomplete")
    rollback, reapply = successors
    inverse, replacement = references[index:index + 2]
    require(inverse["pull"] == 478 and replacement["pull"] > 478
            and len({inverse["control"]["run"], replacement["control"]["run"], FAILED_RUN}) == 3,
            "validation-restoration-separate-pulls")
    replacement_head = replacement["control"]["head"]
    previous_tree = git(objects, "rev-parse", PREVIOUS + "^{tree}")
    original_tree = git(objects, "rev-parse", ORIGINAL + "^{tree}")
    require(previous_tree != original_tree, "validation-restoration-empty")
    for commit, base, head, tree in [(ORIGINAL, PREVIOUS, FEATURE, original_tree),
                                     (rollback, ORIGINAL, INVERSE_HEAD, previous_tree),
                                     (reapply, rollback, replacement_head, original_tree)]:
        require(git(objects, "show", "-s", "--format=%P", commit).split() == [base, head]
                and git(objects, "merge-base", "--all", base, head) == base
                and git(objects, "rev-parse", head + "^{tree}") == tree
                and git(objects, "rev-parse", commit + "^{tree}") == tree,
                "validation-restoration-exact-graph-and-trees")
    for row, base, head in [(inverse, ORIGINAL, INVERSE_HEAD), (replacement, rollback, replacement_head)]:
        pull = api.call(f"repos/{REPOSITORY}/pulls/{row['pull']}")
        merged_subject(pull, row["pull"], base, head, row["merge"])
        checked_review(api, pull, row)

    run = api.call(f"repos/{REPOSITORY}/actions/runs/{FAILED_RUN}")
    job = api.call(f"repos/{REPOSITORY}/actions/jobs/{FAILED_JOB}")
    require(native_required(run, REPOSITORY) and run["id"] == FAILED_RUN and run["run_attempt"] == 1
            and run["head_sha"] == FEATURE and run["repository"]["id"] == REPOSITORY_ID
            and run["event"] == "pull_request" and run["workflow_id"] == 388059047
            and run["status"] == "completed" and run["conclusion"] == "failure"
            and job["id"] == FAILED_JOB and job["run_id"] == FAILED_RUN and job["run_attempt"] == 1
            and job["head_sha"] == FEATURE and job["name"] == "Current revision review"
            and job["status"] == "completed" and job["conclusion"] == "failure"
            and instant(job["completed_at"]) >= instant(original_pull["merged_at"])
            and [(s["name"], s["conclusion"]) for s in job["steps"]
                 if s["name"] in {FINAL_STEP, "Persist exact native acceptance proof"}] ==
                [(FINAL_STEP, "failure"), ("Persist exact native acceptance proof", "skipped")],
            "validation-restoration-original-failure")
    return {"pull": 477, "merge": ORIGINAL, "head": FEATURE, "run": FAILED_RUN, "attempt": 1,
            "job": FAILED_JOB, "conclusion": "failure", "previous_tree": previous_tree,
            "original_tree": original_tree, "rollback": {"pull": 478, "merge": rollback},
            "reapplication": {"pull": replacement["pull"], "merge": reapply}}
