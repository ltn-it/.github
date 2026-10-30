"""One Cloud release's historical review and current verification stay separate.

No model/gateway, upload or selector mutation is performed by this consumer.
The old receipt is verified only with its original Source015 metadata. Current
quality, conversations and purpose-bound approval remain in common control.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import workflow_review_restore as archive
from workflow_control import (
    AUTHORIZED_OPERATORS, SOURCE, WORKFLOW, binding, canonical, digest, identity,
    live_pull, native_required, require, sha, source_identity,
)
from workflow_subject import capture, materialize

CUSTODY = "ltn-it/shared-assets-lit"
CUSTODY_ID = 1120841013
CUSTODY_REF = "lit-review-operations"
CUSTODY_RULE = 24526630
APP_ID = 4355159
INSTALLATION_ID = 148019054
CLIENT_ID = "Iv23liSIvZRkHWKxczlb"
MARKER = "<!-- native-review-copy/v1 -->\n"
TARGET = {"number": 276, "base": "036df8aee1f9511154e62cc8c88294433da1ad70",
          "head": "471334b443d5aa258b9ee70fe217044160fbcb43",
          "run": 40992197896, "attempt": 1, "job": 123857300939}
PROGRAMS = ("workflow_review_restore.py", "workflow_review_copy.py", "workflow_review_copy_producer.py",
            "workflow_review_copy_grant.cjs")
FILES = {"copy-manifest.json": archive.MAX_OPERATION_BYTES, "operation.zip": archive.MAX_COPY_BYTES,
         "receipt.zip": archive.MAX_COPY_BYTES}
IDENTITY_ONLY = {"central_source_sha", "source_assets", "input_sha256"}


def target(pull, repo):
    if repo != archive.REPOSITORY or pull.get("number") != TARGET["number"]:
        return False
    from workflow_collection_release import normal_release
    require(normal_release(pull, repo) and pull["base"]["sha"] == TARGET["base"]
            and pull["head"]["sha"] == TARGET["head"], "copy-fixed-subject-drift")
    return True


def original_scope(request):
    archive.manifest(request)
    require(request["pull_request"] == TARGET["number"]
            and all(request[k] == TARGET[k] for k in ("run", "attempt", "job")), "copy-original-producer-scope")


def locate(api, repo, pull, source):
    """An owner locator is data, never approval, a source selector or funding."""
    if not target(pull, repo):
        return None
    require(sha(source) != archive.ORIGINAL_SOURCE, "copy-old-source-cannot-consume-new-helper")
    comments = api.pages(f"repos/{repo}/issues/{pull['number']}/comments")
    require(type(comments) is list, "copy-locator-inventory")
    candidates = [c for c in comments if identity(c.get("user", {})) in AUTHORIZED_OPERATORS
                  and type(c.get("body")) is str and c["body"].startswith(MARKER)]
    require(len(candidates) == 1, "copy-locator-required-or-ambiguous")
    item = candidates[0]
    require(type(item.get("id")) is int and item["id"] > 0
            and type(item.get("created_at")) is str and item["created_at"] == item.get("updated_at"),
            "copy-locator-edited-or-unknown")
    value = archive.decode(item["body"][len(MARKER):].encode(), 4096)
    require(type(value) is dict and set(value) == {
        "repository_id", "pull_request", "base", "head", "commit", "manifest_sha256", "plan_sha256"
    }, "copy-locator-shape")
    require(item["body"] == MARKER + canonical(value).decode()
            and type(value["repository_id"]) is int and value["repository_id"] == archive.REPOSITORY_ID
            and type(value["pull_request"]) is int and value["pull_request"] == pull["number"]
            and value["base"] == pull["base"]["sha"] and value["head"] == pull["head"]["sha"],
            "copy-locator-binding")
    sha(value["commit"])
    require(all(type(value[k]) is str and re.fullmatch(r"[0-9a-f]{64}", value[k])
                for k in ("manifest_sha256", "plan_sha256")), "copy-locator-digests")
    return {"comment": item["id"], "comment_sha256": digest(item["body"]),
            "operator": list(identity(item["user"])), **value}


def program_hashes():
    root = Path(__file__).parent
    return {name: archive.sha256((root / name).read_bytes()) for name in PROGRAMS}


def select_route(api, repo, pull, source, route, security):
    """The fixed incident must never fall back to a new paid review."""
    if not target(pull, repo):
        return route, None
    require(route == "codex" and security is None, "copy-original-normal-route-required")
    return "review-copy", locate(api, repo, pull, source)


def validate_native_proof(repo, pull, record, run, gate):
    """A historical copy proof is admitted only for this incident and run."""
    require(target(pull, repo), "copy-ingress-target")
    evidence = record.get("evidence") or {}
    historical = evidence.get("historical_review") or {}
    current = evidence.get("current_verification") or {}
    execution = current.get("execution") or {}
    require(evidence.get("kind") == "scoped-historical-review-copy/v1"
            and historical.get("source") == archive.ORIGINAL_SOURCE
            and historical.get("native_producer") == {k: TARGET[k] for k in ("run", "attempt", "job")}
            and record.get("source_sha") != archive.ORIGINAL_SOURCE
            and execution == {"source": record.get("source_sha"), "run": run["id"],
                              "attempt": run["run_attempt"], "job": gate["id"]}
            and evidence.get("provider_requests_performed") == 0
            and evidence.get("normal_current_approval_required") is True
            and (evidence.get("custody") or {}).get("credential_revocation")
            == {"delete_status": 204, "subsequent_read_status": 401}
            and ((evidence.get("custody") or {}).get("credential_grant") or {}).get("permissions")
            == {"contents": "read", "metadata": "read"}
            and (record.get("authorization") or {}).get("run") == run["id"]
            and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in (historical.get("metadata_sha256"), historical.get("response_sha256"),
                                  current.get("metadata_sha256"), current.get("semantic_subject_sha256")))
            and historical["metadata_sha256"] != current["metadata_sha256"], "copy-ingress-dual-source-proof")


def source_programs(api, revision):
    sha(revision)
    values = {name: archive.sha256(api.file(SOURCE, "scripts/" + name, revision)) for name in PROGRAMS}
    require(values == program_hashes(), "copy-producer-program-drift")
    return values


class PrivateReader:
    """The existing App token is used for a fixed private read protocol only."""
    def __init__(self, token):
        require(type(token) is str and bool(token), "copy-private-read-token-required")
        require(os.environ.get("REVIEW_COPY_CLIENT_ID") == CLIENT_ID
                and os.environ.get("REVIEW_COPY_APP_SLUG") == "lightning-it-release-automation"
                and os.environ.get("REVIEW_COPY_INSTALLATION_ID") == str(INSTALLATION_ID),
                "copy-private-app-installation")
        self.token = token
        self.grant = None

    def call(self, path):
        allowed = (
            path in {f"repos/{CUSTODY}", "installation/repositories", f"repos/{CUSTODY}/git/ref/heads/{CUSTODY_REF}",
                     f"repos/{CUSTODY}/rules/branches/{CUSTODY_REF}"}
            or re.fullmatch(rf"repos/{re.escape(CUSTODY)}/(?:commits|git/trees|git/blobs)/[0-9a-f]{{40}}", path)
            or re.fullmatch(rf"repos/{re.escape(CUSTODY)}/compare/[0-9a-f]{{40}}\.\.\.[0-9a-f]{{40}}", path)
        )
        require(bool(allowed), "copy-private-endpoint-scope")
        if self.grant is None:
            self.grant = read_grant(self.token)
        # A fresh config prevents ambient CLI credentials/config from replacing
        # this installation token. No token appears in argv or returned errors.
        with tempfile.TemporaryDirectory(prefix="copy-gh-config-") as config:
            environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": config,
                           "GH_CONFIG_DIR": config, "GH_TOKEN": self.token, "GH_PROMPT_DISABLED": "1",
                           "LANG": "C.UTF-8"}
            wire = capture(["gh", "api", "--hostname", "github.com", "--method", "GET", path],
                           environment=environment, limit=min(archive.resources.wire_limit(), 20_000_000), timeout=60)
        return archive.decode(wire, 20_000_000)

    def scope(self):
        repository = self.call(f"repos/{CUSTODY}")
        require(repository.get("id") == CUSTODY_ID and type(repository.get("id")) is int
                and repository.get("full_name") == CUSTODY and repository.get("private") is True
                and repository.get("archived") is False, "copy-private-repository-identity")
        installed = self.call("installation/repositories")
        require(type(installed.get("total_count")) is int and installed["total_count"] == 1
                and type(installed.get("repositories")) is list
                and len(installed["repositories"]) == 1
                and installed["repositories"][0].get("id") == CUSTODY_ID
                and installed["repositories"][0].get("private") is True, "copy-private-token-repository-scope")

    def close(self):
        """Revoke before historical interpretation; never infer it from a log."""
        token = self.token
        self.token = None
        require(type(token) is str and bool(token), "copy-private-token-already-closed")
        require(token_status(token, "DELETE", "/installation/token") == 204,
                "copy-private-revoke-not-confirmed")
        require(token_status(token, "GET", "/installation/repositories") == 401,
                "copy-private-revoke-independent-readback")
        return {"delete_status": 204, "subsequent_read_status": 401}


def token_status(token, method, path):
    """No redirects, retries, shell argv or response-body logging."""
    require((method, path) in {("DELETE", "/installation/token"), ("GET", "/installation/repositories")},
            "copy-private-lifecycle-endpoint")
    connection = http.client.HTTPSConnection("api.github.com", timeout=30)
    try:
        connection.request(method, path, headers={"Authorization": "Bearer " + token,
                           "Accept": "application/vnd.github+json", "User-Agent": "lit-native-review-copy",
                           "X-GitHub-Api-Version": "2022-11-28"})
        response = connection.getresponse()
        require(len(response.read(2049)) <= 2048, "copy-private-lifecycle-body-size")
        return response.status
    finally:
        connection.close()


def grant_path():
    run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    root = Path(os.environ["RUNNER_TEMP"])
    require(root.is_absolute() and all(re.fullmatch(r"[1-9][0-9]*", v) for v in (run, attempt)), "copy-grant-path")
    return root / f"review-copy-grant-{run}-{attempt}.json"


def read_grant(token):
    path = grant_path()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        try:
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_uid == os.getuid() and 0 < info.st_size <= 4096, "copy-grant-file")
            raw = stream.read(4097)
        finally:
            path.unlink()
    value = archive.decode(raw, 4096)
    job = json.loads(os.environ["NATIVE_JOB"])
    expected = {"source": source_identity(job), "run": int(os.environ["GITHUB_RUN_ID"]),
                "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "job": job["check_run_id"]}
    require(type(value) is dict and set(value) == {"schema", "execution", "app_id", "installation_id", "permissions", "repository_selection", "repositories",
            "obtained_at", "expires_at", "token_sha256"} and value["schema"] == "private-review-copy-grant/v1"
            and value["execution"] == expected and value["app_id"] == APP_ID
            and value["installation_id"] == INSTALLATION_ID and value["permissions"] == {"contents": "read", "metadata": "read"}
            and value["repository_selection"] == "selected" and value["repositories"] == [{"id": CUSTODY_ID,
                "full_name": CUSTODY, "name": "shared-assets-lit", "private": True}]
            and value["token_sha256"] == archive.sha256(token.encode()), "copy-grant-native-binding")
    obtained, expires = [datetime.fromisoformat(value[k].replace("Z", "+00:00")) for k in ("obtained_at", "expires_at")]
    now = datetime.now(timezone.utc)
    require(obtained.tzinfo == expires.tzinfo == timezone.utc and 0 < (expires - obtained).total_seconds() <= 3660
            and -60 <= (now - obtained).total_seconds() <= 3660 and 0 < (expires - now).total_seconds() <= 3660,
            "copy-grant-expiry")
    return {"permissions": value["permissions"], "obtained_at": value["obtained_at"], "expires_at": value["expires_at"],
            "native_receipt_sha256": archive.sha256(raw)}


def custody_ref(reader):
    value = reader.call(f"repos/{CUSTODY}/git/ref/heads/{CUSTODY_REF}")
    require(value.get("ref") == "refs/heads/" + CUSTODY_REF
            and value.get("object", {}).get("type") == "commit", "copy-custody-ref")
    return sha(value["object"]["sha"])


def retained(reader, commit):
    tip = custody_ref(reader)
    comparison = reader.call(f"repos/{CUSTODY}/compare/{commit}...{tip}")
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0,
            "copy-custody-ancestry")
    return tip


def read_blobs(reader, root, directory):
    for part in directory.split("/"):
        tree = reader.call(f"repos/{CUSTODY}/git/trees/{sha(root)}")
        require(tree.get("sha") == root and tree.get("truncated") is False
                and type(tree.get("tree")) is list, "copy-custody-tree")
        entries = [entry for entry in tree["tree"] if entry.get("path") == part]
        require(len(entries) == 1 and entries[0].get("type") == "tree"
                and entries[0].get("mode") == "040000", "copy-custody-directory")
        root = sha(entries[0]["sha"])
    tree = reader.call(f"repos/{CUSTODY}/git/trees/{root}")
    entries = tree.get("tree")
    require(tree.get("sha") == root and tree.get("truncated") is False and type(entries) is list
            and len(entries) == len(FILES) and {x.get("path") for x in entries} == set(FILES),
            "copy-custody-exact-files")
    result = {}
    for entry in entries:
        name = entry["path"]
        require(entry.get("type") == "blob" and entry.get("mode") == "100644"
                and type(entry.get("size")) is int and 0 < entry["size"] <= FILES[name], "copy-custody-blob-size")
        blob = reader.call(f"repos/{CUSTODY}/git/blobs/{sha(entry['sha'])}")
        require(blob.get("sha") == entry["sha"] and blob.get("size") == entry["size"]
                and blob.get("encoding") == "base64" and type(blob.get("content")) is str
                and len(blob["content"]) <= 2 * entry["size"] + 1024, "copy-custody-blob")
        data = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
        require(len(data) == entry["size"]
                and hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == entry["sha"],
                "copy-custody-blob-digest")
        result[name] = data
    return result


def package(api, reader, pull, locator):
    reader.scope()
    commit = reader.call(f"repos/{CUSTODY}/commits/{locator['commit']}")
    require(commit.get("sha") == locator["commit"] and identity(commit.get("author") or {}) == tuple(locator["operator"])
            and identity(commit.get("committer") or {}) == ("web-flow", 19864447, "User")
            and commit.get("commit", {}).get("verification", {}).get("verified") is True,
            "copy-custody-signed-producer")
    retained(reader, locator["commit"])
    directory = f"review-copies/cloud-276/{locator['plan_sha256']}"
    payloads = read_blobs(reader, commit["commit"]["tree"]["sha"], directory)
    require(archive.sha256(payloads["copy-manifest.json"]) == locator["manifest_sha256"], "copy-manifest-digest")
    manifest = archive.decode(payloads["copy-manifest.json"], archive.MAX_OPERATION_BYTES)
    require(type(manifest) is dict and set(manifest) == {"schema", "plan", "plan_sha256", "report"}
            and manifest["schema"] == "private-native-review-copy/v1", "copy-custody-manifest")
    plan = manifest["plan"]
    require(type(plan) is dict and set(plan) == {"schema", "operator", "producer_source", "programs", "created_at",
            "binding_sha256", "custody_base", "original", "report_sha256"}
            and plan["schema"] == "cloud-review-copy-plan/v1"
            and plan["operator"] == locator["operator"] and plan["binding_sha256"] == digest(binding(pull))
            and manifest["plan_sha256"] == locator["plan_sha256"] == digest(plan)
            and plan["report_sha256"] == digest(manifest["report"]), "copy-saved-plan-binding")
    original_scope(plan["original"])
    require(plan["programs"] == source_programs(api, plan["producer_source"]), "copy-producer-programs")
    require([x.get("sha") for x in commit.get("parents", [])] == [sha(plan["custody_base"])],
            "copy-custody-parent")
    diff = reader.call(f"repos/{CUSTODY}/compare/{plan['custody_base']}...{locator['commit']}")
    changes = diff.get("files")
    require(diff.get("status") == "ahead" and diff.get("ahead_by") == 1 and diff.get("behind_by") == 0
            and diff.get("total_commits") == 1 and type(changes) is list and len(changes) == 3
            and {x.get("filename") for x in changes} == {directory + "/" + name for name in FILES}
            and all(x.get("status") == "added" for x in changes), "copy-custody-additions-only")
    reader.scope()
    retained(reader, locator["commit"])
    return manifest, payloads


def historical_subject(api, repo, pull, destination, *, public_token, expected_metadata_sha256):
    """Run only immutable Source015's data materializer in a separate process.

    The child gets no NATIVE_JOB and no custody/model credential. Its old source
    label describes a historical interpretation, not today's defining source.
    """
    original = destination.parent / "historical-source"
    original.mkdir(mode=0o700)
    lines, sections = archive.log_sections(api.native_job_log(repo, TARGET["job"]))
    expected = archive.log_context(lines, sections, TARGET["job"])
    require(digest(expected) == expected_metadata_sha256, "copy-historical-native-metadata")
    commit = api.call(f"repos/{SOURCE}/git/commits/{archive.ORIGINAL_SOURCE}")
    tree = api.call(f"repos/{SOURCE}/git/trees/{commit['tree']['sha']}?recursive=1")
    require(commit.get("sha") == archive.ORIGINAL_SOURCE and tree.get("sha") == commit["tree"]["sha"]
            and tree.get("truncated") is False and type(tree.get("tree")) is list, "copy-historical-tree")
    entries = [x for x in tree["tree"] if re.fullmatch(r"scripts/[A-Za-z0-9_-]+\.py", x.get("path", ""))]
    require({Path(x["path"]).name for x in entries} == set(expected["source_assets"])
            and len(entries) == len(expected["source_assets"])
            and all(x.get("mode") in {"100644", "100755"} and x.get("type") == "blob"
                    and type(x.get("size")) is int and x["size"] > 0 for x in entries)
            and sum(x["size"] for x in entries) <= archive.MAX_SOURCE_BYTES, "copy-historical-assets")
    paths = [x["path"] for x in entries]
    paths += [".github/codex/prompts/review-exact-head.md", ".github/codex/schemas/exact-head-review.schema.json"]
    for path in paths:
        data = api.file(SOURCE, path, archive.ORIGINAL_SOURCE)
        require(len(data) <= archive.MAX_SOURCE_BYTES, "copy-historical-source-size")
        expected_digest = (expected["source_assets"][Path(path).name] if path.startswith("scripts/") else
                           expected["prompt_sha256"] if "/prompts/" in path else expected["schema_sha256"])
        require(archive.sha256(data) == expected_digest, "copy-historical-source-bytes")
        file = original / path
        file.parent.mkdir(parents=True, exist_ok=True)
        with file.open("xb") as stream:
            stream.write(data)
        file.chmod(0o400)
    snapshot = destination.parent / "historical-pull.json"
    snapshot.write_bytes(canonical(pull)); snapshot.chmod(0o400)
    program = (
        "import json,sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
        "import workflow_subject as s;from workflow_control import API,canonical;"
        "m=s.materialize(API(),sys.argv[2],json.loads(Path(sys.argv[3]).read_bytes()),"
        "sys.argv[4],Path(sys.argv[5]));print(canonical(m).decode())"
    )
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"),
                   "GH_TOKEN": public_token, "GH_PROMPT_DISABLED": "1", "LANG": "C.UTF-8"}
    wire = capture([sys.executable, "-I", "-B", "-c", program, str(original / "scripts"), repo,
                    str(snapshot), archive.ORIGINAL_SOURCE, str(destination)], environment=environment,
                   limit=archive.MAX_OPERATION_BYTES, timeout=180)
    return archive.decode(wire, archive.MAX_OPERATION_BYTES)


def native_context(api, repo, pull, source):
    job = json.loads(os.environ["NATIVE_JOB"])
    require(source_identity(job) == source and source != archive.ORIGINAL_SOURCE, "copy-executing-source")
    run_id, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    run = api.call(f"repos/{repo}/actions/runs/{run_id}")
    require(run.get("id") == run_id and native_required(run, repo) and run.get("run_attempt") == attempt
            and run.get("head_sha") == pull["head"]["sha"]
            and len(run.get("pull_requests", [])) == 1
            and run["pull_requests"][0].get("number") == pull["number"]
            and run["pull_requests"][0].get("base", {}).get("sha") == pull["base"]["sha"]
            and run["pull_requests"][0].get("head", {}).get("sha") == pull["head"]["sha"], "copy-current-native-run")
    actual = api.call(f"repos/{repo}/actions/jobs/{job['check_run_id']}")
    require(actual.get("id") == job["check_run_id"] and actual.get("run_id") == run_id
            and type(actual.get("run_attempt")) is int and actual["run_attempt"] == attempt
            and actual.get("name") in {"Protected current revision", "Current revision review"}
            and actual.get("status") == "in_progress", "copy-current-native-job")
    return {"source": source, "run": run_id, "attempt": attempt, "job": job["check_run_id"]}


def evidence(api, repo, pull, source, locator, *, reader=None, private_token=None):
    ambient = os.environ.pop("REVIEW_COPY_TOKEN", "")
    token = ambient if private_token is None else private_token
    require(not os.environ.get("NODE_OPTIONS"), "copy-observer-must-not-reach-consumer")
    require(target(pull, repo), "copy-target-required")
    context = native_context(api, repo, pull, source)
    require(locate(api, repo, pull, source) == locator, "copy-current-locator-drift")
    # Revoke the credential and confirm denial before starting any historical
    # interpreter. The pinned action's post handler is a failure cleanup fallback.
    private = reader or PrivateReader(token)
    try:
        manifest, payloads = package(api, private, pull, locator)
    finally:
        revocation = private.close()
    with tempfile.TemporaryDirectory(prefix="native-review-copy-") as temp:
        root = Path(temp)
        for name in ("operation.zip", "receipt.zip"):
            file = root / name; file.write_bytes(payloads[name]); file.chmod(0o600)
        report = archive.authenticate(api, manifest["plan"]["original"], root)
        require(report == manifest["report"], "copy-reauthenticated-original-drift")
        old = historical_subject(api, repo, pull, root / "historical-subject",
                                 public_token=os.environ.get("GH_TOKEN", ""),
                                 expected_metadata_sha256=report["metadata_sha256"])
        current = materialize(api, repo, pull, source, root / "current-subject")
        require(digest(old) == report["metadata_sha256"] and old.get("central_source_sha") == archive.ORIGINAL_SOURCE
                and current.get("central_source_sha") == source and source != archive.ORIGINAL_SOURCE,
                "copy-dual-source-identities")
        require({k: v for k, v in old.items() if k not in IDENTITY_ONLY}
                == {k: v for k, v in current.items() if k not in IDENTITY_ONLY}
                and (root / "historical-subject/change.patch").read_bytes()
                == (root / "current-subject/change.patch").read_bytes(), "copy-semantic-subject-drift")
        semantic = digest({k: v for k, v in old.items() if k not in IDENTITY_ONLY})
    require(locate(api, repo, pull, source) == locator and native_context(api, repo, pull, source) == context,
                "copy-current-generation-drift")
    live_pull(api, repo, pull["number"], binding(pull))
    return {"kind": "scoped-historical-review-copy/v1", "locator": locator,
                "historical_review": {"source": archive.ORIGINAL_SOURCE, "metadata_sha256": report["metadata_sha256"],
                                      "response_sha256": report["response_sha256"], "native_producer": {
                                          key: manifest["plan"]["original"][key] for key in ("run", "attempt", "job")}},
                "current_verification": {"execution": context, "metadata_sha256": digest(current),
                                         "semantic_subject_sha256": semantic},
                "custody": {"repository_id": CUSTODY_ID, "commit": locator["commit"],
                            "plan_sha256": locator["plan_sha256"], "producer_source": manifest["plan"]["producer_source"],
                            "credential_grant": private.grant,
                            "credential_revocation": revocation},
                "provider_requests_performed": 0, "normal_current_approval_required": True}


if __name__ == "__main__":
    # Pre-mint validation only. The pinned action supplies app-slug and
    # installation-id (it has no app-id output); Reader checks those afterwards.
    try:
        if sys.argv[1:] == ["cleanup-grant"]:
            grant_path().unlink(missing_ok=True)
        else:
            require(sys.argv[1:] == ["validate-token-input"] and os.environ.get("REVIEW_COPY_CLIENT_ID") == CLIENT_ID
                    and not grant_path().exists(), "copy-private-client-input")
    except Exception:
        print("Private review-copy token contract input rejected.", file=sys.stderr)
        raise SystemExit(1) from None
    print("Private review-copy grant metadata operation completed; no token issued.")
