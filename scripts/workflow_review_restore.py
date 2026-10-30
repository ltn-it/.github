"""Authenticate an archived review copy; never produce current acceptance.

This read-only, deliberately unconnected verifier supports the original Cloud
Source015 producer only. Every locator is untrusted until checked against live
GitHub records and that producer's still-native log. Copies retain their own
identity; neither original artifact IDs nor a current successful gate are made.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

import bounded_review_transport as transport
import exact_revision_gateway as gateway
import single_review_resources as resources
from workflow_collection_release import normal_release
from workflow_control import API, ControlError, MAX_OPERATION_BYTES, SOURCE, WORKFLOW, binding, canonical, require, source_identity

ORIGINAL_SOURCE = "015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f"
ORIGINAL_WORKFLOW_SHA256 = "54e4f08e630c8e61c3bca51d96557c68ee55775b371e4499e539e65c8814234a"
REPOSITORY = "ltn-it/ansible-collection-cloud"
REPOSITORY_ID = 1318852819
UPLOAD_ACTION = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
EXPORT_COMMAND = ('Run python3 -B -E -s "/run/exact-review/code/exact_revision_gateway.py" '
                  'export-native --run-id "$GITHUB_RUN_ID"')
TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z ?")
MAX_COPY_BYTES = 9_000_000
MAX_SOURCE_BYTES = 16_000_000
REQUIRED_STEPS = (
    "Classify protected current revision", "Persist protected operation binding",
    "Materialize complete data-only review subject", "Collect and verify the protected model receipt",
    "Export protected native Codex evidence", "Persist protected Codex receipt",
)


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def integer(value):
    return type(value) is int and value > 0


def decode(payload, maximum):
    limits = resources.memory_contract()
    require(type(payload) is bytes and 0 < len(payload) <= min(maximum, limits["max_wire_bytes"]),
            "restore-json-size")
    return transport.strict_json(payload, json_limits=(limits["max_json_nodes"], limits["max_json_depth"]))


def regular_file(path, maximum):
    # Admit the opened descriptor, rather than stat-ing a path and following a
    # replacement symlink afterwards. File names come from this source only.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "restore-copy-file-size")
        payload = stream.read(maximum + 1)
    require(len(payload) == info.st_size and len(payload) <= maximum, "restore-copy-file-drift")
    return payload


def manifest(value):
    require(type(value) is dict and set(value) == {
        "schema", "repository", "repository_id", "pull_request", "run", "attempt", "job", "source_sha", "artifacts"
    }, "restore-manifest-shape")
    require(value["schema"] == "native-review-copy/v1" and value["repository"] == REPOSITORY
            and type(value["repository_id"]) is int and value["repository_id"] == REPOSITORY_ID
            and value["source_sha"] == ORIGINAL_SOURCE, "restore-scope")
    require(all(integer(value[k]) for k in ("pull_request", "run", "attempt", "job")), "restore-native-locators")
    artifacts = value["artifacts"]
    require(type(artifacts) is dict and set(artifacts) == {"operation", "receipt"}, "restore-artifact-set")
    for kind, prefix in (("operation", "control-operation"), ("receipt", "codex-receipt")):
        item = artifacts[kind]
        require(type(item) is dict and set(item) == {"id", "name", "bytes", "sha256"}, "restore-artifact-shape")
        require(integer(item["id"]) and integer(item["bytes"]) and item["bytes"] <= MAX_COPY_BYTES
                and item["name"] == f"{prefix}-{value['attempt']}"
                and type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
                "restore-artifact-identity")
    require(artifacts["operation"]["id"] != artifacts["receipt"]["id"], "restore-artifact-id-ambiguity")
    return value


def log_sections(log):
    require(type(log) is str and 0 < len(log.encode("utf-8")) <= MAX_OPERATION_BYTES, "restore-native-log-size")
    # Preserve all other characters. In particular, ANSI/control sequences
    # cannot normalize a forged upload record into one of the exact matches.
    lines = [TIMESTAMP.sub("", line) for line in log.splitlines()]
    starts = [i for i, line in enumerate(lines) if line.startswith("##[group]")
              or line.startswith("Post job cleanup.") or line.startswith("##[start-action")]
    sections = [(lines[i], lines[i:j]) for i, j in zip(starts, starts[1:] + [len(lines)])]
    return lines, sections


def upload_record(sections, item, repo, run):
    matches = [block for title, block in sections if title == "##[group]Run " + UPLOAD_ACTION
               and f"  name: {item['name']}" in block]
    require(len(matches) == 1, "restore-native-upload-ambiguous")
    block = matches[0]
    paths = (["  path: control-operation.json"] if item["name"].startswith("control-operation-") else
             ["  path: exact-revision-review/provider-native.json", "exact-revision-review/provider-response.bin"])
    require(all(block.count(line) == 1 for line in paths)
            and block.count("  overwrite: false") == 1 and block.count("  archive: true") == 1,
            "restore-native-upload-path")
    expected = (
        f"  name: {item['name']}", "##[endgroup]", f"Uploading artifact: {item['name']}.zip",
        f"Uploaded bytes {item['bytes']}", "Finished uploading artifact content to blob storage!",
        f"SHA256 digest of uploaded artifact is {item['sha256']}",
        f"Artifact {item['name']} successfully finalized. Artifact ID {item['id']}",
        f"Artifact {item['name']} has been successfully uploaded! Final size is {item['bytes']} bytes. Artifact ID is {item['id']}",
        f"Artifact download URL: https://github.com/{repo}/actions/runs/{run}/artifacts/{item['id']}",
    )
    require(all(block.count(line) == 1 for line in expected), "restore-native-upload-binding")
    require([block.index(line) for line in expected] == sorted(block.index(line) for line in expected),
            "restore-native-upload-order")
    # One conflicting digest/size/ID cannot hide behind the matching claim.
    prefixes = ("  name:", "Uploaded bytes ", "SHA256 digest of uploaded artifact is ",
                "Artifact download URL: ", f"Artifact {item['name']} successfully finalized.",
                f"Artifact {item['name']} has been successfully uploaded!")
    require(all(sum(line.startswith(prefix) for line in block) == 1 for prefix in prefixes),
            "restore-native-upload-conflict")


def log_context(lines, sections, job):
    blocks = [block for title, block in sections if title == "##[group]" + EXPORT_COMMAND]
    require(len(blocks) == 1, "restore-native-export-ambiguous")
    block = blocks[0]
    require(block.count("python3 -B scripts/workflow_control.py verify-codex") == 1
            and block.count("Protected actual model response and complete native request receipt verified.") == 1,
            "restore-native-export-verification")
    starts = [i for i, line in enumerate(block) if line == "  NATIVE_JOB: {"]
    require(len(starts) == 1, "restore-native-source-context")
    start = starts[0]
    ends = [i for i in range(start + 1, len(block)) if block[i] == "}"]
    require(len(ends) == 1, "restore-native-source-context")
    context = decode(("{\n" + "\n".join(block[start + 1:ends[0] + 1])).encode(), MAX_OPERATION_BYTES)
    require(source_identity(context) == ORIGINAL_SOURCE and context["check_run_id"] == job
            and context.get("status") == "success", "restore-native-source-binding")
    markers = [i for i, line in enumerate(lines) if line == "Protected review-metadata.json:"]
    require(len(markers) == 1 and markers[0] + 1 < len(lines), "restore-native-metadata-ambiguous")
    return decode(lines[markers[0] + 1].encode(), MAX_OPERATION_BYTES)


def unpack(payload, item, allowed):
    require(len(payload) == item["bytes"] and sha256(payload) == item["sha256"], "restore-copy-zip-binding")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            require(len(entries) == len(allowed) and {x.filename for x in entries} == set(allowed),
                    "restore-zip-exact-files")
            require(not archive.comment, "restore-zip-comment")
            maximum = min(sum(allowed.values()), resources.wire_limit())
            for entry in entries:
                mode = entry.external_attr >> 16
                require(not entry.is_dir() and not entry.flag_bits & 1 and not entry.comment
                        and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                        and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        and 0 < entry.file_size <= min(allowed[entry.filename], maximum), "restore-zip-entry")
            require(sum(x.file_size for x in entries) <= maximum, "restore-zip-expanded-size")
            result = {}
            for entry in entries:
                with archive.open(entry) as stream:
                    result[entry.filename] = stream.read(allowed[entry.filename] + 1)
                require(len(result[entry.filename]) == entry.file_size, "restore-zip-expanded-drift")
            return result
    except ControlError:
        raise
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError):
        require(False, "restore-zip-invalid")


def source_metadata(api, metadata, pull):
    require(type(metadata) is dict and metadata.get("schema_version") == 7
            and metadata.get("central_source_sha") == ORIGINAL_SOURCE
            and metadata.get("repository") == REPOSITORY and metadata.get("pull_request") == pull["number"]
            and metadata.get("base_sha") == pull["base"]["sha"] and metadata.get("head_sha") == pull["head"]["sha"],
            "restore-original-subject-binding")
    require(metadata.get("input_sha256") == sha256(canonical({k: v for k, v in metadata.items() if k != "input_sha256"})),
            "restore-original-input-digest")
    require(sha256(api.file(SOURCE, WORKFLOW, ORIGINAL_SOURCE)) == ORIGINAL_WORKFLOW_SHA256,
            "restore-original-workflow")
    commit = api.call(f"repos/{SOURCE}/git/commits/{ORIGINAL_SOURCE}")
    require(commit.get("sha") == ORIGINAL_SOURCE and type(commit.get("tree")) is dict
            and type(commit["tree"].get("sha")) is str
            and re.fullmatch(r"[0-9a-f]{40}", commit["tree"]["sha"]), "restore-source-commit")
    tree = api.call(f"repos/{SOURCE}/git/trees/{commit['tree']['sha']}?recursive=1")
    require(tree.get("sha") == commit["tree"]["sha"] and tree.get("truncated") is False
            and type(tree.get("tree")) is list, "restore-source-tree")
    files = [x for x in tree["tree"] if re.fullmatch(r"scripts/[A-Za-z0-9_-]+\.py", x.get("path", ""))]
    require(0 < len(files) <= 256 and len({x["path"] for x in files}) == len(files)
            and all(x.get("type") == "blob" and x.get("mode") in {"100644", "100755"}
                    and integer(x.get("size")) and x["size"] <= MAX_SOURCE_BYTES for x in files)
            and sum(x["size"] for x in files) <= MAX_SOURCE_BYTES, "restore-source-files")
    assets = {}
    for item in files:
        require(item["size"] <= resources.wire_limit(), "restore-source-file-size")
        payload = api.file(SOURCE, item["path"], ORIGINAL_SOURCE)
        require(len(payload) == item["size"], "restore-source-file-size")
        assets[Path(item["path"]).name] = sha256(payload)
    require(metadata.get("source_assets") == assets, "restore-original-source-assets")
    for path, key in ((".github/codex/prompts/review-exact-head.md", "prompt_sha256"),
                      (".github/codex/schemas/exact-head-review.schema.json", "schema_sha256")):
        require(metadata.get(key) == sha256(api.file(SOURCE, path, ORIGINAL_SOURCE)), "restore-original-prompt-schema")


def authenticate(api, request, copies):
    """Return copy provenance after live GETs; this is not a replay installer."""
    plan = manifest(request)
    repo, number = plan["repository"], plan["pull_request"]
    repository = api.call(f"repos/{repo}")
    require(repository.get("full_name") == repo and type(repository.get("id")) is int
            and repository["id"] == REPOSITORY_ID, "restore-repository-identity")
    pull = api.call(f"repos/{repo}/pulls/{number}")
    require(pull.get("number") == number and pull.get("state") == "open" and pull.get("draft") is False
            and normal_release(pull, repo), "restore-current-release")
    run = api.call(f"repos/{repo}/actions/runs/{plan['run']}")
    require(run.get("id") == plan["run"] and run.get("event") == "pull_request" and native_run(run)
            and integer(run.get("run_attempt")) and run["run_attempt"] >= plan["attempt"]
            and run.get("head_sha") == pull["head"]["sha"], "restore-native-run")
    associations = [x for x in run.get("pull_requests", []) if x.get("number") == number
                    and x.get("head", {}).get("sha") == pull["head"]["sha"]
                    and x.get("base", {}).get("sha") == pull["base"]["sha"]]
    require(len(associations) == 1 and len(run.get("pull_requests", [])) == 1, "restore-native-association")
    jobs = api.pages(f"repos/{repo}/actions/runs/{plan['run']}/attempts/{plan['attempt']}/jobs", "jobs")
    producers = [x for x in jobs if x.get("name") == "Protected current revision"]
    require(len(producers) == 1, "restore-native-producer-ambiguous")
    job = producers[0]
    require(job.get("id") == plan["job"] and job.get("run_id") == plan["run"]
            and type(job.get("run_attempt")) is int and job["run_attempt"] == plan["attempt"]
            and job.get("status") == "completed" and job.get("conclusion") == "success",
            "restore-native-producer-success")
    require(all(len([x for x in job.get("steps", []) if x.get("name") == name]) == 1
                and next(x for x in job["steps"] if x.get("name") == name).get("conclusion") == "success"
                for name in REQUIRED_STEPS), "restore-native-producer-steps")
    require(api.call(f"repos/{repo}/actions/jobs/{plan['job']}") == job, "restore-native-job-origin")
    log = api.native_job_log(repo, plan["job"])
    lines, sections = log_sections(log)
    metadata = log_context(lines, sections, plan["job"])
    for item in plan["artifacts"].values():
        upload_record(sections, item, repo, plan["run"])
    source_metadata(api, metadata, pull)
    maximum = min(MAX_COPY_BYTES, resources.wire_limit())
    operation_zip = regular_file(copies / "operation.zip", maximum)
    receipt_zip = regular_file(copies / "receipt.zip", maximum)
    operation = unpack(operation_zip, plan["artifacts"]["operation"], {"control-operation.json": MAX_OPERATION_BYTES})
    receipt = unpack(receipt_zip, plan["artifacts"]["receipt"], {
        "provider-native.json": MAX_OPERATION_BYTES, "provider-response.bin": transport.MAX_RESPONSE_BYTES,
    })
    record = decode(receipt["provider-native.json"], MAX_OPERATION_BYTES)
    operation = decode(operation["control-operation.json"], MAX_OPERATION_BYTES)
    require(operation == {"version": 1, "source_sha": ORIGINAL_SOURCE, "binding": binding(pull)},
            "restore-original-operation-binding")
    from workflow_codex import validate_record
    wire = receipt["provider-response.bin"]
    validate_record(record, wire, metadata, ORIGINAL_SOURCE)
    response = transport.completed_response(wire, streaming=wire.startswith(b"event:"),
                                            json_limits=(resources.MAX_JSON_NODES, resources.MAX_JSON_DEPTH))
    require(response.get("status") == "completed" and response.get("error") is None
            and record["receipt"]["provider"].get("response_ids") == [response.get("id")]
            and response.get("model") == record["receipt"]["provider"]["model"]
            and gateway.final_packet(response, json_limits=(resources.MAX_JSON_NODES, resources.MAX_JSON_DEPTH))
                == record["receipt"]["result"], "restore-original-response-binding")
    require(api.call(f"repos/{repo}/actions/jobs/{plan['job']}") == job, "restore-native-job-drift")
    require(api.call(f"repos/{repo}/actions/runs/{plan['run']}") == run, "restore-native-run-drift")
    require(binding(api.call(f"repos/{repo}/pulls/{number}")) == binding(pull), "restore-current-subject-drift")
    return {
        "schema": "authenticated-native-review-copy/v1", "original": plan,
        "native_log_sha256": sha256(log.encode()), "metadata_sha256": sha256(canonical(metadata)),
        "response_sha256": sha256(wire), "historical_review_verdict": "PASS",
        "copy": {"transport": "local-files", "native_artifact": False,
                 "verifier_sha256": sha256(Path(__file__).read_bytes()),
                 "operation_zip_sha256": sha256(operation_zip), "receipt_zip_sha256": sha256(receipt_zip)},
        "current_gate_pass": False, "provider_requests_performed": 0,
    }


def native_run(run):
    from workflow_control import native_required
    return native_required(run, REPOSITORY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--copies", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan = decode(regular_file(args.manifest, MAX_OPERATION_BYTES), MAX_OPERATION_BYTES)
        result = authenticate(API(), plan, args.copies)
    except Exception:
        print("Archived native review copy verification failed.", file=sys.stderr)
        return 1
    print(canonical(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
