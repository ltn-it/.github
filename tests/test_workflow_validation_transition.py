"""Captured native history exercises the production Validation transition.

Only Git/API/artifact transport is replaced. These offline cases grant no native
admission, review allocation, runtime acceptance or authority to publish.
"""
import base64
import copy
import hashlib
import json
import os
import sys
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_control as control
import workflow_subject as subject
import workflow_root_ancestry as ancestry
import workflow_validation_transition as transition

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).with_name("fixtures") / "validation-transition-native.json"
REPOSITORY = "ltn-it/modulix-validation"
PREFIX = "repos/" + REPOSITORY
MAIN = "c2a251041b121e59809b06e158b52dc6df81a0a3"
BASELINE = "4af68360a5d5625f9407e3f91b0549b33994f5d3"
SOURCE = "530b8fb175b7fccf238b03aab652bd5ee2ad2a41"
QUALITY = [
    {"workflow": ".github/workflows/repository-quality.yml", "job": "repository / quality"},
    {"workflow": ".github/workflows/validation-contracts.yml", "job": "validation / contracts"},
]


def captured_payload():
    envelope = json.loads(FIXTURE.read_bytes())
    raw = zlib.decompress(base64.b64decode(envelope["payload_zlib_base64"]))
    if hashlib.sha256(raw).hexdigest() != envelope["payload_sha256"]:
        raise AssertionError("Corrupted captured transport fixture")
    return json.loads(raw)


class NativeCapture:
    """Return recorded public native data; every unrecorded effect/read fails."""

    def __init__(self):
        self.value = captured_payload()
        self.records = self.value["records"]
        self.calls = []
        self.git_calls = []
        self.full_diff = zlib.decompress(base64.b64decode(
            self.value["git"]["full_binary_diff_zlib_base64"]))
        self.config = {"version": 1, "repository": REPOSITORY, "mode": "reference",
                       "accepted_sources": [SOURCE], "quality": copy.deepcopy(QUALITY),
                       "distribution_sources": [], "artifact_publication": False}
        self.promotion = {"base": {"sha": MAIN, "ref": "main"},
                          "head": {"sha": BASELINE, "ref": "develop"},
                          "user": dict(zip(("login", "id", "type"), control.RELEASE))}

    def call(self, path, *, method="GET", data=None):
        if path == "graphql" and method == "POST" and set(data or {}) == {"query"}:
            import re
            match = re.search(r"pullRequest\(number:(\d+)\)", data["query"])
            if match is None or "mutation" in data["query"]:
                raise AssertionError("Uncaptured GraphQL operation")
            nodes = copy.deepcopy(self.value["threads"][match[1]])
            return {"data": {"repository": {"pullRequest": {"reviewThreads": {
                "totalCount": len(nodes), "pageInfo": {"hasNextPage": False}, "nodes": nodes}}}}}
        if method != "GET" or data is not None:
            raise AssertionError("Historical evidence reader attempted a write")
        self.calls.append(path)
        if getattr(self, "on_read", None) is not None:
            self.on_read(path)
        if path in self.records:
            return copy.deepcopy(self.records[path])
        # Scalar check reads remain tied to the original head inventory.
        if "/check-runs/" in path:
            identifier = int(path.rsplit("/", 1)[1])
            matches = [check for key, value in self.records.items()
                       if "/check-runs?filter=all" in key
                       for check in value["check_runs"] if check["id"] == identifier]
            if len(matches) == 1:
                return copy.deepcopy(matches[0])
        raise AssertionError("Uncaptured native GET: " + path)

    def pages(self, path, key=None):
        value = self.call(path)
        if key is None:
            if not isinstance(value, list):
                raise AssertionError("Captured list shape changed")
            return value
        items = value[key]
        if value.get("total_count", len(items)) != len(items):
            raise AssertionError("Captured pagination is incomplete")
        return items

    def file(self, repository, path, revision):
        return self.value["files"][f"{repository}:{revision}:{path}"].encode()

    def artifact(self, api, repository, run, name, filename):
        if repository != REPOSITORY or getattr(api, "delegate", api) is not self:
            raise AssertionError("Borrowed artifact origin")
        subjects = {41016535359: 450, 40971712209: 452}
        number = subjects[run["id"]]
        expected = {450: 2, 452: 1}[number]
        kind = {"control-proof.json": "control-proof", "control-operation.json": "control-operation"}.get(filename)
        if kind is None or name != f"{kind}-{expected}":
            raise AssertionError("Uncaptured artifact subject")
        return copy.deepcopy(self.value["decoded_artifacts"][f"{number}:{filename}"])

    def git(self, objects, *arguments, binary=False):
        self.git_calls.append(arguments)
        graph = self.value["git"]["commits"]
        if arguments[:2] == ("merge-base", "--all"):
            left, right = arguments[-2:]
            if left == MAIN and right in {MAIN, BASELINE}:
                return MAIN
            if left == BASELINE and (right == BASELINE or right == getattr(self, "new_tail", None)):
                return BASELINE
            if left == MAIN and right == getattr(self, "new_tail", None):
                return MAIN
        if arguments[0] == "rev-list":
            return "\n".join(self.value["git"]["first_parent_merges"])
        if arguments[0] == "rev-parse" and arguments[-1].endswith("^{tree}"):
            return graph[arguments[-1][:-7]]["tree"]
        if arguments[:3] == ("show", "-s", "--format=%P"):
            return " ".join(graph[arguments[-1]]["parents"])
        if arguments[:3] == ("show", "-s", "--format=%T"):
            return graph[arguments[-1]]["tree"]
        if arguments[:2] == ("merge-tree", "--write-tree"):
            return graph[arguments[-1]]["tree"]
        if arguments[:2] == ("diff", "--name-only"):
            return self.value["git"]["name_only_diffs"][arguments[-2] + ":" + arguments[-1]]
        if arguments[0] == "diff" and "--binary" in arguments:
            if binary:
                if arguments[-1] == getattr(self, "new_tree", None):
                    return self.full_diff + b"\nSynthetic new-tail transport bytes\n"
                return self.full_diff
            return self.full_diff.decode()
        raise AssertionError("Uncaptured immutable Git request: " + repr(arguments))

    def integration_git(self, objects, *arguments, binary=False):
        # promotion_ingress owns a real temporary bare Git directory. Even a
        # captured transport must fail if final authentication outlives it.
        if not Path(objects).is_dir():
            raise AssertionError("Historical finalizer used a removed Git object directory")
        return self.git(objects, *arguments, binary=binary)

    def pull(self, number):
        return self.call(f"{PREFIX}/pulls/{number}")

    def prepare(self, *, repository=REPOSITORY, promotion=None, commits=None):
        with patch.object(subject, "git", side_effect=self.git), \
                patch.object(transition, "git", side_effect=self.git), \
                patch.object(control, "artifact_record", side_effect=self.artifact):
            return transition.prepare(self, repository,
                promotion if promotion is not None else self.promotion, self.config,
                Path("captured-immutable-objects.git"),
                commits if commits is not None else self.value["git"]["first_parent_merges"])


@contextmanager
def isolated_git_environment():
    git_keys = {key for key in os.environ if key.startswith("GIT_")}
    with patch.dict(os.environ, {key: value for key, value in os.environ.items()
                                 if key not in git_keys}, clear=True):
        yield


class ValidationTransitionTests(unittest.TestCase):
    def test_all_fourteen_real_ingresses_have_a_bounded_historical_disposition(self):
        api = NativeCapture()
        context = api.prepare()
        self.assertIsNotNone(context)
        descriptor = json.loads((ROOT / ".lit/validation-historical-transition.json").read_bytes())
        self.assertEqual(14, len(descriptor["rows"]))
        with patch.object(transition, "git", side_effect=api.git), \
                patch.object(control, "artifact_record", side_effect=api.artifact):
            for row in descriptor["rows"]:
                with self.subTest(pull=row["pr"]):
                    result = context.control(api.pull(row["pr"]), row["merge"])
                    self.assertIsInstance(result, dict)
                    self.assertFalse(result.get("source_admission_granted", False))
                    self.assertFalse(result.get("model_funding_granted", False))
        self.assertTrue(all(not call.startswith("http") for call in api.calls))

    def test_actual_promotion_reader_composes_the_fourteen_real_native_ingresses(self):
        api = NativeCapture()
        with isolated_git_environment(), \
                patch.object(subject, "git", side_effect=api.integration_git), \
                patch.object(transition, "git", side_effect=api.integration_git), \
                patch.object(subject, "fetch_objects"), \
                patch.object(control, "artifact_record", side_effect=api.artifact):
            result = control.promotion_ingress(api, REPOSITORY, api.promotion, api.config)
        self.assertEqual(14, len(result["ingress"]))
        self.assertEqual(BASELINE, result["head"])
        self.assertEqual("1e08adea12bbb60160dcb62604f943f60ce26a580fc836f0bfee487c86eb0150",
                         result["diff_sha256"])
        self.assertEqual(BASELINE, result["validation_historical_transition"]["baseline"])

    def test_final_read_catches_first_ingress_drift_during_later_acquisition(self):
        api = NativeCapture()
        first_head = api.pull(409)["head"]["sha"]
        first_checks = api.records[f"{PREFIX}/commits/{first_head}/check-runs?filter=latest"]["check_runs"]
        first_gate = next(check for check in first_checks if check["name"] == "Current revision review")
        changed = []

        def after_later_acquisition(path):
            if path == f"{PREFIX}/pulls/450" and not changed:
                first_gate["output"]["summary"] = "Changed after the first ingress was authenticated"
                changed.append(True)

        api.on_read = after_later_acquisition
        with isolated_git_environment(), \
                patch.object(subject, "git", side_effect=api.integration_git), \
                patch.object(transition, "git", side_effect=api.integration_git), \
                patch.object(subject, "fetch_objects"), \
                patch.object(control, "artifact_record", side_effect=api.artifact), \
                self.assertRaises(control.ControlError):
            control.promotion_ingress(api, REPOSITORY, api.promotion, api.config)
        self.assertEqual([True], changed)

    def test_other_repositories_cannot_use_the_validation_history(self):
        api = NativeCapture()
        self.assertIsNone(api.prepare(repository="ltn-it/ansible-collection-supplementary"))
        self.assertEqual([], api.calls)
        wrong = copy.deepcopy(api.promotion)
        wrong["base"]["sha"] = "f" * 40
        self.assertIsNone(api.prepare(promotion=wrong))
        self.assertEqual([], api.calls)

    def test_main_or_native_numeric_identity_drift_is_rejected(self):
        for change in [
            lambda api: api.records[PREFIX].update(id=1103407173),
            lambda api: api.records[PREFIX].update(full_name="ltn-it/borrowed-validation"),
            lambda api: api.records[PREFIX + "/branches/main"].update(protected=False),
        ]:
            api = NativeCapture()
            change(api)
            with self.subTest(change=change), self.assertRaises(control.ControlError):
                api.prepare()

    def test_frozen_graph_order_omission_and_complete_binary_diff_are_not_waivers(self):
        api = NativeCapture()
        commits = api.value["git"]["first_parent_merges"]
        for candidate in [commits[1:], list(reversed(commits))]:
            with self.subTest(graph=candidate), self.assertRaises(control.ControlError):
                api.prepare(commits=candidate)
        api = NativeCapture()
        api.full_diff += b"\nUnreviewed extra bytes\n"
        with self.assertRaises(control.ControlError):
            api.prepare()

    def test_historical_merge_parent_or_tree_change_is_rejected(self):
        for key in ["parents", "tree"]:
            api = NativeCapture()
            merge = api.value["git"]["first_parent_merges"][0]
            record = api.value["git"]["commits"][merge]
            if key == "parents":
                record["parents"].reverse()
            else:
                record["tree"] = "f" * 40
            with self.subTest(field=key), self.assertRaises(control.ControlError):
                api.prepare()

    def test_legacy_checks_producer_and_historical_authority_cannot_be_borrowed(self):
        descriptor = json.loads((ROOT / ".lit/validation-historical-transition.json").read_bytes())
        row = descriptor["rows"][0]
        for change in [
            lambda api, check: check["app"].update(id=1),
            lambda api, check: check.update(head_sha="f" * 40),
            lambda api, check: check["output"].update(summary="Borrowed green check"),
            lambda api, check: api.records[f"{PREFIX}/actions/runs/{row['legacy']['required_run']}"]
                .update(workflow_url=f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/338399472"),
        ]:
            api = NativeCapture()
            context = api.prepare()
            path = f"{PREFIX}/commits/{row['head']}/check-runs?filter=latest"
            check = next(c for c in api.records[path]["check_runs"]
                         if c["id"] == row["legacy"]["checks"][0]["id"])
            change(api, check)
            with self.subTest(change=change), self.assertRaises(control.ControlError):
                context.control(api.pull(row["pr"]), row["merge"])
        api = NativeCapture()
        context = api.prepare()
        key = "ltn-it/.github:8f3a6e96b9ddddbd5936f1120c2e5cdf1ac1038d:AGENTS.md"
        api.value["files"][key] += "\nInvented historical approval\n"
        row = next(r for r in descriptor["rows"] if r["pr"] == 451)
        with self.assertRaises(control.ControlError):
            context.control(api.pull(451), row["merge"])

    def test_new_policy_generation_cannot_reuse_old_successful_checks(self):
        row = transition.descriptor()["rows"][0]
        producer_id = row["legacy"]["schema4"]["producer_run_id"]
        for identifier, attempt, status, conclusion in [
            (producer_id + 1, 1, "completed", "failure"),
            (producer_id + 1, 1, "queued", None),
            (producer_id, 2, "in_progress", None),
        ]:
            api = NativeCapture()
            context = api.prepare()
            newer = copy.deepcopy(api.records[f"{PREFIX}/actions/runs/{producer_id}"])
            newer.update(id=identifier, run_attempt=attempt, status=status, conclusion=conclusion)
            inventory = api.records[f"{PREFIX}/actions/runs?head_sha={row['head']}"]
            inventory["workflow_runs"].append(newer)
            inventory["total_count"] += 1
            with patch.object(transition, "git", side_effect=api.git), \
                    self.subTest(run=identifier, attempt=attempt), self.assertRaisesRegex(
                    control.ControlError, "new-policy-generation"):
                context.control(api.pull(row["pr"]), row["merge"])

    def test_ordinary_copilot_reader_keeps_denial_for_missing_native_pr_locators(self):
        for number in [437, 439, 441, 444]:
            api = NativeCapture()
            with self.subTest(pull=number), self.assertRaisesRegex(
                    control.ControlError, "native-copilot-pr-association-unavailable"):
                control.copilot_review(api, REPOSITORY, api.pull(number))

    def test_common_ingresses_use_the_actual_unchanged_native_proof_reader(self):
        api = NativeCapture()
        context = api.prepare()
        with patch.object(control, "artifact_record", side_effect=api.artifact), \
                patch.object(transition, "check_native_control", wraps=control.check_native_control) as reader:
            result = context.control(api.pull(450), BASELINE)
        self.assertTrue(reader.called)
        self.assertEqual((41016535359, 2, SOURCE),
                         (result["run"], result["attempt"], result["source_sha"]))

    def test_borrowed_common_source_head_and_unknown_later_generation_are_denied(self):
        for mutate in [
            lambda api: api.value["decoded_artifacts"]["450:control-proof.json"].update(source_sha="f" * 40),
            lambda api: api.value["decoded_artifacts"]["450:control-proof.json"]["binding"].update(head="f" * 40),
            lambda api: api.records[f"{PREFIX}/actions/runs/41016535359"].update(conclusion="failure"),
        ]:
            api = NativeCapture()
            mutate(api)
            with self.subTest(mutate=mutate), self.assertRaises(control.ControlError):
                context = api.prepare()
                with patch.object(control, "artifact_record", side_effect=api.artifact):
                    context.control(api.pull(450), BASELINE)
        api = NativeCapture()
        context = api.prepare()
        path = f"{PREFIX}/actions/runs?head_sha={api.pull(450)['head']['sha']}"
        borrowed = copy.deepcopy(api.records[f"{PREFIX}/actions/runs/41016535359"])
        borrowed.update(id=41016535360, status="queued", conclusion=None, pull_requests=[])
        api.records[path]["workflow_runs"].append(borrowed)
        api.records[path]["total_count"] += 1
        api.records[f"{PREFIX}/actions/runs/41016535360"] = borrowed
        api.records[f"{PREFIX}/actions/runs/41016535360/artifacts"] = {"total_count": 0, "artifacts": []}
        with patch.object(control, "artifact_record", side_effect=api.artifact), \
                self.assertRaises(control.ControlError):
            context.control(api.pull(450), BASELINE)

    def test_new_tail_uses_ordinary_ingress_and_a_missing_current_proof_still_blocks(self):
        # The historical prefix is real. Only this new tail is synthetic, to
        # establish that a future ordinary ingress never inherits its exemption.
        api = NativeCapture()
        api.new_tail, api.new_tree = "e" * 40, "d" * 40
        new = api.pull(450)
        new.update(number=999, merge_commit_sha=api.new_tail)
        new["base"]["sha"] = BASELINE
        new["head"]["sha"] = "f" * 40
        api.records[f"{PREFIX}/pulls/999"] = new
        api.records[f"{PREFIX}/commits/{api.new_tail}/pulls"] = [new]
        api.records[f"{PREFIX}/branches/develop"]["commit"]["sha"] = api.new_tail
        api.promotion["head"]["sha"] = api.new_tail
        api.value["git"]["first_parent_merges"].append(api.new_tail)
        api.value["git"]["commits"][api.new_tail] = {
            "tree": api.new_tree, "parents": [BASELINE, new["head"]["sha"]]}
        for result in [{"route": "copilot", "kind": "synthetic-tail-transport-only"},
                       control.ControlError("new-current-native-proof-missing")]:
            with isolated_git_environment(), \
                    patch.object(subject, "git", side_effect=api.integration_git), \
                    patch.object(transition, "git", side_effect=api.integration_git), \
                    patch.object(subject, "fetch_objects"), \
                    patch.object(control, "artifact_record", side_effect=api.artifact), \
                    patch.object(ancestry, "control_for_ingress") as ordinary:
                if isinstance(result, Exception):
                    ordinary.side_effect = result
                    with self.assertRaisesRegex(control.ControlError, "new-current-native-proof-missing"):
                        control.promotion_ingress(api, REPOSITORY, api.promotion, api.config)
                else:
                    ordinary.return_value = result
                    actual = control.promotion_ingress(api, REPOSITORY, api.promotion, api.config)
                    self.assertEqual(15, len(actual["ingress"]))
                    self.assertEqual(result, actual["ingress"][-1]["control"])
                    self.assertNotEqual(api.value["git"]["full_binary_diff_sha256"], actual["diff_sha256"])
                ordinary.assert_called_once()
                self.assertEqual(999, ordinary.call_args.args[3]["number"])

    def test_new_ingress_cannot_borrow_a_frozen_historical_disposition(self):
        api = NativeCapture()
        context = api.prepare()
        new = api.pull(450)
        new.update(number=999)
        new["head"]["sha"] = "f" * 40
        self.assertIsNone(context.control(new, "e" * 40))
        old = api.pull(450)
        old["head"]["sha"] = "f" * 40
        with self.assertRaises(control.ControlError):
            context.control(old, BASELINE)

    def test_public_consumer_needs_only_public_history_and_contains_no_private_source(self):
        api = NativeCapture()
        self.assertEqual({"ltn-it/.github", REPOSITORY}, {
            "/".join(path.split("/")[1:3]) for path in api.records if path.startswith("repos/")})
        self.assertTrue(all(key.startswith(("ltn-it/.github:", REPOSITORY + ":"))
                            for key in api.value["files"]))
        with isolated_git_environment(), \
                patch.object(subject, "git", side_effect=api.integration_git), \
                patch.object(transition, "git", side_effect=api.integration_git), \
                patch.object(subject, "fetch_objects"), \
                patch.object(control, "artifact_record", side_effect=api.artifact):
            result = control.promotion_ingress(api, REPOSITORY, api.promotion, api.config)
        self.assertEqual(14, len(result["ingress"]))
        self.assertFalse(any("repos/ltn-it/github-management-lit/" in p
                             or "repos/ltn-it/shared-assets-lit/" in p for p in api.calls))


if __name__ == "__main__":
    unittest.main()
