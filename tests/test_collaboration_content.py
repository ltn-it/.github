"""Exercise the actual offline admission and complete read-only observer."""
import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import collaboration_content as content
import collaboration_inventory as observation

NOW = datetime(2026, 10, 24, 20, 0, 0, tzinfo=timezone.utc)


def inventory():
    return {"version": 1, "organization": "ltn-it", "started_at": "2026-10-24T19:59:00Z",
            "finished_at": "2026-10-24T19:59:10Z", "complete": True,
            "repositories": [{"id": 1, "full_name": "ltn-it/.github", "visibility": "public", "archived": False},
                             {"id": 2, "full_name": "ltn-it/example", "visibility": "private", "archived": False}]}


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.policy = content.policy_from(ROOT / ".lit/collaboration-content-policy.json")
        self.inventory = inventory()

    def validate(self, title="Public change", body="Safe technical description.", kind="issue"):
        return content.validate({"kind": kind, "repository": "ltn-it/.github", "title": title, "body": body},
                                self.inventory, self.policy, now=NOW)

    def test_all_publication_surfaces_reject_the_same_private_body_and_title(self):
        for kind in ("issue", "pull_request", "review", "comment", "review_comment"):
            for field in ("title", "body"):
                with self.subTest(kind=kind, field=field):
                    result = self.validate(kind=kind, **{field: "See TEST-123"})
                    self.assertFalse(result["admitted"])
                    self.assertIn("private-identifier", result["categories"])
                    self.assertNotIn("TEST-123", json.dumps(result))

    def test_public_sources_pass_without_allowing_private_repository_links(self):
        self.assertTrue(self.validate(body="https://github.com/ltn-it/.github/issues/556")["admitted"])
        self.assertFalse(self.validate(body="https://github.com/ltn-it/example/issues/1")["admitted"])
        self.assertFalse(self.validate(body="https://github.com/unknown/example/issues/1")["admitted"])

    def test_external_exception_is_an_exact_public_url_not_a_domain_bypass(self):
        self.assertTrue(self.validate(body="https://docs.github.com/en/rest")["admitted"])
        for target in ("https://docs.github.com/en/rest?internal=value", "https://docs.github.com/en/other",
                       "https://docs.github.com.evil.test/en/rest", "https://user@docs.github.com/en/rest"):
            with self.subTest(target=target):
                self.assertFalse(self.validate(body=target)["admitted"])

    def test_private_systems_and_normalized_identifiers_fail_in_code_and_links(self):
        for value in ("```\nTEST-123\n```", "test-123", "ＴＥＳＴ－１２３", "TEST%2D123",
                      "TEST&#45;123", "https://example.atlassian.net/a", "example.atlassian.net",
                      "https://github.com/ltn-it/.github/issues/1?x=TEST-123", "host.internal"):
            with self.subTest(value=value):
                self.assertFalse(self.validate(body=value)["admitted"])

    def test_credentials_personal_data_and_protected_network_values_fail(self):
        for value in ("ghp_" + "a" * 36, "-----BEGIN RSA PRIVATE KEY-----", "token: abcdefghi",
                      "person@example.com", "10.1.2.3", "[fd00::1]", "fd00::1"):
            with self.subTest(value=value):
                self.assertFalse(self.validate(body=value)["admitted"])

    def test_normal_technical_terms_do_not_fail_private_identifier_check(self):
        for value in ("SHA-256", "UTF-8", "RFC-9110", "CWE-79", "CVE-2026-12345", "v1.2.3", "issue #556"):
            with self.subTest(value=value):
                self.assertTrue(self.validate(body=value)["admitted"])

    def test_hash_only_supplement_does_not_echo_protected_value(self):
        self.policy["protected_value_sha256"] = [content.sha256("host.example.test")]
        result = self.validate(body="host.example.test")
        self.assertEqual(["protected-value"], result["categories"])
        self.assertNotIn("host.example.test", json.dumps(result))

    def test_safe_receipt_changes_when_final_title_or_body_changes(self):
        first = self.validate()
        self.assertNotEqual(first["content_sha256"], self.validate(body="Another safe text")["content_sha256"])
        self.assertNotEqual(first["content_sha256"], self.validate(title="Another title")["content_sha256"])

    def test_missing_malformed_future_stale_or_partial_inventory_fails_closed(self):
        for mutate in (lambda v: v.update(complete=False), lambda v: v.update(repositories=[]),
                       lambda v: v.update(finished_at="2026-10-25T00:00:00Z"),
                       lambda v: v.update(started_at="2026-10-24T18:00:00Z"),
                       lambda v: v.update(finished_at="not-a-date"),
                       lambda v: v["repositories"][0].update(visibility=None),
                       lambda v: v["repositories"].append(copy.deepcopy(v["repositories"][0]))):
            with self.subTest(mutate=mutate):
                self.inventory = inventory()
                mutate(self.inventory)
                with self.assertRaises(content.AdmissionError):
                    self.validate()

    def test_malformed_content_and_hidden_characters_fail_without_echo(self):
        for value in (None, {}, ["text"], "x" * 262145, "TE\u200bST-123", "\ud800", "\x00"):
            with self.subTest(value=type(value).__name__), self.assertRaises(content.AdmissionError):
                self.validate(body=value)

    def test_private_source_cannot_be_whitelisted_by_policy(self):
        self.policy["approved_public_urls"].append("https://example.atlassian.net/")
        with self.assertRaisesRegex(content.AdmissionError, "policy-public-source"):
            self.validate()

    def test_unknown_payload_kind_or_fields_do_not_silently_skip_validation(self):
        with self.assertRaisesRegex(content.AdmissionError, "publication-kind"):
            self.validate(kind="unknown")
        value = {"kind": "issue", "repository": "ltn-it/.github", "title": "Safe", "body": "Safe", "comments": []}
        with self.assertRaisesRegex(content.AdmissionError, "publication-shape"):
            content.validate(value, self.inventory, self.policy, now=NOW)

    def test_versioned_positive_and_negative_fixtures(self):
        fixtures = json.loads((ROOT / "tests/fixtures/collaboration-content.json").read_text())
        self.assertEqual(1, fixtures["version"])
        for expected, name in ((True, "positive"), (False, "negative")):
            for value in fixtures[name]:
                with self.subTest(group=name, value=value):
                    self.assertEqual(expected, self.validate(body=value)["admitted"])

    def test_guarded_transport_sends_the_exact_validated_frozen_bytes_once(self):
        from unittest.mock import Mock
        send = Mock(return_value={"id": 10})
        payload = {"title": "Safe", "body": "Safe", "head": "feature", "base": "develop", "draft": True}
        result = content.guarded_payload("pull_request", "ltn-it/.github", payload, self.inventory, self.policy, send, now=NOW)
        self.assertEqual({"id": 10}, result)
        send.assert_called_once_with(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())

    def test_guarded_transport_rejects_nested_private_comment_before_any_effect(self):
        from unittest.mock import Mock
        send = Mock()
        payload = {"body": "Safe", "event": "COMMENT", "comments": [{"body": "TEST-123", "path": "file.py", "line": 1}]}
        with self.assertRaisesRegex(content.AdmissionError, "publication-content-rejected"):
            content.guarded_payload("review", "ltn-it/.github", payload, self.inventory, self.policy, send, now=NOW)
        send.assert_not_called()

    def test_guarded_transport_cannot_skip_inventory_for_empty_body(self):
        from unittest.mock import Mock
        send = Mock()
        self.inventory["complete"] = False
        with self.assertRaises(content.AdmissionError):
            content.guarded_payload("comment", "ltn-it/.github", {"body": None}, self.inventory, self.policy, send, now=NOW)
        send.assert_not_called()

    def test_history_observation_never_authorizes_redaction(self):
        target = {"node_id": "node_1", "revision_id": "revision_2", "deleted_at": None, "diff_available": True}
        self.assertEqual("exact-human-authorization-required", content.history_disposition(target))
        target.update(deleted_at="2026-10-24T19:59:00Z", diff_available=False)
        self.assertEqual("deleted-revision-observed", content.history_disposition(target))
        target["diff_available"] = True
        with self.assertRaisesRegex(content.AdmissionError, "history-inconsistent"):
            content.history_disposition(target)


class FakeAPI:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


class PaginationTests(unittest.TestCase):
    def test_short_page_still_requires_empty_terminal_page(self):
        api = FakeAPI({"items?per_page=100&page=1": [{"id": 1}],
                       "items?per_page=100&page=2": [{"id": 2}], "items?per_page=100&page=3": []})
        self.assertEqual([1, 2], [row["id"] for row in observation.pages(api, "items")])
        self.assertEqual(3, len(api.calls))

    def test_missing_page_and_transport_failure_never_return_partial_result(self):
        for bad in ({"items": []}, content.AdmissionError("read-unavailable"), [{"id": 1}]):
            api = FakeAPI({"items?per_page=100&page=1": [{"id": 1}], "items?per_page=100&page=2": bad})
            with self.subTest(bad=type(bad).__name__), self.assertRaises(content.AdmissionError):
                observation.pages(api, "items")

    def test_bound_exhaustion_does_not_claim_complete_pagination(self):
        api = FakeAPI({"items?per_page=100&page=1": [{"id": 1}]})
        with self.assertRaisesRegex(content.AdmissionError, "pagination-bound"):
            observation.pages(api, "items", maximum=1)

    def test_actual_api_client_cannot_mutate_or_echo_provider_errors(self):
        response = type("Response", (), {"returncode": 1, "stdout": b"private provider body", "stderr": b"secret"})()
        with patch.object(observation.subprocess, "run", return_value=response) as run:
            with self.assertRaisesRegex(content.AdmissionError, "read-unavailable") as error:
                observation.GitHubReadOnly().get("repos/ltn-it/.github")
            self.assertNotIn("private", str(error.exception))
            command = run.call_args.args[0]
            self.assertIn("GET", command)
            self.assertNotIn("POST", command)


class OrganizationInventoryTests(unittest.TestCase):
    def setUp(self):
        self.org = {"id": 1, "login": "ltn-it", "public_repos": 1, "owned_private_repos": 1}
        self.rows = [dict(row, owner={"login": "ltn-it"}, private=row["visibility"] != "public")
                     for row in inventory()["repositories"]]
        self.responses = {"orgs/ltn-it": self.org,
                          "orgs/ltn-it/memberships/litroc": {"state": "active", "role": "admin", "organization": {"login": "ltn-it"}},
                          "orgs/ltn-it/repos?type=all&per_page=100&page=1": self.rows,
                          "orgs/ltn-it/repos?type=all&per_page=100&page=2": []}

    def test_complete_inventory_includes_private_repositories_but_not_source_bodies(self):
        result = observation.organization_inventory(FakeAPI(self.responses))
        self.assertTrue(result["complete"])
        self.assertEqual(2, len(result["repositories"]))
        self.assertEqual({"id", "full_name", "visibility", "archived"}, set(result["repositories"][0]))

    def test_partial_inventory_cannot_match_authoritative_counts(self):
        self.rows.pop()
        with self.assertRaisesRegex(content.AdmissionError, "inventory-count"):
            observation.organization_inventory(FakeAPI(self.responses))

    def test_missing_visibility_and_selected_access_fail_closed(self):
        for field, value in (("visibility", None), ("private", True), ("archived", None)):
            with self.subTest(field=field):
                values = copy.deepcopy(self.responses)
                values["orgs/ltn-it/repos?type=all&per_page=100&page=1"][0][field] = value
                with self.assertRaises(content.AdmissionError):
                    observation.organization_inventory(FakeAPI(values))

    def test_missing_admin_inventory_visibility_blocks(self):
        self.responses["orgs/ltn-it/memberships/litroc"]["role"] = "member"
        with self.assertRaisesRegex(content.AdmissionError, "inventory-authority"):
            observation.organization_inventory(FakeAPI(self.responses))

    def test_changed_organization_inventory_generation_blocks(self):
        api = FakeAPI(self.responses)
        original = api.get
        calls = []

        def get(path):
            value = original(path)
            if path == "orgs/ltn-it":
                calls.append(path)
                if len(calls) > 1:
                    value["public_repos"] = 2
            return value

        api.get = get
        with self.assertRaisesRegex(content.AdmissionError, "inventory-generation"):
            observation.organization_inventory(api)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.policy = content.policy_from(ROOT / ".lit/collaboration-content-policy.json")
        self.inventory = inventory()
        self.item = {"id": 10, "number": 556, "state": "open", "title": "Safe", "body": "Safe", "comments": 1, "updated_at": "2026-10-24T19:59:00Z"}
        self.comment = {"id": 20, "body": "TEST-123", "updated_at": "2026-10-24T19:59:00Z"}
        self.responses = {
            "repos/ltn-it/.github": copy.deepcopy(self.inventory["repositories"][0]),
            "repos/ltn-it/.github/issues?state=open&sort=created&direction=asc&per_page=100&page=1": [self.item],
            "repos/ltn-it/.github/issues?state=open&sort=created&direction=asc&per_page=100&page=2": [],
            "repos/ltn-it/.github/issues/556": self.item,
            "repos/ltn-it/.github/issues/556/comments?per_page=100&page=1": [self.comment],
            "repos/ltn-it/.github/issues/556/comments?per_page=100&page=2": []}

    def observe(self, api=None):
        with patch.object(content, "datetime") as clock:
            clock.now.return_value = NOW
            clock.strptime.side_effect = datetime.strptime
            return observation.observe_open_issues(api or FakeAPI(self.responses), self.inventory, self.policy, ["ltn-it/.github"])

    def test_current_comments_report_only_safe_locator_categories_and_hash(self):
        report = self.observe()
        self.assertFalse(report["clean"])
        self.assertEqual({"issues": 1, "comments": 1}, report["counts"])
        self.assertEqual("owner-remediation-required", report["objects"][1]["disposition"])
        wire = json.dumps(report)
        self.assertNotIn("TEST-123", wire)
        self.assertNotIn("body", report["objects"][1])
        self.assertIn("edit-history", report["excluded"])

    def test_comments_count_mismatch_is_incomplete_not_clean(self):
        self.item["comments"] = 2
        with self.assertRaisesRegex(content.AdmissionError, "comment-count"):
            self.observe()

    def test_unreadable_visibility_is_not_treated_as_private_or_clean(self):
        self.responses["repos/ltn-it/.github"]["visibility"] = None
        with self.assertRaisesRegex(content.AdmissionError, "scope-visibility-drift"):
            self.observe()

    def test_edits_during_observation_fail_instead_of_reusing_old_content(self):
        api = FakeAPI(self.responses)
        original = api.get
        reads = []

        def get(path):
            result = original(path)
            if path == "repos/ltn-it/.github/issues/556":
                reads.append(path)
                if len(reads) > 1:
                    result["body"] = "TEST-123"
            return result

        api.get = get
        with self.assertRaisesRegex(content.AdmissionError, "issue-observation-drift"):
            self.observe(api)

    def test_comment_edit_without_issue_timestamp_change_is_detected(self):
        api = FakeAPI(self.responses)
        original = api.get
        calls = []

        def get(path):
            value = original(path)
            if path.endswith("/comments?per_page=100&page=1"):
                calls.append(path)
                if len(calls) > 1:
                    value[0]["body"] = "Edited without parent timestamp change"
            return value

        api.get = get
        with self.assertRaisesRegex(content.AdmissionError, "comment-observation-drift"):
            self.observe(api)

    def test_receipt_is_private_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            observation.private_write(path, {"clean": True})
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                observation.private_write(path, {"clean": False})

    def test_public_report_directory_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(content.AdmissionError, "private-report-directory"):
                observation.private_write(Path(directory) / "report.json", {})


class PullObservationTests(unittest.TestCase):
    def setUp(self):
        self.policy = content.policy_from(ROOT / ".lit/collaboration-content-policy.json")
        self.inventory = inventory()
        self.pull = {"id": 30, "number": 3, "state": "open", "title": "Public change", "body": "Safe",
                     "comments": 1, "review_comments": 1, "updated_at": "2026-10-24T19:59:00Z"}
        self.comment = {"id": 40, "body": "Safe conversation", "updated_at": "2026-10-24T19:59:00Z"}
        self.review = {"id": 50, "body": "TEST-123", "state": "DISMISSED", "commit_id": "a" * 40}
        self.inline = {"id": 60, "body": "Safe inline", "pull_request_review_id": 50,
                       "updated_at": "2026-10-24T19:59:00Z"}
        root = "repos/ltn-it/.github"
        self.responses = {root: copy.deepcopy(self.inventory["repositories"][0]),
                          f"{root}/pulls/3": self.pull}
        for path, rows in (
            (f"{root}/issues?state=open&sort=created&direction=asc", [dict(self.pull, pull_request={})]),
            (f"{root}/pulls?state=open&sort=created&direction=asc", [self.pull]),
            (f"{root}/issues/3/comments", [self.comment]),
            (f"{root}/pulls/3/reviews", [self.review]),
            (f"{root}/pulls/3/comments", [self.inline]),
        ):
            separator = "&" if "?" in path else "?"
            self.responses[f"{path}{separator}per_page=100&page=1"] = rows
            self.responses[f"{path}{separator}per_page=100&page=2"] = []

    def observe(self, api=None):
        with patch.object(content, "datetime") as clock:
            clock.now.return_value = NOW
            clock.strptime.side_effect = datetime.strptime
            return observation.observe_open_collaboration(api or FakeAPI(self.responses), self.inventory,
                                                          self.policy, ["ltn-it/.github"])

    def test_all_public_pull_surfaces_include_dismissed_reviews_without_raw_values(self):
        report = self.observe()
        self.assertFalse(report["clean"])
        self.assertEqual({"issues": 0, "comments": 0, "pull_requests": 1, "pull_comments": 1,
                          "reviews": 1, "inline_comments": 1}, report["counts"])
        self.assertEqual({"pull_request", "comment", "review", "review_comment"},
                         {row["kind"] for row in report["objects"]})
        self.assertNotIn("TEST-123", json.dumps(report))
        self.assertNotIn("reviews", report["excluded"])
        self.assertIn("closed-pull-requests", report["excluded"])

    def test_pending_review_draft_and_its_inline_comment_are_not_public_content(self):
        self.review["state"] = "PENDING"
        self.inline["body"] = "TEST-456"
        report = self.observe()
        self.assertTrue(report["clean"])
        self.assertEqual(1, report["pending_review_drafts_excluded"])
        self.assertEqual(0, report["counts"]["reviews"])
        self.assertEqual(0, report["counts"]["inline_comments"])

    def test_review_page_failure_never_returns_partial_clean_result(self):
        self.responses["repos/ltn-it/.github/pulls/3/reviews?per_page=100&page=2"] = content.AdmissionError("read-unavailable")
        with self.assertRaisesRegex(content.AdmissionError, "read-unavailable"):
            self.observe()

    def test_orphan_inline_comment_and_unknown_review_state_fail_closed(self):
        self.inline["pull_request_review_id"] = 999
        with self.assertRaisesRegex(content.AdmissionError, "inline-review-binding"):
            self.observe()
        self.inline["pull_request_review_id"] = 50
        self.review["state"] = "UNKNOWN"
        with self.assertRaisesRegex(content.AdmissionError, "review-state"):
            self.observe()

    def test_review_edit_during_observation_is_incomplete(self):
        api = FakeAPI(self.responses)
        original = api.get
        reads = []

        def get(path):
            value = original(path)
            if path == "repos/ltn-it/.github/pulls/3/reviews?per_page=100&page=1":
                reads.append(path)
                if len(reads) > 1:
                    value[0]["body"] = "Edited review"
            return value

        api.get = get
        with self.assertRaisesRegex(content.AdmissionError, "pull-content-drift"):
            self.observe(api)

    def test_pull_close_and_visibility_change_during_observation_block(self):
        for target in ("pull", "visibility"):
            with self.subTest(target=target):
                api = FakeAPI(self.responses)
                original = api.get
                reads = []
                path = "repos/ltn-it/.github/pulls/3" if target == "pull" else "repos/ltn-it/.github"

                def get(request):
                    value = original(request)
                    if request == path:
                        reads.append(request)
                        if len(reads) > (1 if target == "pull" else 2):
                            value["state" if target == "pull" else "visibility"] = "closed" if target == "pull" else "private"
                    return value

                api.get = get
                with self.assertRaises(content.AdmissionError):
                    self.observe(api)


if __name__ == "__main__":
    unittest.main()
