"""Exercise the actual offline admission and complete read-only observer."""
import copy
import io
import ipaddress
import json
import re
import signal
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
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


def parsed_sensitive_cases():
    # Generated token-shaped values are synthetic; diagnostics use case hashes.
    return ((r"TEST\-123", "private-identifier"),
            (r"ghp\_" + "A" * 22, "credential"),
            (r"github\_pat\_" + "A" * 22, "credential"),
            (r"password\: fixture", "secret-like"),
            (r"person\@example.com", "personal-data"),
            (r"node\.internal", "private-system"),
            (r"10\.1\.2\.3", "protected-infrastructure"),
            (r"fixture\_resource", "protected-value"),
            ("TE**ST**-123", "private-identifier"),
            (r"**ghp**\_" + "A" * 22, "credential"),
            (r"**fixture**\_resource", "protected-value"),
            (r"https\://github.com/ltn-it/example/issues/1", "unverified-public-source"))


def decoded_title_cases():
    for value, category in ((r"TEST\-123", "private-identifier"),
                            (r"ghp\_" + "A" * 22, "credential"),
                            (r"fixture\_resource", "protected-value")):
        for body in (f'[public](https://docs.github.com/en/rest "{value}")',
                     f'![public](https://docs.github.com/en/rest "{value}")',
                     f'[public][ref]\n\n[ref]: https://docs.github.com/en/rest "{value}"'):
            yield body, category


def html_text_cases():
    return (("<div>TE<strong>ST</strong>-123</div>", "private-identifier"),
            ("<div>TE<!-- split -->ST<!-- split -->-123</div>", "private-identifier"),
            ("<div>ghp<span>_</span>" + "A" * 22 + "</div>", "credential"),
            ("<div>ghp<source>_" + "A" * 22 + "</div>", "credential"),
            ("<div>person<em>@</em>example.com</div>", "personal-data"),
            ("<div>node<span>.</span>internal</div>", "private-system"),
            ("<div>10<span>.</span>1.2.3</div>", "protected-infrastructure"),
            ("<div>fixture<span>_</span>resource</div>", "protected-value"),
            ("<div>ltn-it/<strong>example</strong>#1</div>", "unverified-public-source"))


def strikethrough_cases():
    return (("TE~~ST~~-123", "private-identifier"),
            ("~~TEST-123~~", "private-identifier"),
            ("TE~~S**T**~~-123", "private-identifier"),
            ("**TE~~ST~~-123**", "private-identifier"),
            ("TE~ST~-123", "private-identifier"),
            ("g~~hp~~_" + "A" * 22, "credential"),
            ("g~hp~_" + "A" * 22, "credential"),
            ("github_~~pat~~_" + "A" * 22, "credential"),
            ("pass~~word~~: fixture", "secret-like"),
            ("per~~son~~@example.com", "personal-data"),
            ("no~~de~~.internal", "private-system"),
            ("1~~0.1~~.2.3", "protected-infrastructure"),
            ("fix~~ture~~_resource", "protected-value"),
            ("ltn-it/~~example~~#1", "unverified-public-source"),
            ("`TE~~ST~~-123`", "private-identifier"),
            ("```text\nTE~~ST~~-123\n```", "private-identifier"))


def html_boundary_cases():
    return ("TEST<br>-123", "TEST<br/>-123", "TEST<br />-123", "TEST<BR>-123",
            "<span>TEST</span><br><span>-123</span>", "**TEST**<br>**-123**",
            "~~TEST~~<br>~~-123~~", "ghp<br>_" + "A" * 22,
            "`ghp`<br>_" + "A" * 22, "TEST<hr>-123", "TEST<div>-123</div>",
            "<div>TEST<br>-123</div>", "<div>TEST</div><div>-123</div>")


def literal_strikethrough_cases():
    # Delimiter flanking and escaped/long runs retain literal tildes in GFM.
    return (r"TE\~\~ST\~\~-123", r"TE\~ST\~-123", "TE~~~ST~~~-123",
            "TE~~**ST**~~-123", "github~~_pat~~_" + "A" * 22,
            "person~~@~~example.com", "node~~.~~internal", "10~~.~~1.2.3",
            "fixture~~_~~resource")


@contextmanager
def scanner_deadline():
    # A generous hang guard, not a timing-based throughput requirement.
    def expired(signum, frame):
        raise TimeoutError("bounded-content-scan-exceeded")
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 5)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def maximum_scanner_cases(limit):
    for label, unit in (("dot-free", "z"), ("dotted-hostlike", "a."), ("colon-free-hex", "f")):
        yield label, (unit * (limit // len(unit) + 1))[:limit], None
    for suffix, category in ((" node.internal", "private-system"),
                             (" person@example.com", "personal-data"),
                             (" [fd00::1]", "protected-infrastructure")):
        yield category, "f" * (limit - len(suffix)) + suffix, category


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.policy = content.policy_from(ROOT / ".lit/collaboration-content-policy.json")
        self.inventory = inventory()

    def validate(self, title="Public change", body="Safe technical description.", kind="issue"):
        return content.validate({"kind": kind, "repository": "ltn-it/.github", "title": title, "body": body},
                                self.inventory, self.policy, now=NOW)

    def assert_destination_blocked_before_send(self, body):
        self.assertFalse(self.validate(body=body)["admitted"])
        sends = []
        with self.assertRaises(content.AdmissionError):
            content.guarded_payload("comment", "ltn-it/.github", {"body": body},
                self.inventory, self.policy, sends.append, now=NOW)
        self.assertEqual([], sends)

    def test_maximum_wire_content_scans_without_stalling_or_changing_final_bytes(self):
        overhead = len(json.dumps({"body": ""}, separators=(",", ":")).encode())
        for label, body, category in maximum_scanner_cases(self.policy["max_text_bytes"] - overhead):
            sends = []
            with self.subTest(case=label), scanner_deadline():
                if category is None:
                    content.guarded_payload("comment", "ltn-it/.github", {"body": body},
                        self.inventory, self.policy, sends.append, now=NOW)
                    self.assertEqual(1, len(sends))
                    self.assertEqual(self.policy["max_text_bytes"], len(sends[0]))
                    self.assertEqual(content.sha256(body), content.sha256(json.loads(sends[0])["body"]))
                else:
                    self.assertIn(category, self.validate(body=body)["categories"])
                    with self.assertRaises(content.AdmissionError):
                        content.guarded_payload("comment", "ltn-it/.github", {"body": body},
                            self.inventory, self.policy, sends.append, now=NOW)
                    self.assertEqual([], sends)

    def test_raw_scanner_handles_full_size_runs_without_overlapping_suffix_searches(self):
        for label, body, category in maximum_scanner_cases(self.policy["max_text_bytes"]):
            with self.subTest(case=label), scanner_deadline():
                categories = content._sensitive_value_categories(body, self.policy)
                if category is None:
                    self.assertEqual(set(), categories)
                else:
                    self.assertIn(category, categories)

    def test_candidate_search_work_is_bounded_and_scales_with_input_bytes(self):
        extractor = getattr(content, "_lexical_runs", None)
        if extractor is None:
            self.skipTest("predecessor-has-no-candidate-work-instrumentation")
        repositories = {row["full_name"]: row for row in self.inventory["repositories"]}
        for unit in ("z", "a.", "f"):
            measured = []
            for size in (4096, 8192, self.policy["max_text_bytes"]):
                # Explicit paragraph termination keeps the parser's generated
                # separators within the same existing byte limit.
                body = (unit * (size // len(unit) + 1))[:size - 8] + "\n" * 8
                work = {"subjects": 0, "spans": 0}
                def record(pattern, value, flags=0):
                    work["subjects"] += len(value)
                    end = 0
                    for candidate in extractor(pattern, value, flags):
                        self.assertGreaterEqual(candidate.start(), end)
                        work["spans"] += candidate.end() - candidate.start()
                        end = candidate.end()
                        yield candidate
                with self.subTest(unit=unit, size=size), patch.object(content, "_lexical_runs", record), scanner_deadline():
                    self.assertEqual([], content.scan_text(body, self.policy, repositories))
                self.assertLessEqual(work["spans"], work["subjects"])
                self.assertLessEqual(work["subjects"], 32 * size + 1024)
                measured.append(work["subjects"])
            self.assertLessEqual(measured[1], 2 * measured[0] + 1024)

    def test_lexical_classification_preserves_existing_boundaries_and_addresses(self):
        host = r"(?i)(?:[a-z0-9-]+\.)*atlassian\.net\b|\b[a-z0-9.-]+\.(?:internal|local|corp|lan)\b"
        email = r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
        address = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|\[?[0-9a-fA-F]*:[0-9a-fA-F:]+\]?"
        values = ("team.atlassian.net", "xatlassian.net", "atlassian.net_", "host.local", ".local",
                  "host.local123", "a-b.corp", "host.İnternal", "example.org", "person@example.com",
                  "person@.com", "person@..com", "person@example.com_", "a@b.c@d.net",
                  "10.1.2.3", "[10.1.2.3]", "fd00::1", "[fd00::1]", "::1", ":::1",
                  "8.8.8.8", "2001:4860:4860::8888", "::ffff:192.0.2.1", "::ffff:8.8.8.8")
        for value in values:
            for before in ("", " ", "_", "é", "a.", "a-"):
                for after in ("", " ", "_", "é", ".", "-x"):
                    text = before + value + after
                    expected_address = False
                    for found in re.findall(address, text):
                        try:
                            expected_address |= not ipaddress.ip_address(found.strip("[]")).is_global
                        except ValueError:
                            pass
                    with self.subTest(case=content.sha256(text)):
                        categories = content._sensitive_value_categories(text, self.policy)
                        self.assertEqual(bool(re.search(host, text)), "private-system" in categories)
                        self.assertEqual(bool(re.search(email, text)), "personal-data" in categories)
                        self.assertEqual(expected_address, "protected-infrastructure" in categories)

    def test_prose_candidate_boundaries_preserve_existing_exact_destinations(self):
        extractor = getattr(content, "_prose_destinations", None)
        if extractor is None:
            self.skipTest("predecessor-has-no-separated-prose-candidates")
        pattern = r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>\"'`]+"
        for value in ("www.", "https://", "https://?", "www..", "www.example.com", "WWW.example.com?x=1",
                      "https://docs.github.com/en/rest", "prefix:https://docs.github.com/en/rest",
                      "123abc.def://path", "www.example.com/https://second.example",
                      "https://example.org/next www.example.org", "a.a.a.a", "x" * 128):
            for before in ("", "_", "é", ".", "(", " "):
                for after in ("", ".", ")", ">", " "):
                    text = before + value + after
                    expected = {m.group().rstrip(".,;:!?)]}") for m in re.finditer(pattern, text)}
                    with self.subTest(case=content.sha256(text)):
                        self.assertEqual(expected, set(extractor(text)))

    def test_parsed_sensitive_text_blocks_publication_before_send(self):
        self.policy["protected_value_sha256"].append(content.sha256("fixture_resource"))
        for body, category in parsed_sensitive_cases():
            with self.subTest(case=content.sha256(body), category=category):
                result = self.validate(body=body)
                self.assertFalse(result["admitted"])
                self.assertIn(category, result["categories"])
                self.assertNotIn(body, json.dumps(result))
                self.assert_destination_blocked_before_send(body)

    def test_parsed_text_preserves_public_exceptions_and_block_boundaries(self):
        self.policy["approved_public_identifiers"].append("TEST-123")
        for body in (r"Approved **TEST\-123**", r"**CVE\-2026\-1234**", r"**RFC\-9110**",
                     r"**https**\://docs.github.com/en/rest",
                     "TEST\n\n-123", "ghp\n\n_" + "A" * 22):
            with self.subTest(case=content.sha256(body)):
                sends = []
                content.guarded_payload("comment", "ltn-it/.github", {"body": body},
                    self.inventory, self.policy, sends.append, now=NOW)
                self.assertEqual(1, len(sends))
                self.assertEqual(body, json.loads(sends[0])["body"])

    def test_formatted_native_reference_keeps_strict_destination_policy(self):
        self.assert_destination_blocked_before_send("ltn-it/**example**#1")
        self.assertTrue(self.validate(body="ltn-it/**.github**#556")["admitted"])

    def test_strikethrough_values_cannot_bypass_publication_admission(self):
        self.policy["protected_value_sha256"].append(content.sha256("fixture_resource"))
        for body, category in strikethrough_cases():
            with self.subTest(case=content.sha256(body), category=category):
                result = self.validate(body=body)
                self.assertIn(category, result["categories"])
                self.assertNotIn(body, json.dumps(result))
                self.assert_destination_blocked_before_send(body)

    def test_inline_and_block_html_boundaries_preserve_safe_publication(self):
        for body in html_boundary_cases():
            with self.subTest(case=content.sha256(body)):
                sends = []
                content.guarded_payload("comment", "ltn-it/.github", {"body": body},
                    self.inventory, self.policy, sends.append, now=NOW)
                self.assertEqual([body], [json.loads(wire)["body"] for wire in sends])

    def test_strikethrough_preserves_literal_markers_and_public_exceptions(self):
        for body in (*literal_strikethrough_cases(), "~~RFC-9110~~", "~~CVE-2026-1234~~",
                     "ltn-it/~~.github~~#556"):
            with self.subTest(case=content.sha256(body)):
                self.assertTrue(self.validate(body=body)["admitted"])
        self.policy["approved_public_identifiers"].append("TEST-123")
        self.assertTrue(self.validate(body="TE~~ST~~-123")["admitted"])

    def test_missing_strikethrough_rule_fails_before_publication(self):
        sends = []
        for method in ("enable", "parse"):
            with (self.subTest(parser_method=method),
                  patch.object(content.MarkdownIt, method, side_effect=KeyError("private parser details")),
                  self.assertRaisesRegex(content.AdmissionError, "^content-parser-unavailable$")):
                content.guarded_payload("comment", "ltn-it/.github", {"body": "Public text"},
                    self.inventory, self.policy, sends.append, now=NOW)
            self.assertEqual([], sends)

    def test_decoded_titles_and_html_text_block_publication_before_send(self):
        self.policy["protected_value_sha256"].append(content.sha256("fixture_resource"))
        for body, category in (*decoded_title_cases(), *html_text_cases()):
            with self.subTest(case=content.sha256(body), category=category):
                self.assertIn(category, self.validate(body=body)["categories"])
                self.assert_destination_blocked_before_send(body)

    def test_titles_html_blocks_and_explicit_public_exceptions_remain_supported(self):
        self.policy["approved_public_identifiers"].append("TEST-123")
        bodies = (
            r'[public](https://docs.github.com/en/rest "TEST\-123")',
            r'![public](https://docs.github.com/en/rest "RFC\-9110")',
            '[public][ref]\n\n[ref]: https://docs.github.com/en/rest "CVE\\-2026\\-1234"',
            '<div><strong>TEST</strong>-123</div>',
            '<div><strong>CVE</strong>-2026-1234</div>',
            '<div>TEST</div><div>-123</div>',
            '<div>ghp</div><div>_' + 'A' * 22 + '</div>',
            '<div>ghp<br>_' + 'A' * 22 + '</div>',
            '<a href="https://docs.github.com/en/rest" title="Public">Source</a>',
        )
        for body in bodies:
            with self.subTest(case=content.sha256(body)):
                self.assertTrue(self.validate(body=body)["admitted"])

    def test_metadata_surfaces_remain_separate_and_reference_titles_can_repeat(self):
        title = "_" + "A" * 22
        bodies = (
            f'[ghp](https://docs.github.com/en/rest "{title}")',
            f'<span title="ghp">{title}</span>',
            '[public][ref] ' * 80 + '\n\n[ref]: https://docs.github.com/en/rest "Public context"',
        )
        for body in bodies:
            with self.subTest(case=content.sha256(body)):
                self.assertTrue(self.validate(body=body)["admitted"])

    def test_html_parser_failure_cannot_send_or_echo_parser_details(self):
        sends = []
        with (patch.object(content.HTMLDestinations, "feed", side_effect=AssertionError("private")),
              self.assertRaisesRegex(content.AdmissionError, "^content-parser-unavailable$")):
            content.guarded_payload("comment", "ltn-it/.github", {"body": "<div>Public</div>"},
                self.inventory, self.policy, sends.append, now=NOW)
        self.assertEqual([], sends)

    def test_quoted_html_whitespace_cannot_split_exact_url_policy(self):
        for whitespace in ("\n", "\r", "\t", " ", "&#10;", "%09"):
            for attribute in ("href", "src"):
                with self.subTest(whitespace=repr(whitespace), attribute=attribute):
                    self.assert_destination_blocked_before_send(
                        f'<a {attribute}="https://docs.github.com/en/rest{whitespace}?extra=value">x</a>')

    def test_raw_html_attribute_boundaries_survive_global_entity_decoding(self):
        # HTML resolves an entity inside an unquoted attribute without turning
        # that decoded whitespace into a new attribute delimiter. Global text
        # decoding before extraction would lose this original destination.
        for encoded in ("&#10;", "&#x09;", "&NewLine;", "&Tab;"):
            for attribute in ("href", "src"):
                with self.subTest(encoded=encoded, attribute=attribute):
                    self.assert_destination_blocked_before_send(
                        f'<a {attribute}=https://docs.github.com/en/rest{encoded}?extra=value>x</a>')

    def test_bare_www_autolinks_do_not_bypass_visibility_or_exact_url_policy(self):
        for body in ("www.github.com/ltn-it/example/issues/1", "WWW.github.com/ltn-it/example/issues/1",
                     "www.docs.github.com/en/rest?extra=value", "[source](www.github.com/ltn-it/example)"):
            with self.subTest(case=content.sha256(body)):
                self.assert_destination_blocked_before_send(body)

    def test_backslash_traversal_and_browser_normalization_fail_before_url_policy(self):
        for link in (r"https://github.com/ltn-it/.github/blob/main/..\..\..\example/issues/1",
                     "https://github.com/ltn-it/.github/blob/main/..%5c..%5cexample/issues/1",
                     "https://github.com/ltn-it/.github/blob/main/../other",
                     "https://github.com/ltn-it/.github/blob/main/..//other"):
            for body in (link, f'[source]({link})', f'<a href="{link}">source</a>'):
                with self.subTest(case=content.sha256(body)):
                    self.assert_destination_blocked_before_send(body)

    def test_all_link_forms_share_exact_destination_policy_and_preserve_public_controls(self):
        wrappers = (lambda url: url, lambda url: f'[source]({url})',
                    lambda url: f'[source](<{url}>)', lambda url: f'[source][ref]\n[ref]: {url}',
                    lambda url: f'<a href="{url}">source</a>', lambda url: f"<img src='{url}'/>")
        for target, admitted in (("https://docs.github.com/en/rest", True),
                ("https://github.com/ltn-it/.github/issues/1", True),
                ("https://github.com/ltn-it/example/issues/1", False),
                ("https://github.com/ltn-it/.github/settings", False),
                ("https://docs.github.com/en/rest?extra=value", False),
                ("https://user@docs.github.com/en/rest", False),
                ("https://docs.github.com:443/en/rest", False)):
            for wrap in wrappers:
                body = wrap(target)
                with self.subTest(case=content.sha256(body)):
                    self.assertEqual(admitted, self.validate(body=body)["admitted"])
        for body in ('<a href="#overview">section</a>', '[section](#overview)',
                     'The relative file path src/a.py is ordinary text.'):
            self.assertTrue(self.validate(body=body)["admitted"])
        for target in ("https://docs.github.com/en/rest\n", "https://docs.github.com/en/rest\\",
                       "https://docs.github.com/en/é"):
            policy = copy.deepcopy(self.policy)
            policy["approved_public_urls"].append(target)
            with self.assertRaisesRegex(content.AdmissionError, "policy-public-source"):
                content.validate_policy(policy)

    def test_multiline_and_container_reference_destinations_cannot_bypass_visibility(self):
        for body in ("[source][ref]\n\n[ref]:\n  //github.com/ltn-it/example/issues/1",
                     "> [source][ref]\n>\n> [ref]: /ltn-it/example/issues/1",
                     "- [source][ref]\n\n  [ref]:\n    //github.com/ltn-it/example/issues/1",
                     "[source][ref]\n\n[ref]: /ltn-it/example/issues/1",
                     "```markdown\n[source][ref]\n\n[ref]:\n  /ltn-it/example/issues/1\n```",
                     "[source](javascript:alert(1))"):
            with self.subTest(case=content.sha256(body)):
                self.assert_destination_blocked_before_send(body)

    def test_native_repository_issue_and_commit_references_use_inventory_policy(self):
        for body in ("ltn-it/example#1", "ltn-it/example@" + "a" * 40,
                     "unknown/example#1", "`ltn-it/example#1`", "ltn-it&#47;example&#35;1",
                     "ltn-it/.github@" + "a" * 7):
            with self.subTest(case=content.sha256(body)):
                self.assert_destination_blocked_before_send(body)
        for body in ("ltn-it/.github#556", "ltn-it/.github@" + "b" * 40,
                     "[source][ref]\n\n[ref]:\n  https://docs.github.com/en/rest",
                     "> [source][ref]\n>\n> [ref]: https://github.com/ltn-it/.github/issues/1"):
            with self.subTest(case=content.sha256(body)):
                self.assertTrue(self.validate(body=body)["admitted"])

    def test_unavailable_or_unqualified_parser_never_falls_back_to_partial_scanning(self):
        for name, value in (("MarkdownIt", None), ("MARKDOWN_VERSION", "0.0.0")):
            with self.subTest(name=name), patch.object(content, name, value):
                with self.assertRaisesRegex(content.AdmissionError, "content-parser-unavailable"):
                    self.validate(body="Public ordinary text")
                sends = []
                with self.assertRaises(content.AdmissionError):
                    content.guarded_payload("comment", "ltn-it/.github", {"body": "Safe"},
                        self.inventory, self.policy, sends.append, now=NOW)
                self.assertEqual([], sends)
        with patch.object(content, "MarkdownIt", side_effect=RuntimeError("private")):
            with self.assertRaisesRegex(content.AdmissionError, "content-parser-unavailable"):
                self.validate()

    def test_markdown_nesting_limit_is_unknown_without_partial_clean_or_send(self):
        body = "> " * 25 + "[source][ref]\n\n" + "> " * 25 + "[ref]: /ltn-it/example/issues/1"
        sends = []
        with self.assertRaisesRegex(content.AdmissionError, "content-markdown-bound"):
            self.validate(body=body)
        with self.assertRaises(content.AdmissionError):
            content.guarded_payload("comment", "ltn-it/.github", {"body": body},
                self.inventory, self.policy, sends.append, now=NOW)
        self.assertEqual([], sends)

    def test_decode_then_compatibility_normalization_blocks_sender_and_observer(self):
        for index, value in enumerate(("TEST&#xFF0D;123", "TEST%EF%BC%8D123", "TEST&amp;#xFF0D;123",
                                       "&#xFF34;&#xFF25;&#xFF33;&#xFF34;&#xFF0D;123")):
            with self.subTest(case=index):
                self.assertIn("private-identifier", self.validate(body=value)["categories"])
                sends = []
                with self.assertRaises(content.AdmissionError):
                    content.guarded_payload("comment", "ltn-it/.github", {"body": value},
                        self.inventory, self.policy, sends.append, now=NOW)
                self.assertEqual([], sends)

    def test_stateless_installation_token_is_rejected_on_every_content_surface(self):
        value = "ghs_123456_" + "eyJhbGciOiJSUzI1NiJ9." + "a" * 600 + ".offline-signature_with-dashes"
        for kind in ("issue", "pull_request", "comment", "review", "review_comment"):
            for field in ("title", "body"):
                with self.subTest(kind=kind, field=field):
                    result = self.validate(kind=kind, **{field: value})
                    self.assertIn("credential", result["categories"])
                    self.assertNotIn(value, json.dumps(result))
        sends = []
        with self.assertRaises(content.AdmissionError):
            content.guarded_payload("review", "ltn-it/.github", {"body": "Public result",
                "comments": [{"body": value, "path": "src/a.py", "line": 1, "side": "RIGHT"}]},
                self.inventory, self.policy, sends.append, now=NOW)
        self.assertEqual([], sends)

    def test_relative_markdown_destinations_cannot_bypass_inventory_visibility(self):
        for index, value in enumerate(("[source](//github.com/ltn-it/example/issues/1)",
                "[source](/ltn-it/example/issues/1)", "[outer [inner]](/ltn-it/example/issues/1)",
                "[source](<//github.com/ltn-it/example/issues/1>)", "![image](/ltn-it/example/blob/main/a.png)",
                "[source][ref]\n\n[ref]: /ltn-it/example/issues/1", '[source](https://github.com/ltn-it/.github/issues/1) <a href="/ltn-it/example">x</a>',
                "[source](&#xFF0F;&#xFF0F;github.com/ltn-it/example/issues/1)", "[source](../example)",
                "[source](javascript:alert(1))")):
            with self.subTest(case=index):
                self.assertFalse(self.validate(body=value)["admitted"])
                sends = []
                with self.assertRaises(content.AdmissionError):
                    content.guarded_payload("comment", "ltn-it/.github", {"body": value},
                        self.inventory, self.policy, sends.append, now=NOW)
                self.assertEqual([], sends)
        for value in ("[source](https://github.com/ltn-it/.github/issues/1)",
                      "[source][ref]\n[ref]: https://docs.github.com/en/rest", "[section](#overview)",
                      "The relative file path src/a.py is ordinary text."):
            self.assertTrue(self.validate(body=value)["admitted"])

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

    def test_maximum_comment_scans_stay_bounded_and_keep_existing_detection(self):
        for label, body, category in maximum_scanner_cases(self.policy["max_text_bytes"] - 8):
            self.comment["body"] = body + "\n" * 8
            with self.subTest(case=label), scanner_deadline():
                self.assertEqual(self.policy["max_text_bytes"], len(self.comment["body"].encode()))
                report = self.observe()
                self.assertEqual(category is None, report["clean"])
                if category is not None:
                    self.assertIn(category, report["objects"][1]["categories"])
                self.assertNotIn(body, json.dumps(report))

    def test_observer_detects_parsed_sensitive_values_without_echoing_text(self):
        self.policy["protected_value_sha256"].append(content.sha256("fixture_resource"))
        for body, category in parsed_sensitive_cases():
            with self.subTest(case=content.sha256(body), category=category):
                self.comment["body"] = body
                report = self.observe()
                self.assertFalse(report["clean"])
                self.assertIn(category, report["objects"][1]["categories"])
                self.assertEqual("owner-remediation-required", report["objects"][1]["disposition"])
                self.assertNotIn(body, json.dumps(report))

    def test_observer_preserves_formatted_public_identifier_exception(self):
        self.policy["approved_public_identifiers"].append("TEST-123")
        self.comment["body"] = r"Approved **TEST\-123** with **RFC\-9110**"
        self.assertTrue(self.observe()["clean"])

    def test_observer_detects_strikethrough_values_without_raw_text(self):
        self.policy["protected_value_sha256"].append(content.sha256("fixture_resource"))
        for body, category in strikethrough_cases():
            with self.subTest(case=content.sha256(body), category=category):
                self.comment["body"] = body
                report = self.observe()
                self.assertFalse(report["clean"])
                self.assertIn(category, report["objects"][1]["categories"])
                self.assertNotIn(body, json.dumps(report))

    def test_observer_preserves_inline_and_block_html_boundaries(self):
        for body in html_boundary_cases():
            with self.subTest(case=content.sha256(body)):
                self.comment["body"] = body
                self.assertTrue(self.observe()["clean"])

    def test_observer_preserves_literal_markers_and_public_strikethrough(self):
        for body in (*literal_strikethrough_cases(), "~~RFC-9110~~", "~~CVE-2026-1234~~",
                     "ltn-it/~~.github~~#556"):
            with self.subTest(case=content.sha256(body)):
                self.comment["body"] = body
                self.assertTrue(self.observe()["clean"])
        self.policy["approved_public_identifiers"].append("TEST-123")
        self.comment["body"] = "TE~~ST~~-123"
        self.assertTrue(self.observe()["clean"])

    def test_observer_cannot_report_clean_when_strikethrough_rule_is_missing(self):
        self.comment["body"] = "Public text"
        for method in ("enable", "parse"):
            with (self.subTest(parser_method=method),
                  patch.object(content.MarkdownIt, method, side_effect=KeyError("private parser details")),
                  self.assertRaisesRegex(content.AdmissionError, "^content-parser-unavailable$")):
                self.observe()

    def test_observer_checks_decoded_titles_and_html_text_without_echoing_values(self):
        self.policy["protected_value_sha256"].append(content.sha256("fixture_resource"))
        for body, category in (*decoded_title_cases(), *html_text_cases()):
            with self.subTest(case=content.sha256(body), category=category):
                self.comment["body"] = body
                report = self.observe()
                self.assertFalse(report["clean"])
                self.assertIn(category, report["objects"][1]["categories"])
                self.assertNotIn(body, json.dumps(report))

    def test_observer_requires_present_bodies_and_issue_title(self):
        for target, field in ((self.item, "body"), (self.comment, "body"), (self.item, "title")):
            value = target.pop(field)
            try:
                with self.subTest(field=field, object_id=target["id"]), self.assertRaises(content.AdmissionError):
                    self.observe()
            finally:
                target[field] = value

    def test_observer_accepts_explicit_null_bodies_and_present_empty_strings(self):
        self.item["body"], self.comment["body"] = None, None
        self.assertTrue(self.observe()["clean"])
        self.item["title"], self.item["body"], self.comment["body"] = "", "", ""
        self.assertTrue(self.observe()["clean"])

    def test_null_issue_or_comment_body_disappearing_during_recheck_is_unknown(self):
        self.item["body"], self.comment["body"] = None, None
        for target in ("issue", "comment"):
            api = FakeAPI(self.responses)
            original, reads = api.get, []
            expected = ("repos/ltn-it/.github/issues/556" if target == "issue" else
                        "repos/ltn-it/.github/issues/556/comments?per_page=100&page=1")

            def get(path, original=original, reads=reads, expected=expected, target=target):
                value = original(path)
                if path == expected:
                    reads.append(path)
                    if len(reads) > 1:
                        (value if target == "issue" else value[0]).pop("body")
                return value

            api.get = get
            with self.subTest(target=target), self.assertRaises(content.AdmissionError):
                self.observe(api)

    def test_html_parser_failure_cannot_report_clean_observation(self):
        self.comment["body"] = "<div>Public</div>"
        with (patch.object(content.HTMLDestinations, "feed", side_effect=AssertionError("private")),
              self.assertRaisesRegex(content.AdmissionError, "^content-parser-unavailable$")):
            self.observe()

    def test_observer_flags_all_three_url_bypasses_without_echoing_destinations(self):
        for body in ('<a href="https://docs.github.com/en/rest\n?extra=value">x</a>',
                     'www.github.com/ltn-it/example/issues/1',
                     r'https://github.com/ltn-it/.github/blob/main/..\..\..\example/issues/1'):
            with self.subTest(case=content.sha256(body)):
                self.comment["body"] = body
                report = self.observe()
                self.assertFalse(report["clean"])
                self.assertEqual("owner-remediation-required", report["objects"][1]["disposition"])
                self.assertNotIn(body, json.dumps(report))

    def test_observer_detects_container_references_and_native_repository_references(self):
        for body in ("[source][ref]\n\n[ref]:\n  //github.com/ltn-it/example/issues/1",
                     "> [source][ref]\n>\n> [ref]: /ltn-it/example/issues/1",
                     "ltn-it/example#1", "ltn-it/example@" + "a" * 40):
            with self.subTest(case=content.sha256(body)):
                self.comment["body"] = body
                report = self.observe()
                self.assertFalse(report["clean"])
                self.assertEqual("owner-remediation-required", report["objects"][1]["disposition"])
                self.assertNotIn(body, json.dumps(report))

    def test_unavailable_parser_never_produces_a_clean_observation(self):
        with patch.object(content, "MarkdownIt", None):
            with self.assertRaisesRegex(content.AdmissionError, "content-parser-unavailable"):
                self.observe()

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

    def test_all_observed_pull_surfaces_require_body_and_parent_title(self):
        self.review["body"] = "Safe review"
        for target, field in ((self.pull, "body"), (self.comment, "body"), (self.review, "body"),
                              (self.inline, "body"), (self.pull, "title")):
            value = target.pop(field)
            try:
                with self.subTest(field=field, object_id=target["id"]), self.assertRaises(content.AdmissionError):
                    self.observe()
            finally:
                target[field] = value

    def test_explicit_null_pull_surface_bodies_are_known_empty_content(self):
        for target in (self.pull, self.comment, self.review, self.inline):
            target["body"] = None
        self.assertTrue(self.observe()["clean"])

    def test_missing_body_on_excluded_pending_review_is_not_claimed_observed(self):
        self.review["state"] = "PENDING"
        self.review.pop("body")
        self.inline.pop("body")
        report = self.observe()
        self.assertTrue(report["clean"])
        self.assertEqual(0, report["counts"]["reviews"])
        self.assertEqual(0, report["counts"]["inline_comments"])

    def test_null_pull_surface_body_disappearance_during_recheck_is_unknown(self):
        for target in (self.pull, self.comment, self.review, self.inline):
            target["body"] = None
        targets = (
            ("pull", "repos/ltn-it/.github/pulls/3"),
            ("comment", "repos/ltn-it/.github/issues/3/comments?per_page=100&page=1"),
            ("review", "repos/ltn-it/.github/pulls/3/reviews?per_page=100&page=1"),
            ("inline", "repos/ltn-it/.github/pulls/3/comments?per_page=100&page=1"),
        )
        for target, expected in targets:
            api = FakeAPI(self.responses)
            original, reads = api.get, []

            def get(path, original=original, reads=reads, expected=expected, target=target):
                value = original(path)
                if path == expected:
                    reads.append(path)
                    if len(reads) > 1:
                        (value if target == "pull" else value[0]).pop("body")
                return value

            api.get = get
            with self.subTest(target=target), self.assertRaises(content.AdmissionError):
                self.observe(api)

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
