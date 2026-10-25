"""Current GitHub names never substitute for immutable organization/repo IDs."""
import json
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_control as control


class NamespaceIdentityTests(unittest.TestCase):
    def test_archive_keys_preserve_old_namespace_and_reject_similar_foreign_names(self):
        spec = importlib.util.spec_from_file_location("namespace_archive", Path(__file__).resolve().parents[1]
                                                     / "scripts/lit-release-archive.py")
        archive = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = archive
        spec.loader.exec_module(archive)
        for repository in ("lightning-it/.github", "ltn-it/.github"):
            key = archive.object_key(repository, 3, "a" * 40, "b" * 64, "c" * 32)
            self.assertEqual(f"runs/github-release/v1/{repository}/3/"
                             + "a" * 40 + "/" + "c" * 32 + "/" + "b" * 64 + ".json", key)
        for repository in ("evil/ltn-it/.github", "ltn-it-evil/.github", "ltn-it/../.github"):
            with self.subTest(repository=repository), self.assertRaises(archive.ArchiveError):
                archive.object_key(repository, 3, "a" * 40, "b" * 64, "c" * 32)

    def repository(self, name=".github"):
        return {"id": control.RENAMED_REPOSITORIES[name], "full_name": f"ltn-it/{name}",
                "owner": {"login": "ltn-it", "id": 54334171},
                "archived": False, "disabled": False}

    def test_current_renamed_repositories_require_the_original_numeric_ids(self):
        for name, identifier in control.RENAMED_REPOSITORIES.items():
            api = Mock(); api.call.return_value = self.repository(name)
            with self.subTest(name=name):
                self.assertEqual(identifier, control.current_repository(api, f"ltn-it/{name}"))
            api.call.assert_called_once_with(f"repos/ltn-it/{name}")

    def test_prefix_alias_and_path_variants_fail_before_any_api_access(self):
        for name in ("lightning-it/.github", "ltn-it-evil/.github", "evil/ltn-it/.github",
                     "ltn-it/.github/extra", "ltn-it/.github?ref=main", "ltn-it/.github\n"):
            api = Mock()
            with self.subTest(name=name), self.assertRaises(control.ControlError):
                control.current_repository(api, name)
            api.call.assert_not_called()

    def test_recreated_repository_foreign_owner_boolean_and_disabled_targets_block(self):
        original = self.repository()
        variants = [original | {"id": value} for value in (True, 1, None)]
        variants += [original | {"full_name": "lightning-it/.github"},
                     original | {"owner": {"login": "ltn-it", "id": 1}},
                     original | {"owner": {"login": "other", "id": 54334171}},
                     original | {"owner": {"login": "ltn-it", "id": True}},
                     original | {"archived": True}, original | {"disabled": True}]
        for value in variants:
            api = Mock(); api.call.return_value = value
            with self.subTest(value=value), self.assertRaises(control.ControlError):
                control.current_repository(api, "ltn-it/.github")

    def test_identity_failure_blocks_the_real_entrypoint_before_event_or_funding(self):
        api = Mock(); api.call.return_value = self.repository() | {"id": 1}
        job = {"workflow_repository": "ltn-it/.github", "workflow_file_path": control.WORKFLOW,
               "workflow_sha": "a" * 40, "check_run_id": 123}
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "ltn-it/.github",
                                    "NATIVE_JOB": json.dumps(job)}, clear=True), \
                patch.object(sys, "argv", ["control", "classify"]), \
                patch.object(control, "API", return_value=api), \
                patch.object(control, "reserve_request") as reserve, \
                self.assertRaisesRegex(control.ControlError, "renamed-repository-id-drift"):
            control.main()
        reserve.assert_not_called()
        api.call.assert_called_once_with("repos/ltn-it/.github")

    def test_historical_source_admissions_and_app_identities_are_not_renamed(self):
        self.assertEqual("lightning-it/shared-assets-lit", control.SOURCE_GENERATED_SUBJECT["repository"])
        self.assertEqual(("lightning-it-release-automation[bot]", 307565056, "Bot"), control.RELEASE)
        self.assertEqual(("lightning-it-shared-assets-sync[bot]", 307342877, "Bot"), control.SYNC)
