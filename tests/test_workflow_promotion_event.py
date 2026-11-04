"""Exercise the exact frozen event helper selected by the real workflow."""
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import workflow_promotion_event as candidate


class FrozenPromotionEventTests(unittest.TestCase):
    def test_actual_checkout_runs_all_event_scenarios_with_its_own_reader(self):
        import yaml
        defining = "95f499ff8d58a74f3427d3e8234b9e6de2485958"
        workflow_path = ".github/workflows/delivery-operations.yml"
        git = ["git", "-c", f"safe.directory={ROOT}"]
        workflow = subprocess.check_output(git + ["show", f"{defining}:{workflow_path}"], cwd=ROOT)
        self.assertEqual(workflow, (ROOT / workflow_path).read_bytes())
        checkout = yaml.safe_load(workflow)["jobs"]["prepare"]["steps"][0]["with"]["ref"]
        self.assertEqual("80dfd878b4ce9c4f7431f54c7188016424e8f42b", checkout)
        helper = subprocess.check_output(git + ["show", f"{checkout}:scripts/workflow_promotion_event.py"], cwd=ROOT)
        self.assertEqual(helper, (ROOT / "scripts/workflow_promotion_event.py").read_bytes())
        payload = subprocess.check_output(git + ["archive", checkout, "scripts", ".lit"], cwd=ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                archive.extractall(root, filter="data")
            # Defining workflow95 selects helper80. Preserve both real inputs;
            # current candidate reader bytes never enter this subprocess.
            (root / workflow_path).parent.mkdir(parents=True)
            (root / workflow_path).write_bytes(workflow)
            scenario = root / "tests/test_workflow_promotion_event.py"
            scenario.parent.mkdir()
            scenario.write_bytes((ROOT / "tests/fixtures/promotion_event_scenarios.py").read_bytes())
            result = subprocess.run([sys.executable, "-IB", str(scenario)], cwd=root,
                                    text=True, capture_output=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("Ran 19 tests", result.stderr)

    def test_frozen_helper_rejects_candidate_reader_before_any_native_access(self):
        api = Mock()
        with self.assertRaisesRegex(candidate.ControlError, "admitted-reader-drift"):
            candidate.current_head(api, {}, {"GITHUB_REPOSITORY": "ltn-it/shared-assets-lit"})
        api.call.assert_not_called()
        api.pages.assert_not_called()
