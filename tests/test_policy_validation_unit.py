import importlib
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "testing"))
validation = importlib.import_module("Test-AdoPolicyLab")


class PolicyValidationTests(unittest.TestCase):
    def setUp(self):
        self.suite = object.__new__(validation.Suite)

    def rejection(self, status, kind, message):
        error = RuntimeError(
            f"POST git/repositories/test/pushes: HTTP {status}: "
            + json.dumps({"typeKey": kind, "message": message})
        )
        error.__cause__ = urllib.error.HTTPError("https://example.invalid", status, "test", {}, None)

        def operation():
            raise error
        return operation

    def test_expected_policy_rejection_passes(self):
        result = self.suite.rejection(
            self.rejection(400, "GitPushRejectedByPolicyException", "Maximum file size policy rejected this file"),
            ("size",),
        )
        self.assertEqual(result["httpStatus"], 400)

    def test_observed_git_object_rejection_passes(self):
        result = self.suite.rejection(
            self.rejection(400, "GitObjectRejectedException", "VS403658: file exceeds object limit"),
            ("VS403658",),
        )
        self.assertEqual(result["httpStatus"], 400)

    def test_observed_case_enforcement_rejection_passes(self):
        result = self.suite.rejection(
            self.rejection(400, "InvalidArgumentValueException", "Files differ; disable case-enforcement"),
            ("case-enforcement",),
        )
        self.assertEqual(result["httpStatus"], 400)

    def test_other_invalid_argument_is_not_a_policy_pass(self):
        with self.assertRaisesRegex(AssertionError, "not attributable"):
            self.suite.rejection(
                self.rejection(400, "InvalidArgumentValueException", "Invalid file size argument"),
                ("size",),
            )

    def test_permission_denial_is_not_a_policy_pass(self):
        with self.assertRaisesRegex(AssertionError, "not attributable"):
            self.suite.rejection(
                self.rejection(403, "GitNeedsPermissionException", "No edit policy permission for file size"),
                ("size",),
            )

    def test_wrong_policy_reason_is_not_a_pass(self):
        with self.assertRaisesRegex(AssertionError, "Wrong rejection reason"):
            self.suite.rejection(
                self.rejection(400, "GitPushRejectedByPolicyException", "Commit author email is prohibited"),
                ("size",),
            )

    def test_unexpected_acceptance_is_failure(self):
        with self.assertRaisesRegex(AssertionError, "unexpectedly accepted"):
            self.suite.rejection(lambda: {"pushId": 1}, ("size",))

    def test_authentication_error_is_not_a_policy_pass(self):
        with self.assertRaisesRegex(AssertionError, "Unexpected rejection HTTP"):
            self.suite.rejection(
                self.rejection(401, "GitPushRejectedByPolicyException", "size"),
                ("size",),
            )

    def test_test_guard_forbids_policy_mutation(self):
        with self.assertRaisesRegex(RuntimeError, "cannot mutate"):
            self.suite.api("policy/configurations/1", "PUT", {})

    def test_path_boundaries_include_the_leading_slash(self):
        seen = []

        def push(name, label, changes):
            length = int(label.split("-")[1])
            self.assertEqual(len("/" + changes[0][0]), length)
            seen.append((name, length))
            if length == 181:
                return self.rejection(400, "GitObjectRejectedException", "VS403656: maximum path length")()
            return {"objectId": "a" * 40}

        def check(name, entries, level, action):
            if "/path-" in name:
                action()

        self.suite.run_id = "run1"
        self.suite.push = push
        self.suite.check = check
        self.suite.push_tests()
        self.assertEqual(seen, [("sample3", 180), ("sample3", 181), ("sample2", 180), ("sample2", 181)])

    def test_queued_evaluation_is_blocked_not_failed_or_passed(self):
        self.suite.policy_state = {"policies": {"ADO-032": {"id": 20}}}
        self.suite.evaluations = lambda name: {20: {"status": "queued"}}
        with self.assertRaises(validation.Blocked):
            self.suite.evaluation("sample2", "ADO-032", {"rejected"}, timeout=0)

    def test_exclusions_leave_35_inventory_entries(self):
        self.assertEqual(len(validation.EXCLUDED), 7)
        self.assertIn("ADO-005", validation.EXCLUDED)
        self.assertIn("ADO-008", validation.EXCLUDED)
        self.assertEqual(42 - len(validation.EXCLUDED), 35)

    def test_only_owned_fixture_refs_extend_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            path = out / "policy-tests" / "run1" / "resources.json"
            path.parent.mkdir(parents=True)
            ref = "refs/heads/policy-tests/run1/allowed"
            manifest = {"destination": list(validation.lab.TARGET), "refs": {"repo": {ref: "b" * 40}}}
            validation.write_json(path, manifest)
            original = {"refs/heads/master": "a" * 40}
            with patch.object(validation.lab, "OUT", out):
                expected = validation.lab.expected_destination_refs("repo", original)
                self.assertEqual(expected, {**original, ref: "b" * 40})
                manifest["refs"]["repo"] = {"refs/heads/master": "b" * 40}
                validation.write_json(path, manifest)
                with self.assertRaisesRegex(RuntimeError, "Unowned"):
                    validation.lab.expected_destination_refs("repo", original)

    def test_manifest_cannot_change_existing_fixture_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            path = out / "policy-tests" / "run1" / "resources.json"
            path.parent.mkdir(parents=True)
            ref = "refs/heads/policy-tests/run1/allowed"
            validation.write_json(path, {
                "destination": list(validation.lab.TARGET), "refs": {"repo": {ref: "b" * 40}},
            })
            with patch.object(validation.lab, "OUT", out):
                with self.assertRaisesRegex(RuntimeError, "overwrite"):
                    validation.lab.expected_destination_refs("repo", {ref: "a" * 40})


if __name__ == "__main__":
    unittest.main()
