import importlib
import csv
import json
import shutil
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "testing"))
validation = importlib.import_module("Test-AdoPolicyLab")
migration = importlib.import_module("Test-Ado2GhMigration")


class MigrationComparisonTests(unittest.TestCase):
    def setUp(self):
        self.repo = {
            "exists": True, "repository": {"full_name": "fixture/repo"},
            "protection": {"main": {"status": 404, "body": {}}},
            "effectiveRules": {"main": {"status": 200, "body": []}},
            "rulesets": [], "rulesetsComplete": True,
        }
        self.baseline = {"repositories": {
            name: {"repository": {"id": name + "-id"}} for name in ("alpha", "beta")
        }}
        self.readback = {"repositories": {
            name: {**self.repo, "rulesets": []} for name in ("alpha", "beta")
        }}
        self.size_policy = {
            "isEnabled": True, "isBlocking": True,
            "settings": {"maximumGitBlobSizeInBytes": 1048576,
                         "scope": [{"repositoryId": None}]},
        }

    def add_size_rule(self, repo, megabytes=1, enforcement="active", target="push"):
        self.readback["repositories"][repo]["rulesets"].append({
            "name": "size", "target": target, "enforcement": enforcement,
            "rules": [{"type": "max_file_size", "parameters": {"max_file_size": megabytes}}],
        })

    def test_build_context_requires_explicit_mapping(self):
        settings = {"buildDefinitionId": 1, "displayName": "Not a job name"}
        self.assertEqual(migration.observe_branch("build", settings, self.repo, "main")[0],
                         "UNVERIFIED")
        self.repo["effectiveRules"]["main"]["body"] = [{
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "build-job"}]},
        }]
        result = migration.observe_branch(
            "build", settings, self.repo, "main",
            context_map={"pipelines": {"pipeline-name": "build-job"}},
            pipeline_names={"1": "pipeline-name"})
        self.assertEqual(result[0], "MIGRATED")

    def test_status_context_does_not_accept_unrelated_or_substring_checks(self):
        settings = {"statusGenre": "policy-lab", "statusName": "validation"}
        mapping = {"statuses": {"policy-lab/validation": "required-job"}}
        for context in ("unrelated", "required-job-extra"):
            with self.subTest(context=context):
                self.repo["effectiveRules"]["main"]["body"] = [{
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": [{"context": context}]},
                }]
                self.assertEqual(migration.observe_branch(
                    "status", settings, self.repo, "main", context_map=mapping)[0],
                    "NOT MIGRATED")

    def test_inaccessible_check_evidence_is_unverified(self):
        self.repo["effectiveRules"]["main"]["status"] = 403
        self.assertEqual(migration.observe_branch(
            "build", {"buildDefinitionId": 1}, self.repo, "main",
            context_map={"pipelines": {"1": "job"}})[0], "UNVERIFIED")

    def test_conflicting_context_mappings_fail_instead_of_guessing(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            migration.expected_check_context(
                "build", {"buildDefinitionId": 1},
                {"pipelines": {"1": "job-a", "pipeline-name": "job-b"}},
                {"1": "pipeline-name"})

    def test_last_pusher_semantics_are_not_exact_parity(self):
        self.repo["effectiveRules"]["main"]["body"] = [{
            "type": "pull_request",
            "parameters": {"required_approving_review_count": 2,
                           "require_last_push_approval": True},
        }]
        self.assertEqual(migration.observe_branch(
            "reviewers", {"minimumApproverCount": 2, "blockLastPusherVote": True},
            self.repo, "main")[0], "PARTIAL")

    def test_requester_restriction_does_not_require_last_push_approval(self):
        self.repo["effectiveRules"]["main"]["body"] = [{
            "type": "pull_request",
            "parameters": {"required_approving_review_count": 2},
        }]
        self.assertEqual(migration.observe_branch(
            "reviewers", {"minimumApproverCount": 2, "prohibitRequesterFromApproving": True},
            self.repo, "main")[0], "MIGRATED")

    def test_push_policy_requires_every_applicable_repository(self):
        self.add_size_rule("alpha")
        result = migration.observe_push("size", self.size_policy, self.baseline, self.readback)
        self.assertEqual(result[0], "PARTIAL")
        self.assertIn("beta", result[2])
        self.add_size_rule("beta")
        self.assertEqual(migration.observe_push(
            "size", self.size_policy, self.baseline, self.readback)[0], "MIGRATED")

    def test_wrong_repository_disabled_and_wrong_target_do_not_satisfy_policy(self):
        self.size_policy["settings"]["scope"] = [{"repositoryId": "alpha-id"}]
        self.add_size_rule("beta")
        self.assertEqual(migration.observe_push(
            "size", self.size_policy, self.baseline, self.readback)[0], "NOT MIGRATED")
        for enforcement, target in (("disabled", "push"), ("evaluate", "push"),
                                    ("active", "branch")):
            with self.subTest(enforcement=enforcement, target=target):
                self.readback["repositories"]["alpha"]["rulesets"] = []
                self.add_size_rule("alpha", enforcement=enforcement, target=target)
                self.assertNotEqual(migration.observe_push(
                    "size", self.size_policy, self.baseline, self.readback)[0], "MIGRATED")

    def test_unknown_repository_and_incomplete_readback_are_unverified(self):
        self.size_policy["settings"]["scope"] = [{"repositoryId": "unknown"}]
        self.assertEqual(migration.observe_push(
            "size", self.size_policy, self.baseline, self.readback)[0], "UNVERIFIED")
        self.add_size_rule("alpha")
        self.add_size_rule("beta")
        self.readback["repositories"]["beta"].pop("rulesetsComplete")
        self.assertEqual(migration.observe_push(
            "size", self.size_policy, self.baseline, self.readback)[0], "UNVERIFIED")
        self.size_policy["settings"]["scope"] = [{"repositoryId": None}]
        self.readback["repositories"]["beta"]["rulesetsComplete"] = False
        self.assertEqual(migration.observe_push(
            "size", self.size_policy, self.baseline, self.readback)[0], "UNVERIFIED")

    def test_non_whole_mebibyte_is_a_parity_difference(self):
        self.size_policy["settings"]["maximumGitBlobSizeInBytes"] = 1500000
        for name in self.baseline["repositories"]:
            self.add_size_rule(name)
        result = migration.observe_push("size", self.size_policy, self.baseline, self.readback)
        self.assertEqual(result[0], "PARTIAL")
        self.assertIn("1500000", result[2])
        self.assertIn("1048576", result[2])

    def test_advisory_push_rule_does_not_require_active_enforcement(self):
        self.size_policy["isBlocking"] = False
        for name in self.baseline["repositories"]:
            self.add_size_rule(name, enforcement="evaluate")
        self.assertEqual(migration.observe_push(
            "size", self.size_policy, self.baseline, self.readback)[0], "MIGRATED")

    def test_path_and_length_parameters_must_match_not_just_rule_type(self):
        for kind, source, rule_type, correct, wrong in (
                ("length", {"maxPathLength": 180}, "max_file_path_length",
                 {"max_file_path_length": 180}, {"max_file_path_length": 200}),
                ("path", {"filenamePatterns": ["*.exe"]}, "file_path_restriction",
                 {"restricted_file_paths": ["*.exe"]}, {"restricted_file_paths": ["*.dll"]})):
            config = {"settings": {**source, "scope": [{"repositoryId": "alpha-id"}]}}
            for parameters, expected in ((correct, "MIGRATED"), (wrong, "PARTIAL")):
                with self.subTest(kind=kind, parameters=parameters):
                    self.readback["repositories"]["alpha"]["rulesets"] = [{
                        "name": "paths", "target": "push", "enforcement": "active",
                        "rules": [{"type": rule_type, "parameters": parameters}],
                    }]
                    self.assertEqual(migration.observe_push(
                        kind, config, self.baseline, self.readback)[0], expected)

    def test_stricter_composed_file_limit_is_not_exact_parity(self):
        self.size_policy["settings"]["maximumGitBlobSizeInBytes"] = 2 * 1048576
        for name in self.baseline["repositories"]:
            self.add_size_rule(name, megabytes=2)
            self.add_size_rule(name, megabytes=1)
        self.assertEqual(migration.observe_push(
            "size", self.size_policy, self.baseline, self.readback)[0], "PARTIAL")

    def test_email_regex_is_canonical_but_branch_only_coverage_is_partial(self):
        patterns = ["a?@company.com", "Z+ci@company.com"]
        regex = migration.email_allowlist_regex(patterns)
        self.assertEqual(regex, r"^(Z\+ci@company\.com|a.@company\.com)$")
        config = {"settings": {"authorEmailPatterns": patterns,
                               "scope": [{"repositoryId": "alpha-id"}]}}
        self.readback["repositories"]["alpha"]["rulesets"] = [{
            "name": "email", "target": "branch", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
            "rules": [{"type": "commit_author_email_pattern",
                       "parameters": {"operator": "regex", "pattern": regex, "negate": False}}],
        }]
        result = migration.observe_push("email", config, self.baseline, self.readback)
        self.assertEqual(result[0], "PARTIAL")
        self.assertIn("regex matches", result[2])
        self.assertIn("tag coverage", result[2])

    def test_context_mapping_roundtrip_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contexts.json"
            path.write_text(json.dumps({"pipelines": {"1": "job"}}), encoding="utf-8")
            self.assertEqual(migration.load_context_map(path), {"pipelines": {"1": "job"}})
            path.write_text('{"pipelines":{"1":""}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                migration.load_context_map(path)

    def test_comparison_persists_scoped_results_without_changing_original_evidence(self):
        source = ROOT / "output" / "ado2gh-migration" / "20261023Ado2GhMigration01"
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            for name in ("ado-baseline.json", "github-readback.json", "migration-results.json",
                         "github-org-before.json", "github-org-after.json"):
                shutil.copyfile(source / name, run / name)
            back = migration.read(run / "github-readback.json")
            for repo in back["repositories"].values():
                repo.update(rulesets=[], rulesetsComplete=True)
            back["repositories"]["sample4"]["rulesets"] = [{
                "target": "push", "enforcement": "disabled", "name": "unrelated",
                "rules": [{"type": "max_file_size", "parameters": {"max_file_size": 1}}],
            }]
            migration.write(run / "github-readback.json", back)
            with patch("builtins.print"):
                migration.compare(run)
            with (run / "Migration-Comparison.csv").open(encoding="utf-8-sig", newline="") as file:
                rows = {row["Inventory ID"]: row for row in csv.DictReader(file)}
            self.assertEqual(len(rows), 42)
            for key in ("ADO-018", "ADO-031"):
                self.assertEqual(rows[key]["Observed in GitHub"], "NOT MIGRATED")
            summary = migration.read(run / "comparison-summary.json")
            self.assertEqual(sum(summary["observedCounts"].values()), 42)
            self.assertTrue(any(row["Observed in GitHub"] == "UNVERIFIED" for row in rows.values()))
            for row in rows.values():
                if row["Observed in GitHub"] == "UNVERIFIED":
                    self.assertEqual(row["Docs vs observed"], "UNVERIFIED")

    def test_readback_marks_inaccessible_rulesets_incomplete(self):
        github = Mock()
        github.pages.return_value = []
        github.graphql.return_value = {}

        def get(path, allow=(200,)):
            if "/rulesets?" in path:
                return {"status": 403, "body": {"message": "Forbidden"}}
            if "/contents/" in path or "/protection" in path:
                return {"status": 404, "body": {}}
            if "/rules/branches/" in path:
                return {"status": 200, "body": []}
            return {"status": 200, "body": {"default_branch": "main"}}

        github.get.side_effect = get
        saved = {}
        with patch.object(migration, "REPOS", ("alpha",)), \
                patch.object(migration, "LAB_BRANCH", {"alpha": "main"}), \
                patch.object(migration, "write", side_effect=lambda path, value: saved.update({path.name: value})), \
                patch("builtins.print"):
            migration.readback(Path("unused"), github)
        repo = saved["github-readback.json"]["repositories"]["alpha"]
        self.assertFalse(repo["rulesetsComplete"])
        self.assertEqual(repo["rulesets"], [])

    def test_readback_paginates_and_fetches_inherited_rulesets(self):
        github = Mock()
        github.pages.return_value = []
        github.graphql.return_value = {}

        def get(path, allow=(200,)):
            if "/rulesets?" in path:
                body = ([{"id": number, "source_type": "Repository"} for number in range(100)]
                        if "&page=1" in path else
                        [{"id": 100, "source_type": "Organization", "source": "fixture-org"}])
                return {"status": 200, "body": body}
            if "/rulesets/" in path:
                return {"status": 200, "body": {"name": path, "rules": []}}
            if "/contents/" in path or "/protection" in path:
                return {"status": 404, "body": {}}
            if "/rules/branches/" in path:
                return {"status": 200, "body": []}
            return {"status": 200, "body": {"default_branch": "main"}}

        github.get.side_effect = get
        saved = {}
        with patch.object(migration, "REPOS", ("alpha",)), \
                patch.object(migration, "LAB_BRANCH", {"alpha": "main"}), \
                patch.object(migration, "write", side_effect=lambda path, value: saved.update({path.name: value})), \
                patch("builtins.print"):
            migration.readback(Path("unused"), github)
        repo = saved["github-readback.json"]["repositories"]["alpha"]
        self.assertTrue(repo["rulesetsComplete"])
        self.assertEqual(len(repo["rulesets"]), 101)
        self.assertTrue(any(call.args[0] == "/orgs/fixture-org/rulesets/100"
                            for call in github.get.call_args_list))


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
