import argparse
import csv
import importlib
import json
import sys
import time
import urllib.error
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lab"))
lab = importlib.import_module("Initialize-NewOrgPolicyLab")
EXCLUDED = {
    "ADO-005": "User excluded Restrict PAT creation",
    "ADO-008": "User excluded non-interactive IP Conditional Access validation",
    "ADO-006": "Retired public-project capability",
    **{f"TEN-{i:03d}": "User excluded tenant-wide policies" for i in range(1, 5)},
}
AUTHOR = {"name": "Policy Lab Test", "email": "admin@MngEnvMCAP267305.onmicrosoft.com"}


def write_json(path, value):
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


class Blocked(RuntimeError):
    pass


class Suite:
    def __init__(self, run_id=None):
        self.client = lab.copy_lab.Client()
        self.policy_state = json.loads((lab.OUT / "policy-state.json").read_text())
        self.copied = json.loads((lab.OUT / "copy-state.json").read_text())
        self.run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        if not self.run_id.isalnum() or len(self.run_id) > 64:
            raise ValueError("Run ID must contain 1-64 letters or digits.")
        self.out = lab.OUT / "policy-tests" / self.run_id
        self.out.mkdir(parents=True, exist_ok=True)
        path = self.out / "results.json"
        self.results = json.loads(path.read_text()) if path.exists() else []
        path = self.out / "resources.json"
        self.resources = json.loads(path.read_text()) if path.exists() else {
            "destination": list(lab.TARGET), "refs": {}, "prs": {}, "workItems": [],
        }
        if tuple(self.resources["destination"]) != lab.TARGET:
            raise RuntimeError("Test resources belong to a different destination.")
        self.repos = {name: record["destination"]["id"]
                      for name, record in self.copied["repositories"].items()}
        path = self.out / "baseline.json"
        if path.exists():
            self.baseline = json.loads(path.read_text())
        else:
            repos = self.api("git/repositories")["value"]
            self.baseline = {
                "capturedAt": datetime.now(timezone.utc).isoformat(),
                "policies": self.client.policies(lab.TARGET),
                "sourcePolicies": self.client.policies(lab.copy_lab.SOURCE),
                "repositories": {
                    r["id"]: {"metadata": r, "refs": self.client.refs(lab.TARGET, r["id"])}
                    for r in repos
                },
                "sourceRefs": {
                    name: self.client.refs(lab.copy_lab.SOURCE, record["source"]["id"])
                    for name, record in self.copied["repositories"].items()
                },
            }
            write_json(path, self.baseline)
        self.checkpoint()

    def api(self, path, method="GET", body=None, query=None, content_type="application/json"):
        if method != "GET" and not path.startswith(("git/repositories/", "wit/workitems/")):
            raise RuntimeError(f"Tests cannot mutate policies, permissions or organization settings: {path}")
        return self.client.call(lab.TARGET, path, method, body, query, content_type=content_type)

    def checkpoint(self):
        write_json(self.out / "resources.json", self.resources)
        write_json(self.out / "results.json", self.results)

    def check(self, name, entries, level, action):
        if any(result["name"] == name for result in self.results):
            return
        result = {"name": name, "entries": entries, "level": level,
                  "timestamp": datetime.now(timezone.utc).isoformat()}
        try:
            result["evidence"] = action()
            result["status"] = "PASS"
        except Blocked as error:
            result.update(status="BLOCKED", detail=str(error))
        except AssertionError as error:
            result.update(status="FAIL", detail=str(error))
        except RuntimeError as error:
            result.update(status="ERROR", detail=str(error))
        self.results.append(result)
        self.checkpoint()
        print(f"{result['status']}: {name}" + (f" - {result['detail']}" if "detail" in result else ""), flush=True)

    def ref(self, name, branch):
        refs = self.client.refs(lab.TARGET, self.repos[name])
        if branch not in refs:
            raise RuntimeError(f"Missing expected branch {name}/{branch}.")
        return refs[branch]

    def push(self, name, label, changes, author=None, branch=None, parent=None):
        repo = self.repos[name]
        ref = branch or f"refs/heads/policy-tests/{self.run_id}/{label}"
        if not ref.startswith(f"refs/heads/policy-tests/{self.run_id}/"):
            raise RuntimeError("Test pushes must target this run's fixture namespace.")
        known = self.resources["refs"].get(repo, {}).get(ref)
        if known and branch is None:
            return {"ref": ref, "objectId": known, "reused": True}
        parent = parent or self.ref(name, "refs/heads/master")
        response = self.api(f"git/repositories/{repo}/pushes", "POST", {
            "refUpdates": [{"name": ref, "oldObjectId": known or "0" * 40}],
            "commits": [{
                "comment": (
                    f"Policy validation fixture: {label}\n\n"
                    "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
                ),
                "parents": [parent], "author": author or AUTHOR,
                "changes": [
                    {"changeType": "add", "item": {"path": "/" + path},
                     "newContent": {"content": text, "contentType": "rawtext"}}
                    for path, text in changes
                ],
            }],
        })
        update = next(r for r in response["refUpdates"] if r["name"] == ref)
        sha = update["newObjectId"]
        self.resources["refs"].setdefault(repo, {})[ref] = sha
        self.checkpoint()
        return {"ref": ref, "objectId": sha, "pushId": response["pushId"]}

    def rejection(self, operation, keywords):
        try:
            accepted = operation()
        except RuntimeError as error:
            cause = error.__cause__
            if not isinstance(cause, urllib.error.HTTPError):
                raise
            message = str(error)
            assert cause.code in (400, 403), f"Unexpected rejection HTTP {cause.code}: {message}"
            detail = message.partition(f"HTTP {cause.code}: ")[2]
            try:
                payload = json.loads(detail)
            except json.JSONDecodeError as invalid:
                raise AssertionError(f"Non-JSON rejection cannot prove policy enforcement: {message}") from invalid
            policy_error = payload.get("typeKey") in (
                "GitPushRejectedByPolicyException", "GitObjectRejectedException",
            )
            case_error = (payload.get("typeKey") == "InvalidArgumentValueException"
                          and "case-enforcement" in payload.get("message", ""))
            assert policy_error or case_error, (
                f"Rejection is not attributable to a Git push policy: {message}"
            )
            assert any(word.lower() in message.lower() for word in keywords), (
                f"Wrong rejection reason; expected {keywords}: {message}"
            )
            return {"httpStatus": cause.code, "rejection": message}
        raise AssertionError(f"Operation unexpectedly accepted: {accepted}")

    def configuration(self):
        for entry, record in self.policy_state["policies"].items():
            def check(record=record):
                actual = self.api(f"policy/configurations/{record['id']}")
                mismatches = lab.rules.policy_mismatches(actual, record["expected"])
                assert not mismatches, f"Read-back mismatches: {mismatches}"
                return actual
            self.check(f"configuration/{entry}", [entry], "configuration", check)
        for name in self.repos:
            numbers = {
                "sample2": list(range(13, 19)) + list(range(26, 39)),
                "sample3": list(range(13, 26)), "sample4": list(range(13, 19)),
            }[name]
            entries = [f"ADO-{i:03d}" for i in numbers]
            def check(name=name, entries=entries):
                actual = self.api("git/policy/configurations", query={
                    "repositoryId": self.repos[name], "refName": lab.BRANCHES[name], "$top": 100,
                })["value"]
                expected = {self.policy_state["policies"][e]["id"] for e in entries}
                assert {p["id"] for p in actual} == expected, "Effective scope differs from configured IDs."
                return {"repository": name, "effectivePolicyIds": sorted(expected)}
            self.check(f"effective-scope/{name}", entries, "configuration", check)

    def push_tests(self):
        prefix = f"policy-tests/{self.run_id}/"
        for name, first in (("sample3", 13), ("sample2", 26)):
            ids = [f"ADO-{n:03d}" for n in range(first, first + 6)]
            level = "enforcement" if name == "sample3" else "combined-enforcement"
            positive = lambda name=name: self.push(name, "allowed", [(prefix + "allowed.txt", "valid\n")])
            self.check(f"push/{name}/allowed", ids, level, positive)
            cases = [
                ("email", [ids[0]], [(prefix + "bad-email.txt", "invalid author\n")],
                 {"name": "Unapproved Test Author", "email": "unapproved@example.invalid"}, ("VS403702",)),
                ("path", [ids[1]], [(prefix + "policy-lab-blocked/forbidden.txt", "blocked\n")],
                 None, ("VS403694",)),
                ("case", [ids[2]], [(prefix + "Case.txt", "one\n"), (prefix + "case.txt", "two\n")],
                 None, ("case-enforcement",)),
                ("reserved", [ids[3]], [(prefix + "CON.txt", "reserved\n")],
                 None, ("VS403655",)),
            ]
            for label, entries, changes, author, keywords in cases:
                self.check(f"push/{name}/reject-{label}", entries, level,
                           lambda name=name, label=label, changes=changes, author=author, keywords=keywords:
                           self.rejection(lambda: self.push(name, label, changes, author), keywords))
            for length, reject in ((180, False), (181, True)):
                path = prefix + "x" * (length - len(prefix) - 5) + ".txt"
                assert len("/" + path) == length
                operation = lambda name=name, length=length, path=path: self.push(
                    name, f"path-{length}", [(path, "path boundary\n")])
                self.check(f"push/{name}/path-{length}", [ids[4]], level,
                           (lambda operation=operation: self.rejection(operation, ("VS403656",)))
                           if reject else operation)
            for size, reject in ((1048576, False), (1048577, True)):
                operation = lambda name=name, size=size: self.push(
                    name, f"size-{size}", [(prefix + f"size-{size}.txt", "a" * size)])
                self.check(f"push/{name}/size-{size}", [ids[5]], level,
                           (lambda operation=operation: self.rejection(operation, ("VS403658",)))
                           if reject else operation)
            if name == "sample2":
                def isolated():
                    raise Blocked("Identical project push policies also apply; rejection proves combined enforcement, "
                                  "not independent attribution to the explicit repository layer. No policies disabled.")
                self.check("push/sample2/independent-layer-attribution", ids, "enforcement", isolated)

    def create_pr(self, name):
        if name in self.resources["prs"]:
            return self.resources["prs"][name]
        source = self.push(name, "pr-fixture", [
            (f"policy-tests/{self.run_id}/pr-fixture.txt", f"{name} validation fixture\n")
        ], parent=self.ref(name, lab.BRANCHES[name]))
        actual = self.api(f"git/repositories/{self.repos[name]}/pullRequests", "POST", {
            "sourceRefName": source["ref"], "targetRefName": lab.BRANCHES[name],
            "title": f"Policy validation {self.run_id}: {name}",
            "description": "Dedicated enforcement-test fixture; do not merge without the independent reviewer checks.",
        })
        resource = {"id": actual["pullRequestId"], "repository": self.repos[name],
                    "source": source, "target": lab.BRANCHES[name], "createdBy": actual["createdBy"]["id"]}
        self.resources["prs"][name] = resource
        self.checkpoint()
        return resource

    def pr_path(self, name):
        resource = self.resources["prs"][name]
        return f"git/repositories/{resource['repository']}/pullRequests/{resource['id']}"

    def evaluations(self, name):
        resource = self.resources["prs"][name]
        artifact = f"vstfs:///CodeReview/CodeReviewId/{lab.TARGET[1]}/{resource['id']}"
        values = self.api("policy/evaluations", query={
            "artifactId": artifact, "api-version": "7.1-preview.1",
        })["value"]
        return {value["configuration"]["id"]: value for value in values}

    def evaluation(self, name, entry, expected, timeout=45):
        policy = self.policy_state["policies"][entry]["id"]
        deadline = time.monotonic() + timeout
        last = None
        while True:
            last = self.evaluations(name).get(policy)
            if last and last["status"].lower() in expected:
                return last
            if time.monotonic() >= deadline:
                if last and last["status"].lower() in {"queued", "running"}:
                    raise Blocked(
                        f"{entry}: evaluation remained {last['status']} after {timeout}s; "
                        f"expected {sorted(expected)}. Pending is not counted as rejection or approval."
                    )
                raise AssertionError(f"{entry}: expected evaluation {expected}, got {last}")
            time.sleep(3)

    def pr_tests(self):
        for name, first in (("sample2", 32), ("sample3", 19)):
            ids = [f"ADO-{n:03d}" for n in range(first, first + 7)]
            self.check(f"pr/{name}/create", ids, "fixture", lambda name=name: self.create_pr(name))
            if name not in self.resources["prs"]:
                continue
            path = self.pr_path(name)
            self.check(f"pr/{name}/minimum-reviewers-blocks", [ids[0]], "enforcement",
                       lambda name=name, entry=ids[0]: self.evaluation(name, entry, {"rejected"}))
            def required(name=name):
                pr = self.api(self.pr_path(name))
                configured = self.policy_state["policies"][ids[6]]["expected"]["settings"]["requiredReviewerIds"]
                reviewers = {r["id"]: r for r in pr["reviewers"]}
                assert set(configured).issubset(reviewers), f"Missing automatic reviewers: {reviewers}"
                assert all(reviewers[identity].get("isRequired") for identity in configured), (
                    "Named automatic reviewers are not marked required."
                )
                return pr["reviewers"]
            self.check(f"pr/{name}/automatic-required-reviewers", [ids[6]], "enforcement", required)
            def creator_vote(name=name, entry=ids[0]):
                creator = self.resources["prs"][name]["createdBy"]
                self.api(self.pr_path(name) + f"/reviewers/{creator}", "PUT", {"vote": 10})
                try:
                    result = self.evaluation(name, entry, {"rejected"})
                    return {"creatorVote": 10, "evaluation": result}
                finally:
                    self.api(self.pr_path(name) + f"/reviewers/{creator}", "PUT", {"vote": 0})
            self.check(f"pr/{name}/single-creator-vote-insufficient-for-two-approvers",
                       [ids[0]], "enforcement", creator_vote)
            def creator_isolation():
                raise Blocked("A single creator vote is insufficient for two approvers regardless of exclusion. "
                              "Proving creator-vote exclusion independently needs an authenticated non-creator vote.")
            self.check(f"pr/{name}/creator-vote-exclusion-isolation", [ids[0]], "enforcement", creator_isolation)
            self.check(f"pr/{name}/work-item-missing-blocks", [ids[1]], "enforcement",
                       lambda name=name, entry=ids[1]: self.evaluation(name, entry, {"rejected"}))
            def work_item(name=name, entry=ids[1]):
                resource = self.resources["prs"][name]
                url = (f"vstfs:///Git/PullRequestId/{lab.TARGET[1]}%2F"
                       f"{resource['repository']}%2F{resource['id']}")
                task = self.api("wit/workitems/$Task", "POST", [
                    {"op": "add", "path": "/fields/System.Title",
                     "value": f"Policy validation fixture {self.run_id} {name}"},
                    {"op": "add", "path": "/relations/-", "value": {
                        "rel": "ArtifactLink", "url": url, "attributes": {"name": "Pull Request"},
                    }},
                ], content_type="application/json-patch+json")
                self.resources["workItems"].append(task["id"])
                self.checkpoint()
                return {"workItemId": task["id"], "evaluation": self.evaluation(name, entry, {"approved"})}
            self.check(f"pr/{name}/linked-work-item-allows", [ids[1]], "enforcement", work_item)
            def comment(name=name, entry=ids[2]):
                thread = self.api(self.pr_path(name) + "/threads", "POST", {
                    "comments": [{"parentCommentId": 0, "content": "Intentional unresolved policy-test comment.",
                                  "commentType": 1}], "status": 1,
                })
                self.resources["prs"][name]["threadId"] = thread["id"]
                self.checkpoint()
                blocked = self.evaluation(name, entry, {"rejected"})
                self.api(self.pr_path(name) + f"/threads/{thread['id']}", "PATCH", {"status": 2})
                allowed = self.evaluation(name, entry, {"approved"})
                return {"threadId": thread["id"], "unresolved": blocked, "resolved": allowed}
            self.check(f"pr/{name}/comment-unresolved-then-resolved", [ids[2]], "enforcement", comment)
            def statuses(name=name, entry=ids[5]):
                context = {"genre": "policy-lab", "name": "external-validation"}
                iterations = self.api(self.pr_path(name) + "/iterations")["value"]
                iteration = max(value["id"] for value in iterations)
                status_path = self.pr_path(name) + f"/iterations/{iteration}/statuses"
                self.api(status_path, "POST", {
                    "context": context, "state": "failed", "description": "Intentional negative test status.",
                })
                rejected = self.evaluation(name, entry, {"rejected"})
                posted = self.api(status_path, "POST", {
                    "context": context, "state": "succeeded", "description": "Controlled policy-test fixture passed.",
                })
                approved = self.evaluation(name, entry, {"approved"})
                return {"failed": rejected, "succeeded": approved, "statusId": posted["id"],
                        "iterationId": iteration,
                        "producer": "This test runner; scoped to this synthetic PR only."}
            self.check(f"pr/{name}/status-failed-then-succeeded", [ids[5]], "enforcement", statuses)
            def reviews():
                raise Blocked("Positive completion needs authenticated independent approvals from both named "
                              "reviewers. The runner will not impersonate them or bypass policies.")
            self.check(f"pr/{name}/independent-reviewer-positive-path", [ids[0], ids[6]], "enforcement", reviews)
            def merge():
                raise Blocked("Squash-only configuration verified, but alternative merge-strategy completion cannot "
                              "be isolated while independent-reviewer gates remain unsatisfied. No policy disabled.")
            self.check(f"pr/{name}/merge-strategy-enforcement", [ids[3]], "enforcement", merge)
        def control():
            self.create_pr("sample4")
            evaluations = self.evaluations("sample4")
            branch_types = {lab.rules.TYPES[k] for k in
                            ("reviewers", "workitems", "comments", "merge", "build", "status", "required")}
            assert not any(v["configuration"]["type"]["id"] in branch_types for v in evaluations.values()), (
                "Branch policies unexpectedly apply to the comparison branch."
            )
            self.api(self.pr_path("sample4"), "PATCH", {"status": "abandoned"})
            return {"pullRequestId": self.resources["prs"]["sample4"]["id"], "evaluations": evaluations,
                    "finalStatus": "abandoned"}
        self.check("pr/sample4/branch-policy-control", [], "enforcement", control)

    def build_tests(self):
        for name, entry in (("sample2", "ADO-036"), ("sample3", "ADO-023")):
            if name not in self.resources["prs"]:
                continue
            def build(name=name, entry=entry):
                evaluation = self.evaluation(name, entry, {"approved"}, timeout=180)
                definition = self.policy_state["pipelines"][name]["id"]
                branch = f"refs/pull/{self.resources['prs'][name]['id']}/merge"
                runs = self.api("build/builds", query={
                    "definitions": definition, "branchName": branch, "$top": 10,
                })["value"]
                matches = [r for r in runs if r.get("result") == "succeeded"
                           and r["reason"].lower() == "pullrequest"
                           and r["repository"]["id"] == self.repos[name]]
                assert matches, f"No successful automatic PR build found for {branch}."
                return {"evaluation": evaluation, "build": matches[0]}
            self.check(f"pr/{name}/automatic-build-validation", [entry], "enforcement", build)

    def organization_tests(self):
        observations = json.loads((lab.OUT / "organization-policy-observations.json").read_text())
        for entry in lab.ORG_PROPOSALS:
            if entry in EXCLUDED:
                continue
            def manual(entry=entry):
                observed = "On" if observations["values"][entry] else "Off"
                desired = lab.ORG_PROPOSALS[entry][0]
                raise Blocked(
                    f"No authenticated admin-page or policy API read-back. Last user screenshot "
                    f"({observations['providedAt']}) showed {observed}; target {desired}. "
                    "Not counted as a live pass. No invitations, SSH keys or organization settings changed."
                )
            self.check(f"organization/{entry}", [entry], "organization-live-check", manual)

    def preservation(self):
        def destination():
            assert self.client.policies(lab.TARGET) == self.baseline["policies"], "Destination policies changed."
            for repo, record in self.baseline["repositories"].items():
                current = self.client.refs(lab.TARGET, repo)
                assert current == lab.expected_destination_refs(repo, record["refs"]), (
                    f"Destination refs differ from the baseline and tracked fixtures in {repo}."
                )
                metadata = self.api(f"git/repositories/{repo}")
                assert metadata.get("defaultBranch") == record["metadata"].get("defaultBranch"), (
                    f"Default branch changed in {repo}."
                )
            return {"policiesUnchanged": True, "originalRefsUnchanged": True, "defaultsUnchanged": True}
        self.check("preservation/destination", [], "safety", destination)
        def source():
            assert self.client.policies(lab.copy_lab.SOURCE) == self.baseline["sourcePolicies"], (
                "Original source policies changed."
            )
            for name, record in self.copied["repositories"].items():
                assert self.client.refs(lab.copy_lab.SOURCE, record["source"]["id"]) == self.baseline["sourceRefs"][name], (
                    f"Original source refs changed in {name}."
                )
            return {"sourcePoliciesUnchanged": True, "sourceRefsUnchanged": True}
        self.check("preservation/source", [], "safety", source)

    def report(self):
        from openpyxl import load_workbook

        workbook = load_workbook(ROOT / "docs" / "Azure_DevOps_Policies.xlsx",
                                 read_only=True, data_only=True)
        rows = list(workbook["Policy Inventory"].values)[1:]
        assert len(rows) == 42 and len({r[0] for r in rows}) == 42
        behavior_counts = Counter()
        configuration_counts = Counter()
        with (self.out / "Policy-Test-Matrix.csv").open("w", newline="", encoding="utf-8-sig") as file:
            writer = csv.writer(file)
            writer.writerow(["Inventory ID", "Scope", "Policy", "In scope", "Configuration",
                             "Behavior", "Passed checks", "Failed/error checks", "Blocked checks", "Notes"])
            for row in rows:
                entry = row[0]
                if entry in EXCLUDED:
                    writer.writerow([entry, row[1], row[3], "No", "EXCLUDED", "EXCLUDED", 0, 0, 0, EXCLUDED[entry]])
                    continue
                selected = [r for r in self.results if entry in r["entries"]]
                configuration = [r for r in selected if r["level"] == "configuration"]
                behavior = [r for r in selected if r["level"] in ("enforcement", "combined-enforcement",
                                                                 "organization-live-check")]
                def status(results):
                    if not results:
                        return "NOT TESTED"
                    statuses = {r["status"] for r in results}
                    if statuses & {"FAIL", "ERROR"}:
                        return "FAIL"
                    if "BLOCKED" in statuses:
                        return "PARTIAL" if "PASS" in statuses else "BLOCKED"
                    return "PASS"
                counts = Counter(r["status"] for r in selected)
                behavior_counts[status(behavior)] += 1
                configuration_counts[status(configuration)] += 1
                notes = " | ".join(f"{r['name']}: {r.get('detail', r['status'])}" for r in selected)
                writer.writerow([entry, row[1], row[3], "Yes", status(configuration), status(behavior),
                                 counts["PASS"], counts["FAIL"] + counts["ERROR"], counts["BLOCKED"], notes])
        workbook.close()
        summary = {
            "runId": self.run_id, "destination": list(lab.TARGET), "inScopeEntries": 35,
            "excluded": EXCLUDED, "caseCounts": dict(Counter(r["status"] for r in self.results)),
            "inventoryBehaviorCounts": dict(behavior_counts),
            "inventoryConfigurationCounts": dict(configuration_counts),
            "caseCountsByLevel": {
                level: dict(Counter(r["status"] for r in self.results if r["level"] == level))
                for level in sorted({r["level"] for r in self.results})
            },
            "resources": self.resources,
            "limitations": [
                "Screenshot observations are not live organization-policy enforcement tests.",
                "Identical project and repository push policies prevent independent repository-layer attribution.",
                "Positive required-reviewer completion needs independent credentials; no impersonation or bypass used.",
                "PR fixtures and accepted test branches/work items are retained as reusable migration evidence.",
            ],
        }
        write_json(self.out / "summary.json", summary)
        print(json.dumps({"runId": self.run_id, "caseCounts": summary["caseCounts"],
                          "matrix": str(self.out / "Policy-Test-Matrix.csv")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description="Run isolated ADO policy enforcement checks without bypasses.")
    parser.add_argument("--run-id", help="Resume the same run without duplicating completed checks.")
    parser.add_argument("--retry-check", action="append", default=[],
                        help="Retry a named read-only, vote, or push check and retain its previous evidence.")
    args = parser.parse_args()
    if args.retry_check and not args.run_id:
        parser.error("--retry-check requires an existing --run-id.")
    suite = Suite(args.run_id)
    if args.retry_check:
        selected = set(args.retry_check)
        known = {r["name"] for r in suite.results}
        if selected - known:
            parser.error(f"Unknown checks: {sorted(selected - known)}")
        for name in selected:
            retryable = (name.startswith(("configuration/", "effective-scope/", "preservation/", "push/"))
                         or name.endswith(("/minimum-reviewers-blocks",
                                           "/single-creator-vote-insufficient-for-two-approvers",
                                           "/automatic-build-validation")))
            if not retryable:
                parser.error(f"Stateful check cannot be individually retried: {name}; start a fresh run.")
        path = suite.out / "attempt-history.json"
        history = json.loads(path.read_text()) if path.exists() else []
        history.extend(r for r in suite.results if r["name"] in selected)
        write_json(path, history)
        suite.results = [r for r in suite.results if r["name"] not in selected]
        suite.checkpoint()
    suite.configuration()
    suite.push_tests()
    suite.pr_tests()
    suite.build_tests()
    suite.organization_tests()
    suite.preservation()
    suite.report()
    if any(result["status"] in ("FAIL", "ERROR") for result in suite.results):
        raise SystemExit(1)
    if any(result["status"] == "BLOCKED" for result in suite.results):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
