import argparse
import csv
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ORG = "https://dev.azure.com/contosodevopstest"
SOURCE_PROJECT = "027fa3fb-f624-4754-9d1f-639baea883a2"
PROJECT = "85357c78-817f-44fd-b5c7-d77a97d1c650"
PROJECT_NAME = "ado2gh-policy-lab"
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output" / PROJECT_NAME
REPOS = {
    "sample2": ("", "policy-direct/main"),
    "sample3": ("", "policy-lab/main"),
    "sample4": ("", "policy-control/main"),
}
REVIEWERS = [
    "5250e609-5e8d-6403-9e6a-7f627014779e",
    "3a47de95-f9c0-653b-a9df-0df1690b7e73",
]
TYPES = {
    "email": "77ed4bd3-b063-4689-934a-175e4d0a78d7",
    "path": "51c78909-e838-41a2-9496-c647091e3c61",
    "case": "7ed39669-655c-494e-b4a0-a08b4da0fcce",
    "reserved": "db2b9b4c-180d-4529-9701-01541d19f36b",
    "length": "001a79cf-fda1-4c4e-9e7c-bac40ee5ead8",
    "size": "2e26e725-8201-4edd-8bf5-978563c34a80",
    "reviewers": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd",
    "workitems": "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e",
    "comments": "c6a1889d-b943-4856-b76f-9e46bb6b0df2",
    "merge": "fa4e907d-c16b-4a4c-9dfa-4916e5d171ab",
    "build": "0609b952-1397-4640-95ec-e00a01b2c241",
    "status": "cbdc66da-9728-4af8-aada-9a5a32e4a226",
    "required": "fd2167ab-b0be-447a-8ec8-39368250530e",
}


def save(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / name
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(target)


class Ado:
    def __init__(self):
        az = shutil.which("az")
        if not az:
            raise RuntimeError("Azure CLI is required; sign in with az login first.")
        result = subprocess.run(
            [az, "account", "get-access-token", "--resource",
             "499b84ac-1321-427f-aa17-267ca6975798", "--output", "json"],
            capture_output=True, text=True, check=True,
        )
        self.token = json.loads(result.stdout)["accessToken"]

    def call(self, path, method="GET", body=None, query=None, project=PROJECT):
        if method != "GET" and project != PROJECT:
            raise RuntimeError("Writes are permitted only in the isolated destination project.")
        params = {"api-version": "7.1", **(query or {})}
        url = f"{ORG}/{project}/_apis/{path}?{urllib.parse.urlencode(params)}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                if "json" not in response.headers.get("Content-Type", ""):
                    raise RuntimeError(f"{method} {path}: expected JSON, received a sign-in or HTML page")
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {detail}") from error

    def policies(self, query=None, project=PROJECT):
        values = []
        continuation = None
        while True:
            params = {"$top": 100, **(query or {})}
            if continuation is not None:
                params["continuationToken"] = continuation
            page = self.call("policy/configurations", query=params, project=project)["value"]
            values.extend(page)
            if len(page) < 100:
                return values
            continuation = page[-1]["id"]


def repository_refs(ado, repo, project):
    refs = ado.call(f"git/repositories/{repo}/refs", project=project)["value"]
    return {ref["name"]: ref["objectId"] for ref in refs
            if ref["name"].startswith(("refs/heads/", "refs/tags/"))}


def copy_source(ado):
    state_file = OUT / "copy-state.json"
    if state_file.exists():
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if state["destinationProject"] != PROJECT:
            raise RuntimeError("Copy state belongs to a different destination.")
    else:
        source = ado.call("git/repositories", project=SOURCE_PROJECT)["value"]
        state = {
            "sourceProject": SOURCE_PROJECT, "destinationProject": PROJECT,
            "capturedAt": datetime.now(timezone.utc).isoformat(),
            "sourcePolicies": ado.policies(project=SOURCE_PROJECT),
            "repositories": {
                repo["name"]: {
                    "source": repo,
                    "sourceRefs": repository_refs(ado, repo["id"], SOURCE_PROJECT),
                } for repo in source
            },
        }
        save("copy-state.json", state)
    git_env = os.environ.copy()
    git_env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://dev.azure.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {ado.token}",
    })

    def git(*args):
        result = subprocess.run(["git", "--no-pager", *args], env=git_env,
                                text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(f"Git operation failed ({result.returncode}): {result.stderr}")
        return result.stdout

    for name, record in state["repositories"].items():
        if "destination" not in record:
            existing = ado.call("git/repositories")["value"]
            if any(repo["name"] == name for repo in existing):
                raise RuntimeError(f"Untracked destination repository {name} already exists; refusing to overwrite.")
            if name == "sample-repo-testing":
                initial = next((repo for repo in existing if repo["name"] == PROJECT_NAME), None)
                if initial is None or repository_refs(ado, initial["id"], PROJECT):
                    raise RuntimeError("Expected the empty auto-created destination repository.")
                destination = ado.call(f"git/repositories/{initial['id']}", "PATCH", {"name": name})
            else:
                destination = ado.call("git/repositories", "POST", {
                    "name": name, "project": {"id": PROJECT},
                })
            record["destination"] = destination
            save("copy-state.json", state)
        destination = record["destination"]
        if not record.get("copied"):
            current = repository_refs(ado, destination["id"], PROJECT)
            if any(record["sourceRefs"].get(ref) != sha for ref, sha in current.items()):
                raise RuntimeError(f"{name}: destination contains unexpected refs; refusing to overwrite.")
            if record["sourceRefs"]:
                clone = OUT / "git-copies" / f"{name}.git"
                clone.parent.mkdir(parents=True, exist_ok=True)
                if not clone.exists():
                    git("clone", "--bare", record["source"]["remoteUrl"], str(clone))
                if any(ref.startswith("refs/heads/") for ref in record["sourceRefs"]):
                    git("-C", str(clone), "push", destination["remoteUrl"], "refs/heads/*:refs/heads/*")
                if any(ref.startswith("refs/tags/") for ref in record["sourceRefs"]):
                    git("-C", str(clone), "push", destination["remoteUrl"], "refs/tags/*:refs/tags/*")
                default = record["source"].get("defaultBranch")
                if default:
                    ado.call(f"git/repositories/{destination['id']}", "PATCH", {"defaultBranch": default})
            actual = repository_refs(ado, destination["id"], PROJECT)
            if actual != record["sourceRefs"]:
                raise RuntimeError(f"{name}: copied heads/tags differ from the source snapshot.")
            record["copied"] = True
            record["verifiedRefs"] = actual
            save("copy-state.json", state)
            print(f"Copied {name}: {len(actual)} branches/tags, preserving object IDs.", flush=True)
    verify_source(ado, state)
    state["verifiedAt"] = datetime.now(timezone.utc).isoformat()
    save("copy-state.json", state)
    print(f"Verified {len(state['repositories'])} copied repositories; source unchanged.")


def verify_source(ado, state):
    if ado.policies(project=SOURCE_PROJECT) != state["sourcePolicies"]:
        raise RuntimeError("Source policies changed since the copy snapshot.")
    for name, record in state["repositories"].items():
        if repository_refs(ado, record["source"]["id"], SOURCE_PROJECT) != record["sourceRefs"]:
            raise RuntimeError(f"{name}: source refs changed since the copy snapshot.")
        actual = ado.call(f"git/repositories/{record['source']['id']}", project=SOURCE_PROJECT)
        if actual.get("defaultBranch") != record["source"].get("defaultBranch"):
            raise RuntimeError(f"{name}: source default branch changed.")


def load_targets():
    state = json.loads((OUT / "copy-state.json").read_text(encoding="utf-8"))
    if state["destinationProject"] != PROJECT or not state.get("verifiedAt"):
        raise RuntimeError("Repository copies must be verified before configuring policies.")
    for name, (_, branch) in list(REPOS.items()):
        record = state["repositories"][name]
        if not record.get("copied"):
            raise RuntimeError(f"{name} has not been copied.")
        REPOS[name] = (record["destination"]["id"], branch)


def baseline(ado):
    file = OUT / "baseline.json"
    if file.exists():
        snapshot = json.loads(file.read_text(encoding="utf-8"))
        if snapshot["project"] != PROJECT:
            raise RuntimeError("Baseline belongs to a different project.")
        return snapshot
    snapshot = {
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "organization": ORG, "project": PROJECT, "policies": ado.policies(),
        "repositories": {},
    }
    for name, (repo, branch) in REPOS.items():
        metadata = ado.call(f"git/repositories/{repo}")
        refs = ado.call(f"git/repositories/{repo}/refs", query={"filter": "heads/"})["value"]
        if any(ref["name"] == f"refs/heads/{branch}" for ref in refs):
            raise RuntimeError(f"Refusing to reuse pre-existing lab branch in {name}.")
        snapshot["repositories"][name] = {"metadata": metadata, "refs": refs}
    save("baseline.json", snapshot)
    return snapshot


def push_specs():
    return [
        ("email", {"authorEmailPatterns": ["*@MngEnvMCAP267305.onmicrosoft.com"]}),
        ("path", {"filenamePatterns": ["/policy-lab-blocked/*", "*/policy-lab-blocked/*"]}),
        ("case", {"enforceConsistentCase": True}),
        ("reserved", {}),
        ("length", {"maxPathLength": 180}),
        ("size", {"maximumGitBlobSizeInBytes": 1048576, "useUncompressedSize": True}),
    ]


def branch_specs(pipeline, reviewer_ids=None):
    return [
        ("reviewers", {"minimumApproverCount": 2, "creatorVoteCounts": False,
                       "allowDownvotes": False, "resetOnSourcePush": True}),
        ("workitems", {}),
        ("comments", {}),
        ("merge", {"allowSquash": True, "allowRebase": False,
                   "allowRebaseMerge": False, "allowNoFastForward": False}),
        ("build", {"buildDefinitionId": pipeline, "manualQueueOnly": False,
                   "queueOnSourceUpdateOnly": False, "validDuration": 0,
                   "displayName": "Policy lab fixture validation"}),
        ("status", {"statusGenre": "policy-lab", "statusName": "external-validation",
                    "invalidateOnSourceUpdate": True, "policyApplicability": 0}),
        ("required", {"requiredReviewerIds": REVIEWERS if reviewer_ids is None else reviewer_ids,
                      "message": "Policy migration lab: both named reviewers must approve."}),
    ]


def desired_policies(state, repositories=None, reviewer_ids=None):
    repositories = REPOS if repositories is None else repositories
    direct = repositories["sample2"][0]
    result = []
    for first_id, scope in [(13, [{"repositoryId": None}]),
                            (26, [{"repositoryId": direct}])]:
        for offset, (kind, settings) in enumerate(push_specs()):
            result.append((f"ADO-{first_id + offset:03d}", kind, {
                "isEnabled": True, "isBlocking": True, "type": {"id": TYPES[kind]},
                "settings": {**settings, "scope": scope},
            }))
    scopes = [
        (19, "sample3", [{"repositoryId": None, "refName": "refs/heads/policy-lab/",
                         "matchKind": "Prefix"}]),
        (32, "sample2", [{"repositoryId": direct, "refName": "refs/heads/policy-direct/main",
                         "matchKind": "Exact"}]),
    ]
    for first_id, name, scope in scopes:
        for offset, (kind, settings) in enumerate(branch_specs(state["pipelines"][name]["id"], reviewer_ids)):
            result.append((f"ADO-{first_id + offset:03d}", kind, {
                "isEnabled": True, "isBlocking": True, "type": {"id": TYPES[kind]},
                "settings": {**settings, "scope": scope},
            }))
    return result


PIPELINE = """trigger: none
pr: none
pool:
  vmImage: ubuntu-latest
steps:
- checkout: self
- script: |
    python3 -c "import json; from pathlib import Path; p=Path('policy-lab-fixture.json'); d=json.loads(p.read_text()); assert d['purpose']=='ado2gh-policy-lab'; assert d['repository'] in ('sample2','sample3'); print('Policy lab fixture validated')"
  displayName: Validate policy lab fixture
"""


def policy_mismatches(actual, expected):
    mismatches = []
    for key in ("isEnabled", "isBlocking"):
        if actual[key] != expected[key]:
            mismatches.append(key)
    if actual["type"]["id"] != expected["type"]["id"]:
        mismatches.append("type")
    for key, value in expected["settings"].items():
        actual_value = actual["settings"].get(key)
        if key == "scope":
            if not isinstance(actual_value, list):
                mismatches.append("settings.scope")
                continue
            actual_value = [{**scope, "repositoryId": scope.get("repositoryId") or None}
                            for scope in actual_value]
            value = [{**scope, "repositoryId": scope.get("repositoryId") or None}
                     for scope in value]
        # The merge-policy API omits disabled strategy booleans in its response.
        if (expected["type"]["id"] == TYPES["merge"]
                and key in ("allowRebase", "allowRebaseMerge", "allowNoFastForward")
                and key not in actual["settings"]):
            actual_value = False
        if actual_value != value:
            mismatches.append(f"settings.{key}")
    return mismatches


def setup(ado, original):
    state_file = OUT / "state.json"
    state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {
        "branches": {}, "pipelines": {}, "policies": {},
    }
    queues = ado.call("distributedtask/queues")["value"]
    queue = next((q for q in queues if q["name"] == "Azure Pipelines"), None)
    if queue is None:
        raise RuntimeError("The new project has no Azure Pipelines agent queue.")
    for name, (repo, branch) in REPOS.items():
        if name not in state["branches"]:
            refs = original["repositories"][name]["refs"]
            default = original["repositories"][name]["metadata"]["defaultBranch"]
            head = next(ref["objectId"] for ref in refs if ref["name"] == default)
            files = {
                "/policy-lab-fixture.json": json.dumps({
                    "purpose": "ado2gh-policy-lab", "repository": name,
                    "role": {"sample2": "explicit", "sample3": "project", "sample4": "comparison"}[name],
                }, indent=2) + "\n",
            }
            if name != "sample4":
                files["/azure-pipelines-policy-lab.yml"] = PIPELINE
            push = ado.call(f"git/repositories/{repo}/pushes", "POST", {
                "refUpdates": [{"name": f"refs/heads/{branch}", "oldObjectId": "0" * 40}],
                "commits": [{
                    "comment": (
                        "Add isolated ADO policy migration lab fixtures\n\n"
                        "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
                    ),
                    "parents": [head],
                    "author": {"name": "Policy Lab", "email": "admin@MngEnvMCAP267305.onmicrosoft.com"},
                    "changes": [
                        {"changeType": "add", "item": {"path": path},
                         "newContent": {"content": content, "contentType": "rawtext"}}
                        for path, content in files.items()
                    ],
                }],
            })
            state["branches"][name] = {"ref": f"refs/heads/{branch}", "pushId": push["pushId"]}
            save("state.json", state)
            print(f"Created {name}: {branch}", flush=True)
        if name != "sample4" and name not in state["pipelines"]:
            definition = ado.call("build/definitions", "POST", {
                "name": f"policy-lab-{name}", "path": "\\policy-lab", "type": "build",
                "queue": {"id": queue["id"]},
                "repository": {"id": repo, "name": name, "type": "TfsGit",
                               "url": f"{ORG}/{PROJECT_NAME}/_git/{name}",
                               "defaultBranch": f"refs/heads/{branch}"},
                "process": {"type": 2, "yamlFilename": "azure-pipelines-policy-lab.yml"},
                "triggers": [],
            })
            state["pipelines"][name] = {"id": definition["id"], "name": definition["name"]}
            save("state.json", state)
            print(f"Created pipeline {definition['id']} for {name}", flush=True)
    existing = ado.policies()
    for entry, kind, payload in desired_policies(state):
        record = state["policies"].get(entry)
        if record and record["expected"] != payload:
            actual = ado.call(f"policy/configurations/{record['id']}")
            mismatches = policy_mismatches(actual, payload)
            if mismatches:
                raise RuntimeError(f"{entry}: changed desired settings require review: {mismatches}")
            record["expected"] = payload
            save("state.json", state)
        if entry not in state["policies"]:
            conflicts = [
                p for p in existing
                if p["type"]["id"] == payload["type"]["id"]
                and p["settings"].get("scope") == payload["settings"]["scope"]
            ]
            if conflicts:
                raise RuntimeError(f"{entry}: scope already has policy IDs {[p['id'] for p in conflicts]}; refusing to overwrite.")
            policy = ado.call("policy/configurations", "POST", payload)
            state["policies"][entry] = {"id": policy["id"], "kind": kind, "expected": payload}
            save("state.json", state)
            print(f"Configured {entry}: {kind} (policy {policy['id']})", flush=True)
    return state


def verify(ado, original, state):
    errors = []
    evidence = {"verifiedAt": datetime.now(timezone.utc).isoformat(),
                "policies": {}, "effectivePolicies": {}, "pipelines": {}, "buildRuns": {}}
    current = {p["id"]: p for p in ado.policies()}
    for before in original["policies"]:
        after = current.get(before["id"])
        if after is None or any(after[key] != before[key] for key in
                                ("revision", "isEnabled", "isBlocking", "type", "settings")):
            errors.append(f"Pre-existing policy {before['id']} changed.")
    for entry, record in state["policies"].items():
        actual = ado.call(f"policy/configurations/{record['id']}")
        expected = record["expected"]
        mismatches = policy_mismatches(actual, expected)
        evidence["policies"][entry] = {"policy": actual, "mismatches": mismatches}
        if mismatches:
            errors.append(f"{entry}: read-back mismatch: {mismatches}")
    for name, (repo, branch) in REPOS.items():
        metadata = ado.call(f"git/repositories/{repo}")
        if metadata["defaultBranch"] != original["repositories"][name]["metadata"]["defaultBranch"]:
            errors.append(f"{name}: default branch changed.")
        refs = ado.call(f"git/repositories/{repo}/refs", query={"filter": "heads/"})["value"]
        by_name = {ref["name"]: ref["objectId"] for ref in refs}
        for ref in original["repositories"][name]["refs"]:
            if by_name.get(ref["name"]) != ref["objectId"]:
                errors.append(f"{name}: pre-existing ref {ref['name']} changed.")
        if f"refs/heads/{branch}" not in by_name:
            errors.append(f"{name}: lab branch missing.")
        evidence["effectivePolicies"][name] = ado.call("git/policy/configurations", query={
            "repositoryId": repo, "refName": f"refs/heads/{branch}", "$top": 100,
        })
        entries = {
            "sample2": list(range(13, 19)) + list(range(26, 39)),
            "sample3": list(range(13, 26)),
            "sample4": list(range(13, 19)),
        }[name]
        expected_ids = {state["policies"][f"ADO-{number:03d}"]["id"] for number in entries}
        actual_ids = {p["id"] for p in evidence["effectivePolicies"][name]["value"]}
        if actual_ids != expected_ids:
            errors.append(f"{name}: effective policy IDs differ: expected {sorted(expected_ids)}, got {sorted(actual_ids)}.")
    for name, pipeline in state["pipelines"].items():
        actual = ado.call(f"build/definitions/{pipeline['id']}")
        evidence["pipelines"][name] = actual
        if actual["repository"]["type"] != "TfsGit" or actual["repository"]["id"] != REPOS[name][0]:
            errors.append(f"{name}: pipeline is not backed by the correct ADO repository.")
        evidence["buildRuns"][name] = ado.call("build/builds", query={
            "definitions": pipeline["id"], "branchName": f"refs/heads/{REPOS[name][1]}",
            "$top": 1,
        })["value"]
    if len(state["policies"]) != 26:
        errors.append(f"Expected 26 configured entries, found {len(state['policies'])}.")
    copy_state = json.loads((OUT / "copy-state.json").read_text(encoding="utf-8"))
    verify_source(ado, copy_state)
    for name, record in copy_state["repositories"].items():
        if name not in REPOS:
            destination = record["destination"]["id"]
            if repository_refs(ado, destination, PROJECT) != record["sourceRefs"]:
                errors.append(f"{name}: untouched destination refs differ from the copied source.")
            metadata = ado.call(f"git/repositories/{destination}")
            if metadata.get("defaultBranch") != record["source"].get("defaultBranch"):
                errors.append(f"{name}: untouched destination default branch changed.")
    evidence["errors"] = errors
    save("verification.json", evidence)
    write_report(state, evidence)
    if errors:
        raise RuntimeError("\n".join(errors))
    print("Verified 26 persisted policy configurations; existing policies, branches and defaults unchanged.")
    for name, data in evidence["effectivePolicies"].items():
        print(f"{name}: {len(data['value'])} effective policies reported by Git API")


def write_report(state, evidence, blocker="Setup has not completed."):
    from openpyxl import load_workbook

    workbook = load_workbook(ROOT / "docs" / "Azure_DevOps_Policies.xlsx", read_only=True, data_only=True)
    rows = list(workbook["Policy Inventory"].values)[1:]
    if len(rows) != 42 or len({row[0] for row in rows}) != 42:
        raise RuntimeError("Source Policy Inventory no longer contains 42 unique entries.")
    with (OUT / "Policy-Assessment.csv").open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(["Inventory ID", "Scope", "Policy", "Configuration status",
                         "ADO policy ID", "Configured settings", "Enforcement status", "Notes", "Microsoft source"])
        for row in rows:
            entry = row[0]
            record = state["policies"].get(entry)
            if record:
                result = evidence["policies"][entry]
                status = "Verified persisted" if not result["mismatches"] else "Read-back mismatch"
                notes = "Explicit sample2 repository/branch configuration."
                if 13 <= int(entry[4:]) <= 18:
                    notes = "All Repositories push configuration; Git policy API reports these IDs effective on all three existing copied lab repositories."
                elif 19 <= int(entry[4:]) <= 25:
                    notes = "Cross-repository policy; refs/heads/policy-lab/ prefix; repositoryId=null."
                enforcement = "Deferred to next-phase behavioral test suite"
                if record["kind"] == "status":
                    enforcement = "Pending status producer and next-phase tests"
                    notes += " Required context policy-lab/external-validation; no success status was fabricated."
                elif record["kind"] == "build":
                    name = "sample3" if entry == "ADO-023" else "sample2"
                    runs = evidence["buildRuns"][name]
                    if runs and runs[0].get("result") == "succeeded":
                        enforcement = f"Pipeline smoke run {runs[0]['id']} succeeded; PR enforcement tests deferred"
                    else:
                        enforcement = "Pipeline dependency configured; successful execution not yet verified"
                writer.writerow([entry, row[1], row[3], status, record["id"],
                                 json.dumps(record["expected"]["settings"]), enforcement, notes, row[9]])
            elif entry.startswith("ADO-") and 13 <= int(entry[4:]) <= 38:
                writer.writerow([entry, row[1], row[3], "Blocked; not configured", "", "",
                                 "Not tested", blocker, row[9]])
            else:
                notes = "Not changed: organization/tenant controls excluded by user approval; current value not verified."
                if entry == "ADO-006":
                    notes += " Public-project capability is retired; do not enable for this lab."
                writer.writerow([entry, row[1], row[3], "Outside approved scope", "", "",
                                 "Not tested", notes, row[9]])
    workbook.close()


def main():
    parser = argparse.ArgumentParser(description="Configure only the approved contosodevopstest policy lab.")
    parser.add_argument("mode", choices=["copy", "assess", "baseline", "setup", "verify"])
    parser.add_argument("--blocker", default="Setup has not completed.")
    args = parser.parse_args()
    ado = Ado()
    if args.mode == "copy":
        copy_source(ado)
        return
    load_targets()
    original = baseline(ado)
    if args.mode == "assess":
        state_file = OUT / "state.json"
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {
            "branches": {}, "pipelines": {}, "policies": {},
        }
        if state["policies"]:
            raise RuntimeError("Use verify after policy creation; assess must not imply unverified success.")
        current = {p["id"]: p for p in ado.policies()}
        for before in original["policies"]:
            after = current.get(before["id"])
            if after is None or any(after[key] != before[key] for key in
                                    ("revision", "isEnabled", "isBlocking", "settings")):
                raise RuntimeError(f"Pre-existing policy {before['id']} changed since baseline.")
        write_report(state, {"policies": {}}, args.blocker)
        print("Saved 42-entry assessment: 26 blocked configurations; 16 outside approved scope.")
        return
    if args.mode == "baseline":
        print(f"Saved baseline: {len(original['policies'])} existing policies; 3 repositories.")
        return
    if args.mode == "setup":
        state = setup(ado, original)
    else:
        state = json.loads((OUT / "state.json").read_text(encoding="utf-8"))
    verify(ado, original, state)


if __name__ == "__main__":
    main()
