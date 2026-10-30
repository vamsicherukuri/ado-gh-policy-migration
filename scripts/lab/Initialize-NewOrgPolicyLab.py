import argparse
import csv
import importlib
import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

rules = importlib.import_module("Initialize-AdoPolicyLab")
copy_lab = importlib.import_module("Copy-AdoPolicyLabRepositories")
OUT = copy_lab.OUT
TARGET = copy_lab.DESTINATION
ORG = f"https://dev.azure.com/{TARGET[0]}"
BRANCHES = {
    "sample2": "refs/heads/policy-direct/main",
    "sample3": "refs/heads/policy-lab/main",
    "sample4": "refs/heads/policy-control/main",
}
EMAILS = ("kiran@MngEnvMCAP267305.onmicrosoft.com",
          "kiranch@MngEnvMCAP267305.onmicrosoft.com")
ORG_PROPOSALS = {
    "ADO-001": ("Off", "Disable legacy third-party ADO OAuth access; Entra OAuth is separate."),
    "ADO-002": ("On", "Allow SSH for lab authentication tests."),
    "ADO-003": ("On", "Reject expired SSH keys."),
    "ADO-004": ("On, if available", "Enable audit collection in this Entra-backed organization."),
    "ADO-005": ("Leave unchanged until migration PAT is prepared",
                "Review PAT creation restrictions and exemptions before the ADO2GH phase."),
    "ADO-006": ("Do not enable; retired capability", "No public project is needed."),
    "ADO-007": ("On", "Enable public package-registry protections."),
    "ADO-008": ("Leave unchanged pending Conditional Access review",
                "Do not risk blocking non-interactive access without checking tenant CA rules."),
    "ADO-009": ("Off", "The approved lab reviewers are tenant members, not external guests."),
    "ADO-010": ("Off", "Restrict invitations to organization administrators."),
    "ADO-011": ("Off", "No internal access-request URL is required for this lab."),
    "ADO-012": ("Off", "Disable Microsoft feedback collection for the lab."),
}


def save(name, value):
    copy_lab.save(name, value)


def cli(*args):
    result = subprocess.run([shutil.which("az"), *args, "--organization", ORG, "--output", "json"],
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def expected_destination_refs(repository, original):
    expected = dict(original)
    for path in sorted((OUT / "policy-tests").glob("*/resources.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if tuple(manifest["destination"]) != TARGET:
            raise RuntimeError(f"Test fixture manifest belongs to another destination: {path}")
        prefix = f"refs/heads/policy-tests/{path.parent.name}/"
        for ref, sha in manifest["refs"].get(repository, {}).items():
            if not ref.startswith(prefix):
                raise RuntimeError(f"Unowned test fixture ref in {path}: {ref}")
            if ref in expected and expected[ref] != sha:
                raise RuntimeError(f"Test manifest would overwrite an existing ref: {ref}")
            expected[ref] = sha
    return expected


def preflight(client, copied):
    if tuple(copied["destination"]) != TARGET or not copied.get("verifiedAt"):
        raise RuntimeError("The three repository copies must be verified first.")
    for name, record in copied["repositories"].items():
        repository = record["destination"]["id"]
        if client.refs(TARGET, repository) != expected_destination_refs(repository, record["sourceRefs"]):
            raise RuntimeError(f"{name}: copied destination refs changed.")
    if client.policies(copy_lab.SOURCE) != copied["sourcePolicies"]:
        raise RuntimeError("Source policy configuration changed.")
    users = cli("devops", "user", "list")["items"]
    identities = {}
    for email in EMAILS:
        match = next((u for u in users if u["user"]["principalName"].lower() == email.lower()), None)
        if match is None:
            raise RuntimeError(f"Approved reviewer is not an organization member: {email}")
        identities[email] = match["id"]
    groups = cli("devops", "security", "group", "list", "--project", TARGET[1])["graphGroups"]
    contributors = next(g for g in groups if g["displayName"] == "Contributors")
    members = cli("devops", "security", "group", "membership", "list",
                  "--id", contributors["descriptor"], "--relationship", "members")
    emails = {member.get("principalName", "").lower() for member in members.values()}
    if not all(email.lower() in emails for email in EMAILS):
        raise RuntimeError("Both approved reviewers must belong to project1 Contributors.")
    save("reviewer-membership.json", {"identities": identities, "members": members})
    return list(identities.values())


def baseline(client):
    path = OUT / "policy-baseline.json"
    if path.exists():
        result = json.loads(path.read_text(encoding="utf-8"))
        if tuple(result["destination"]) != TARGET:
            raise RuntimeError("Policy baseline belongs to a different destination.")
        return result
    repositories = client.call(TARGET, "git/repositories")["value"]
    result = {
        "capturedAt": datetime.now(timezone.utc).isoformat(), "destination": TARGET,
        "policies": client.policies(TARGET),
        "repositories": {
            repo["id"]: {"metadata": repo, "refs": client.refs(TARGET, repo["id"])}
            for repo in repositories
        },
    }
    save("policy-baseline.json", result)
    return result


def setup(client, copied, repositories, reviewer_ids, state):
    queues = client.call(TARGET, "distributedtask/queues")["value"]
    queue = next((q for q in queues if q["name"] == "Azure Pipelines"), None)
    if queue is None:
        raise RuntimeError("No Azure Pipelines queue is available in project1.")
    available = {p["id"] for p in client.call(TARGET, "policy/types")["value"]}
    if not set(rules.TYPES.values()).issubset(available):
        raise RuntimeError("The destination does not expose all 13 required policy types.")
    definitions = client.call(TARGET, "build/definitions")["value"]
    for name in ("sample2", "sample3"):
        repo = repositories[name][0]
        fixture = client.call(TARGET, f"git/repositories/{repo}/items", query={
            "path": "/policy-lab-fixture.json", "includeContent": "true",
            "versionDescriptor.versionType": "branch",
            "versionDescriptor.version": BRANCHES[name].removeprefix("refs/heads/"),
        })
        contents = json.loads(fixture["content"])
        if contents.get("purpose") != "ado2gh-policy-lab" or contents.get("repository") != name:
            raise RuntimeError(f"{name}: invalid copied lab fixture.")
        yaml = client.call(TARGET, f"git/repositories/{repo}/items", query={
            "path": "/azure-pipelines-policy-lab.yml", "includeContent": "true",
            "versionDescriptor.versionType": "branch",
            "versionDescriptor.version": BRANCHES[name].removeprefix("refs/heads/"),
        })
        if yaml["content"] != rules.PIPELINE:
            raise RuntimeError(f"{name}: copied validation pipeline differs from the approved fixture.")
        if name not in state["pipelines"]:
            pipeline_name = f"policy-lab-{name}"
            if any(d["name"] == pipeline_name for d in definitions):
                raise RuntimeError(f"Untracked pipeline {pipeline_name} exists; refusing to duplicate it.")
            actual = client.call(TARGET, "build/definitions", "POST", {
                "name": pipeline_name, "path": "\\policy-lab", "type": "build",
                "queue": {"id": queue["id"]},
                "repository": {
                    "id": repo, "name": name, "type": "TfsGit",
                    "url": copied["repositories"][name]["destination"]["remoteUrl"],
                    "defaultBranch": BRANCHES[name],
                },
                "process": {"type": 2, "yamlFilename": "azure-pipelines-policy-lab.yml"},
                "triggers": [],
            })
            state["pipelines"][name] = {"id": actual["id"], "name": actual["name"]}
            save("policy-state.json", state)
            print(f"Created {pipeline_name}: pipeline {actual['id']}", flush=True)
    existing = client.policies(TARGET)
    for entry, kind, payload in rules.desired_policies(state, repositories, reviewer_ids):
        if entry in state["policies"]:
            if state["policies"][entry]["expected"] != payload:
                raise RuntimeError(f"{entry}: desired configuration changed; explicit review is required.")
            continue
        if any(p["type"]["id"] == payload["type"]["id"]
               and p["settings"].get("scope") == payload["settings"]["scope"] for p in existing):
            raise RuntimeError(f"{entry}: an untracked policy exists at this scope; refusing to duplicate it.")
        actual = client.call(TARGET, "policy/configurations", "POST", payload)
        state["policies"][entry] = {"id": actual["id"], "kind": kind, "expected": payload}
        save("policy-state.json", state)
        print(f"Configured {entry}: policy {actual['id']} ({kind})", flush=True)


def smoke(client, state):
    for name, pipeline in state["pipelines"].items():
        if name not in state["smokeBuilds"]:
            build = client.call(TARGET, "build/builds", "POST", {
                "definition": {"id": pipeline["id"]}, "sourceBranch": BRANCHES[name],
            })
            state["smokeBuilds"][name] = build["id"]
            save("policy-state.json", state)
            print(f"Queued {name} smoke build {build['id']}", flush=True)
    deadline = time.monotonic() + 120
    while True:
        builds = {name: client.call(TARGET, f"build/builds/{build_id}")
                  for name, build_id in state["smokeBuilds"].items()}
        if all(build["status"] == "completed" for build in builds.values()) or time.monotonic() >= deadline:
            return
        time.sleep(5)


def retry_smoke(client, state):
    for name, build_id in list(state["smokeBuilds"].items()):
        build = client.call(TARGET, f"build/builds/{build_id}")
        if build.get("result") == "succeeded":
            continue
        timeline = client.call(TARGET, f"build/builds/{build_id}/timeline")
        state.setdefault("smokeHistory", []).append({"name": name, "build": build, "timeline": timeline})
        save("policy-state.json", state)
        if build["status"] != "completed":
            client.call(TARGET, f"build/builds/{build_id}", "PATCH", {"status": "cancelling"})
        del state["smokeBuilds"][name]
        save("policy-state.json", state)
    smoke(client, state)


def verify(client, copied, original, repositories, state):
    evidence = {"verifiedAt": datetime.now(timezone.utc).isoformat(), "destination": TARGET,
                "policies": {}, "effectivePolicies": {}, "buildRuns": {}, "errors": []}
    current = {p["id"]: p for p in client.policies(TARGET)}
    for policy in original["policies"]:
        if current.get(policy["id"]) != policy:
            evidence["errors"].append(f"Pre-existing destination policy {policy['id']} changed.")
    for entry, record in state["policies"].items():
        actual = client.call(TARGET, f"policy/configurations/{record['id']}")
        mismatches = rules.policy_mismatches(actual, record["expected"])
        evidence["policies"][entry] = {"policy": actual, "mismatches": mismatches}
        if mismatches:
            evidence["errors"].append(f"{entry}: {mismatches}")
    if len(state["policies"]) != 26:
        evidence["errors"].append(f"Expected 26 policies, got {len(state['policies'])}.")
    expected_all = {p["id"] for p in original["policies"]} | {
        p["id"] for p in state["policies"].values()
    }
    if set(current) != expected_all:
        evidence["errors"].append("Unexpected destination policy IDs were found.")
    for repo, record in original["repositories"].items():
        metadata = client.call(TARGET, f"git/repositories/{repo}")
        if metadata.get("defaultBranch") != record["metadata"].get("defaultBranch"):
            evidence["errors"].append(f"Destination default branch changed: {metadata['name']}.")
        if client.refs(TARGET, repo) != expected_destination_refs(repo, record["refs"]):
            evidence["errors"].append(f"Destination refs changed: {metadata['name']}.")
    for name, (repo, _) in repositories.items():
        effective = client.call(TARGET, "git/policy/configurations", query={
            "repositoryId": repo, "refName": BRANCHES[name], "$top": 100,
        })["value"]
        numbers = {
            "sample2": list(range(13, 19)) + list(range(26, 39)),
            "sample3": list(range(13, 26)),
            "sample4": list(range(13, 19)),
        }[name]
        expected_ids = {state["policies"][f"ADO-{n:03d}"]["id"] for n in numbers}
        if {p["id"] for p in effective} != expected_ids:
            evidence["errors"].append(f"{name}: unexpected effective policy IDs.")
        evidence["effectivePolicies"][name] = effective
    for name, pipeline in state["pipelines"].items():
        definition = client.call(TARGET, f"build/definitions/{pipeline['id']}")
        if (definition["repository"]["id"] != repositories[name][0]
                or definition["repository"]["type"] != "TfsGit"
                or definition["repository"]["defaultBranch"] != BRANCHES[name]
                or definition["process"]["yamlFilename"] != "azure-pipelines-policy-lab.yml"):
            evidence["errors"].append(f"{name}: incorrect pipeline repository/YAML binding.")
        if name in state["smokeBuilds"]:
            build = client.call(TARGET, f"build/builds/{state['smokeBuilds'][name]}")
            timeline = client.call(TARGET, f"build/builds/{build['id']}/timeline")
            issues = [issue for record in timeline.get("records", []) for issue in record.get("issues", [])]
            evidence["buildRuns"][name] = {"build": build, "issues": issues}
            if build["status"] == "completed":
                expected_version = original["repositories"][repositories[name][0]]["refs"][BRANCHES[name]]
                if (build["definition"]["id"] != pipeline["id"]
                        or build["repository"]["id"] != repositories[name][0]
                        or build["sourceBranch"] != BRANCHES[name]
                        or build["sourceVersion"] != expected_version):
                    evidence["errors"].append(f"{name}: smoke build did not validate the expected pipeline/commit.")
            print(f"{name}: build {build['id']}, status={build['status']}, result={build.get('result')}", flush=True)
            for issue in issues:
                print(f"Build {build['id']} {issue['type']}: {issue['message']}", flush=True)
    if client.policies(copy_lab.SOURCE) != copied["sourcePolicies"]:
        evidence["errors"].append("Source policy configuration changed.")
    for name, record in copied["repositories"].items():
        if client.refs(copy_lab.SOURCE, record["source"]["id"]) != record["sourceRefs"]:
            evidence["errors"].append(f"{name}: source refs changed.")
        metadata = client.call(copy_lab.SOURCE, f"git/repositories/{record['source']['id']}")
        if metadata.get("defaultBranch") != record["source"].get("defaultBranch"):
            evidence["errors"].append(f"{name}: source default branch changed.")
    save("policy-verification.json", evidence)
    report(state, evidence)
    if evidence["errors"]:
        raise RuntimeError("\n".join(evidence["errors"]))
    print("Verified 26 configured policies, effective scope counts 19/13/6, and unchanged source/copied refs.")


def report(state, evidence):
    from openpyxl import load_workbook

    workbook = load_workbook(rules.ROOT / "docs" / "Azure_DevOps_Policies.xlsx",
                             read_only=True, data_only=True)
    rows = list(workbook["Policy Inventory"].values)[1:]
    if len(rows) != 42 or len({r[0] for r in rows}) != 42:
        raise RuntimeError("Source workbook must contain 42 unique policy entries.")
    observations_path = OUT / "organization-policy-observations.json"
    observations = None
    if observations_path.exists():
        observations = json.loads(observations_path.read_text(encoding="utf-8"))
        if observations["organization"] != ORG:
            raise RuntimeError("Organization screenshot evidence belongs to another organization.")
        expected_entries = set(ORG_PROPOSALS) - {"ADO-006"}
        if (set(observations["values"]) != expected_entries
                or set(observations["proposedStates"]) != expected_entries):
            raise RuntimeError("Screenshot evidence must cover the 11 active organization entries.")
    with (OUT / "Policy-Assessment.csv").open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(["Inventory ID", "Scope", "Policy", "Configuration status", "Policy ID",
                         "Enforcement status", "Proposed organization setting", "Notes", "Microsoft source"])
        for row in rows:
            entry = row[0]
            if entry in state["policies"]:
                record = state["policies"][entry]
                status = "Verified persisted" if not evidence["policies"][entry]["mismatches"] else "Mismatch"
                enforcement = "Behavioral tests deferred"
                if record["kind"] == "status":
                    enforcement = "Configured; status producer still pending"
                if record["kind"] == "build":
                    name = "sample3" if entry == "ADO-023" else "sample2"
                    run = evidence["buildRuns"].get(name)
                    if run:
                        build = run["build"]
                        enforcement = f"Smoke build {build['id']}: {build['status']}/{build.get('result')}"
                writer.writerow([entry, row[1], row[3], status, record["id"], enforcement, "",
                                 json.dumps(record["expected"]["settings"]), row[9]])
            elif entry in ORG_PROPOSALS:
                proposed, note = ORG_PROPOSALS[entry]
                status = ("Retired; not applicable" if entry == "ADO-006"
                          else "Approved scope; blocked by organization admin sign-in")
                enforcement = "Current value not verified; no change made"
                if observations is not None:
                    if entry != "ADO-006":
                        observed = observations["values"][entry]
                        target = observations["proposedStates"][entry]
                        if type(observed) is not bool or (target is not None and type(target) is not bool):
                            raise RuntimeError(f"{entry}: screenshot states must be boolean or a pending target.")
                        status = ("Prerequisite review required" if target is None else
                                  "Observed matching proposed setting (screenshot)" if observed == target else
                                  "Change required (screenshot)")
                        enforcement = f"Screenshot shows {'On' if observed else 'Off'}; not behavior-tested"
                        note += f" User screenshots supplied {observations['providedAt']}; not API-verified or changed by assistant."
                writer.writerow([entry, row[1], row[3], status, "",
                                 enforcement, proposed, note, row[9]])
            else:
                writer.writerow([entry, row[1], row[3], "Tenant controls excluded", "", "Not tested", "",
                                 "A separate organization does not isolate tenant-wide controls.", row[9]])
    workbook.close()


def main():
    parser = argparse.ArgumentParser(description="Recreate approved policy entries in ado-policy-testing/project1 only.")
    parser.add_argument("mode", choices=["setup", "verify", "retry-smoke"])
    args = parser.parse_args()
    copied = json.loads((OUT / "copy-state.json").read_text(encoding="utf-8"))
    client = copy_lab.Client()
    reviewer_ids = preflight(client, copied)
    original = baseline(client)
    repositories = {
        name: (record["destination"]["id"], BRANCHES[name].removeprefix("refs/heads/"))
        for name, record in copied["repositories"].items()
    }
    path = OUT / "policy-state.json"
    state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
        "destination": TARGET, "pipelines": {}, "policies": {}, "smokeBuilds": {},
    }
    if tuple(state["destination"]) != TARGET:
        raise RuntimeError("Policy state belongs to a different destination.")
    if args.mode == "setup":
        setup(client, copied, repositories, reviewer_ids, state)
        smoke(client, state)
    elif args.mode == "retry-smoke":
        retry_smoke(client, state)
    verify(client, copied, original, repositories, state)


if __name__ == "__main__":
    main()
