"""Convert a raw ADO policy capture into a portable JSON export and a human-readable review CSV.

Input : output/ado2gh-migration/<run-id>/ado-baseline.json (raw REST capture, read-only)
        output/ado-policy-testing-project1/policy-state.json      (inventory ID + pipeline names)
        output/ado-policy-testing-project1/reviewer-membership.json (reviewer identity names)
Output: output/policy-export/<run-id>/ado-policies.portable.json  (source of truth for re-creating policies)
        output/policy-export/<run-id>/ado-policies-review.csv      (one row per setting, for reviewers)

No API calls are made. Environment-specific IDs (repositories, identities, pipelines) are replaced with
named references so the export can be mapped onto another ADO organization/project before applying.
"""
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "output" / "ado-policy-testing-project1"
SCHEMA_VERSION = "1.0"

SETTING_LABELS = {
    "authorEmailPatterns": "Allowed commit author email pattern(s)",
    "filenamePatterns": "Blocked file path pattern(s)",
    "enforceConsistentCase": "Block case-only path conflicts",
    "maxPathLength": "Maximum path length (characters)",
    "maximumGitBlobSizeInBytes": "Maximum file size (bytes)",
    "useUncompressedSize": "Measure uncompressed size",
    "minimumApproverCount": "Minimum approvals required",
    "creatorVoteCounts": "PR creator's vote counts",
    "allowDownvotes": "Allow completion with 'waiting'/'rejected' votes",
    "resetOnSourcePush": "Reset all votes on new push",
    "resetRejectionsOnSourcePush": "Reset rejections on new push",
    "requireVoteOnLastIteration": "Require approval on latest iteration",
    "requireVoteOnEachIteration": "Require approval on each iteration",
    "blockLastPusherVote": "Last pusher cannot approve",
    "allowNoFastForward": "Allow basic merge (no fast-forward)",
    "allowSquash": "Allow squash merge",
    "allowRebase": "Allow rebase and fast-forward",
    "allowRebaseMerge": "Allow rebase with merge commit",
    "buildDefinitionId": "Build pipeline",
    "displayName": "Policy display name",
    "validDuration": "Build expiration (minutes; 0 = never)",
    "manualQueueOnly": "Manual trigger only",
    "queueOnSourceUpdateOnly": "Queue only when source updates",
    "statusName": "Status name",
    "statusGenre": "Status genre",
    "authorId": "Authorized status author",
    "invalidateOnSourceUpdate": "Reset status on new push",
    "defaultDisplayName": "Status display name",
    "policyApplicability": "Applicability (0 = always, 1 = only when status posted)",
    "requiredReviewerIds": "Required reviewer",
    "message": "Message shown to PR author",
}
NO_SETTINGS = {
    "Reserved names restriction": "Blocks reserved file/folder names (no parameters)",
    "Work item linking": "PR must link a work item (no parameters)",
    "Comment requirements": "All PR comments must be resolved (no parameters)",
}


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def build_references(base):
    state = load(LAB / "policy-state.json")
    membership = load(LAB / "reviewer-membership.json")
    repositories = {r["repository"]["id"]: r["repository"]["name"] for r in base["repositories"].values()}
    identities = {}
    for principal, identity_id in membership["identities"].items():
        member = next((m for m in membership["members"].values()
                       if (m.get("principalName") or "").lower() == principal.lower()), {})
        identities[identity_id] = {"principalName": principal, "displayName": member.get("displayName"),
                                   "origin": member.get("origin"), "subjectKind": member.get("subjectKind")}
    pipelines = {p["id"]: p["name"] for p in state.get("pipelines", {}).values()}
    inventory = {v["id"]: k for k, v in state["policies"].items()}
    return repositories, identities, pipelines, inventory


def portable(base, repositories, identities, pipelines, inventory):
    used = {"repositories": set(), "identities": set(), "pipelines": set()}

    def repo_ref(repository_id):
        if repository_id is None:
            return None
        used["repositories"].add(repository_id)
        return {"$ref": f"repository:{repositories.get(repository_id, repository_id)}"}

    policies = []
    for raw in base["policies"]:
        settings = {k: v for k, v in raw["settings"].items() if k != "scope"}
        if "requiredReviewerIds" in settings:
            used["identities"].update(settings["requiredReviewerIds"])
            settings["requiredReviewerIds"] = [
                {"$ref": f"identity:{identities.get(i, {}).get('principalName', i)}"}
                for i in settings["requiredReviewerIds"]]
        if "buildDefinitionId" in settings:
            used["pipelines"].add(settings["buildDefinitionId"])
            settings["buildDefinitionId"] = {
                "$ref": f"pipeline:{pipelines.get(settings['buildDefinitionId'], settings['buildDefinitionId'])}"}
        if settings.get("authorId"):
            used["identities"].add(settings["authorId"])
            settings["authorId"] = {"$ref": f"identity:{identities.get(settings['authorId'], {}).get('principalName', settings['authorId'])}"}
        scope = [{"repository": repo_ref(s.get("repositoryId")), "refName": s.get("refName"),
                  "matchKind": s.get("matchKind")} for s in raw["settings"].get("scope", [])]
        policies.append({
            "inventoryId": inventory.get(raw["id"]),
            "source": {"policyId": raw["id"], "revision": raw["revision"], "createdDate": raw.get("createdDate"),
                       "createdBy": (raw.get("createdBy") or {}).get("uniqueName")},
            "type": {"id": raw["type"]["id"], "displayName": raw["type"]["displayName"]},
            "isEnabled": raw["isEnabled"], "isBlocking": raw["isBlocking"], "isDeleted": raw.get("isDeleted", False),
            "scope": scope, "settings": settings,
        })
    references = {
        "repositories": {repositories[i]: {"sourceId": i} for i in sorted(used["repositories"])},
        "identities": {identities.get(i, {}).get("principalName", i): {"sourceId": i, **identities.get(i, {})}
                       for i in sorted(used["identities"])},
        "pipelines": {pipelines.get(i, str(i)): {"sourceId": i} for i in sorted(used["pipelines"])},
    }
    return {
        "schemaVersion": SCHEMA_VERSION,
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "source": {"organization": base["adoOrganization"], "project": base["adoProject"],
                   "capturedAt": base["capturedAt"]},
        "howToApply": ("For each policy: resolve every {'$ref': 'kind:name'} to the destination's ID "
                       "(repository by name, identity by principal name, pipeline by name), set "
                       "settings.scope = [{repositoryId, refName, matchKind}] (repositoryId null = all repositories "
                       "in the project), then POST {isEnabled, isBlocking, type:{id}, settings} to "
                       "https://dev.azure.com/{org}/{project}/_apis/policy/configurations?api-version=7.1. "
                       "Stop if any reference cannot be resolved."),
        "references": references,
        "policies": policies,
    }


def describe(value):
    if isinstance(value, dict) and "$ref" in value:
        kind, _, name = value["$ref"].partition(":")
        return f"{kind.capitalize()} '{name}'"
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    if isinstance(value, list):
        return ", ".join(describe(v) for v in value)
    return str(value)


def applies_to(scope):
    parts = []
    for s in scope or [{}]:
        repo = describe(s["repository"]).split("'")[1] if s.get("repository") else "All repositories"
        if s.get("refName"):
            branch = s["refName"].removeprefix("refs/heads/")
            parts.append(f"{repo} > {branch}{'*' if s.get('matchKind') == 'Prefix' else ''} ({s.get('matchKind')})")
        else:
            parts.append(repo)
    return "; ".join(parts)


def level(policy):
    scope = policy["scope"][0] if policy["scope"] else {}
    if scope.get("refName"):
        return "Branch" if scope.get("repository") else "Project (cross-repo branch)"
    return "Repository" if scope.get("repository") else "Project (all repositories)"


def review_rows(export):
    for p in export["policies"]:
        common = [p["inventoryId"] or "", p["source"]["policyId"], level(p), applies_to(p["scope"]),
                  p["type"]["displayName"], describe(p["isEnabled"]), describe(p["isBlocking"])]
        settings = p["settings"]
        if not settings:
            yield common + ["(none)", "", NO_SETTINGS.get(p["type"]["displayName"], "No parameters"), "On/off only"]
            continue
        for key, value in settings.items():
            values = value if key == "requiredReviewerIds" else [value]
            for index, item in enumerate(values):
                setting = f"{key}[{index}]" if key == "requiredReviewerIds" else key
                if item is None:
                    yield common + [setting, "null", f"{SETTING_LABELS.get(key, key)}: not set", "ADO default"]
                else:
                    raw = item["$ref"] if isinstance(item, dict) and "$ref" in item else json.dumps(item)
                    yield common + [setting, raw, f"{SETTING_LABELS.get(key, key)}: {describe(item)}", "Set"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True, help="Folder under output/ado2gh-migration holding ado-baseline.json")
    args = parser.parse_args()
    base = load(ROOT / "output" / "ado2gh-migration" / args.run_id / "ado-baseline.json")
    export = portable(base, *build_references(base))
    out = ROOT / "output" / "policy-export" / args.run_id
    write_atomic(out / "ado-policies.portable.json", json.dumps(export, indent=2))
    rows = list(review_rows(export))
    csv_path = out / "ado-policies-review.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(["Inventory ID", "Source policy ID", "Level", "Applies to", "Policy type", "Enabled",
                         "Blocking", "Setting", "Raw value", "Meaning", "Value source"])
        writer.writerows(rows)
    unresolved = [r for r in rows if r[8].startswith(("repository:", "identity:", "pipeline:"))
                  and any(c in r[8] for c in "-") and len(r[8].split(":", 1)[1]) == 36]
    print(json.dumps({"policies": len(export["policies"]), "csvRows": len(rows),
                      "references": {k: list(v) for k, v in export["references"].items()},
                      "unresolvedIdReferences": len(unresolved), "output": str(out)}, indent=2))


if __name__ == "__main__":
    main()
