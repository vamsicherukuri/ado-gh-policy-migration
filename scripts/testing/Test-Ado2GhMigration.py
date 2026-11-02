"""Evidence harness for ADO -> GitHub (GEI / gh ado2gh) policy migration.

Subcommands (all write under output/ado2gh-migration/<run-id>/):
  baseline  Read-only ADO snapshot (policies, refs, PRs) and GitHub org pre-snapshot.
  migrate   Re-verifies the ADO baseline, then runs `gh ado2gh migrate-repo` per repository.
  readback  Read-only GitHub snapshot (protection, rulesets, PRs, refs, mannequins, org settings).
  compare   Classifies all 42 inventory entries: documented expectation vs observed result.

Tokens are read from the user-level GH_PAT / ADO_PAT environment variables and are never written out.
"""
import argparse
import csv
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import winreg
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lab"))
copy_lab = importlib.import_module("Copy-AdoPolicyLabRepositories")
ADO_TARGET = copy_lab.DESTINATION
ADO_ORG = ADO_TARGET[0]
ADO_PROJECT = "project1"
GH_ORG = "ago2gh-policy-migration"
REPOS = ("sample2", "sample3", "sample4")
LAB_BRANCH = {"sample2": "policy-direct/main", "sample3": "policy-lab/main", "sample4": "policy-control/main"}
OUT_ROOT = ROOT / "output" / "ado2gh-migration"
POLICY_STATE = ROOT / "output" / "ado-policy-testing-project1" / "policy-state.json"
INVENTORY = ROOT / "docs" / "Azure_DevOps_Policies.xlsx"
EXCLUDED_FROM_ADO_TESTING = {"ADO-005", "ADO-006", "ADO-008", "TEN-001", "TEN-002", "TEN-003", "TEN-004"}
ORG_VOLATILE = {"updated_at", "total_private_repos", "owned_private_repos", "disk_usage", "private_gists",
                "collaborators", "public_repos", "plan"}

GEI_DOC = ("https://docs.github.com/en/migrations/ado/understand-migrations-from-azure-devops-to-github"
           " - 'Branch policies for the repository (user-scoped branch policies and cross-repo branch"
           " policies are not included)'")


def now():
    return datetime.now(timezone.utc).isoformat()


def user_env(name):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value or None
    except FileNotFoundError:
        return None


def secrets():
    gh, ado = user_env("GH_PAT"), user_env("ADO_PAT")
    if not gh or not ado:
        raise SystemExit("GH_PAT and ADO_PAT must be set as user environment variables.")
    return gh, ado


def scrub(text, values):
    for value in values:
        if value:
            text = text.replace(value, "***")
    return text


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
    temporary.replace(path)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


class GitHub:
    def __init__(self, token):
        self.token = token

    def request(self, path, method="GET", body=None, allow=(200,)):
        url = path if path.startswith("https://") else f"https://api.github.com{path}"
        request = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                         headers={"Authorization": f"Bearer {self.token}",
                                                  "Accept": "application/vnd.github+json",
                                                  "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return response.status, json.load(response), response.headers
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            if error.code in allow:
                return error.code, json.loads(detail) if detail.startswith("{") else detail, error.headers
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {detail}") from error

    def get(self, path, allow=(200,)):
        status, body, _ = self.request(path, allow=allow)
        return {"status": status, "body": body}

    def pages(self, path):
        result, url = [], f"https://api.github.com{path}{'&' if '?' in path else '?'}per_page=100"
        while url:
            _, body, headers = self.request(url)
            result.extend(body)
            match = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link", "") or "")
            url = match.group(1) if match else None
        return result

    def graphql(self, query, variables):
        _, body, _ = self.request("/graphql", method="POST", body={"query": query, "variables": variables})
        return body


def branch_path(name):
    return urllib.parse.quote(name, safe="")


def gh_repo(name):
    return f"{ADO_PROJECT}-{name}"


def org_snapshot(github):
    org = github.get(f"/orgs/{GH_ORG}")["body"]
    rulesets = github.get(f"/orgs/{GH_ORG}/rulesets", allow=(200, 403, 404))
    return {"capturedAt": now(), "org": org, "orgRulesets": rulesets}


def ado_policies(client):
    return sorted(client.policies(ADO_TARGET), key=lambda p: p["id"])


def policy_fingerprint(policies):
    return [{"id": p["id"], "revision": p["revision"], "isEnabled": p["isEnabled"],
             "isBlocking": p["isBlocking"], "isDeleted": p.get("isDeleted", False),
             "settings": p["settings"]} for p in policies]


def baseline(run, client, github):
    if (run / "ado-baseline.json").exists():
        raise SystemExit(f"Baseline already exists for this run: {run}")
    repositories = {r["name"]: r for r in client.call(ADO_TARGET, "git/repositories")["value"]}
    snapshot = {"capturedAt": now(), "adoOrganization": ADO_ORG, "adoProject": ADO_PROJECT,
                "policies": ado_policies(client), "repositories": {}}
    for name in REPOS:
        repository = repositories[name]
        prs = client.call(ADO_TARGET, f"git/repositories/{repository['id']}/pullrequests",
                          query={"searchCriteria.status": "all", "$top": 200})["value"]
        effective = {}
        for branch in sorted({LAB_BRANCH[name], repository["defaultBranch"].removeprefix("refs/heads/")}):
            effective[branch] = client.call(ADO_TARGET, "git/policy/configurations",
                                            query={"repositoryId": repository["id"],
                                                   "refName": f"refs/heads/{branch}"})["value"]
        snapshot["repositories"][name] = {
            "repository": repository, "refs": client.refs(ADO_TARGET, repository["id"]),
            "pullRequests": [{"id": p["pullRequestId"], "status": p["status"], "title": p["title"],
                              "sourceRefName": p["sourceRefName"], "targetRefName": p["targetRefName"],
                              "createdBy": p["createdBy"]["uniqueName"],
                              "reviewers": [{"name": r.get("uniqueName") or r["displayName"], "vote": r["vote"],
                                             "isRequired": r.get("isRequired", False)} for r in p.get("reviewers", [])]}
                             for p in prs],
            "effectivePolicies": {b: [{"id": p["id"], "type": p["type"]["displayName"], "isEnabled": p["isEnabled"],
                                       "isBlocking": p["isBlocking"], "settings": p["settings"]} for p in v]
                                  for b, v in effective.items()},
        }
    write(run / "ado-baseline.json", snapshot)
    for name in REPOS:
        status = github.get(f"/repos/{GH_ORG}/{gh_repo(name)}", allow=(200, 404))["status"]
        if status != 404:
            raise SystemExit(f"Target repository {GH_ORG}/{gh_repo(name)} already exists; refusing to continue.")
    write(run / "github-org-before.json", org_snapshot(github))
    summary = {n: {"refs": len(r["refs"]), "pullRequests": len(r["pullRequests"]),
                   "effectivePolicies": {b: len(v) for b, v in r["effectivePolicies"].items()}}
               for n, r in snapshot["repositories"].items()}
    print(json.dumps({"policies": len(snapshot["policies"]), "repositories": summary}, indent=2))


def migrate(run, client, github, tokens):
    base = read(run / "ado-baseline.json")
    if policy_fingerprint(ado_policies(client)) != policy_fingerprint(base["policies"]):
        raise SystemExit("ADO policies changed since the baseline; capture a new baseline run.")
    repositories = {r["name"]: r["id"] for r in client.call(ADO_TARGET, "git/repositories")["value"]}
    for name in REPOS:
        if client.refs(ADO_TARGET, repositories[name]) != base["repositories"][name]["refs"]:
            raise SystemExit(f"ADO refs for {name} changed since the baseline; capture a new baseline run.")
    gh_cli = shutil.which("gh")
    environment = {**os.environ, "GH_PAT": tokens[0], "ADO_PAT": tokens[1]}
    version = subprocess.run([gh_cli, "extension", "list"], capture_output=True, text=True).stdout
    results = {"startedAt": now(),
               "toolVersion": next((l.strip() for l in version.splitlines() if "ado2gh" in l), "unknown"),
               "repositories": {}}
    logs = run / "migration-logs"
    logs.mkdir(parents=True, exist_ok=True)
    for name in REPOS:
        target = gh_repo(name)
        if github.get(f"/repos/{GH_ORG}/{target}", allow=(200, 404))["status"] != 404:
            raise SystemExit(f"{GH_ORG}/{target} already exists; refusing to overwrite.")
        command = ["ado2gh", "migrate-repo", "--ado-org", ADO_ORG, "--ado-team-project", ADO_PROJECT,
                   "--ado-repo", name, "--github-org", GH_ORG, "--github-repo", target,
                   "--target-repo-visibility", "private", "--verbose"]
        started = now()
        process = subprocess.run([gh_cli, *command], capture_output=True, text=True, env=environment, timeout=3600)
        output = scrub(process.stdout + process.stderr, tokens)
        (logs / f"{target}-cli.log").write_text(output, encoding="utf-8")
        migration_id = next(iter(re.findall(r"\b(RM_[A-Za-z0-9_-]+)", output)), None)
        log_file = logs / f"{target}-migration.log"
        downloaded = subprocess.run([gh_cli, "ado2gh", "download-logs", "--github-org", GH_ORG,
                                     "--github-repo", target, "--migration-log-file", str(log_file), "--overwrite"],
                                    capture_output=True, text=True, env=environment, timeout=600)
        results["repositories"][name] = {
            "githubRepository": f"{GH_ORG}/{target}", "command": "gh " + " ".join(command),
            "startedAt": started, "finishedAt": now(), "exitCode": process.returncode, "migrationId": migration_id,
            "succeeded": process.returncode == 0 and "State: SUCCEEDED" in output,
            "migrationLogDownloaded": downloaded.returncode == 0 and log_file.exists(),
            "downloadLogsOutput": scrub(downloaded.stdout + downloaded.stderr, tokens)[-2000:]}
        write(run / "migration-results.json", results)
        print(f"{name} -> {GH_ORG}/{target}: exit {process.returncode}, "
              f"succeeded={results['repositories'][name]['succeeded']}, id={migration_id}")
    results["finishedAt"] = now()
    write(run / "migration-results.json", results)


def readback(run, github):
    snapshot = {"capturedAt": now(), "repositories": {}}
    for name in REPOS:
        repo = f"/repos/{GH_ORG}/{gh_repo(name)}"
        meta = github.get(repo, allow=(200, 404))
        if meta["status"] == 404:
            snapshot["repositories"][name] = {"exists": False}
            continue
        branches = github.pages(f"{repo}/branches")
        protected = [b["name"] for b in branches if b.get("protected")]
        interesting = sorted(set(protected) | {LAB_BRANCH[name], meta["body"]["default_branch"]})
        rulesets = []
        for item in github.get(f"{repo}/rulesets?includes_parents=true", allow=(200, 403, 404))["body"] or []:
            if isinstance(item, dict) and "id" in item:
                rulesets.append(github.get(f"{repo}/rulesets/{item['id']}", allow=(200, 403, 404))["body"])
        codeowners = {}
        for branch in (LAB_BRANCH[name], meta["body"]["default_branch"]):
            for path in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
                found = github.get(f"{repo}/contents/{path}?ref={branch_path(branch)}", allow=(200, 404))
                codeowners[f"{branch}:{path}"] = found["status"] == 200
        refs = {}
        for prefix in ("heads", "tags"):
            for ref in github.pages(f"{repo}/git/matching-refs/{prefix}/"):
                refs[ref["ref"]] = ref["object"]["sha"]
        snapshot["repositories"][name] = {
            "exists": True, "repository": meta["body"],
            "branchCount": len(branches), "protectedBranches": protected,
            "protection": {b: github.get(f"{repo}/branches/{branch_path(b)}/protection", allow=(200, 403, 404))
                           for b in interesting},
            "effectiveRules": {b: github.get(f"{repo}/rules/branches/{branch_path(b)}", allow=(200, 403, 404))
                               for b in interesting},
            "rulesets": rulesets, "codeowners": codeowners, "refs": refs,
            "pullRequests": [{"number": p["number"], "state": p["state"], "title": p["title"],
                              "head": p["head"]["ref"], "base": p["base"]["ref"], "merged_at": p.get("merged_at"),
                              "user": (p.get("user") or {}).get("login")}
                             for p in github.pages(f"{repo}/pulls?state=all")],
            "collaborators": [c["login"] for c in github.pages(f"{repo}/collaborators?affiliation=direct")],
            "teams": [t["slug"] for t in github.pages(f"{repo}/teams")],
        }
    mannequins = github.graphql(
        "query($org:String!){organization(login:$org){mannequins(first:100){nodes{login email claimant{login}}}}}",
        {"org": GH_ORG})
    snapshot["mannequins"] = mannequins
    write(run / "github-readback.json", snapshot)
    after = org_snapshot(github)
    write(run / "github-org-after.json", after)
    for name, value in snapshot["repositories"].items():
        if value.get("exists"):
            print(f"{name}: branches={value['branchCount']} protected={value['protectedBranches']} "
                  f"rulesets={len(value['rulesets'])} prs={len(value['pullRequests'])}")
        else:
            print(f"{name}: repository not found")


def protection_of(readback_repo, branch):
    if not readback_repo.get("exists"):
        return None, []
    protection = readback_repo["protection"].get(branch, {})
    rules = readback_repo["effectiveRules"].get(branch, {})
    return (protection["body"] if protection.get("status") == 200 else None,
            rules["body"] if rules.get("status") == 200 and isinstance(rules.get("body"), list) else [])


def rule(rules, kind):
    return next((r.get("parameters", {}) for r in rules if r.get("type") == kind), None)


def observe_branch(kind, settings, readback_repo, branch):
    """Return (result, github_equivalent, evidence) for one ADO branch-policy kind on one migrated branch."""
    classic, rules = protection_of(readback_repo, branch)
    reviews = (classic or {}).get("required_pull_request_reviews")
    pull_rule = rule(rules, "pull_request")
    checks = (classic or {}).get("required_status_checks")
    check_rule = rule(rules, "required_status_checks")
    where = f"{readback_repo.get('repository', {}).get('full_name', '?')}@{branch}"
    if kind == "reviewers":
        expected = settings.get("minimumApproverCount")
        actual = (reviews or {}).get("required_approving_review_count")
        actual = actual if actual is not None else (pull_rule or {}).get("required_approving_review_count")
        reset_expected = bool(settings.get("resetOnSourcePush"))
        reset_actual = bool((reviews or {}).get("dismiss_stale_reviews") or (pull_rule or {}).get("dismiss_stale_reviews_on_push"))
        last_pusher_expected = bool(settings.get("blockLastPusherVote") or settings.get("prohibitRequesterFromApproving"))
        last_pusher_actual = bool((reviews or {}).get("require_last_push_approval") or (pull_rule or {}).get("require_last_push_approval"))
        extra = {"dismiss_stale_reviews": reset_actual, "require_last_push_approval": last_pusher_actual}
        if actual is None:
            return "NOT MIGRATED", "Required approving reviews", f"{where}: no required-reviews protection"
        count_matches = (actual == expected)
        sub_settings_match = (reset_expected == reset_actual) and (last_pusher_expected == last_pusher_actual)
        result = "MIGRATED" if (count_matches and sub_settings_match) else ("PARTIAL" if count_matches else "DIFFERS")
        return result, "Required approving reviews", f"{where}: count {actual} (ADO {expected}); {extra}"
    if kind == "workitems":
        return "NOT MIGRATED", "No GitHub equivalent", f"{where}: GitHub has no linked-work-item gate"
    if kind == "comments":
        classic_on = ((classic or {}).get("required_conversation_resolution") or {}).get("enabled")
        rule_on = (pull_rule or {}).get("required_review_thread_resolution")
        if classic_on or rule_on:
            return "MIGRATED", "Require conversation resolution", f"{where}: enabled"
        return "NOT MIGRATED", "Require conversation resolution", f"{where}: not enabled"
    if kind == "merge":
        linear = ((classic or {}).get("required_linear_history") or {}).get("enabled")
        methods = (pull_rule or {}).get("allowed_merge_methods")
        repo = readback_repo.get("repository", {})
        repo_flags = {k: repo.get(k) for k in ("allow_merge_commit", "allow_squash_merge", "allow_rebase_merge")}
        ado = {k: settings.get(k) for k in ("allowNoFastForward", "allowSquash", "allowRebase", "allowRebaseMerge")}
        if linear or methods:
            return "MIGRATED", "Linear history / allowed merge methods", \
                f"{where}: linear={linear} methods={methods}; ADO {ado}"
        return "NOT MIGRATED", "Allowed merge methods", \
            f"{where}: no branch-level merge restriction; repo-wide flags {repo_flags}; ADO {ado}"
    if kind in ("build", "status"):
        contexts = sorted(set((checks or {}).get("contexts") or []) |
                          {c.get("context") for c in (check_rule or {}).get("required_status_checks", [])})
        label = "Required status checks"
        if contexts:
            return "MIGRATED", label, f"{where}: required checks {contexts}"
        return "NOT MIGRATED", label, f"{where}: no required status checks"
    if kind == "required":
        code_owner = (reviews or {}).get("require_code_owner_reviews") or (pull_rule or {}).get(
            "require_code_owner_review")
        files = [k for k, v in readback_repo.get("codeowners", {}).items() if v]
        if code_owner and files:
            return "MIGRATED", "CODEOWNERS + require code owner review", f"{where}: {files}"
        if code_owner or files:
            return "PARTIAL", "CODEOWNERS + require code owner review", \
                f"{where}: code_owner_review={code_owner} files={files}"
        return "NOT MIGRATED", "CODEOWNERS + require code owner review", f"{where}: neither present"
    raise ValueError(kind)


def push_rules_present(readback):
    kinds = {"commit_author_email_pattern", "file_path_restriction", "max_file_path_length",
             "file_extension_restriction", "max_file_size"}
    found = []
    for name, value in readback["repositories"].items():
        for ruleset in value.get("rulesets", []):
            if not isinstance(ruleset, dict):
                continue
            for item in ruleset.get("rules", []):
                if item.get("type") in kinds:
                    found.append({
                        "repository": name,
                        "ruleset_name": ruleset.get("name"),
                        "target": ruleset.get("target"),
                        "enforcement": ruleset.get("enforcement"),
                        "type": item.get("type"),
                        "parameters": item.get("parameters", {})
                    })
    return found


def compare(run):
    from openpyxl import load_workbook

    base, back = read(run / "ado-baseline.json"), read(run / "github-readback.json")
    migration = read(run / "migration-results.json")
    org_before, org_after = read(run / "github-org-before.json"), read(run / "github-org-after.json")
    mapping = read(POLICY_STATE)["policies"]
    policies = {p["id"]: p for p in base["policies"]}
    workbook = load_workbook(INVENTORY, read_only=True, data_only=True)
    rows = list(workbook["Policy Inventory"].values)[1:]
    assert len(rows) == 42 and len({r[0] for r in rows}) == 42

    org_diff = sorted(k for k in set(org_before["org"]) | set(org_after["org"])
                      if k not in ORG_VOLATILE and org_before["org"].get(k) != org_after["org"].get(k))
    push_rules = push_rules_present(back)
    repos = back["repositories"]
    any_protection = {n: (v.get("protectedBranches") or [], len(v.get("rulesets") or []))
                      for n, v in repos.items()}

    out_rows, counts = [], Counter()
    for row in rows:
        entry, scope, policy = row[0], row[1], row[3]
        ado_cfg, expected, result, equivalent, evidence = "", "", "", "", ""
        if entry.startswith("TEN-") or scope == "Organization":
            expected = "Not migrated - outside GEI scope (organization/tenant setting, not repository data)"
            result = "NOT MIGRATED"
            equivalent = "GitHub enterprise/org settings (manual)"
            evidence = (f"GitHub org settings unchanged by migration (non-counter diffs: {org_diff or 'none'})")
        elif entry in mapping:
            info = mapping[entry]
            config = policies.get(info["id"])
            ado_cfg = (f"policy {info['id']} enabled={config['isEnabled']} blocking={config['isBlocking']}"
                       if config else f"policy {info['id']} MISSING in baseline")
            kind = info["kind"]
            if kind in ("email", "path", "case", "reserved", "length", "size"):
                expected = "Not migrated - repository/push policy, not a branch policy"
                target_type = {"email": "commit_author_email_pattern",
                               "path": "file_path_restriction",
                               "length": "max_file_path_length",
                               "size": "max_file_size"}.get(kind)
                matching_rules = [r for r in push_rules if r.get("type") == target_type] if target_type else []
                result = "MIGRATED" if matching_rules else "NOT MIGRATED"
                equivalent = {"email": "Ruleset: commit author email pattern",
                              "path": "Push ruleset: restrict file paths",
                              "case": "No GitHub equivalent",
                              "reserved": "No GitHub equivalent",
                              "length": "Push ruleset: max file path length",
                              "size": "Push ruleset: max file size"}[kind]
                evidence = f"Matching rules in migrated repos: {matching_rules or 'none'}"
            else:
                cross_repo = (config or {}).get("settings", {}).get("scope", [{}])[0].get("repositoryId") is None
                name = "sample3" if cross_repo else "sample2"
                expected = ("Not migrated - cross-repo branch policy" if cross_repo else
                            "Migrated - branch policy for the repository" if kind != "required" else
                            "Uncertain - branch policy, but named reviewers may be 'user-scoped'")
                result, equivalent, evidence = observe_branch(kind, config["settings"], repos[name],
                                                              LAB_BRANCH[name])
        else:
            expected, result, evidence = "Unmapped", "UNKNOWN", "No policy mapping in policy-state.json"
        if expected.startswith("Not migrated") and result == "NOT MIGRATED":
            verdict = "MATCHES DOCS"
        elif expected.startswith("Migrated") and result == "MIGRATED":
            verdict = "MATCHES DOCS"
        elif expected.startswith("Uncertain"):
            verdict = "DOCS UNCLEAR"
        else:
            verdict = "DIFFERS FROM DOCS"
        counts[result] += 1
        out_rows.append([entry, scope, policy, "No" if entry in EXCLUDED_FROM_ADO_TESTING else "Yes",
                         ado_cfg, expected, result, equivalent, verdict, evidence])

    with (run / "Migration-Comparison.csv").open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(["Inventory ID", "Scope", "Policy", "In ADO test scope", "ADO configuration",
                         "Documented GEI expectation", "Observed in GitHub", "GitHub equivalent",
                         "Docs vs observed", "Evidence"])
        writer.writerows(out_rows)
    summary = {"generatedAt": now(), "documentation": GEI_DOC, "toolVersion": migration.get("toolVersion"),
               "migrations": {n: {k: v[k] for k in ("githubRepository", "succeeded", "migrationId", "exitCode")}
                              for n, v in migration["repositories"].items()},
               "observedCounts": dict(counts),
               "verdictCounts": dict(Counter(r[8] for r in out_rows)),
               "githubProtectionByRepo": any_protection,
               "githubOrgNonCounterChanges": org_diff,
               "pullRequests": {n: {"ado": len(base["repositories"][n]["pullRequests"]),
                                    "github": len(repos[n].get("pullRequests", []))} for n in REPOS},
               "refsMatch": {n: {k.removeprefix("refs/"): v for k, v in base["repositories"][n]["refs"].items()}
                             == {k.removeprefix("refs/"): v for k, v in repos[n].get("refs", {}).items()}
                             for n in REPOS},
               "mannequins": back.get("mannequins")}
    write(run / "comparison-summary.json", summary)
    print(json.dumps({k: summary[k] for k in ("observedCounts", "verdictCounts", "githubProtectionByRepo",
                                                "pullRequests", "refsMatch", "githubOrgNonCounterChanges")},
                     indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("baseline", "migrate", "readback", "compare"))
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9-]{6,40}", args.run_id):
        raise SystemExit("run-id must be 6-40 letters, digits or hyphens.")
    run = OUT_ROOT / args.run_id
    if args.command == "compare":
        return compare(run)
    tokens = secrets()
    github = GitHub(tokens[0])
    if args.command == "readback":
        return readback(run, github)
    client = copy_lab.Client()
    if args.command == "baseline":
        return baseline(run, client, github)
    return migrate(run, client, github, tokens)


if __name__ == "__main__":
    main()
