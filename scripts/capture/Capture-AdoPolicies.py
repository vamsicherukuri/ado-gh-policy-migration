"""Read-only capture of Azure DevOps repository/branch policy state.

Usage:
  python .\\scripts\\capture\\Capture-AdoPolicies.py --org <organization> --project <project> [--repos a,b] [--run-id ID] [--auth pat|az]

Writes output/policy-capture/<run-id>/ado-policy-capture.json, which Export-AdoPolicies.py turns into a
portable JSON export and a review CSV. Only GET requests are issued. The PAT is read from the ADO_PAT user
environment variable and is never written to disk or printed.
"""
import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"


def user_env(name):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            return winreg.QueryValueEx(key, name)[0] or None
    except (ImportError, FileNotFoundError, OSError):
        return os.environ.get(name)


def auth_header(mode):
    if mode == "pat":
        pat = user_env("ADO_PAT")
        if not pat:
            raise SystemExit("ADO_PAT is not set. Store it as a user environment variable or use --auth az.")
        return "Basic " + base64.b64encode(f":{pat}".encode()).decode()
    az = shutil.which("az")
    if not az:
        raise SystemExit("Azure CLI not found. Install it and run 'az login', or use --auth pat.")
    result = subprocess.run([az, "account", "get-access-token", "--resource", ADO_RESOURCE, "--output", "json"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("Could not get an Azure DevOps token from Azure CLI. Run 'az login' first.")
    return "Bearer " + json.loads(result.stdout)["accessToken"]


class Ado:
    def __init__(self, organization, header):
        self.organization, self.header, self.gets = organization, header, 0

    def get(self, url, query=None, allow=(), with_headers=False):
        query = {"api-version": "7.1", **(query or {})}
        full = f"{url}{'&' if '?' in url else '?'}{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(full, headers={"Authorization": self.header, "Accept": "application/json"})
        self.gets += 1
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                if "json" not in response.headers.get("Content-Type", ""):
                    raise SystemExit(f"GET {url}: non-JSON response; the token is probably invalid or expired.")
                body = json.load(response)
                return (body, response.headers) if with_headers else body
        except urllib.error.HTTPError as error:
            if error.code in allow:
                return (None, error.headers) if with_headers else None
            detail = error.read().decode("utf-8", errors="replace")[:500]
            hint = {401: "token invalid/expired", 403: "token lacks a required scope or permission",
                    404: "organization, project or resource not found"}.get(error.code, "")
            raise SystemExit(f"GET {url}: HTTP {error.code} ({hint}). {detail}") from error

    def api(self, project, path, query=None, allow=()):
        base = f"https://dev.azure.com/{self.organization}/"
        base += f"{urllib.parse.quote(project)}/" if project else ""
        return self.get(f"{base}_apis/{path}", query, allow)

    def policies(self, project):
        result, continuation = [], None
        while True:
            query = {"$top": 100, **({"continuationToken": continuation} if continuation else {})}
            body, headers = self.get(f"https://dev.azure.com/{self.organization}/{urllib.parse.quote(project)}"
                                     "/_apis/policy/configurations", query, with_headers=True)
            result.extend(body["value"])
            continuation = headers.get("x-ms-continuationtoken")
            if not continuation:
                return sorted(result, key=lambda p: p["id"])

    def refs(self, project, repository_id):
        result = {}
        for prefix in ("heads/", "tags/"):
            continuation = None
            while True:
                query = {"filter": prefix, "$top": 1000, **({"continuationToken": continuation} if continuation else {})}
                body, headers = self.get(f"https://dev.azure.com/{self.organization}/{urllib.parse.quote(project)}"
                                         f"/_apis/git/repositories/{repository_id}/refs", query, with_headers=True)
                result.update({r["name"]: r["objectId"] for r in body["value"]})
                continuation = headers.get("x-ms-continuationtoken")
                if not continuation:
                    break
        return result


def referenced_ids(policies):
    identities, pipelines = set(), set()
    for policy in policies:
        settings = policy["settings"]
        identities.update(settings.get("requiredReviewerIds") or [])
        if settings.get("authorId"):
            identities.add(settings["authorId"])
        if settings.get("buildDefinitionId") is not None:
            pipelines.add(settings["buildDefinitionId"])
    return identities, pipelines


def resolve_identities(ado, ids):
    resolved = {}
    if not ids:
        return resolved
    body = ado.get(f"https://vssps.dev.azure.com/{ado.organization}/_apis/identities",
                   {"identityIds": ",".join(sorted(ids)), "queryMembership": "None"}, allow=(401, 403))
    for identity in (body or {}).get("value", []) or []:
        if not identity:
            continue
        properties = identity.get("properties", {})
        account = (properties.get("Account") or {}).get("$value")
        mail = (properties.get("Mail") or {}).get("$value")
        resolved[identity["id"]] = {
            "principalName": account or mail or identity.get("providerDisplayName"),
            "displayName": identity.get("customDisplayName") or identity.get("providerDisplayName"),
            "mail": mail, "isGroup": identity.get("isContainer", False),
            "descriptor": identity.get("descriptor")}
    for missing in ids - set(resolved):
        resolved[missing] = {"principalName": None, "unresolved": True,
                             "reason": "Identity not returned (deleted, or token lacks Identity read)"}
    return resolved


def resolve_pipelines(ado, project, ids):
    resolved = {}
    for pipeline_id in sorted(ids):
        body = ado.api(project, f"build/definitions/{pipeline_id}", allow=(401, 403, 404))
        resolved[pipeline_id] = ({"name": body["name"], "path": body.get("path"),
                                  "repository": (body.get("repository") or {}).get("name"),
                                  "yamlFilename": (body.get("process") or {}).get("yamlFilename")}
                                 if body else {"name": None, "unresolved": True,
                                               "reason": "Pipeline not found or token lacks Build read"})
    return resolved


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--org", required=True, help="Azure DevOps organization name (dev.azure.com/<org>)")
    parser.add_argument("--project", required=True, help="Project name")
    parser.add_argument("--repos", help="Comma-separated repository names (default: all repositories)")
    parser.add_argument("--run-id", default=datetime.now().strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--auth", choices=("pat", "az"), default="pat",
                        help="pat = ADO_PAT user environment variable (default); az = Azure CLI sign-in")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9-]{6,40}", args.run_id):
        raise SystemExit("run-id must be 6-40 letters, digits or hyphens.")
    out = ROOT / "output" / "policy-capture" / args.run_id
    target = out / "ado-policy-capture.json"
    if target.exists():
        raise SystemExit(f"Capture already exists: {target}. Use a new --run-id.")

    ado = Ado(args.org, auth_header(args.auth))
    project = ado.api(None, f"projects/{urllib.parse.quote(args.project)}")
    repositories = {r["name"]: r for r in ado.api(args.project, "git/repositories")["value"]}
    selected = [n.strip() for n in args.repos.split(",")] if args.repos else sorted(repositories)
    unknown = [n for n in selected if n not in repositories]
    if unknown:
        raise SystemExit(f"Repositories not found in {args.org}/{args.project}: {unknown}")

    policies = ado.policies(args.project)
    selected_ids = {repositories[n]["id"] for n in selected}

    def in_scope(policy):
        scopes = policy["settings"].get("scope") or [{}]
        return any(s.get("repositoryId") in (None, *selected_ids) for s in scopes)

    policies = [p for p in policies if in_scope(p)]
    snapshot = {"captureVersion": "1.0", "capturedAt": datetime.now(timezone.utc).isoformat(),
                "adoOrganization": args.org, "adoProject": project["name"], "projectId": project["id"],
                "authMode": args.auth, "selectedRepositories": selected, "policies": policies,
                "repositories": {}, "identities": {}, "pipelines": {}, "warnings": []}
    for name in selected:
        repository = repositories[name]
        if repository.get("isDisabled"):
            snapshot["warnings"].append(f"{name}: repository is disabled; refs/branches not captured")
            snapshot["repositories"][name] = {"repository": repository, "refs": {}, "effectivePolicies": {}}
            continue
        refs = ado.refs(args.project, repository["id"])
        effective = {}
        for ref in sorted(r for r in refs if r.startswith("refs/heads/")):
            found = ado.api(args.project, "git/policy/configurations",
                            {"repositoryId": repository["id"], "refName": ref})["value"]
            if found:
                effective[ref.removeprefix("refs/heads/")] = [
                    {"id": p["id"], "type": p["type"]["displayName"], "isEnabled": p["isEnabled"],
                     "isBlocking": p["isBlocking"]} for p in found]
        snapshot["repositories"][name] = {"repository": repository, "refs": refs, "effectivePolicies": effective}

    identity_ids, pipeline_ids = referenced_ids(policies)
    snapshot["identities"] = resolve_identities(ado, identity_ids)
    snapshot["pipelines"] = {str(k): v for k, v in resolve_pipelines(ado, args.project, pipeline_ids).items()}
    for kind in ("identities", "pipelines"):
        for key, value in snapshot[kind].items():
            if value.get("unresolved"):
                snapshot["warnings"].append(f"{kind[:-1]} {key}: {value['reason']}")

    out.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    temporary.replace(target)
    print(json.dumps({
        "capture": str(target), "organization": args.org, "project": project["name"],
        "repositories": selected, "policies": len(policies),
        "branchesWithPolicies": {n: len(r["effectivePolicies"]) for n, r in snapshot["repositories"].items()},
        "identitiesResolved": sum(1 for v in snapshot["identities"].values() if not v.get("unresolved")),
        "pipelinesResolved": sum(1 for v in snapshot["pipelines"].values() if not v.get("unresolved")),
        "warnings": snapshot["warnings"], "getRequests": ado.gets,
        "next": f"python Export-AdoPolicies.py --capture \"{target}\""}, indent=2))


if __name__ == "__main__":
    main()
