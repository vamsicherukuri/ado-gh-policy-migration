import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TENANT = "91deab60-469f-438a-a2a4-831aa559e461"
SOURCE = ("contosodevopstest", "85357c78-817f-44fd-b5c7-d77a97d1c650")
DESTINATION = ("ado-policy-testing", "214eef9d-ce60-45f3-8cd9-0bdfff07bf20")
NAMES = ("sample2", "sample3", "sample4")
OUT = Path(__file__).resolve().parents[2] / "output" / "ado-policy-testing-project1"


def save(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / name
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(target)


class Client:
    def __init__(self):
        az = shutil.which("az")
        if not az:
            raise RuntimeError("Azure CLI is required. Sign in with the approved tenant account.")
        result = subprocess.run(
            [az, "account", "get-access-token", "--tenant", TENANT,
             "--resource", "499b84ac-1321-427f-aa17-267ca6975798", "--output", "json"],
            text=True, capture_output=True, check=True,
        )
        self.token = json.loads(result.stdout)["accessToken"]

    def call(self, target, path, method="GET", body=None, query=None, include_continuation=False,
             content_type="application/json"):
        if target not in (SOURCE, DESTINATION):
            raise RuntimeError("Unapproved organization/project target.")
        if method != "GET" and target != DESTINATION:
            raise RuntimeError("Source-project writes are prohibited.")
        organization, project = target
        url = (
            f"https://dev.azure.com/{organization}/{project}/_apis/{path}?"
            + urllib.parse.urlencode({"api-version": "7.1", **(query or {})})
        )
        request = urllib.request.Request(
            url, method=method,
            data=None if body is None else json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": content_type, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                if "json" not in response.headers.get("Content-Type", ""):
                    raise RuntimeError(f"{method} {path}: expected JSON; authentication may be required.")
                result = json.load(response)
                if include_continuation:
                    return result, response.headers.get("x-ms-continuationtoken")
                return result
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {detail}") from error

    def refs(self, target, repository):
        result = {}
        for prefix in ("heads/", "tags/"):
            continuation = None
            while True:
                query = {"filter": prefix, "$top": 100}
                if continuation:
                    query["continuationToken"] = continuation
                response, continuation = self.call(
                    target, f"git/repositories/{repository}/refs",
                    query=query, include_continuation=True,
                )
                page = response["value"]
                result.update({ref["name"]: ref["objectId"] for ref in page})
                if not continuation:
                    break
        return result

    def policies(self, target):
        result = []
        continuation = None
        while True:
            query = {"$top": 100}
            if continuation is not None:
                query["continuationToken"] = continuation
            page = self.call(target, "policy/configurations", query=query)["value"]
            result.extend(page)
            if len(page) < 100:
                return result
            continuation = page[-1]["id"]


def main():
    client = Client()
    state_file = OUT / "copy-state.json"
    if state_file.exists():
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if tuple(state["source"]) != SOURCE or tuple(state["destination"]) != DESTINATION:
            raise RuntimeError("Copy state belongs to a different source or destination.")
    else:
        source_repos = client.call(SOURCE, "git/repositories")["value"]
        selected = {repo["name"]: repo for repo in source_repos if repo["name"] in NAMES}
        if set(selected) != set(NAMES):
            raise RuntimeError("The source does not contain all three approved repositories.")
        state = {
            "source": SOURCE, "destination": DESTINATION,
            "capturedAt": datetime.now(timezone.utc).isoformat(),
            "sourcePolicies": client.policies(SOURCE),
            "destinationPolicies": client.policies(DESTINATION),
            "repositories": {
                name: {"source": selected[name],
                       "sourceRefs": client.refs(SOURCE, selected[name]["id"])}
                for name in NAMES
            },
        }
        save("copy-state.json", state)
    environment = os.environ.copy()
    environment.update({
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://dev.azure.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {client.token}",
    })

    def git(*args):
        result = subprocess.run(["git", "--no-pager", *args], env=environment,
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"Git copy failed ({result.returncode}): {result.stderr}")

    with tempfile.TemporaryDirectory(prefix="ado-policy-copy-") as temporary:
        for name in NAMES:
            record = state["repositories"][name]
            if "destination" not in record:
                existing = client.call(DESTINATION, "git/repositories")["value"]
                if any(repo["name"] == name for repo in existing):
                    raise RuntimeError(f"Untracked destination {name} exists; refusing to overwrite.")
                record["destination"] = client.call(DESTINATION, "git/repositories", "POST", {
                    "name": name, "project": {"id": DESTINATION[1]},
                })
                save("copy-state.json", state)
            destination = record["destination"]
            current = client.refs(DESTINATION, destination["id"])
            if record.get("verifiedAt") and current != record["sourceRefs"]:
                raise RuntimeError(f"{name}: previously verified destination refs changed; refusing to overwrite.")
            if current != record["sourceRefs"]:
                if any(record["sourceRefs"].get(ref) != sha for ref, sha in current.items()):
                    raise RuntimeError(f"{name}: unexpected destination refs; refusing to overwrite.")
                clone = Path(temporary) / f"{name}.git"
                git("clone", "--bare", record["source"]["remoteUrl"], str(clone))
                for prefix in ("heads", "tags"):
                    if any(ref.startswith(f"refs/{prefix}/") for ref in record["sourceRefs"]):
                        git("-C", str(clone), "push", destination["remoteUrl"],
                            f"refs/{prefix}/*:refs/{prefix}/*")
            default = record["source"].get("defaultBranch")
            metadata = client.call(DESTINATION, f"git/repositories/{destination['id']}")
            if metadata.get("defaultBranch") != default:
                if record.get("verifiedAt"):
                    raise RuntimeError(f"{name}: previously verified default branch changed.")
                if not default:
                    raise RuntimeError(f"{name}: unexpected destination default branch.")
                client.call(DESTINATION, f"git/repositories/{destination['id']}",
                            "PATCH", {"defaultBranch": default})
            actual = client.refs(DESTINATION, destination["id"])
            if actual != record["sourceRefs"]:
                raise RuntimeError(f"{name}: source/destination branch/tag object IDs differ.")
            record["verifiedRefs"] = actual
            record["verifiedAt"] = datetime.now(timezone.utc).isoformat()
            save("copy-state.json", state)
            print(f"Verified {name}: {len(actual)} branch/tag refs copied with identical object IDs.", flush=True)
    if client.policies(SOURCE) != state["sourcePolicies"]:
        raise RuntimeError("Source policy configuration changed since the snapshot.")
    if client.policies(DESTINATION) != state["destinationPolicies"]:
        raise RuntimeError("Destination policies changed; this task must not apply policy changes.")
    for name, record in state["repositories"].items():
        if client.refs(SOURCE, record["source"]["id"]) != record["sourceRefs"]:
            raise RuntimeError(f"{name}: source refs changed since the snapshot.")
        source = client.call(SOURCE, f"git/repositories/{record['source']['id']}")
        destination = client.call(DESTINATION, f"git/repositories/{record['destination']['id']}")
        if source.get("defaultBranch") != record["source"].get("defaultBranch"):
            raise RuntimeError(f"{name}: source default branch changed.")
        if destination.get("defaultBranch") != source.get("defaultBranch"):
            raise RuntimeError(f"{name}: default branches do not match.")
    state["verifiedAt"] = datetime.now(timezone.utc).isoformat()
    save("copy-state.json", state)
    print("Completed: three repositories copied; source and destination policy configurations unchanged.")
    print("Policy definitions, pipelines, PR history and organization/tenant settings were not copied.")


if __name__ == "__main__":
    main()
