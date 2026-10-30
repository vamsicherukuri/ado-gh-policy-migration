# ADO → GitHub policy migration lab

Captures Azure DevOps (ADO) repository/branch policies, tests that they are enforced, migrates repositories
to GitHub with GEI (`gh ado2gh`), and compares which of the 42 inventory policies survive migration.

## Documentation-backed policy crosswalk

[`docs\policy-crosswalk.csv`](docs/policy-crosswalk.csv) maps all 42 entries from the
workbook's **Policy Inventory** tab, preserving inventory IDs and separate source/target scopes.
It preserves the existing policy names, scopes and ADO-to-GHEC mapping, and adds a **Mapping category**,
**User action**, **Prerequisites**, official Microsoft Learn/GitHub source URLs and the review date
(2026-10-27). User actions are a configuration/review checklist, not actions already performed.

Mapping judgments and recommended actions are our analysis, not vendor guarantees. Source definitions
remain in the read-only inventory workbook; the crosswalk keeps its concise policy-oriented layout.

| Mapping category | Meaning |
|---|---|
| Close | Comparable native capability; scope, options, thresholds and enforcement still require validation |
| Partial | Related native control with material scope or behavior differences |
| Custom implementation | No matching native rule; a specific custom enforcement route is proposed and must be designed and maintained |
| No direct equivalent | No matching native control identified in the reviewed documentation; an alternative or accepted gap is needed |

"No direct documented equivalent identified" means none was found in the cited sources, not proof that
no alternative exists. Related documentation in these rows is context, not evidence of an equivalent control.
For example, the GitHub Packages and privacy links do not establish equivalents for ADO upstream protection
or feedback collection. The linked-work-item check is a custom design proposal, not a built-in GitHub policy.
ADO-011 uses the documented **Request access** setting: enabled allows requests; disabled requires an
internal access-process URL, correcting the inventory's ambiguous wording. ADO-006 is retained as a retired control.

[`docs\policy-crosswalk-supplemental.csv`](docs/policy-crosswalk-supplemental.csv) separately lists
**SUP-001 force-push protection**, **SUP-002 branch-deletion protection** and **SUP-003 auto-merge**.
These are permissions/workflow controls outside the original 42-entry inventory; the workbook and original
IDs are unchanged. Resetting votes on new pushes remains an option under ADO-019/ADO-032, not a new policy.

This is a configuration crosswalk independent of migration tooling, **not a claim that GEI or ELM
migrates these controls**. Migration evidence remains in the separate lab results; capability categories
are not migration outcomes. Neither CSV applies policies or changes either environment.
GitHub Projects is not a replacement for the ADO project scope; project-wide policies instead require
explicit target-repository selection. Rulesets require appropriate repository/organization permissions;
review enforcement state, overlapping rules, optional-versus-required source intent and bypass actors before
enabling them. Private/internal push rules also affect the fork network.

## Layout

| Path | Contents |
|---|---|
| `docs/` | `Azure_DevOps_Policies.xlsx` (42-entry inventory, read-only), `ADO-Policy-Lab.txt` (lab narrative and results), GitHub ruleset walkthrough |
| `scripts\lab\` | Lab initialization, repository copying, and shared policy helpers |
| `scripts\capture\` | PowerShell 7+ read-only capture and offline export; original Python scripts retained as legacy references |
| `scripts\transform\` | Transforms ADO snapshots into native `safe-settings` YAML (`settings.yml`, `suborgs/`, `repos/`) and PR gap report |
| `scripts\pipeline\` | Stages generated safe-settings YAML into admin repo and opens GitOps Pull Request |
| `scripts\testing\` | Behavioral policy tests and GEI migration evidence harness |
| `scripts\github\` | GitHub ruleset application script |
| `tests\` | Unit tests for the ADO test harness |
| `config\` | `ado-policy-config.csv` capture selections, policy CSV inputs, and `repos.sample.txt` |
| `output/ado-policy-testing-project1/` | Lab state (`policy-state.json`, reviewers, assessment) and behavioral test runs under `policy-tests/` |
| `output/ado2gh-migration/<run-id>/` | Migration evidence: ADO baseline, GitHub read-back, org snapshots, `migration-logs/` |
| `output/_archive/policy-export/<run-id>/` | Historical migration-baseline exports retained as regression evidence |
| `output/policy-capture/<run-id>/` | New runs: project-named capture JSON, portable JSON, and review CSV together; older runs retain their original layout |
| `output/_archive/` | Historical first-lab output and legacy exports; not part of normal capture runs |
| `logs/` | Ad-hoc command/console logs |

Scripts resolve workspace data paths from their installed location, independently of the current working directory.
Run the relative command examples below from the workspace root.
The hidden `.gated-change\` directory is retained PRSquad state/audit history, not part of the active tooling.

Do not move `output/ado-policy-testing-project1/policy-tests/*` – `Initialize-NewOrgPolicyLab.py verify` reads every
`resources.json` there to recognise test branches that still exist in ADO.

## Scripts

| Script | Purpose | Writes to ADO/GitHub? |
|---|---|---|
| `Capture-AdoPolicies.ps1` | Read-only capture of current ADO repository/branch policy state | No |
| `Export-AdoPolicies.ps1` | Portable JSON + review CSV from a fresh capture or legacy migration baseline | No (offline) |
| `Convert-AdoToSafeSettings.ps1` | Transforms portable JSON to safe-settings `.github/` YAML bundle + PR report | No (offline) |
| `Submit-SafeSettingsPR.ps1` | Stages safe-settings YAML into admin repo & opens GitOps Pull Request | Yes (Git repo / PR) |
| `Initialize-NewOrgPolicyLab.py` | Set up / `verify` the `ado-policy-testing/project1` lab | Setup: yes · verify: no |
| `Copy-AdoPolicyLabRepositories.py` | Copy sample repos into the lab project | Yes (lab project only) |
| `Test-AdoPolicyLab.py` | Behavioral enforcement tests (uses test branches/PRs) | Yes (test branches/PRs) |
| `Test-Ado2GhMigration.py` | `baseline` → `migrate` → `readback` → `compare` | `migrate` creates GitHub repos |
| `Initialize-AdoPolicyLab.py` | First lab (`contosodevopstest`), superseded; also provides shared rule helpers | Yes |
| `Invoke-GitHubRulesetPolicies.ps1` | Apply GitHub rulesets from CSV (earlier work) | Yes |

## Prerequisites

- Capture/export: **PowerShell 7+** (`pwsh`), no Python or extra PowerShell modules required.
- Capture auth: `ADO_PAT` user/process environment variable with Code, Build, Identity, Project and Team read permissions; or Azure CLI with `az login` and `-Auth az`. User-scoped PAT takes precedence. Tokens are never accepted as script parameters or config values and are not written into the capture.
- Lab/migration harnesses only: Python 3.9+ (`openpyxl` for scripts that read the Excel inventory). These remain Python.
- GitHub (migration only): `GH_PAT` user environment variable, `gh` CLI with the `ado2gh` extension

## Common commands

**Config path is optional:** the script defaults to `config\ado-policy-config.csv` relative to its workspace,
independently of the current terminal directory. Use `-ConfigPath` only to select another CSV.
An empty/missing config or a config without a valid organization is rejected; there is no automatic target fallback.

**Input file: `config\ado-policy-config.csv`.** CSV replaces the previous JSON configuration.
Use exactly these three columns, in this order. A standalone `*` explicitly means "all"; blanks are errors.
The supplied file selects the entire `ado-policy-testing` organization:

```csv
Organization,Project,Repository
ado-policy-testing,*,*
```

To select two projects with two repositories each, replace its rows with:

```csv
Organization,Project,Repository
your-ado-org,project-one,repo-one
your-ado-org,project-one,repo-two
your-ado-org,project-two,repo-three
your-ado-org,project-two,repo-four
```

| Selection | Project | Repository |
|---|---|---|
| Entire organization | `*` | `*` |
| All repositories in one project | Project name/ID | `*` |
| One repository | Project name/ID | Repository name |

For all repos in a project, use `your-ado-org,project-one,*`.
Different projects may select all repositories or individual repositories.
One organization per execution is enforced. Duplicate or overlapping selections are rejected:
do not combine `*,*` with other rows, or `project-one,*` with repository rows for that same project.
Missing/unknown columns, blank fields, and inconsistent row widths fail before authentication.
`*,repo-one`, partial wildcard patterns such as `repo-*`, and semicolon-separated lists are rejected.
Use one repository per row, not a comma-separated list. Quote project names containing commas using standard CSV quoting.
Organization names must be names, not URLs; project names or IDs are accepted; repo names are exact names.
Selections using both a project's name and its ID are also rejected if they resolve to the same project.
CSV contains **no credential columns**. All PAT-based CSV runs use `ADO_PAT`.

The terminal shows organization/project/repository counts and the total unique policy configurations,
broken down into project-wide, repository-wide, cross-repository branch, repository branch, and mixed scopes.
Policies are counted once per project configuration, not once per affected branch or repository.
Organization security settings are explicitly labeled not captured. Detailed JSON remains in the output files.
No extra flag is needed for the screen summary. Preview shows target counts only, not policy counts, and writes no files.

```powershell
# Resolve and display selections only; requires credentials, issues GETs, writes no captures:
pwsh -File .\scripts\capture\Capture-AdoPolicies.ps1 -Preview

# Capture the selections:
pwsh -File .\scripts\capture\Capture-AdoPolicies.ps1 -RunId Snapshot01
```

To scan another organization, change the CSV and replace `ADO_PAT` with that organization's PAT before running again.
Never put a PAT in CSV or a script.

### Safe-Settings GitOps Transformation & PR Submission

Once policies are captured and exported into portable JSON, transform them directly into **`safe-settings`** configuration files:

```powershell
# 1. Transform portable JSON snapshot into Safe-Settings YAML bundle + PR report:
pwsh -File .\scripts\transform\Convert-AdoToSafeSettings.ps1

# Staged files generated in output\safe-settings:
#   .github\settings.yml            -> Org-wide defaults
#   .github\suborgs\<project>.yml   -> Project rulesets & repo settings
#   .github\repos\<repo>.yml        -> Repo-specific overrides
#   MIGRATION-REPORT.md             -> Actionable PR gap report

# 2. Stage to Safe-Settings admin repo and create Pull Request:
pwsh -File .\scripts\pipeline\Submit-SafeSettingsPR.ps1 -AdminRepoPath "..\safe-settings-admin" -ProjectName "project1" -CreatePr
```
To set a session-only PAT interactively without echoing it or recording it in command history:

```powershell
$pat = Read-Host "ADO PAT for ado-policy-testing" -AsSecureString
try {
    $env:ADO_PAT = [System.Net.NetworkCredential]::new('', $pat).Password
} finally {
    $pat.Dispose()
    Remove-Variable pat
}
# Run capture in this PowerShell session (or its child pwsh process).
# Remove the session variable when finished:
# Remove-Item Env:\ADO_PAT
```

Environment variables are not encrypted secret storage. Use a trusted session, avoid environment dumps/transcripts,
and restrict machine/account access. For persistent variables, use your organization's approved secret provisioning.
Do not store both a stale user-scoped variable and a newer process-scoped variable with the same name.

Config-driven captures are separated as:

```text
output\policy-capture\<run-id>\
  capture-summary.json
  project1.capture.json
  project1.portable.json
  project1.review.csv
  project2.capture.json
  project2.portable.json
  project2.review.csv
```

New runs use one folder only, with no organization/project/export subfolders.
Project names form filenames; unsafe or colliding names receive an ID suffix.
Organization/project IDs remain recorded in the raw captures and the summary records organization and capture paths.
Historical captures are not moved. Portable JSON and CSV are created by the separate export step.

Export each project capture with `Export-AdoPolicies.ps1 -Capture <path-from-summary>`.
The summary includes every project's capture path. Captures remain available if a later project fails, but the
script terminates with an error and does not write a complete summary. Use a new run ID when retrying.
Access-limited projects invisible to the credentials cannot be inventoried; explicitly selected inaccessible
projects or repositories fail rather than being silently skipped.

The original direct single-project invocation remains supported (cannot be combined with `-ConfigPath`):

```powershell
pwsh -File .\scripts\capture\Capture-AdoPolicies.ps1 -Org ado-policy-testing -Project project1 -RunId MyCapture01
pwsh -File .\scripts\capture\Export-AdoPolicies.ps1 -Capture .\output\policy-capture\MyCapture01\project1.capture.json
```

New outputs are `<project>.capture.json`, `<project>.portable.json`, and `<project>.review.csv`, all
in the same run folder. Exporting historical `ado-policy-capture.json` inputs still uses the original
`export\ado-policies.portable.json` and `export\ado-policies-review.csv` layout.
Capture/export refuse to overwrite existing files; use a new run ID or export directory.
`-OutputRoot` changes the capture root, and `-OutputDir` changes the export directory.

`-Repos` and `-RunId` are optional for capture. Omit `-Repos` to include all repositories; use
`-Repos sample2,sample3` from PowerShell, or `-Repos "sample2,sample3"` with `pwsh -File`.
Use `-Auth az` for Azure CLI authentication instead of a PAT.
Use `-PatEnvironmentVariable YOUR_ORG_PAT` to override `ADO_PAT` in direct mode.

To export the existing migration baseline with its lab-specific inventory IDs and name mappings:

```powershell
pwsh -File .\scripts\capture\Export-AdoPolicies.ps1 -RunId 20261023Ado2GhMigration01 -OutputDir .\output\policy-export\PowerShellBaseline01
```

Other lab commands:

```powershell
python .\scripts\lab\Initialize-NewOrgPolicyLab.py verify
python -m unittest discover -s .\tests -p "test_*.py"
pwsh -File .\tests\Test-PolicyCapture.ps1
```

The PowerShell regression suite is offline and uses the retained lab/migration evidence as fixtures.
It requires no credentials, modules, or Python.

## Capture scope and safety

Capture uses GET requests only and retains the raw policy settings, repository refs, branch-effective policies,
and resolved identity/pipeline names. It is **not** a full organization backup: organization security switches,
tenant Conditional Access, permissions, and pipeline variables/secrets are not captured.
It does not claim coverage of all 42 inventory entries.

Portable JSON retains setting types and replaces environment-specific IDs with named references.
Fresh captures do not depend on the lab's state files; their inventory IDs remain null because policy IDs
cannot be reliably mapped to this lab's inventory in another environment. Unresolved IDs are preserved and
explicitly listed in `unresolvedReferences`, with warnings. Duplicate reference names cause an error.
The JSON is input for a future restore tool, **not** an implemented restore operation or an automatic rollback.

Review CSV includes raw values and human-readable meanings. Potential spreadsheet formula prefixes are
escaped with an apostrophe in the CSV only; the JSON retains exact values. Treat exports as sensitive internal
configuration: control access to the output folder and do not publish them. Use least-privilege credentials.
Both scripts require PowerShell 7+ explicitly and stop rather than silently truncating JSON at the depth limit.

GitHub ruleset example (preview only):

```powershell
.\scripts\github\Invoke-GitHubRulesetPolicies.ps1 -RepoListPath .\config\repos.sample.txt -UseGhCliAuth -DryRun
```
