#Requires -Version 7.0
<#
.SYNOPSIS
    Transforms an exported ADO policy snapshot into native safe-settings YAML configurations
    and produces an auditable Migration Gap & Review Report.

.DESCRIPTION
    Consumes the portable JSON produced by Export-AdoPolicies.ps1, parses policies across
    Organization, Project, and Repository scopes, and maps them to:
      1. .github/settings.yml             -> Org-wide baseline defaults
      2. .github/suborgs/<project>.yml    -> Project-level sub-org rulesets and repo settings
      3. .github/repos/<repo>.yml         -> Repo-specific ruleset overrides
      4. MIGRATION-REPORT.md              -> Actionable audit report for PR review
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$PortableJsonPath,

    [string]$OutputDir = (Join-Path $PSScriptRoot "..\..\output\safe-settings"),

    [string]$CrosswalkCsvPath = (Join-Path $PSScriptRoot "..\..\docs\policy-crosswalk.csv"),

    [ValidateSet("active", "evaluate", "disabled")]
    [string]$Enforcement = "active",

    [string]$DefaultBranchRef = "~DEFAULT_BRANCH"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Load YAML serializing helper
. (Join-Path $PSScriptRoot "ConvertTo-Yaml.ps1")

function Get-Prop {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Name)) { return $Obj[$Name] }
        return $Default
    }
    if ($Obj.PSObject -and $Obj.PSObject.Properties[$Name]) {
        return $Obj.$Name
    }
    return $Default
}

# ---------------------------------------------------------------------------
# 1. Locate Portable JSON Snapshot
# ---------------------------------------------------------------------------
if (-not $PortableJsonPath) {
    $latestCapture = Get-ChildItem (Join-Path $PSScriptRoot "..\..\output\policy-capture") -Filter "*.portable.json" -Recurse |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $latestCapture) {
        throw "No *.portable.json found in output\policy-capture. Run Capture-AdoPolicies.ps1 and Export-AdoPolicies.ps1 first."
    }
    $PortableJsonPath = $latestCapture.FullName
}

if (-not (Test-Path $PortableJsonPath)) {
    throw "Portable JSON file not found: $PortableJsonPath"
}

Write-Host "Reading ADO snapshot: $PortableJsonPath" -ForegroundColor Cyan
$adoData = Get-Content -LiteralPath $PortableJsonPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 100

$orgName = if (Get-Prop $adoData.source "organization") { $adoData.source.organization } else { "ado-org" }
$projectName = if (Get-Prop $adoData.source "project") { $adoData.source.project } else { "ado-project" }

# Extract all repositories discovered in this project (check capture-summary.json or capture.json)
$allRepos = [System.Collections.Generic.List[string]]::new()

$parentDir = Split-Path $PortableJsonPath
$summaryJsonPath = Join-Path $parentDir "capture-summary.json"
if (Test-Path $summaryJsonPath) {
    $sumData = Get-Content -LiteralPath $summaryJsonPath -Raw -Encoding utf8 | ConvertFrom-Json
    if ($sumData.captures -and $sumData.captures[0].repositories) {
        foreach ($r in $sumData.captures[0].repositories) {
            if (-not $allRepos.Contains($r)) { $allRepos.Add($r) }
        }
    }
}

$captureJsonPath = $PortableJsonPath -replace '\.portable\.json$', '.capture.json'
if ($allRepos.Count -eq 0 -and (Test-Path $captureJsonPath)) {
    $capData = Get-Content -LiteralPath $captureJsonPath -Raw -Encoding utf8 | ConvertFrom-Json
    if (Get-Prop $capData "repositories") {
        foreach ($p in $capData.repositories.PSObject.Properties.Name) {
            if (-not $allRepos.Contains($p)) { $allRepos.Add($p) }
        }
    }
}

if ($allRepos.Count -eq 0 -and (Get-Prop $adoData "references") -and (Get-Prop $adoData.references "repositories")) {
    foreach ($rName in $adoData.references.repositories.PSObject.Properties.Name) {
        if (-not $allRepos.Contains($rName)) { $allRepos.Add($rName) }
    }
}
if ($allRepos.Count -eq 0) {
    $allRepos.Add($projectName)
}

Write-Host "Discovered $($adoData.policies.Count) policies for Project '$projectName' across $($allRepos.Count) repositories ($($allRepos -join ', '))" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 2. Partition Policies by Scope
# ---------------------------------------------------------------------------
$projectPolicies = [System.Collections.Generic.List[object]]::new()
$repoScopedPolicies = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new()

foreach ($pol in $adoData.policies) {
    $isEnabled = Get-Prop $pol "isEnabled" $true
    $isDeleted = Get-Prop $pol "isDeleted" $false
    if (-not $isEnabled -or $isDeleted) {
        continue # Skip disabled or deleted policies
    }

    $repoRef = $null
    $scope = Get-Prop $pol "scope"
    if ($scope -and $scope.Count -gt 0) {
        $firstScope = $scope[0]
        $repoObj = Get-Prop $firstScope "repository"
        if ($repoObj) {
            $refStr = Get-Prop $repoObj '$ref'
            if ($refStr -and $refStr -match '^repository:(.+)$') {
                $repoRef = $Matches[1]
            }
        }
    }

    if ($null -eq $repoRef) {
        $projectPolicies.Add($pol)
    } else {
        if (-not $repoScopedPolicies.ContainsKey($repoRef)) {
            $repoScopedPolicies[$repoRef] = [System.Collections.Generic.List[object]]::new()
        }
        $repoScopedPolicies[$repoRef].Add($pol)
    }
}

# ---------------------------------------------------------------------------
# 3. Helper: Map Policy List to Rulesets & Repo Settings
# ---------------------------------------------------------------------------
function Convert-PolicyListToSafeSettingsBlocks {
    param(
        [System.Collections.Generic.List[object]]$Policies,
        [string]$ScopeName,
        [string]$BranchRefPattern
    )

    $branchRules = [System.Collections.Generic.List[object]]::new()
    $pushRules = [System.Collections.Generic.List[object]]::new()
    $repoSettings = [ordered]@{}

    # Aggregated Pull Request Rule parameters
    $prParams = [ordered]@{
        required_approving_review_count = 1
        dismiss_stale_reviews_on_push = $false
        require_code_owner_review = $false
        require_last_push_approval = $false
        required_review_thread_resolution = $false
    }
    $hasPrPolicy = $false
    $allowedMergeMethods = [System.Collections.Generic.List[string]]::new()

    # Status checks list
    $statusChecksList = [System.Collections.Generic.List[object]]::new()

    foreach ($pol in $Policies) {
        $typeName = $pol.type.displayName
        $st = Get-Prop $pol "settings"

        switch ($typeName) {
            "Minimum number of reviewers" {
                $hasPrPolicy = $true
                $minApprovers = Get-Prop $st "minimumApproverCount"
                if ($minApprovers) {
                    $prParams.required_approving_review_count = [int]$minApprovers
                }
                $resetOnPush = Get-Prop $st "resetOnSourcePush" $false
                if ($resetOnPush) {
                    $prParams.dismiss_stale_reviews_on_push = $true
                }
                $blockLastPusher = Get-Prop $st "blockLastPusherVote" $false
                $prohibitRequester = Get-Prop $st "prohibitRequesterFromApproving" $false
                if ($blockLastPusher -or $prohibitRequester) {
                    $prParams.require_last_push_approval = $true
                }
            }

            "Comment requirements" {
                $hasPrPolicy = $true
                $prParams.required_review_thread_resolution = $true
            }

            "Require a merge strategy" {
                $allowSquash = Get-Prop $st "allowSquash" $false
                $allowNoFF = Get-Prop $st "allowNoFastForward" $false
                $allowRebase = Get-Prop $st "allowRebase" $false
                $allowRebaseMerge = Get-Prop $st "allowRebaseMerge" $false

                if ($allowSquash) {
                    $allowedMergeMethods.Add("squash")
                    $repoSettings["allow_squash_merge"] = $true
                }
                if ($allowNoFF) {
                    $allowedMergeMethods.Add("merge")
                    $repoSettings["allow_merge_commit"] = $true
                }
                if ($allowRebase -or $allowRebaseMerge) {
                    $allowedMergeMethods.Add("rebase")
                    $repoSettings["allow_rebase_merge"] = $true
                }
            }

            "Build" {
                $pipelineName = "build"
                $buildDef = Get-Prop $st "buildDefinitionId"
                if ($buildDef) {
                    $refVal = Get-Prop $buildDef '$ref'
                    if ($refVal) {
                        $pipelineName = ($refVal -replace '^pipeline:', '')
                    } else {
                        $pipelineName = "pipeline-$buildDef"
                    }
                }
                $statusChecksList.Add([ordered]@{ context = $pipelineName })
            }

            "Status" {
                $genre = Get-Prop $st "genre"
                $sName = Get-Prop $st "name"
                $ctx = if ($genre -and $sName) { "$genre/$sName" } elseif ($sName) { $sName } else { "status-check" }
                $statusChecksList.Add([ordered]@{ context = $ctx })
            }

            "File size restriction" {
                $maxBytes = Get-Prop $st "maximumGitBlobSizeInBytes" 104857600
                $maxMb = [math]::Max(1, [math]::Round([int64]$maxBytes / 1048576))
                $pushRules.Add([ordered]@{
                    type = "max_file_size"
                    parameters = [ordered]@{ max_file_size = [int]$maxMb }
                })
            }

            "Path Length restriction" {
                $maxLen = Get-Prop $st "maxPathLength" 248
                $pushRules.Add([ordered]@{
                    type = "max_file_path_length"
                    parameters = [ordered]@{ max_file_path_length = [int]$maxLen }
                })
            }

            "File name restriction" {
                $rawPaths = Get-Prop $st "filenamePatterns"
                $patterns = if ($rawPaths -is [System.Collections.IEnumerable] -and $rawPaths -isnot [string]) {
                    @($rawPaths)
                } elseif ($rawPaths) {
                    @([string]$rawPaths)
                } else {
                    @("*.exe", "*.dll")
                }
                $pushRules.Add([ordered]@{
                    type = "file_path_restriction"
                    parameters = [ordered]@{ restricted_file_paths = $patterns }
                })
            }

            "Commit author email validation" {
                $rawList = Get-Prop $st "authorEmailPatterns"
                $rawPattern = if ($rawList -is [System.Collections.IEnumerable] -and $rawList -isnot [string]) {
                    [string]($rawList | Select-Object -First 1)
                } elseif ($rawList) {
                    [string]$rawList
                } else {
                    "*@contoso.com"
                }

                $operator = "ends_with"
                $cleanPattern = $rawPattern
                if ($rawPattern -match '^\*@(.+)$') {
                    $cleanPattern = "@$($Matches[1])"
                    $operator = "ends_with"
                } elseif ($rawPattern -match '\*') {
                    $cleanPattern = $rawPattern
                    $operator = "regex"
                }

                $pushRules.Add([ordered]@{
                    type = "commit_author_email_pattern"
                    parameters = [ordered]@{
                        operator = $operator
                        pattern = $cleanPattern
                        negate = $false
                    }
                })
            }
        }
    }

    # If any PR settings were present, add the pull_request rule
    if ($hasPrPolicy -or $allowedMergeMethods.Count -gt 0) {
        if ($allowedMergeMethods.Count -gt 0) {
            $prParams["allowed_merge_methods"] = $allowedMergeMethods
        }
        $branchRules.Add([ordered]@{
            type = "pull_request"
            parameters = $prParams
        })
    }

    # Add required status checks if any
    if ($statusChecksList.Count -gt 0) {
        $branchRules.Add([ordered]@{
            type = "required_status_checks"
            parameters = [ordered]@{
                strict_required_status_checks_policy = $true
                required_status_checks = $statusChecksList
            }
        })
    }

    # Add implicit safe branch protections (prevent deletion, prevent force-push)
    if ($branchRules.Count -gt 0) {
        $branchRules.Add([ordered]@{ type = "non_fast_forward" })
        $branchRules.Add([ordered]@{ type = "deletion" })
    }

    # Assemble rulesets list
    $rulesets = [System.Collections.Generic.List[object]]::new()
    if ($branchRules.Count -gt 0) {
        $rulesets.Add([ordered]@{
            name = "$ScopeName-branch-policy"
            target = "branch"
            enforcement = $Enforcement
            conditions = [ordered]@{
                ref_name = [ordered]@{
                    include = @($BranchRefPattern)
                    exclude = @()
                }
            }
            rules = $branchRules
        })
    }

    if ($pushRules.Count -gt 0) {
        $rulesets.Add([ordered]@{
            name = "$ScopeName-push-policy"
            target = "push"
            enforcement = $Enforcement
            rules = $pushRules
        })
    }

    return @{
        RepositorySettings = $repoSettings
        Rulesets = $rulesets
    }
}

# ---------------------------------------------------------------------------
# 4. Generate Safe-Settings Output Files
# ---------------------------------------------------------------------------
$suborgDir = Join-Path $OutputDir ".github\suborgs"
$repoDir = Join-Path $OutputDir ".github\repos"
$null = New-Item -ItemType Directory -Path $suborgDir -Force
$null = New-Item -ItemType Directory -Path $repoDir -Force

# --- A. Generate .github/settings.yml (Org Baseline) ---
$orgSettingsObj = [ordered]@{
    repository = [ordered]@{
        enable_automated_security_fixes = $true
        enable_vulnerability_alerts = $true
        delete_branch_on_merge = $true
    }
}
$orgSettingsYaml = ConvertTo-Yaml -InputObject $orgSettingsObj
$settingsFilePath = Join-Path $OutputDir ".github\settings.yml"
Set-Content -Path $settingsFilePath -Value $orgSettingsYaml -Encoding utf8
Write-Host "Created: $settingsFilePath" -ForegroundColor Green

# --- B. Generate .github/suborgs/<project>.yml ---
$projectBlocks = Convert-PolicyListToSafeSettingsBlocks -Policies $projectPolicies -ScopeName $projectName -BranchRefPattern $DefaultBranchRef

$suborgDoc = [ordered]@{
    suborg = [ordered]@{
        name = $projectName
        repos = @($allRepos)
    }
}
if ($projectBlocks.RepositorySettings.Count -gt 0) {
    $suborgDoc["repository"] = $projectBlocks.RepositorySettings
}
if ($projectBlocks.Rulesets.Count -gt 0) {
    $suborgDoc["repository_rulesets"] = $projectBlocks.Rulesets
}

$suborgYaml = ConvertTo-Yaml -InputObject $suborgDoc
$suborgFilePath = Join-Path $suborgDir "$projectName.yml"
Set-Content -Path $suborgFilePath -Value $suborgYaml -Encoding utf8
Write-Host "Created: $suborgFilePath" -ForegroundColor Green

# --- C. Generate .github/repos/<repo>.yml for Repo-scoped overrides ---
$repoFilesCreated = 0
foreach ($rName in $repoScopedPolicies.Keys) {
    $rPolicies = $repoScopedPolicies[$rName]
    $repoBlocks = Convert-PolicyListToSafeSettingsBlocks -Policies $rPolicies -ScopeName $rName -BranchRefPattern $DefaultBranchRef

    $repoDoc = [ordered]@{
        name = $rName
    }
    if ($repoBlocks.RepositorySettings.Count -gt 0) {
        $repoDoc["repository"] = $repoBlocks.RepositorySettings
    }
    if ($repoBlocks.Rulesets.Count -gt 0) {
        $repoDoc["repository_rulesets"] = $repoBlocks.Rulesets
    }

    $repoYaml = ConvertTo-Yaml -InputObject $repoDoc
    $repoFilePath = Join-Path $repoDir "$rName.yml"
    Set-Content -Path $repoFilePath -Value $repoYaml -Encoding utf8
    Write-Host "Created: $repoFilePath" -ForegroundColor Green
    $repoFilesCreated++
}

# ---------------------------------------------------------------------------
# 5. Generate Auditable MIGRATION-REPORT.md
# ---------------------------------------------------------------------------
$reportPath = Join-Path $OutputDir "MIGRATION-REPORT.md"
$totalPolicies = $adoData.policies.Count
$mappedPoliciesCount = $projectPolicies.Count
foreach ($k in $repoScopedPolicies.Keys) { $mappedPoliciesCount += $repoScopedPolicies[$k].Count }
$allReposStr = ($allRepos -join ', ')

$lines = @(
    "# ADO to GitHub Policy Migration Report",
    "",
    "## Migration Overview",
    "- **Source ADO Organization:** $orgName",
    "- **Source ADO Project:** $projectName",
    "- **Total Policies Captured:** $totalPolicies",
    "- **Policies Processed into Safe-Settings:** $mappedPoliciesCount",
    "- **Sub-Org Config File:** `.github/suborgs/$projectName.yml` (governs $($allRepos.Count) repositories: $allReposStr)",
    "- **Repository-specific Override Files:** $repoFilesCreated (under `.github/repos/`)",
    "",
    "---",
    "",
    "## Parity & Mapping Summary",
    "",
    "| ADO Policy Name | Scope | Safe-Settings Mapping Status | GitHub Equivalent Feature | Action Required |",
    "|---|---|---|---|---|",
    "| Commit author email validation | Project & Repo | **Mapped (Close)** | Ruleset: ``commit_author_email_pattern`` | Verify domain pattern |",
    "| File size restriction | Project & Repo | **Mapped (Exact)** | Ruleset: ``max_file_size`` | Converted from bytes to MB |",
    "| Path Length restriction | Project & Repo | **Mapped (Exact)** | Ruleset: ``max_file_path_length`` | Exact match |",
    "| File name restriction | Project & Repo | **Mapped (Exact)** | Ruleset: ``file_path_restriction`` | Uses fnmatch path patterns |",
    "| Minimum number of reviewers | Project & Repo | **Mapped (Close)** | Ruleset: ``pull_request`` approvals | Approver count & reset-on-push mapped |",
    "| Comment requirements | Project & Repo | **Mapped (Exact)** | Ruleset: ``required_review_thread_resolution`` | Blocks merge until threads resolved |",
    "| Require a merge strategy | Project & Repo | **Mapped (Exact)** | Ruleset ``allowed_merge_methods`` & Repo settings | Squash / Merge / Rebase toggles |",
    "| Build validation | Project & Repo | **Mapped (Action Needed)** | Ruleset: ``required_status_checks`` | **Confirm check context matches GitHub Actions workflow** |",
    "| Status checks | Project & Repo | **Mapped (Action Needed)** | Ruleset: ``required_status_checks`` | Verify publisher App/status name |",
    "| Work item linking | Project & Repo | **Gap / Custom Implementation** | Custom Status Check / GHA | Informational only in native GitHub; require GHA if blocking |",
    "| Reserved names restriction | Project & Repo | **Partial / Workaround** | Ruleset: ``file_path_restriction`` | Enumerate OS reserved names (CON, NUL) if required |",
    "| Git repository settings (Case enforcement) | Project & Repo | **No Direct Equivalent** | Not supported natively | Catch via pre-commit or CI linting |",
    "",
    "---",
    "",
    "## Action Checklist for Pull Request Reviewers",
    "1. [ ] **Verify Sub-Org Target Repos:** Check ``.github/suborgs/$projectName.yml`` to ensure all migrated repos are listed under ``repos:``.",
    "2. [ ] **Confirm Build Check Names:** In ADO, builds used pipeline names (e.g., ``policy-lab-sample2``). Ensure the corresponding GitHub Actions workflow job is named identically so status checks unblock merges.",
    "3. [ ] **Review Dry-Run Output:** Review the Safe-Settings bot comment on this Pull Request to inspect the exact API changes before merging."
)

Set-Content -Path $reportPath -Value ($lines -join "`n") -Encoding utf8
Write-Host "Created Migration Report: $reportPath" -ForegroundColor Green

Write-Host "`nTransformation complete! Files staged in: $OutputDir" -ForegroundColor Cyan
