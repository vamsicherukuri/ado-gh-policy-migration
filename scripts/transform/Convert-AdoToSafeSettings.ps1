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
# 1. Locate Portable JSON Snapshot & Disambiguate Capture
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

# Resolve repositories from summary or capture JSON with unambiguous matching
$allRepos = [System.Collections.Generic.List[string]]::new()
$parentDir = Split-Path $PortableJsonPath
$summaryJsonPath = Join-Path $parentDir "capture-summary.json"

if (Test-Path $summaryJsonPath) {
    $sumData = Get-Content -LiteralPath $summaryJsonPath -Raw -Encoding utf8 | ConvertFrom-Json
    if ($sumData.captures) {
        $normalizedPortable = [System.IO.Path]::GetFullPath($PortableJsonPath)
        $expectedCapturePath = $normalizedPortable -replace '\.portable\.json$', '.capture.json'
        
        $matches = @($sumData.captures | Where-Object {
            ($_.project -eq $projectName -and (-not $_.organization -or $_.organization -eq $orgName)) -or
            ([System.IO.Path]::GetFullPath($_.capture) -eq $expectedCapturePath)
        })

        if ($matches.Count -gt 1) {
            throw "Ambiguous capture match: Found $($matches.Count) entries for Project '$projectName' in '$summaryJsonPath'. Specify an exact capture file."
        } elseif ($matches.Count -eq 1 -and $matches[0].repositories) {
            foreach ($r in $matches[0].repositories) {
                if (-not $allRepos.Contains($r)) { $allRepos.Add($r) }
            }
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
# 2. Ref Translation Helper (ADO matchKind -> GitHub Ruleset ref_name)
# ---------------------------------------------------------------------------
function Convert-AdoRefToGitHubPattern {
    param(
        [string]$RefName,
        [string]$MatchKind,
        [string]$FallbackPattern
    )

    if (-not $RefName) {
        return $FallbackPattern
    }

    switch ($MatchKind) {
        "Prefix" {
            # In ADO, refs/heads/policy-lab/ with Prefix means anything under that hierarchy
            $trimmed = $RefName.TrimEnd('/')
            return "$trimmed/**"
        }
        "Exact" {
            return $RefName
        }
        "DefaultBranch" {
            return "~DEFAULT_BRANCH"
        }
        default {
            if ($RefName.EndsWith('/')) {
                return "$($RefName.TrimEnd('/'))/**"
            }
            return $RefName
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Partition Policies by Target Repository, Branch Ref, and Blocking Mode
# ---------------------------------------------------------------------------
# Structured item: @{ Policy = $pol; TargetRepo = $repo; RefPattern = $ref; IsBlocking = $bool }
$projectScopedItems = [System.Collections.Generic.List[object]]::new()
$repoScopedItems = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new()

# Audit lists for report
$processedPolicies = [System.Collections.Generic.List[object]]::new()
$requiredReviewerPolicies = [System.Collections.Generic.List[object]]::new()
$mergeOnlyPolicies = [System.Collections.Generic.List[object]]::new()

foreach ($pol in $adoData.policies) {
    $isEnabled = Get-Prop $pol "isEnabled" $true
    $isDeleted = Get-Prop $pol "isDeleted" $false
    if (-not $isEnabled -or $isDeleted) {
        continue
    }

    $isBlocking = [bool](Get-Prop $pol "isBlocking" $true)
    $processedPolicies.Add($pol)

    $scopes = Get-Prop $pol "scope"
    if (-not $scopes -or $scopes.Count -eq 0) {
        $scopes = @([ordered]@{ repository = $null; refName = $null; matchKind = $null })
    }

    # Each tuple in scope represents an explicit target pairing
    foreach ($sc in $scopes) {
        $repoRef = $null
        $repoObj = Get-Prop $sc "repository"
        if ($repoObj) {
            $refStr = Get-Prop $repoObj '$ref'
            if ($refStr -and $refStr -match '^repository:(.+)$') {
                $repoRef = $Matches[1]
            }
        }

        $rawRefName = Get-Prop $sc "refName"
        $rawMatchKind = Get-Prop $sc "matchKind"
        $ghRefPattern = Convert-AdoRefToGitHubPattern -RefName $rawRefName -MatchKind $rawMatchKind -FallbackPattern $DefaultBranchRef

        $item = @{
            Policy = $pol
            TargetRepo = $repoRef
            RawRefName = $rawRefName
            RefPattern = $ghRefPattern
            IsBlocking = $isBlocking
        }

        if ($null -eq $repoRef) {
            $projectScopedItems.Add($item)
        } else {
            if (-not $repoScopedItems.ContainsKey($repoRef)) {
                $repoScopedItems[$repoRef] = [System.Collections.Generic.List[object]]::new()
            }
            $repoScopedItems[$repoRef].Add($item)
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Ruleset & Repository Settings Generator
# ---------------------------------------------------------------------------
function Build-SafeSettingsScopeBlocks {
    param(
        [System.Collections.Generic.List[object]]$Items,
        [string]$ScopeIdentifier
    )

    $repoSettings = [ordered]@{}
    $rulesets = [System.Collections.Generic.List[object]]::new()

    # Partition items by (IsBlocking, RefPattern) for Branch Rules,
    # and (IsBlocking) for Push Rules & Metadata Rules
    $branchBuckets = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new()
    $pushBuckets = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new()
    $emailBuckets = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new()

    foreach ($it in $Items) {
        $pol = $it.Policy
        $typeName = $pol.type.displayName
        $st = Get-Prop $pol "settings"
        $isBlock = $it.IsBlocking
        $refPat = $it.RefPattern

        # Key for grouping
        $blockKey = if ($isBlock) { "blocking" } else { "evaluate" }
        $branchKey = "$blockKey|$refPat"

        switch ($typeName) {
            "Minimum number of reviewers" {
                if (-not $branchBuckets.ContainsKey($branchKey)) { $branchBuckets[$branchKey] = [System.Collections.Generic.List[object]]::new() }
                $branchBuckets[$branchKey].Add($it)
            }
            "Comment requirements" {
                if (-not $branchBuckets.ContainsKey($branchKey)) { $branchBuckets[$branchKey] = [System.Collections.Generic.List[object]]::new() }
                $branchBuckets[$branchKey].Add($it)
            }
            "Build" {
                if (-not $branchBuckets.ContainsKey($branchKey)) { $branchBuckets[$branchKey] = [System.Collections.Generic.List[object]]::new() }
                $branchBuckets[$branchKey].Add($it)
            }
            "Status" {
                if (-not $branchBuckets.ContainsKey($branchKey)) { $branchBuckets[$branchKey] = [System.Collections.Generic.List[object]]::new() }
                $branchBuckets[$branchKey].Add($it)
            }
            "Require a merge strategy" {
                # Merge strategy affects both repo-wide settings and branch rules
                if ((Get-Prop $st "allowSquash") -eq $true) { $repoSettings["allow_squash_merge"] = $true }
                if ((Get-Prop $st "allowNoFastForward") -eq $true) { $repoSettings["allow_merge_commit"] = $true }
                if ((Get-Prop $st "allowRebase") -eq $true -or (Get-Prop $st "allowRebaseMerge") -eq $true) { $repoSettings["allow_rebase_merge"] = $true }

                if (-not $branchBuckets.ContainsKey($branchKey)) { $branchBuckets[$branchKey] = [System.Collections.Generic.List[object]]::new() }
                $branchBuckets[$branchKey].Add($it)
            }
            "Required reviewers" {
                $script:requiredReviewerPolicies.Add($pol)
            }
            "File size restriction" {
                if (-not $pushBuckets.ContainsKey($blockKey)) { $pushBuckets[$blockKey] = [System.Collections.Generic.List[object]]::new() }
                $pushBuckets[$blockKey].Add($it)
            }
            "Path Length restriction" {
                if (-not $pushBuckets.ContainsKey($blockKey)) { $pushBuckets[$blockKey] = [System.Collections.Generic.List[object]]::new() }
                $pushBuckets[$blockKey].Add($it)
            }
            "File name restriction" {
                if (-not $pushBuckets.ContainsKey($blockKey)) { $pushBuckets[$blockKey] = [System.Collections.Generic.List[object]]::new() }
                $pushBuckets[$blockKey].Add($it)
            }
            "Commit author email validation" {
                if (-not $emailBuckets.ContainsKey($blockKey)) { $emailBuckets[$blockKey] = [System.Collections.Generic.List[object]]::new() }
                $emailBuckets[$blockKey].Add($it)
            }
        }
    }

    # Helper: Resolve ruleset-level enforcement
    function Get-RulesetEnforcement([string]$ModeKey) {
        if ($Enforcement -eq "disabled") { return "disabled" }
        if ($ModeKey -eq "evaluate") { return "evaluate" }
        return $Enforcement
    }

    # --- Build Branch Rulesets ---
    foreach ($bKey in $branchBuckets.Keys) {
        $parts = $bKey -split '\|', 2
        $modeKey = $parts[0]
        $refPattern = $parts[1]
        $bucketItems = $branchBuckets[$bKey]

        $branchRules = [System.Collections.Generic.List[object]]::new()
        $statusChecks = [System.Collections.Generic.List[object]]::new()
        $allowedMergeMethods = [System.Collections.Generic.List[string]]::new()

        $hasReviewerPolicy = $false
        $hasPrPolicy = $false
        $minApproverCount = 0
        $dismissStale = $false
        $requireLastPush = $false
        $requireThreads = $false

        foreach ($it in $bucketItems) {
            $tName = $it.Policy.type.displayName
            $s = Get-Prop $it.Policy "settings"

            switch ($tName) {
                "Minimum number of reviewers" {
                    $hasPrPolicy = $true
                    $hasReviewerPolicy = $true
                    $cnt = Get-Prop $s "minimumApproverCount"
                    if ($cnt) { $minApproverCount = [int]$cnt }
                    if ((Get-Prop $s "resetOnSourcePush") -eq $true) { $dismissStale = $true }
                    if ((Get-Prop $s "blockLastPusherVote") -eq $true -or (Get-Prop $s "prohibitRequesterFromApproving") -eq $true) {
                        $requireLastPush = $true
                    }
                }
                "Comment requirements" {
                    $hasPrPolicy = $true
                    $requireThreads = $true
                }
                "Require a merge strategy" {
                    $hasPrPolicy = $true
                    if ((Get-Prop $s "allowSquash") -eq $true -and -not $allowedMergeMethods.Contains("squash")) { $allowedMergeMethods.Add("squash") }
                    if ((Get-Prop $s "allowNoFastForward") -eq $true -and -not $allowedMergeMethods.Contains("merge")) { $allowedMergeMethods.Add("merge") }
                    if (((Get-Prop $s "allowRebase") -eq $true -or (Get-Prop $s "allowRebaseMerge") -eq $true) -and -not $allowedMergeMethods.Contains("rebase")) {
                        $allowedMergeMethods.Add("rebase")
                    }
                    if (-not $hasReviewerPolicy) {
                        $script:mergeOnlyPolicies.Add($it.Policy)
                    }
                }
                "Build" {
                    $pName = "build"
                    $bDef = Get-Prop $s "buildDefinitionId"
                    if ($bDef) {
                        $refVal = Get-Prop $bDef '$ref'
                        if ($refVal) { $pName = ($refVal -replace '^pipeline:', '') }
                        else { $pName = "pipeline-$bDef" }
                    }
                    $statusChecks.Add([ordered]@{ context = $pName })
                }
                "Status" {
                    $genre = Get-Prop $s "genre"
                    $sName = Get-Prop $s "name"
                    $ctx = if ($genre -and $sName) { "$genre/$sName" } elseif ($sName) { $sName } else { "status-check" }
                    $statusChecks.Add([ordered]@{ context = $ctx })
                }
            }
        }

        # Build pull_request rule
        if ($hasPrPolicy) {
            $prParameters = [ordered]@{
                required_approving_review_count = if ($hasReviewerPolicy) { $minApproverCount } else { 0 }
                dismiss_stale_reviews_on_push = $dismissStale
                require_code_owner_review = $false
                require_last_push_approval = $requireLastPush
                required_review_thread_resolution = $requireThreads
            }
            if ($allowedMergeMethods.Count -gt 0) {
                $prParameters["allowed_merge_methods"] = $allowedMergeMethods
            }
            $branchRules.Add([ordered]@{
                type = "pull_request"
                parameters = $prParameters
            })
        }

        # Build required_status_checks rule
        if ($statusChecks.Count -gt 0) {
            $branchRules.Add([ordered]@{
                type = "required_status_checks"
                parameters = [ordered]@{
                    strict_required_status_checks_policy = $true
                    required_status_checks = $statusChecks
                }
            })
        }

        if ($branchRules.Count -gt 0) {
            # Add implicit branch protection rules only to blocking branch rulesets
            if ($modeKey -eq "blocking") {
                $branchRules.Add([ordered]@{ type = "non_fast_forward" })
                $branchRules.Add([ordered]@{ type = "deletion" })
            }

            $refSlug = ($refPattern -replace '[^A-Za-z0-9_-]', '-') -replace '-+', '-'
            $rulesetName = "$ScopeIdentifier-$refSlug-$modeKey"
            
            $rulesets.Add([ordered]@{
                name = $rulesetName
                target = "branch"
                enforcement = Get-RulesetEnforcement $modeKey
                conditions = [ordered]@{
                    ref_name = [ordered]@{
                        include = @($refPattern)
                        exclude = @()
                    }
                }
                rules = $branchRules
            })
        }
    }

    # --- Build Push Rulesets (File size, path length, path restriction) ---
    foreach ($mKey in $pushBuckets.Keys) {
        $pushItems = $pushBuckets[$mKey]
        $pushRules = [System.Collections.Generic.List[object]]::new()

        foreach ($it in $pushItems) {
            $tName = $it.Policy.type.displayName
            $s = Get-Prop $it.Policy "settings"
            switch ($tName) {
                "File size restriction" {
                    $maxBytes = Get-Prop $s "maximumGitBlobSizeInBytes" 104857600
                    $maxMb = [math]::Max(1, [math]::Round([int64]$maxBytes / 1048576))
                    $pushRules.Add([ordered]@{
                        type = "max_file_size"
                        parameters = [ordered]@{ max_file_size = [int]$maxMb }
                    })
                }
                "Path Length restriction" {
                    $maxLen = Get-Prop $s "maxPathLength" 248
                    $pushRules.Add([ordered]@{
                        type = "max_file_path_length"
                        parameters = [ordered]@{ max_file_path_length = [int]$maxLen }
                    })
                }
                "File name restriction" {
                    $rawPaths = Get-Prop $s "filenamePatterns"
                    $patterns = if ($rawPaths -is [System.Collections.IEnumerable] -and $rawPaths -isnot [string]) {
                        @($rawPaths)
                    } elseif ($rawPaths) { @([string]$rawPaths) }
                    else { @("*.exe", "*.dll") }
                    $pushRules.Add([ordered]@{
                        type = "file_path_restriction"
                        parameters = [ordered]@{ restricted_file_paths = $patterns }
                    })
                }
            }
        }

        if ($pushRules.Count -gt 0) {
            $rulesets.Add([ordered]@{
                name = "$ScopeIdentifier-push-$mKey"
                target = "push"
                enforcement = Get-RulesetEnforcement $mKey
                rules = $pushRules
            })
        }
    }

    # --- Build Dedicated Commit Author Email Rulesets (Branch Target ~ALL) ---
    foreach ($mKey in $emailBuckets.Keys) {
        $emailItems = $emailBuckets[$mKey]
        $emailRules = [System.Collections.Generic.List[object]]::new()

        foreach ($it in $emailItems) {
            $s = Get-Prop $it.Policy "settings"
            $rawList = Get-Prop $s "authorEmailPatterns"
            $patterns = if ($rawList -is [System.Collections.IEnumerable] -and $rawList -isnot [string]) {
                @($rawList)
            } elseif ($rawList) { @([string]$rawList) }
            else { @("*@contoso.com") }

            foreach ($rawPattern in $patterns) {
                $pStr = [string]$rawPattern
                $operator = "ends_with"
                $cleanPattern = $pStr

                if ($pStr -match '^\*@(.+)$') {
                    $cleanPattern = "@$($Matches[1])"
                    $operator = "ends_with"
                } elseif ($pStr -match '^\*(.+)$') {
                    $cleanPattern = $Matches[1]
                    $operator = "ends_with"
                } elseif (-not $pStr.Contains('*')) {
                    $operator = "equals"
                    $cleanPattern = $pStr
                } else {
                    $operator = "regex"
                    $cleanPattern = $pStr
                }

                $emailRules.Add([ordered]@{
                    type = "commit_author_email_pattern"
                    parameters = [ordered]@{
                        operator = $operator
                        pattern = $cleanPattern
                        negate = $false
                    }
                })
            }
        }

        if ($emailRules.Count -gt 0) {
            $rulesets.Add([ordered]@{
                name = "$ScopeIdentifier-commit-metadata-$mKey"
                target = "branch"
                enforcement = Get-RulesetEnforcement $mKey
                conditions = [ordered]@{
                    ref_name = [ordered]@{
                        include = @("~ALL")
                        exclude = @()
                    }
                }
                rules = $emailRules
            })
        }
    }

    return @{
        RepositorySettings = $repoSettings
        Rulesets = $rulesets
    }
}

# ---------------------------------------------------------------------------
# 5. Generate Safe-Settings Output Files
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
$projectBlocks = Build-SafeSettingsScopeBlocks -Items $projectScopedItems -ScopeIdentifier $projectName

$suborgDoc = [ordered]@{
    suborgrepos = @($allRepos)
}
if ($projectBlocks.RepositorySettings.Count -gt 0) {
    $suborgDoc["repository"] = $projectBlocks.RepositorySettings
}
if ($projectBlocks.Rulesets.Count -gt 0) {
    $suborgDoc["rulesets"] = $projectBlocks.Rulesets
}

$suborgYaml = ConvertTo-Yaml -InputObject $suborgDoc
$suborgFilePath = Join-Path $suborgDir "$projectName.yml"
Set-Content -Path $suborgFilePath -Value $suborgYaml -Encoding utf8
Write-Host "Created: $suborgFilePath" -ForegroundColor Green

# --- C. Generate .github/repos/<repo>.yml for Repo-scoped overrides ---
$repoFilesCreated = 0
foreach ($rName in $repoScopedItems.Keys) {
    $rItems = $repoScopedItems[$rName]
    $repoBlocks = Build-SafeSettingsScopeBlocks -Items $rItems -ScopeIdentifier $rName

    $repoDoc = [ordered]@{
        repository = [ordered]@{
            name = $rName
        }
    }
    if ($repoBlocks.RepositorySettings.Count -gt 0) {
        foreach ($k in $repoBlocks.RepositorySettings.Keys) {
            $repoDoc.repository[$k] = $repoBlocks.RepositorySettings[$k]
        }
    }
    if ($repoBlocks.Rulesets.Count -gt 0) {
        $repoDoc["rulesets"] = $repoBlocks.Rulesets
    }

    $repoYaml = ConvertTo-Yaml -InputObject $repoDoc
    $repoFilePath = Join-Path $repoDir "$rName.yml"
    Set-Content -Path $repoFilePath -Value $repoYaml -Encoding utf8
    Write-Host "Created: $repoFilePath" -ForegroundColor Green
    $repoFilesCreated++
}

# ---------------------------------------------------------------------------
# 6. Generate Auditable MIGRATION-REPORT.md
# ---------------------------------------------------------------------------
$reportPath = Join-Path $OutputDir "MIGRATION-REPORT.md"
$totalCaptured = $adoData.policies.Count
$processedCount = $processedPolicies.Count
$allReposStr = ($allRepos -join ', ')

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# ADO to GitHub Policy Migration Report")
$lines.Add("")
$lines.Add("## Migration Overview")
$lines.Add("- **Source ADO Organization:** $orgName")
$lines.Add("- **Source ADO Project:** $projectName")
$lines.Add("- **Total Policies Captured:** $totalCaptured")
$lines.Add("- **Active/Evaluated Policies Processed:** $processedCount")
$lines.Add("- **Sub-Org Config File:** `.github/suborgs/$projectName.yml` (governs $($allRepos.Count) repositories: $allReposStr)")
$lines.Add("- **Repository-specific Override Files:** $repoFilesCreated (under `.github/repos/`)")
$lines.Add("")
$lines.Add("---")
$lines.Add("")
$lines.Add("## Parity & Mapping Status")
$lines.Add("")
$lines.Add("| ADO Policy Type | Safe-Settings Status | GitHub Equivalent | Parity Notes |")
$lines.Add("|---|---|---|---|")
$lines.Add("| Commit author email validation | **Mapped** | Dedicated Ruleset (`target: branch`, `~ALL`) | Preserves all patterns; maps to `ends_with`, `equals`, or `regex` |")
$lines.Add("| File size restriction | **Mapped** | Push Ruleset: `max_file_size` | Converted from bytes to MB |")
$lines.Add("| Path Length restriction | **Mapped** | Push Ruleset: `max_file_path_length` | Exact character count |")
$lines.Add("| File name restriction | **Mapped** | Push Ruleset: `file_path_restriction` | fnmatch file patterns |")
$lines.Add("| Minimum number of reviewers | **Mapped** | Branch Ruleset: `pull_request` approvals | Approver count, reset-on-push, and last-pusher blocking |")
$lines.Add("| Comment requirements | **Mapped** | Branch Ruleset: `required_review_thread_resolution` | Unresolved threads block merge |")
$lines.Add("| Require a merge strategy | **Mapped (Behavioral Delta)** | Ruleset `allowed_merge_methods` + Repo settings | **Note:** Applying allowed merge methods via GitHub ruleset mandates a PR requirement even with 0 approvals |")
$lines.Add("| Build validation | **Mapped (Action Needed)** | Branch Ruleset: `required_status_checks` | **Confirm check context matches GitHub Actions workflow** |")
$lines.Add("| Status checks | **Mapped (Action Needed)** | Branch Ruleset: `required_status_checks` | Verify publisher App / context string |")
$lines.Add("| Required reviewers | **Partial / Manual Configuration Required** | `CODEOWNERS` + `require_code_owner_review` | ADO path/identity reviewers require a `CODEOWNERS` file in the repo to bind identities to paths |")
$lines.Add("| Work item linking | **Unsupported / Custom Action Required** | Custom Status Check / GHA | Informational only in native GitHub; require custom Action if blocking |")
$lines.Add("| Case enforcement | **No Direct Equivalent** | None | Enforce via client-side git configuration or CI linting |")
$lines.Add("| Reserved names restriction | **Partial / Workaround** | Push Ruleset: `file_path_restriction` | Enumerate OS reserved names (CON, NUL, COM1) if blocking pushes |")
$lines.Add("")
$lines.Add("---")
$lines.Add("")
$lines.Add("## Action Checklist for Reviewers")
$lines.Add("1. [ ] **Verify Sub-Org Target Repos:** Check `.github/suborgs/$projectName.yml` to ensure all target repositories are listed under `suborgrepos:`.")
$lines.Add("2. [ ] **Provision CODEOWNERS Files:** For repositories with 'Required reviewers' policies in ADO, ensure a corresponding `.github/CODEOWNERS` file is committed to map path filters to GitHub teams/users.")
$lines.Add("3. [ ] **Confirm Status Check Contexts:** Verify that GitHub Actions workflows emit check runs matching the contexts declared in `required_status_checks`.")
$lines.Add("4. [ ] **Review Dry-Run Output:** Review the Safe-Settings bot comment on the Pull Request to verify expected live diffs.")

Set-Content -Path $reportPath -Value ($lines -join "`n") -Encoding utf8
Write-Host "Created Migration Report: $reportPath" -ForegroundColor Green

Write-Host "`nTransformation complete! Files staged in: $OutputDir" -ForegroundColor Cyan
