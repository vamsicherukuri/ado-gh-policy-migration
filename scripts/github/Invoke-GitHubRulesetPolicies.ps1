<#
.SYNOPSIS
    Applies GitHub repository rulesets (branch + repo-wide policies) to one or more repositories,
    driven by a CSV of policies flagged Yes/No for enablement.

.DESCRIPTION
    Reads GitHub_Ruleset_Policies.csv (Policy Name, Description, Documentation URL, Rule Type,
    Ruleset Target, Default Parameters (JSON), Enabled (Yes/No)). Only rows with Enabled = Yes
    are applied. Rows are grouped into two rulesets:
      - "branch" target  -> PR reviews, status checks, signed commits, linear history, force-push,
                             deletion, deployments (mirrors ADO per-branch policies)
      - "push"   target  -> file path/extension/size/length, commit metadata patterns
                             (mirrors ADO repository-wide policies)
    Each ruleset is built once, saved to disk as a reusable JSON template, then applied identically
    to every repo passed in -Repos (or -RepoListPath) in a single run.

.PARAMETER PolicyCsvPath
    Path to the policy CSV. Defaults to config\GitHub_Ruleset_Policies.csv in the workspace.

.PARAMETER Repos
    One or more repositories in "owner/repo" format.

.PARAMETER RepoListPath
    Path to a text file with one "owner/repo" per line. Used instead of -Repos.

.PARAMETER Token
    A GitHub PAT (classic or fine-grained) with 'repo' admin / rulesets permissions.
    Defaults to the GH_TOKEN environment variable if not supplied.

.PARAMETER UseGhCliAuth
    Skip -Token/GH_TOKEN entirely and obtain a token from the GitHub CLI's cached credential
    (the one created by 'gh auth login'). Avoids ever typing or storing a raw PAT for this script.
    Requires the 'gh' CLI to be installed and already authenticated (run 'gh auth login' first).

.PARAMETER RulesetNamePrefix
    Prefix used for the generated ruleset names. Defaults to "ado-migrated-policy".

.PARAMETER DefaultBranchPattern
    Ref pattern used for the "branch" ruleset's conditions. Defaults to "~DEFAULT_BRANCH".

.PARAMETER Enforcement
    Ruleset enforcement level: active, evaluate, or disabled. Defaults to "active".

.PARAMETER OutputDir
    Directory where the reusable ruleset JSON template(s) are written. Defaults to .\output.

.PARAMETER DryRun
    Build and save the ruleset JSON(s) but do not call the GitHub API.

.PARAMETER Undo
    Revert to the state captured before this script last ran, using the backups saved under
    <OutputDir>\backups. For each of "$RulesetNamePrefix-branch", "-tag", "-push": if a ruleset by
    that name existed before the script first touched it, that original ruleset is restored
    (PUT/re-created); if it did not exist before, the ruleset created by this script is deleted.
    If no backup is found for a name, falls back to deleting whatever currently exists with a warning.
    Skips reading the policy CSV entirely.

.EXAMPLE
    .\scripts\github\Invoke-GitHubRulesetPolicies.ps1 -Repos "contoso/repo1","contoso/repo2" -Token $env:GH_TOKEN

.EXAMPLE
    .\scripts\github\Invoke-GitHubRulesetPolicies.ps1 -RepoListPath .\config\repos.sample.txt -DryRun

.EXAMPLE
    gh auth login
    .\scripts\github\Invoke-GitHubRulesetPolicies.ps1 -RepoListPath .\config\repos.sample.txt -UseGhCliAuth

.EXAMPLE
    .\scripts\github\Invoke-GitHubRulesetPolicies.ps1 -RepoListPath .\config\repos.sample.txt -UseGhCliAuth -Undo
#>
[CmdletBinding(DefaultParameterSetName = 'ReposInline')]
param(
    [string]$PolicyCsvPath = (Join-Path $PSScriptRoot "..\..\config\GitHub_Ruleset_Policies.csv"),

    [Parameter(ParameterSetName = 'ReposInline')]
    [string[]]$Repos,

    [Parameter(ParameterSetName = 'ReposFromFile')]
    [string]$RepoListPath,

    [string]$Token = $env:GH_TOKEN,

    [switch]$UseGhCliAuth,

    [string]$RulesetNamePrefix = "ado-migrated-policy",

    [string]$DefaultBranchPattern = "~DEFAULT_BRANCH",

    [ValidateSet("active", "evaluate", "disabled")]
    [string]$Enforcement = "active",

    [string]$OutputDir = (Join-Path $PSScriptRoot "..\..\output"),

    [switch]$DryRun,

    [switch]$Undo
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helper: sanitize a string for use in a filename
# ---------------------------------------------------------------------------
function Get-SafeFileNamePart {
    param([string]$Value)
    ($Value -replace '[\\/:*?"<>|]', '_')
}

function Get-BackupFilePath {
    param([string]$BackupDir, [string]$Repo, [string]$RulesetName)
    $safeRepo = Get-SafeFileNamePart $Repo
    $safeName = Get-SafeFileNamePart $RulesetName
    Join-Path $BackupDir "$safeRepo--$safeName.json"
}

# Strips server-generated/read-only fields so a captured ruleset can be replayed as a request body.
function ConvertTo-RulesetRequestBody {
    param($RulesetObj)
    # NOTE: assigning bypass_actors inline inside the [ordered]@{} literal (e.g. via an if/else
    # expression) causes PowerShell to flatten an empty array to $null, which GitHub's API then
    # rejects ("data cannot be null"). Assigning it as a separate statement avoids that flattening.
    $bypassActors = $RulesetObj.bypass_actors
    if (-not $bypassActors) { $bypassActors = @() }

    $result = [ordered]@{
        name        = $RulesetObj.name
        target      = $RulesetObj.target
        enforcement = $RulesetObj.enforcement
        conditions  = $RulesetObj.conditions
        rules       = $RulesetObj.rules
    }
    $result.bypass_actors = $bypassActors
    $result
}

# ---------------------------------------------------------------------------
# 1. Resolve the repo list
# ---------------------------------------------------------------------------
if ($RepoListPath) {
    if (-not (Test-Path $RepoListPath)) { throw "Repo list file not found: $RepoListPath" }
    $Repos = Get-Content $RepoListPath | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^\s*#' }
}
if (-not $Repos -or $Repos.Count -eq 0) {
    throw "No repositories supplied. Use -Repos 'owner/repo' or -RepoListPath repos.txt"
}
foreach ($r in $Repos) {
    if ($r -notmatch '^[^/\s]+/[^/\s]+$') { throw "Invalid repo format '$r'. Expected 'owner/repo'." }
}

if ($UseGhCliAuth -and (-not $DryRun -or $Undo)) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI ('gh') not found on PATH. Install it from https://cli.github.com, then run 'gh auth login'."
    }
    # 'gh auth status' can exit non-zero if ANY cached account is stale, even when the active
    # account is fine, so ask 'gh auth token' directly for the active account's token instead.
    $Token = (& gh auth token 2>$null | Select-Object -First 1)
    if ($Token) { $Token = $Token.Trim() }
    if (-not $Token) {
        throw "Not logged in to the GitHub CLI (or the active account has no cached token). Run 'gh auth login' first, then re-run this script with -UseGhCliAuth."
    }
    Write-Host "Using GitHub CLI cached credential (gh auth login) - no PAT entered." -ForegroundColor Green
}

if ((-not $DryRun -or $Undo) -and -not $Token) {
    throw "A GitHub token is required. Pass -Token, set GH_TOKEN, or use -UseGhCliAuth after 'gh auth login'."
}

if ($Undo) {
    $namesToRemove = @("$RulesetNamePrefix-branch", "$RulesetNamePrefix-tag", "$RulesetNamePrefix-push")
    $BackupDir = Join-Path $OutputDir "backups"
    $headers = @{
        Authorization          = "Bearer $Token"
        Accept                 = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }
    $undoResults = New-Object System.Collections.Generic.List[object]

    foreach ($repo in $Repos) {
        $owner, $name = $repo -split '/', 2
        Write-Host "`n=== $repo ===" -ForegroundColor Cyan

        $existing = $null
        try {
            $existing = Invoke-RestMethod -Method Get -Uri "https://api.github.com/repos/$owner/$name/rulesets" -Headers $headers
        } catch {
            Write-Warning "Failed to list rulesets for $repo -- $($_.Exception.Message)"
            continue
        }

        foreach ($rsName in $namesToRemove) {
            $currentMatch = $existing | Where-Object { $_.name -eq $rsName }
            $backupFile   = Get-BackupFilePath -BackupDir $BackupDir -Repo $repo -RulesetName $rsName

            if (-not (Test-Path $backupFile)) {
                if (-not $currentMatch) {
                    Write-Host "  '$rsName' not present and no backup found - nothing to do." -ForegroundColor DarkGray
                    continue
                }
                Write-Warning "  No backup found for '$rsName' - original prior state is unknown. Deleting without restore."
                if ($DryRun) {
                    Write-Host "  [DryRun] Would delete ruleset '$rsName' (id $($currentMatch.id)) - no backup available" -ForegroundColor Yellow
                    $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "DryRun - would delete (no backup)" })
                    continue
                }
                try {
                    Invoke-RestMethod -Method Delete -Uri "https://api.github.com/repos/$owner/$name/rulesets/$($currentMatch.id)" -Headers $headers | Out-Null
                    Write-Host "  Deleted ruleset '$rsName' (id $($currentMatch.id)) - no backup to restore" -ForegroundColor Green
                    $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "Deleted (no backup)" })
                } catch {
                    Write-Warning "  Failed to delete ruleset '$rsName' -- $($_.Exception.Message)"
                    $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "Failed: $($_.Exception.Message)" })
                }
                continue
            }

            $backup = Get-Content $backupFile -Raw | ConvertFrom-Json

            if (-not $backup.existed) {
                # This ruleset did not exist before the script ran - undo means deleting it.
                if (-not $currentMatch) {
                    Write-Host "  '$rsName' already absent - nothing to undo." -ForegroundColor DarkGray
                    if (-not $DryRun) { Remove-Item $backupFile -Force -ErrorAction SilentlyContinue }
                    continue
                }
                if ($DryRun) {
                    Write-Host "  [DryRun] Would delete ruleset '$rsName' (id $($currentMatch.id)) - it did not exist before this script ran" -ForegroundColor Yellow
                    $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "DryRun - would delete (did not pre-exist)" })
                    continue
                }
                try {
                    Invoke-RestMethod -Method Delete -Uri "https://api.github.com/repos/$owner/$name/rulesets/$($currentMatch.id)" -Headers $headers | Out-Null
                    Write-Host "  Deleted ruleset '$rsName' (id $($currentMatch.id)) - restored to its original 'did not exist' state" -ForegroundColor Green
                    $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "Deleted (restored to not-existing)" })
                    Remove-Item $backupFile -Force
                } catch {
                    Write-Warning "  Failed to delete ruleset '$rsName' -- $($_.Exception.Message)"
                    $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "Failed: $($_.Exception.Message)" })
                }
                continue
            }

            # existed = true -> replay the originally captured ruleset body to restore it exactly.
            $restoreBody = (ConvertTo-RulesetRequestBody -RulesetObj $backup.ruleset) | ConvertTo-Json -Depth 10

            if ($DryRun) {
                Write-Host "  [DryRun] Would restore original ruleset '$rsName' from backup captured $($backup.capturedAt)" -ForegroundColor Yellow
                $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "DryRun - would restore original" })
                continue
            }

            try {
                if ($currentMatch) {
                    Invoke-RestMethod -Method Put -Uri "https://api.github.com/repos/$owner/$name/rulesets/$($currentMatch.id)" -Headers $headers -Body $restoreBody -ContentType "application/json" | Out-Null
                    Write-Host "  Restored original ruleset '$rsName' (id $($currentMatch.id))" -ForegroundColor Green
                } else {
                    $resp = Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$owner/$name/rulesets" -Headers $headers -Body $restoreBody -ContentType "application/json"
                    Write-Host "  Re-created original ruleset '$rsName' (id $($resp.id))" -ForegroundColor Green
                }
                $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "Restored original" })
                Remove-Item $backupFile -Force
            } catch {
                Write-Warning "  Failed to restore '$rsName' -- $($_.Exception.Message)"
                if ($_.ErrorDetails.Message) { Write-Warning "    Detail: $($_.ErrorDetails.Message)" }
                $undoResults.Add([pscustomobject]@{ Repo = $repo; Ruleset = $rsName; Status = "Failed: $($_.Exception.Message)" })
            }
        }
    }

    Write-Host "`n=== Undo Summary ===" -ForegroundColor Cyan
    $undoResults | Format-Table -AutoSize
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $undoSummaryPath = Join-Path $OutputDir "undo-summary.csv"
    $undoResults | Export-Csv -Path $undoSummaryPath -NoTypeInformation
    Write-Host "Undo summary written to $undoSummaryPath"
    return
}

if (-not (Test-Path $PolicyCsvPath)) { throw "Policy CSV not found: $PolicyCsvPath" }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# ---------------------------------------------------------------------------
# 2. Load and filter the policy CSV
# ---------------------------------------------------------------------------
$allPolicies = Import-Csv -Path $PolicyCsvPath
$enabled = $allPolicies | Where-Object { $_.'Enabled (Yes/No)'.Trim() -ieq 'Yes' }

if ($enabled.Count -eq 0) {
    Write-Warning "No policies are flagged 'Yes' in $PolicyCsvPath. Nothing to do."
    return
}

Write-Host "Enabled policies ($($enabled.Count)):" -ForegroundColor Cyan
$enabled | ForEach-Object { Write-Host "  - $($_.'Policy Name') [$($_.'Rule Type') / $($_.'Ruleset Target')]" }

# ---------------------------------------------------------------------------
# 3. Build one rules[] array per ruleset target (branch / push)
# ---------------------------------------------------------------------------
# Rule types whose GitHub schema has no "parameters" object at all.
$noParamRuleTypes = @('required_signatures', 'required_linear_history', 'non_fast_forward', 'deletion', 'creation')

# pull_request sub-settings are merged into a single rule object.
$pullRequestParams = [ordered]@{
    required_approving_review_count   = 0
    dismiss_stale_reviews_on_push     = $false
    require_code_owner_review         = $false
    require_last_push_approval        = $false
    required_review_thread_resolution = $false
    allowed_merge_methods             = @("merge", "squash", "rebase")
}
$pullRequestRuleNeeded = $false

function New-RulesetContainer {
    param([string]$Target)
    [ordered]@{
        Target = $Target
        Rules  = New-Object System.Collections.Generic.List[object]
    }
}

$branchRuleset = New-RulesetContainer -Target "branch"
$tagRuleset    = New-RulesetContainer -Target "tag"
$pushRuleset   = New-RulesetContainer -Target "push"

foreach ($row in $enabled) {
    $ruleType = $row.'Rule Type'.Trim()
    $target   = $row.'Ruleset Target'.Trim().ToLower()
    $paramsJson = $row.'Default Parameters (JSON)'
    $params = if ([string]::IsNullOrWhiteSpace($paramsJson)) { @{} } else { $paramsJson | ConvertFrom-Json -AsHashtable }

    if ($ruleType -eq 'pull_request') {
        $pullRequestRuleNeeded = $true
        foreach ($key in $params.Keys) { $pullRequestParams[$key] = $params[$key] }
        continue
    }

    $ruleObj = [ordered]@{ type = $ruleType }
    if ($noParamRuleTypes -notcontains $ruleType) { $ruleObj.parameters = $params }

    switch ($target) {
        'push' { $pushRuleset.Rules.Add($ruleObj) }
        'tag'  { $tagRuleset.Rules.Add($ruleObj) }
        default { $branchRuleset.Rules.Add($ruleObj) }
    }
}

if ($pullRequestRuleNeeded) {
    $branchRuleset.Rules.Insert(0, [ordered]@{ type = 'pull_request'; parameters = $pullRequestParams })
}

# ---------------------------------------------------------------------------
# 4. Assemble the final ruleset object(s) and save reusable JSON templates
# ---------------------------------------------------------------------------
$rulesetsToApply = @()

if ($branchRuleset.Rules.Count -gt 0) {
    $branchRulesetObj = [ordered]@{
        name          = "$RulesetNamePrefix-branch"
        target        = "branch"
        enforcement   = $Enforcement
        bypass_actors = @()
        conditions    = @{ ref_name = @{ include = @($DefaultBranchPattern); exclude = @() } }
        rules         = $branchRuleset.Rules
    }
    $branchPath = Join-Path $OutputDir "ruleset-branch.json"
    $branchRulesetObj | ConvertTo-Json -Depth 10 | Set-Content -Path $branchPath -Encoding utf8
    Write-Host "Saved reusable branch ruleset template -> $branchPath" -ForegroundColor Green
    $rulesetsToApply += $branchRulesetObj
}

if ($tagRuleset.Rules.Count -gt 0) {
    $tagRulesetObj = [ordered]@{
        name          = "$RulesetNamePrefix-tag"
        target        = "tag"
        enforcement   = $Enforcement
        bypass_actors = @()
        conditions    = @{ ref_name = @{ include = @("~ALL"); exclude = @() } }
        rules         = $tagRuleset.Rules
    }
    $tagPath = Join-Path $OutputDir "ruleset-tag.json"
    $tagRulesetObj | ConvertTo-Json -Depth 10 | Set-Content -Path $tagPath -Encoding utf8
    Write-Host "Saved reusable tag ruleset template -> $tagPath" -ForegroundColor Green
    $rulesetsToApply += $tagRulesetObj
}

if ($pushRuleset.Rules.Count -gt 0) {
    $pushRulesetObj = [ordered]@{
        name          = "$RulesetNamePrefix-push"
        target        = "push"
        enforcement   = $Enforcement
        bypass_actors = @()
        rules         = $pushRuleset.Rules
    }
    $pushPath = Join-Path $OutputDir "ruleset-push.json"
    $pushRulesetObj | ConvertTo-Json -Depth 10 | Set-Content -Path $pushPath -Encoding utf8
    Write-Host "Saved reusable push ruleset template -> $pushPath" -ForegroundColor Green
    $rulesetsToApply += $pushRulesetObj
}

if ($DryRun) {
    Write-Host "`nDryRun set - skipping API calls. Ruleset template(s) written to $OutputDir." -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# 5. Apply the ruleset(s) to every repo (create, or update if name already exists)
# ---------------------------------------------------------------------------
$headers = @{
    Authorization          = "Bearer $Token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

$BackupDir = Join-Path $OutputDir "backups"
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

$results = New-Object System.Collections.Generic.List[object]

foreach ($repo in $Repos) {
    $owner, $name = $repo -split '/', 2
    Write-Host "`n=== $repo ===" -ForegroundColor Cyan

    $existing = $null
    try {
        $existing = Invoke-RestMethod -Method Get -Uri "https://api.github.com/repos/$owner/$name/rulesets" -Headers $headers
    } catch {
        Write-Warning "Failed to list existing rulesets for $repo -- $($_.Exception.Message)"
    }

    foreach ($ruleset in $rulesetsToApply) {
        $body = $ruleset | ConvertTo-Json -Depth 10
        $match = $existing | Where-Object { $_.name -eq $ruleset.name }

        # Capture a one-time snapshot of whatever existed before we ever touch this ruleset name,
        # so -Undo can restore the exact prior state later. Never overwritten on subsequent runs.
        # (Section 5 only runs when -DryRun is not set - see the early return above.)
        $backupFile = Get-BackupFilePath -BackupDir $BackupDir -Repo $repo -RulesetName $ruleset.name
        if (-not (Test-Path $backupFile)) {
            $backupObj = if ($match) {
                # The list endpoint only returns a summary (no rules/conditions) - fetch full detail.
                $fullMatch = $match
                try {
                    $fullMatch = Invoke-RestMethod -Method Get -Uri "https://api.github.com/repos/$owner/$name/rulesets/$($match.id)" -Headers $headers
                } catch {
                    Write-Warning "  Could not fetch full detail for existing ruleset '$($ruleset.name)' - backup may be incomplete: $($_.Exception.Message)"
                }
                [ordered]@{ existed = $true; capturedAt = (Get-Date).ToString("o"); ruleset = $fullMatch }
            } else {
                [ordered]@{ existed = $false; capturedAt = (Get-Date).ToString("o"); ruleset = $null }
            }
            $backupObj | ConvertTo-Json -Depth 10 | Set-Content -Path $backupFile -Encoding utf8
            Write-Host "  Backed up prior state of '$($ruleset.name)' (existed=$($backupObj.existed)) -> $backupFile" -ForegroundColor DarkGray
        }

        try {
            if ($match) {
                $resp = Invoke-RestMethod -Method Put -Uri "https://api.github.com/repos/$owner/$name/rulesets/$($match.id)" -Headers $headers -Body $body -ContentType "application/json"
                Write-Host "  Updated ruleset '$($ruleset.name)' (id $($match.id))" -ForegroundColor Green
            } else {
                $resp = Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$owner/$name/rulesets" -Headers $headers -Body $body -ContentType "application/json"
                Write-Host "  Created ruleset '$($ruleset.name)' (id $($resp.id))" -ForegroundColor Green
            }
            $results.Add([pscustomobject]@{ Repo = $repo; Ruleset = $ruleset.name; Status = "Success" })
        } catch {
            Write-Warning "  Failed to apply ruleset '$($ruleset.name)' to $repo -- $($_.Exception.Message)"
            $results.Add([pscustomobject]@{ Repo = $repo; Ruleset = $ruleset.name; Status = "Failed: $($_.Exception.Message)" })
        }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$summaryPath = Join-Path $OutputDir "run-summary.csv"
$results | Export-Csv -Path $summaryPath -NoTypeInformation
Write-Host "Summary written to $summaryPath"
