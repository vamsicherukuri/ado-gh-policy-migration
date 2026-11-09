#Requires -Version 7.0
<#
.SYNOPSIS
    Lightweight script to inspect and toggle GitHub policy enforcement modes
    (active, evaluate, disabled) across Org, Custom Org, Repo, and Branch levels.

.DESCRIPTION
    Allows administrators to quickly promote, demote, or disable migrated policies:
      - Org: Organization governance settings (forking, public repos, repo creation)
      - OrgRuleset: Organization-level / Custom Org Rulesets
      - Repo: Repository-level Push Rulesets (file size, path length, path restrictions)
      - Branch: Repository-level Branch Rulesets (PR approvals, thread resolution, author email)
      - All: Toggles across all applicable levels

.PARAMETER TargetOrg
    The GitHub Organization name (defaults to first entry in config\github-org.txt).

.PARAMETER TargetRepo
    Optional repository name (e.g. 'sample2'). If omitted, applies to all repos in the org.

.PARAMETER Level
    Hierarchy level to target: 'Org', 'OrgRuleset', 'Repo', 'Branch', or 'All'. Defaults to 'All'.

.PARAMETER Mode
    Enforcement mode: 'active' (enforced), 'evaluate' (audit/dry-run), or 'disabled' (off). Defaults to 'evaluate'.

.PARAMETER List
    Switch to query and print current policy enforcement status without making changes.

.PARAMETER DryRun
    Preview planned changes without calling GitHub API.

.EXAMPLE
    # View current enforcement status across all levels:
    pwsh .\Set-GitHubPolicyMode.ps1 -List

    # Promote all rulesets on sample2 to active:
    pwsh .\Set-GitHubPolicyMode.ps1 -TargetRepo "sample2" -Mode active

    # Switch all branch rulesets across the org to evaluate mode:
    pwsh .\Set-GitHubPolicyMode.ps1 -Level Branch -Mode evaluate

    # Temporarily disable push rulesets across all repositories:
    pwsh .\Set-GitHubPolicyMode.ps1 -Level Repo -Mode disabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [string]$TargetRepo = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'Org', 'OrgRuleset', 'Repo', 'Branch')]
    [string]$Level = "All",

    [Parameter(Mandatory = $false)]
    [ValidateSet('active', 'evaluate', 'disabled')]
    [string]$Mode = "evaluate",

    [Parameter(Mandatory = $false)]
    [switch]$List,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 1. Resolve Target Organization
if ([string]::IsNullOrWhiteSpace($TargetOrg)) {
    $orgFile = Join-Path $PSScriptRoot "org\config\github-org.txt"
    if (Test-Path $orgFile) {
        $firstLine = (Get-Content $orgFile | Where-Object { $_ -and -not $_.StartsWith('#') } | Select-Object -First 1)
        if ($firstLine) { $TargetOrg = $firstLine.Trim() }
    }
}
if ([string]::IsNullOrWhiteSpace($TargetOrg)) {
    throw "TargetOrg is required. Specify -TargetOrg <name> or configure 'org\config\github-org.txt'."
}

# 2. Resolve GitHub Authentication Token
$token = ""
$tokenSource = ""
if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "AdoToGh-PolicyModeManager/1.0"
        }
        $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 5
        $token = $cleanPat
        $tokenSource = "`$env:GH_PAT (User: $($userObj.login))"
    } catch {}
}

if (-not $token) {
    try {
        $cliToken = (& gh auth token 2>$null)
        if ($cliToken) {
            $cliToken = $cliToken.Trim()
            $testHeaders = @{
                Authorization          = "Bearer $cliToken"
                Accept                 = "application/vnd.github+json"
                "X-GitHub-Api-Version" = "2022-11-28"
                "User-Agent"           = "AdoToGh-PolicyModeManager/1.0"
            }
            $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 5
            $token = $cliToken
            $tokenSource = "gh auth token (User: $($userObj.login))"
        }
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($token)) {
    throw "GitHub authentication token not found or invalid. Please check `$env:GH_PAT or run 'gh auth login'."
}

$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "AdoToGh-PolicyModeManager/1.0"
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   GitHub Policy & Ruleset Enforcement Mode Manager              " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Target Org   : $TargetOrg" -ForegroundColor White
if ($TargetRepo) { Write-Host "Target Repo  : $TargetRepo" -ForegroundColor White }
Write-Host "Target Level : $Level" -ForegroundColor White
Write-Host "Action Mode  : $(if ($List) { 'LIST ONLY (Audit)' } else { $Mode.ToUpper() })" -ForegroundColor $(if ($List) { 'Yellow' } elseif ($Mode -eq 'active') { 'Green' } else { 'Yellow' })
if ($DryRun) { Write-Host "[DRY-RUN MODE: No changes will be applied]" -ForegroundColor Yellow }
Write-Host ""

# 3. Helper: Update a Ruleset
function Set-RulesetEnforcement {
    param(
        [string]$Endpoint,
        [PSCustomObject]$Ruleset,
        [string]$NewMode,
        [string]$ContextLabel
    )

    if ($Ruleset.enforcement -eq $NewMode) {
        Write-Host "  • [$ContextLabel] '$($Ruleset.name)' is already '$NewMode'. (No change)" -ForegroundColor Gray
        return
    }

    Write-Host "  • [$ContextLabel] '$($Ruleset.name)' ($($Ruleset.enforcement) -> $NewMode)" -ForegroundColor Yellow

    if ($DryRun) { return }

    $payload = [ordered]@{
        name        = $Ruleset.name
        target      = $Ruleset.target
        enforcement = $NewMode
        rules       = $Ruleset.rules
    }
    if ($null -ne $Ruleset.conditions) {
        $payload["conditions"] = $Ruleset.conditions
    }
    if ($null -ne $Ruleset.bypass_actors) {
        $payload["bypass_actors"] = $Ruleset.bypass_actors
    }

    $body = $payload | ConvertTo-Json -Depth 15
    try {
        $null = Invoke-RestMethod -Uri $Endpoint -Headers $headers -Method Put -Body $body -ContentType "application/json"
        Write-Host "    [OK] Updated successfully to '$NewMode'!" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to update ruleset '$($Ruleset.name)': $($_.Exception.Message)"
    }
}

# 4. Resolve Repositories to Process
$repos = [System.Collections.Generic.List[string]]::new()
if (-not [string]::IsNullOrWhiteSpace($TargetRepo)) {
    $repos.Add($TargetRepo.Trim())
} else {
    try {
        $repoList = Invoke-RestMethod -Uri "https://api.github.com/orgs/$TargetOrg/repos?per_page=100&type=all" -Headers $headers -Method Get
        foreach ($r in $repoList) { $repos.Add($r.name) }
    } catch {
        Write-Warning "Could not list repositories in '$TargetOrg': $($_.Exception.Message)"
    }
}

# 5. Execute Inspection / Listing
if ($List) {
    $report = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Org Level
    try {
        $orgDetails = Invoke-RestMethod -Uri "https://api.github.com/orgs/$TargetOrg" -Headers $headers -Method Get
        $report.Add([PSCustomObject]@{
            Level       = "Org"
            Target      = $TargetOrg
            PolicyOrRuleset = "members_can_fork_private_repositories"
            Type        = "Org Setting"
            Enforcement = if ($orgDetails.members_can_fork_private_repositories) { "disabled (allowed)" } else { "active (restricted)" }
        })
        $report.Add([PSCustomObject]@{
            Level       = "Org"
            Target      = $TargetOrg
            PolicyOrRuleset = "members_can_create_public_repositories"
            Type        = "Org Setting"
            Enforcement = if ($orgDetails.members_can_create_public_repositories) { "disabled (allowed)" } else { "active (restricted)" }
        })
    } catch {}

    # Org Rulesets
    try {
        $orgRulesets = Invoke-RestMethod -Uri "https://api.github.com/orgs/$TargetOrg/rulesets" -Headers $headers -Method Get
        foreach ($ors in $orgRulesets) {
            $report.Add([PSCustomObject]@{
                Level       = "OrgRuleset"
                Target      = $TargetOrg
                PolicyOrRuleset = $ors.name
                Type        = "Org $($ors.target) Ruleset"
                Enforcement = $ors.enforcement
            })
        }
    } catch {}

    # Repo & Branch Rulesets
    foreach ($rp in $repos) {
        try {
            $repoRulesets = Invoke-RestMethod -Uri "https://api.github.com/repos/$TargetOrg/$rp/rulesets" -Headers $headers -Method Get
            foreach ($rs in $repoRulesets) {
                $lvl = if ($rs.target -eq 'branch') { "Branch" } else { "Repo" }
                $report.Add([PSCustomObject]@{
                    Level       = $lvl
                    Target      = "$TargetOrg/$rp"
                    PolicyOrRuleset = $rs.name
                    Type        = "$($rs.target) Ruleset"
                    Enforcement = $rs.enforcement
                })
            }
        } catch {}
    }

    Write-Host "Current Policy & Ruleset Enforcement Overview:" -ForegroundColor Cyan
    $report | Format-Table -AutoSize
    return
}

# 6. Apply Mode Changes Based on Level

# --- A. Level: Org (Governance Settings) ---
if ($Level -in @('Org', 'All')) {
    Write-Host "--- [1] Organization Governance Settings ($TargetOrg) ---" -ForegroundColor Cyan
    if ($Mode -eq 'evaluate') {
        Write-Host "  • Org boolean settings do not support 'evaluate' mode; leaving unchanged." -ForegroundColor Gray
    } else {
        $patchPayload = [ordered]@{}
        if ($Mode -eq 'active') {
            $patchPayload["members_can_fork_private_repositories"] = $false
            $patchPayload["members_can_create_public_repositories"] = $false
            $patchPayload["members_allowed_repository_creation_type"] = "private"
            Write-Host "  • Enforcing strict org governance (blocking public repos & private forking)..." -ForegroundColor Yellow
        } elseif ($Mode -eq 'disabled') {
            $patchPayload["members_can_fork_private_repositories"] = $true
            $patchPayload["members_can_create_public_repositories"] = $true
            $patchPayload["members_allowed_repository_creation_type"] = "all"
            Write-Host "  • Relaxing org governance (allowing public repos & forking)..." -ForegroundColor Yellow
        }

        if (-not $DryRun) {
            try {
                $patchJson = $patchPayload | ConvertTo-Json
                $null = Invoke-RestMethod -Uri "https://api.github.com/orgs/$TargetOrg" -Headers $headers -Method Patch -Body $patchJson -ContentType "application/json"
                Write-Host "    [OK] Org governance settings updated!" -ForegroundColor Green
            } catch {
                Write-Warning "Could not update org governance settings: $($_.Exception.Message)"
            }
        }
    }
    Write-Host ""
}

# --- B. Level: OrgRuleset (Custom Org / Project Scoped Rulesets) ---
if ($Level -in @('OrgRuleset', 'All')) {
    Write-Host "--- [2] Organization Rulesets ($TargetOrg) ---" -ForegroundColor Cyan
    try {
        $orgRulesets = Invoke-RestMethod -Uri "https://api.github.com/orgs/$TargetOrg/rulesets" -Headers $headers -Method Get
        if ($orgRulesets.Count -eq 0) {
            Write-Host "  No Org-level rulesets found on '$TargetOrg'." -ForegroundColor Gray
        }
        foreach ($orsSummary in $orgRulesets) {
            $ors = Invoke-RestMethod -Uri "https://api.github.com/orgs/$TargetOrg/rulesets/$($orsSummary.id)" -Headers $headers -Method Get
            $endpoint = "https://api.github.com/orgs/$TargetOrg/rulesets/$($ors.id)"
            Set-RulesetEnforcement -Endpoint $endpoint -Ruleset $ors -NewMode $Mode -ContextLabel "Org Ruleset: $TargetOrg"
        }
    } catch {
        Write-Host "  [Note] Org ruleset query skipped or not permitted ($($_.Exception.Message))" -ForegroundColor Gray
    }
    Write-Host ""
}

# --- C. Level: Repo & Branch (Repository Rulesets) ---
if ($Level -in @('Repo', 'Branch', 'All')) {
    Write-Host "--- [3] Repository Rulesets ($($repos.Count) repo(s)) ---" -ForegroundColor Cyan
    foreach ($rp in $repos) {
        try {
            $repoRulesets = Invoke-RestMethod -Uri "https://api.github.com/repos/$TargetOrg/$rp/rulesets" -Headers $headers -Method Get
            if ($repoRulesets.Count -eq 0) { continue }

            Write-Host "Repository: $TargetOrg/$rp" -ForegroundColor White
            foreach ($rsSummary in $repoRulesets) {
                $targetType = $rsSummary.target # 'push' or 'branch'

                # Filter by level
                if ($Level -eq 'Repo' -and $targetType -ne 'push') { continue }
                if ($Level -eq 'Branch' -and $targetType -ne 'branch') { continue }

                $rs = Invoke-RestMethod -Uri "https://api.github.com/repos/$TargetOrg/$rp/rulesets/$($rsSummary.id)" -Headers $headers -Method Get
                $endpoint = "https://api.github.com/repos/$TargetOrg/$rp/rulesets/$($rs.id)"
                Set-RulesetEnforcement -Endpoint $endpoint -Ruleset $rs -NewMode $Mode -ContextLabel "$($targetType.ToUpper()) Ruleset"
            }
        } catch {
            Write-Warning "Could not process rulesets on '$TargetOrg/$rp': $($_.Exception.Message)"
        }
    }
    Write-Host ""
}

Write-Host "=================================================================" -ForegroundColor Green
Write-Host "   OPERATION COMPLETE!                                           " -ForegroundColor Green
Write-Host "=================================================================`n" -ForegroundColor Green
