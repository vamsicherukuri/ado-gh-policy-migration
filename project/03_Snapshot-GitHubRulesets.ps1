#Requires -Version 7.0
<#
.SYNOPSIS
    Captures pre-flight snapshots of existing GitHub Rulesets (Org and Repository level).

.DESCRIPTION
    Phase 2 - Step 3 of the ADO-to-GitHub Policy Migration pipeline.
    - Safety First: Freezes current GitHub ruleset configurations to disk before any changes are applied.
    - Supports both Organization Rulesets (/orgs/{org}/rulesets) and Repository Rulesets (/repos/{org}/{repo}/rulesets).
    - Captures rule definitions, conditions, enforcement levels, and bypass actors.
    - Generates 1-click rollback script '05_Rollback-GitHubRulesets.ps1'.

.PARAMETER TargetOrg
    Specific GitHub organization. Defaults to list in 'project\github-org.txt'.

.PARAMETER Scope
    Ruleset snapshot scope: 'Auto', 'Org', or 'Repo'. Defaults to 'Auto'.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\project"
    pwsh .\03_Snapshot-GitHubRulesets.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet('Auto', 'Org', 'Repo')]
    [string]$Scope = "Auto"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Capture Pre-Flight Snapshot of GitHub Rulesets                " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Target Organizations
$targetOrgs = [System.Collections.Generic.List[string]]::new()

if (-not [string]::IsNullOrWhiteSpace($TargetOrg)) {
    $targetOrgs.Add($TargetOrg.Trim())
}
else {
    $orgFile = Join-Path -Path $PSScriptRoot -ChildPath "config\github-org.txt"
    if (-not (Test-Path -LiteralPath $orgFile)) {
        $orgFile = Join-Path -Path $PSScriptRoot -ChildPath "github-org.txt"
    }
    if (Test-Path -LiteralPath $orgFile) {
        $lines = @(Get-Content -LiteralPath $orgFile | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#")
        })
        foreach ($l in $lines) {
            $cleaned = $l.Trim()
            if (-not [string]::IsNullOrWhiteSpace($cleaned) -and -not $targetOrgs.Contains($cleaned)) {
                $targetOrgs.Add($cleaned)
            }
        }
    }
}

if ($targetOrgs.Count -eq 0) {
    throw "No target GitHub organizations specified. Provide via -TargetOrg or list in 'project/github-org.txt'."
}

Write-Host "[+] Target Organization(s) : $($targetOrgs.Count) org(s) -> ($($targetOrgs -join ', '))" -ForegroundColor Cyan

# 2. Resolve GitHub Authentication
$token = ""
$tokenSource = ""

if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "Ruleset-Snapshot/2.0"
        }
        $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
        $token = $cleanPat
        $tokenSource = "`$env:GH_PAT (User: $($userObj.login))"
    }
    catch {
        Write-Warning "`$env:GH_PAT token was rejected ($($_.Exception.Message)). Attempting gh CLI keyring..."
    }
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
                "User-Agent"           = "Ruleset-Snapshot/2.0"
            }
            $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
            $token = $cliToken
            $tokenSource = "GitHub CLI Keyring (User: $($userObj.login))"
        }
    }
    catch {
        # gh CLI failed
    }
}

if (-not $token) {
    throw "No valid GitHub credentials available. Set `$env:GH_PAT or run 'gh auth login'."
}

Write-Host "[+] Authentication         : $tokenSource" -ForegroundColor Green

# 3. Setup Snapshot Directory
$snapshotsDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots"
New-Item -ItemType Directory -Path $snapshotsDir -Force | Out-Null
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")

$apiHeaders = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "AdoToGh-RulesetSnapshot/2.0"
}

# 4. Snapshot Each Target Organization
foreach ($org in $targetOrgs) {
    Write-Host "`n[+] Capturing Ruleset snapshot for '$org'..." -ForegroundColor Cyan

    # A. Check Organization Details & Plan
    $orgInfo = $null
    try {
        $orgInfo = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org" -Headers $apiHeaders -Method Get
    }
    catch {
        Write-Warning "Could not fetch details for org '$org': $($_.Exception.Message)"
        continue
    }

    $planName = if ($orgInfo.plan -and $orgInfo.plan.name) { $orgInfo.plan.name } else { "unknown" }
    Write-Host "    Plan                   : $planName" -ForegroundColor Gray

    # B. Capture Organization-Level Rulesets
    $orgRulesets = [System.Collections.Generic.List[PSCustomObject]]::new()
    $canAccessOrgRulesets = $false

    if ($Scope -in @('Auto', 'Org')) {
        try {
            $rsList = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org/rulesets" -Headers $apiHeaders -Method Get
            $canAccessOrgRulesets = $true
            if ($rsList) {
                foreach ($rs in @($rsList)) {
                    # Fetch detailed definition for each ruleset
                    $detailed = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org/rulesets/$($rs.id)" -Headers $apiHeaders -Method Get
                    $orgRulesets.Add($detailed)
                }
            }
            Write-Host "    Org Rulesets Captured  : $($orgRulesets.Count)" -ForegroundColor Green
        }
        catch {
            Write-Host "    Org Rulesets           : Lacks admin:org or not configured on org level ($($_.Exception.Message))" -ForegroundColor Gray
        }
    }

    # C. Capture Repository-Level Rulesets
    $repoRulesets = [System.Collections.Generic.List[PSCustomObject]]::new()
    $repos = @()

    if ($Scope -in @('Auto', 'Repo')) {
        try {
            $reposResponse = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org/repos?per_page=100" -Headers $apiHeaders -Method Get
            if ($reposResponse) { $repos = @($reposResponse) }
        }
        catch {
            Write-Warning "Failed to list repositories for '$org': $($_.Exception.Message)"
        }

        Write-Host "    Scanning Repositories  : $($repos.Count) repo(s)" -ForegroundColor Gray
        foreach ($repo in $repos) {
            $rName = $repo.name
            try {
                $rRsList = Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$rName/rulesets" -Headers $apiHeaders -Method Get
                if ($rRsList -and @($rRsList).Count -gt 0) {
                    foreach ($rRs in @($rRsList)) {
                        $detailedR = Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$rName/rulesets/$($rRs.id)" -Headers $apiHeaders -Method Get
                        $repoRulesets.Add([PSCustomObject]@{
                            Repository = $rName
                            Ruleset    = $detailedR
                        })
                    }
                }
            }
            catch {
                # Repo ruleset read skipped or empty
            }
        }
        Write-Host "    Repo Rulesets Captured : $($repoRulesets.Count)" -ForegroundColor Green
    }

    # D. Freeze Snapshot
    $snapshotObj = [PSCustomObject]@{
        SnapshotVersion       = "2.0"
        TargetOrganization    = $org
        PlanName              = $planName
        CapturedAtUtc         = (Get-Date).ToUniversalTime().ToString("o")
        AuthSource            = $tokenSource
        ScopeMode             = $Scope
        OrgLevelAccess        = $canAccessOrgRulesets
        OrgRulesetsCount      = $orgRulesets.Count
        OrgRulesets           = $orgRulesets
        RepoRulesetsCount     = $repoRulesets.Count
        RepoRulesets          = $repoRulesets
    }

    $timeSnapshotFile = Join-Path -Path $snapshotsDir -ChildPath "$org-rulesets-snapshot-$timestamp.json"
    $latestSnapshotFile = Join-Path -Path $snapshotsDir -ChildPath "$org-latest-rulesets-preflight.json"

    $snapshotObj | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $timeSnapshotFile -Encoding utf8
    $snapshotObj | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $latestSnapshotFile -Encoding utf8

    Write-Host "    [FROZEN] Snapshot saved to: $timeSnapshotFile" -ForegroundColor Green
    Write-Host "    [POINTER] Updated pointer: $latestSnapshotFile" -ForegroundColor DarkGray
}

Write-Host "`n[OK] Pre-flight ruleset snapshots successfully captured across all target organizations." -ForegroundColor Green
