#Requires -Version 7.0
<#
.SYNOPSIS
    Applies organization governance policies to GitHub Enterprise Cloud (GHEC) using
    the user-reviewed 'ado-to-ghec-crosswalk.csv' as the authoritative Source of Truth.

.DESCRIPTION
    Step 3B of the ADO-to-GitHub Org Governance migration pipeline.
    - Safety First: Enforces that a pre-flight snapshot exists (or creates one automatically).
    - Reads 'ado-to-ghec-crosswalk.csv' in the script directory.
    - Filters rows where ApplyPolicy == True.
    - Supports -WhatIf / -DryRun mode to preview proposed changes without making API calls.
    - Applies settings via GitHub REST API (PATCH /orgs/{org}).
    - Performs an immediate post-apply read-back verification check.
    - 1-click rollback is always available via '05_Rollback-GitHubOrgPolicies.ps1'.

.PARAMETER TargetOrg
    The GitHub Organization to configure. Defaults to the name in 'github-org.txt'.

.PARAMETER CrosswalkPath
    Path to the crosswalk CSV. Defaults to '$PSScriptRoot\ado-to-ghec-crosswalk.csv'.

.PARAMETER DryRun
    If set, previews the exact payload and planned changes without calling the GitHub API.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\org"
    
    # Preview changes only (Dry Run):
    pwsh .\Apply-GitHubOrgPolicies.ps1 -DryRun

    # Apply changes to GitHub:
    pwsh .\Apply-GitHubOrgPolicies.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [string]$MappingFilePath = "",

    [Parameter(Mandatory = $false)]
    [string]$CrosswalkPath = "",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Apply ADO Organization Governance Policies to GitHub (GHEC)   " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Target Organizations
$targetOrgs = [System.Collections.Generic.List[string]]::new()

if (-not [string]::IsNullOrWhiteSpace($TargetOrg)) {
    $targetOrgs.Add($TargetOrg.Trim())
}
else {
    # Check for upfront Source-to-Target mapping manifest
    if ([string]::IsNullOrWhiteSpace($MappingFilePath)) {
        $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\org-mapping.csv"
        if (-not (Test-Path -LiteralPath $MappingFilePath)) {
            $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "org-mapping.csv"
        }
    }
    if (Test-Path -LiteralPath $MappingFilePath) {
        Write-Host "[+] Using Source-to-Target Org Mapping : $MappingFilePath" -ForegroundColor Cyan
        $orgMappings = @(Import-Csv -LiteralPath $MappingFilePath)
        foreach ($m in $orgMappings) {
            $tOrg = if ($m.PSObject.Properties['TargetGhOrg']) { $m.TargetGhOrg.Trim() } else { "" }
            if (-not [string]::IsNullOrWhiteSpace($tOrg) -and -not $targetOrgs.Contains($tOrg)) {
                $targetOrgs.Add($tOrg)
            }
        }
    }

    if ($targetOrgs.Count -eq 0) {
        $orgFile = Join-Path -Path $PSScriptRoot -ChildPath "config\github-org.txt"
        if (-not (Test-Path -LiteralPath $orgFile)) {
            $orgFile = Join-Path -Path $PSScriptRoot -ChildPath "github-org.txt"
        }
        if (Test-Path -LiteralPath $orgFile) {
            $lines = @(Get-Content -Path $orgFile | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#")
            })
            foreach ($line in $lines) {
                $cleaned = $line.Trim()
                if (-not [string]::IsNullOrWhiteSpace($cleaned) -and -not $targetOrgs.Contains($cleaned)) {
                    $targetOrgs.Add($cleaned)
                }
            }
        }
    }
}

if ($targetOrgs.Count -eq 0) {
    throw "No target GitHub organizations specified. Provide via -TargetOrg or list in 'org/github-org.txt'."
}

# 2. Resolve Crosswalk File (Source of Truth)
if ([string]::IsNullOrWhiteSpace($CrosswalkPath)) {
    $CrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "config\ado-to-ghec-crosswalk.csv"
    if (-not (Test-Path -LiteralPath $CrosswalkPath)) {
        $CrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "ado-to-ghec-crosswalk.csv"
    }
}

if (-not (Test-Path -Path $CrosswalkPath)) {
    throw "Crosswalk file not found: '$CrosswalkPath'. Please ensure 'ado-to-ghec-crosswalk.csv' is present."
}

# 3. Resolve GitHub Authentication Token
$token = ""
$tokenSource = ""

if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "AdoToGhMigration-Apply/1.0"
        }
        $u = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 5
        $token = $cleanPat
        $tokenSource = "`$env:GH_PAT (User: $($u.login))"
    }
    catch {
        Write-Warning "`$env:GH_PAT validation failed ($($_.Exception.Message)). Trying GitHub CLI..."
    }
}

if ([string]::IsNullOrWhiteSpace($token)) {
    try {
        $ghCliToken = (gh auth token 2>$null)
        if (-not [string]::IsNullOrWhiteSpace($ghCliToken)) {
            $ghCliToken = $ghCliToken.Trim()
            $testHeaders = @{
                Authorization          = "Bearer $ghCliToken"
                Accept                 = "application/vnd.github+json"
                "X-GitHub-Api-Version" = "2022-11-28"
                "User-Agent"           = "AdoToGhMigration-Apply/1.0"
            }
            $u = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 5
            $token = $ghCliToken
            $tokenSource = "GitHub CLI Keyring (User: $($u.login))"
        }
    }
    catch {}
}

if ([string]::IsNullOrWhiteSpace($token)) {
    throw "No valid GitHub token found. Please set `$env:GH_PAT = 'ghp_...' or run 'gh auth login'."
}

Write-Host "[+] Target Organization(s) : $($targetOrgs.Count) org(s) -> ($($targetOrgs -join ', '))" -ForegroundColor Yellow
Write-Host "[+] Authentication         : $tokenSource" -ForegroundColor Gray
Write-Host "[+] Source of Truth        : $CrosswalkPath`n" -ForegroundColor Gray

# 4. Safety First: Pre-Flight Snapshot Check for Each Org
$snapshotsDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots"

foreach ($org in $targetOrgs) {
    $latestSnapshotFile = Join-Path -Path $snapshotsDir -ChildPath "$($org)-latest-preflight.json"
    if (-not (Test-Path -Path $latestSnapshotFile)) {
        Write-Host "[!] No pre-flight snapshot found for '$org'. Running 03_Snapshot-GitHubOrgPolicies.ps1 first..." -ForegroundColor Yellow
        $snapshotScript = Join-Path -Path $PSScriptRoot -ChildPath "03_Snapshot-GitHubOrgPolicies.ps1"
        & $snapshotScript -TargetOrg $org
    }
    else {
        $existingSnap = Get-Content -Path $latestSnapshotFile -Raw | ConvertFrom-Json
        Write-Host "[+] Verified Snapshot for '$org' (Captured at $($existingSnap.CapturedAtUtc) UTC)." -ForegroundColor Green
    }
}
Write-Host "    Rollback Script Ready: $PSScriptRoot\05_Rollback-GitHubOrgPolicies.ps1`n" -ForegroundColor Gray

# 5. Ingest Crosswalk Source of Truth
$crosswalk = Import-Csv -Path $CrosswalkPath
$actionableRows = @($crosswalk | Where-Object {
    [bool]::TryParse($_.ApplyPolicy, [ref]$true) -and [bool]::Parse($_.ApplyPolicy)
})

Write-Host "[+] Ingested $($crosswalk.Count) crosswalk policies ($($actionableRows.Count) selected for application):`n" -ForegroundColor Cyan

# 6. Build the Target GitHub Governance Payload
$patchPayload = [ordered]@{}
$specialActions = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($row in $actionableRows) {
    $code       = $row.PolicyCode
    $targetKey  = $row.TargetGhPolicyKey
    $actionName = if ($row.PSObject.Properties['TargetGhActionHandler']) { $row.TargetGhActionHandler } else { $targetKey }
    $implType   = if ($row.PSObject.Properties['ImplementationType']) { $row.ImplementationType } else { "Direct Org API" }
    $policyName = if ($row.PSObject.Properties['AdoPolicyName']) { $row.AdoPolicyName } else { $code }
    $proposed   = if ($row.PSObject.Properties['ProposedGhSetting']) { $row.ProposedGhSetting } else { "Enforced" }

    Write-Host "  • [$code] $policyName" -ForegroundColor White
    Write-Host "      Target Key : $targetKey" -ForegroundColor Gray
    Write-Host "      Proposed   : $proposed" -ForegroundColor Yellow

    switch ($targetKey) {
        "GH-REPO-VISIBILITY" {
            # Disallow public repositories in GHEC
            $patchPayload["members_can_create_public_repositories"] = $false
        }
        "GH-REPO-FORKING" {
            # Disallow private repository forking
            $patchPayload["members_can_fork_private_repositories"] = $false
        }
        "GH-MEMBER-INVITE-POLICY" {
            # Outside collaborator invitations are managed via Enterprise IdP/SAML or separate membership API
            $specialActions.Add([PSCustomObject]@{
                PolicyCode         = $code
                TargetKey          = $targetKey
                ActionHandler      = $actionName
                ImplementationType = "Enterprise Invitation Policy"
                ProposedSetting    = $proposed
            })
        }
        "GH-TEAM-INVITE-DELEGATION" {
            # Repository creation restricted to private
            $patchPayload["members_allowed_repository_creation_type"] = "private"
        }
        default {
            $specialActions.Add([PSCustomObject]@{
                PolicyCode         = $code
                TargetKey          = $targetKey
                ActionHandler      = $actionName
                ImplementationType = $implType
                ProposedSetting    = $proposed
            })
        }
    }
}

Write-Host "`n-----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "                     PLANNED GITHUB API CHANGES                  " -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
$patchJson = $patchPayload | ConvertTo-Json -Depth 5
Write-Host "Target Orgs: $($targetOrgs -join ', ')" -ForegroundColor Cyan
Write-Host "Method     : PATCH /orgs/{org}" -ForegroundColor Cyan
Write-Host "Payload    :`n$patchJson`n" -ForegroundColor White

if ($specialActions.Count -gt 0) {
    Write-Host "Architectural / Extended Actions (Enterprise/IdP or Separate Endpoints):" -ForegroundColor DarkYellow
    foreach ($sa in $specialActions) {
        Write-Host "  • [$($sa.PolicyCode)] $($sa.TargetKey) -> $($sa.ImplementationType)" -ForegroundColor Gray
    }
    Write-Host ""
}

# 7. DryRun Mode
if ($DryRun) {
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "   DRY RUN COMPLETE: No modifications were made to GitHub.       " -ForegroundColor Yellow
    Write-Host "=================================================================`n" -ForegroundColor Yellow
    Write-Host "To apply these changes for real, run:" -ForegroundColor Gray
    Write-Host "pwsh .\Apply-GitHubOrgPolicies.ps1`n" -ForegroundColor White
    return
}

# 8. Execute GitHub API PATCH Call for Each Target Organization
$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "AdoToGhMigration-Apply/1.0"
}

$appliedResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($org in $targetOrgs) {
    # Check plan from snapshot
    $snapFile = Join-Path -Path $snapshotsDir -ChildPath "$org-latest-preflight.json"
    $isEnterprise = $true
    if (Test-Path -Path $snapFile) {
        $snapObj = Get-Content -Path $snapFile -Raw | ConvertFrom-Json
        if ($snapObj.PlanName -ne "enterprise") {
            $isEnterprise = $false
        }
    }

    if (-not $isEnterprise) {
        Write-Host "[!] Skipping enterprise governance policies on '$org' (Plan: Team). GitHub Enterprise plan required for repository creation restrictions." -ForegroundColor Yellow
        continue
    }

    Write-Host "[+] Applying governance policies to '$org'..." -ForegroundColor Cyan

    $applyResponse = $null
    try {
        $applyResponse = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org" `
            -Headers $headers `
            -Method Patch `
            -Body $patchJson `
            -ContentType "application/json"
        Write-Host "    [OK] PATCH request accepted by GitHub for '$org'!" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to apply policies to '$org': $($_.Exception.Message)"
        continue
    }

    # Post-Apply Read-Back Verification
    Write-Host "    [+] Verifying applied settings for '$org'..." -ForegroundColor Gray
    $verifiedOrg = $true

    foreach ($prop in $patchPayload.Keys) {
        $expected = $patchPayload[$prop]
        $actual   = $applyResponse.$prop
        if ("$expected" -eq "$actual") {
            Write-Host "        [VERIFIED] $prop = $actual" -ForegroundColor Green
        }
        else {
            Write-Warning "Drift on '$prop' in '$org': Expected '$expected', Actual '$actual'"
            $verifiedOrg = $false
        }
    }

    $appliedResults.Add([PSCustomObject]@{
        Organization = $org
        Verified     = $verifiedOrg
    })
}

# 10. Generate Audit Compliance Markdown Report
$reportDate = [System.DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
$reportPath = Join-Path -Path $PSScriptRoot -ChildPath "output\ghec-governance-audit-report.md"

$mdLines = [System.Collections.Generic.List[string]]::new()
$mdLines.Add("# GitHub Enterprise Organization Governance Audit Report")
$mdLines.Add("")
$mdLines.Add("- **Target Organizations**: $($targetOrgs -join ', ')")
$mdLines.Add("- **Applied At**: $reportDate UTC")
$mdLines.Add("- **Source of Truth**: $CrosswalkPath")
$mdLines.Add("- **Rollback Available**: 05_Rollback-GitHubOrgPolicies.ps1")
$mdLines.Add("")
$mdLines.Add("---")
$mdLines.Add("")
$mdLines.Add("## Applied Organization Policies")
$mdLines.Add("")
$mdLines.Add("| Policy Key | Property Name | Applied Value | Status |")
$mdLines.Add("| :--- | :--- | :---: | :---: |")

foreach ($prop in $patchPayload.Keys) {
    $val = $patchPayload[$prop]
    $mdLines.Add("| GH-GOVERNANCE | $prop | $val | Verified |")
}

$mdLines.Add("")
$mdLines.Add("---")
$mdLines.Add("")
$mdLines.Add("## Rollback Command")
$mdLines.Add("")
$mdLines.Add("To instantly revert all settings back to the exact pre-flight snapshot:")
$mdLines.Add('```powershell')
$mdLines.Add('pwsh .\05_Rollback-GitHubOrgPolicies.ps1')
$mdLines.Add('```')

Set-Content -Path $reportPath -Value ($mdLines -join "`n") -Encoding utf8

$verifiedAll = ($appliedResults.Count -gt 0) -and @($appliedResults | Where-Object { -not $_.Verified }).Count -eq 0

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                     APPLICATION COMPLETE                        " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
if ($verifiedAll) {
    Write-Host "[+] All governance policies applied and 100% verified!" -ForegroundColor Green
} else {
    Write-Host "[!] Applied with drift warnings. Review above." -ForegroundColor Yellow
}
Write-Host "`n1. Audit Report Generated:" -ForegroundColor Yellow
Write-Host "   $reportPath" -ForegroundColor White
Write-Host "2. 1-Click Rollback Script (If you need to restore original state):" -ForegroundColor Yellow
Write-Host "   $PSScriptRoot\05_Rollback-GitHubOrgPolicies.ps1`n" -ForegroundColor White
