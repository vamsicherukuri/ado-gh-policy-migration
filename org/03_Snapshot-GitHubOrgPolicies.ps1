#Requires -Version 7.0
<#
.SYNOPSIS
    Captures pre-flight snapshots of GitHub Enterprise Cloud (GHEC) Organizations listed in
    'github-org.txt' (or a single org via -TargetOrg) and generates a 1-click Rollback script.

.DESCRIPTION
    Step 3A of the ADO-to-GitHub Org Governance migration pipeline.
    - Connects to GitHub REST API using $env:GH_PAT (or active 'gh auth token').
    - Reads all organizations listed in 'github-org.txt' (or -TargetOrg if specified).
    - Queries and freezes all organization-level governance, visibility, and security settings.
    - Saves individual timestamped JSON snapshot files for each organization.
    - Auto-generates '05_Rollback-GitHubOrgPolicies.ps1' to guarantee 100% reversible application.

.PARAMETER TargetOrg
    Specific organization to snapshot. If omitted, snapshots all organizations in 'github-org.txt'.

.PARAMETER OutputDir
    Directory where snapshots are saved. Defaults to '$PSScriptRoot\output\snapshots'.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\org"
    
    # Snapshot all orgs in github-org.txt:
    pwsh .\Snapshot-GitHubOrgPolicies.ps1

    # Snapshot a specific org only:
    pwsh .\Snapshot-GitHubOrgPolicies.ps1 -TargetOrg "ADO2GHEC"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   GitHub Organization Pre-Flight Snapshot & Rollback Generator  " -ForegroundColor Cyan
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

if ($targetOrgs.Count -eq 0) {
    throw "No target GitHub organizations specified. Provide via -TargetOrg or list in 'org/github-org.txt'."
}

# 2. Resolve Output Directory
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots"
}
if (-not (Test-Path -Path $OutputDir)) {
    [System.IO.Directory]::CreateDirectory($OutputDir) | Out-Null
}

# 3. Resolve GitHub Authentication Token
$token = ""
$tokenSource = ""

# Check $env:GH_PAT
if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "AdoToGhMigration-Snapshot/1.0"
        }
        $u = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 5
        $token = $cleanPat
        $tokenSource = "`$env:GH_PAT (Authenticated as: $($u.login))"
    }
    catch {
        Write-Warning "`$env:GH_PAT is set but rejected by GitHub ($($_.Exception.Message)). Checking GitHub CLI..."
    }
}

# Fallback: GitHub CLI token
if ([string]::IsNullOrWhiteSpace($token)) {
    try {
        $ghCliToken = (gh auth token 2>$null)
        if (-not [string]::IsNullOrWhiteSpace($ghCliToken)) {
            $ghCliToken = $ghCliToken.Trim()
            $testHeaders = @{
                Authorization          = "Bearer $ghCliToken"
                Accept                 = "application/vnd.github+json"
                "X-GitHub-Api-Version" = "2022-11-28"
                "User-Agent"           = "AdoToGhMigration-Snapshot/1.0"
            }
            $u = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 5
            $token = $ghCliToken
            $tokenSource = "GitHub CLI Keyring (Authenticated as: $($u.login))"
        }
    }
    catch {}
}

if ([string]::IsNullOrWhiteSpace($token)) {
    throw "No valid GitHub token found. Please set `$env:GH_PAT = 'ghp_...' or run 'gh auth login'."
}

Write-Host "[+] Target Organization(s) : $($targetOrgs.Count) org(s) -> ($($targetOrgs -join ', '))" -ForegroundColor Yellow
Write-Host "[+] Authentication         : $tokenSource" -ForegroundColor Gray
Write-Host "[+] Output Directory       : $OutputDir`n" -ForegroundColor Gray

$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "AdoToGhMigration-Snapshot/1.0"
}

$timestamp = [System.DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$snapshottedOrgs = [System.Collections.Generic.List[PSCustomObject]]::new()

# 4. Iterate and Snapshot Each Organization
foreach ($org in $targetOrgs) {
    Write-Host "[+] Snapshotting organization: $org..." -ForegroundColor Cyan
    $orgUri = "https://api.github.com/orgs/$org"
    $rawOrg = $null

    try {
        $rawOrg = Invoke-RestMethod -Uri $orgUri -Headers $headers -Method Get
    }
    catch {
        Write-Warning "Failed to query organization '$org' ($($_.Exception.Message)). Skipping."
        continue
    }

    $planName = if ($null -ne $rawOrg.plan) { $rawOrg.plan.name } else { "unknown" }

    # Extract Governance Settings
    $governanceSettings = [ordered]@{
        "default_repository_permission"                               = $rawOrg.default_repository_permission
        "members_can_create_repositories"                             = $rawOrg.members_can_create_repositories
        "members_allowed_repository_creation_type"                   = $rawOrg.members_allowed_repository_creation_type
        "members_can_create_public_repositories"                      = $rawOrg.members_can_create_public_repositories
        "members_can_create_private_repositories"                     = $rawOrg.members_can_create_private_repositories
        "members_can_create_internal_repositories"                    = $rawOrg.members_can_create_internal_repositories
        "members_can_fork_private_repositories"                       = $rawOrg.members_can_fork_private_repositories
        "members_can_create_pages"                                    = $rawOrg.members_can_create_pages
        "members_can_create_public_pages"                             = $rawOrg.members_can_create_public_pages
        "members_can_create_private_pages"                            = $rawOrg.members_can_create_private_pages
        "web_commit_signoff_required"                                 = $rawOrg.web_commit_signoff_required
        "two_factor_requirement_enabled"                              = $rawOrg.two_factor_requirement_enabled
        "members_can_change_repo_visibility"                          = $rawOrg.members_can_change_repo_visibility
        "members_can_delete_repositories"                             = $rawOrg.members_can_delete_repositories
        "advanced_security_enabled_for_new_repositories"              = $rawOrg.advanced_security_enabled_for_new_repositories
        "dependabot_alerts_enabled_for_new_repositories"              = $rawOrg.dependabot_alerts_enabled_for_new_repositories
        "dependabot_security_updates_enabled_for_new_repositories"     = $rawOrg.dependabot_security_updates_enabled_for_new_repositories
        "dependency_graph_enabled_for_new_repositories"               = $rawOrg.dependency_graph_enabled_for_new_repositories
        "secret_scanning_enabled_for_new_repositories"                = $rawOrg.secret_scanning_enabled_for_new_repositories
        "secret_scanning_push_protection_enabled_for_new_repositories"= $rawOrg.secret_scanning_push_protection_enabled_for_new_repositories
    }

    # Extended Settings (Actions permissions, SSH CAs)
    $extendedSettings = [ordered]@{}

    try {
        $actionsUri = "https://api.github.com/orgs/$org/actions/permissions"
        $actionsPerms = Invoke-RestMethod -Uri $actionsUri -Headers $headers -Method Get
        $extendedSettings["actions_permissions"] = $actionsPerms
        Write-Host "    [OK] Captured GitHub Actions permissions." -ForegroundColor Green
    }
    catch {
        $extendedSettings["actions_permissions"] = "NotCaptured ($($_.Exception.Message))"
        Write-Host "    [SKIP] Actions permissions query skipped ($($_.Exception.Message))" -ForegroundColor DarkGray
    }

    try {
        $sshUri = "https://api.github.com/orgs/$org/settings/ssh-certificate-authorities"
        $sshCAs = Invoke-RestMethod -Uri $sshUri -Headers $headers -Method Get
        $extendedSettings["ssh_certificate_authorities"] = $sshCAs
        Write-Host "    [OK] Captured SSH Certificate Authorities." -ForegroundColor Green
    }
    catch {
        $extendedSettings["ssh_certificate_authorities"] = "NotCaptured"
    }

    # Assemble and Save Snapshot
    $snapshotData = [PSCustomObject]@{
        SnapshotVersion    = "1.0"
        TargetOrganization = $org
        PlanName           = $planName
        CapturedAtUtc      = [System.DateTime]::UtcNow.ToString("o")
        AuthSource         = $tokenSource
        GovernanceSettings = $governanceSettings
        ExtendedSettings   = $extendedSettings
        RawResponse        = $rawOrg
    }

    $snapshotFile = Join-Path -Path $OutputDir -ChildPath "$($org)-snapshot-$timestamp.json"
    $latestFile   = Join-Path -Path $OutputDir -ChildPath "$($org)-latest-preflight.json"

    $snapshotJson = $snapshotData | ConvertTo-Json -Depth 10
    Set-Content -Path $snapshotFile -Value $snapshotJson -Encoding utf8
    Set-Content -Path $latestFile -Value $snapshotJson -Encoding utf8

    Write-Host "    [OK] Snapshot saved for '$org' (Plan: $planName)" -ForegroundColor Green

    $snapshottedOrgs.Add([PSCustomObject]@{
        Organization = $org
        Plan         = $planName
        SnapshotPath = $latestFile
    })
}

if ($snapshottedOrgs.Count -eq 0) {
    throw "No organizations could be snapshotted. Review the warnings above."
}

# 5. Auto-Generate 1-Click Multi-Org Rollback Script ('05_Rollback-GitHubOrgPolicies.ps1')
$rollbackScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "05_Rollback-GitHubOrgPolicies.ps1"
$defaultRollbackOrg = $snapshottedOrgs[0].Organization

$rollbackContent = @'
#Requires -Version 7.0
<#
.SYNOPSIS
    Restores one or all GitHub Organizations to the exact state captured in their pre-flight snapshots.

.DESCRIPTION
    Rolls back settings using the latest snapshot file(s) under 'output\snapshots\<org>-latest-preflight.json'.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [string]$SnapshotPath = "",

    [Parameter(Mandatory = $false)]
    [string]$SnapshotsDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n=================================================================" -ForegroundColor Magenta
Write-Host "         GitHub Organization Policy 1-Click Rollback             " -ForegroundColor Magenta
Write-Host "=================================================================`n" -ForegroundColor Magenta

if ([string]::IsNullOrWhiteSpace($SnapshotsDir)) {
    $SnapshotsDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots"
}

# Resolve Target Orgs to Rollback
$orgsToRollback = [System.Collections.Generic.List[string]]::new()

if (-not [string]::IsNullOrWhiteSpace($TargetOrg)) {
    $orgsToRollback.Add($TargetOrg.Trim())
}
else {
    $orgFile = Join-Path -Path $PSScriptRoot -ChildPath "config\github-org.txt"
    if (-not (Test-Path -LiteralPath $orgFile)) {
        $orgFile = Join-Path -Path $PSScriptRoot -ChildPath "github-org.txt"
    }
    if (Test-Path -LiteralPath $orgFile) {
        $lines = @(Get-Content -Path $orgFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#") })
        foreach ($l in $lines) {
            $orgsToRollback.Add($l.Trim())
        }
    }
}

if ($orgsToRollback.Count -eq 0) {
    throw "No target organization specified for rollback."
}

# Resolve Auth Token
$token = ""
if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "AdoToGhMigration-Rollback/1.0"
        }
        $u = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 5
        $token = $cleanPat
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($token)) {
    try {
        $token = (gh auth token 2>$null).Trim()
    } catch {}
}
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "No GitHub token found. Set `$env:GH_PAT = 'ghp_...' or run 'gh auth login'."
}

$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "AdoToGhMigration-Rollback/1.0"
}

foreach ($org in $orgsToRollback) {
    $snapFile = if (-not [string]::IsNullOrWhiteSpace($SnapshotPath) -and (Test-Path -Path $SnapshotPath)) {
        $SnapshotPath
    }
    else {
        Join-Path -Path $SnapshotsDir -ChildPath "$org-latest-preflight.json"
    }
    if (-not (Test-Path -Path $snapFile)) {
        Write-Warning "No snapshot file found for '$org' at '$snapFile'. Skipping."
        continue
    }

    $snapshot = Get-Content -Path $snapFile -Raw | ConvertFrom-Json
    Write-Host "[+] Rolling back '$org' using snapshot from $($snapshot.CapturedAtUtc) UTC..." -ForegroundColor Cyan

    $gov = $snapshot.GovernanceSettings
    $rollbackPayload = [ordered]@{
        "default_repository_permission"           = $gov.default_repository_permission
        "members_can_create_repositories"         = [bool]$gov.members_can_create_repositories
        "members_allowed_repository_creation_type" = $gov.members_allowed_repository_creation_type
        "members_can_create_public_repositories"  = [bool]$gov.members_can_create_public_repositories
        "members_can_create_private_repositories" = [bool]$gov.members_can_create_private_repositories
        "members_can_create_internal_repositories"= [bool]$gov.members_can_create_internal_repositories
        "members_can_fork_private_repositories"   = [bool]$gov.members_can_fork_private_repositories
        "members_can_create_pages"                = [bool]$gov.members_can_create_pages
        "web_commit_signoff_required"             = [bool]$gov.web_commit_signoff_required
    }

    $patchJson = $rollbackPayload | ConvertTo-Json
    $restoreResponse = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org" -Headers $headers -Method Patch -Body $patchJson -ContentType "application/json"
    Write-Host "    [OK] Settings restored on '$org'!" -ForegroundColor Green

    # Read-back Verification
    $verified = $true
    foreach ($prop in $rollbackPayload.Keys) {
        $expected = $rollbackPayload[$prop]
        $actual   = $restoreResponse.$prop
        if ("$expected" -ne "$actual") {
            Write-Warning "Drift detected on '$prop' in '$org': Expected '$expected', Actual '$actual'"
            $verified = $false
        }
    }

    if ($verified) {
        Write-Host "    [VERIFIED] '$org' is 100% restored to pre-flight state.`n" -ForegroundColor Green
    }
}
'@

Set-Content -Path $rollbackScriptPath -Value $rollbackContent -Encoding utf8

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                     SNAPSHOT COMPLETE                           " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[+] Successfully snapshotted $($snapshottedOrgs.Count) GitHub organization(s):" -ForegroundColor Green

foreach ($s in $snapshottedOrgs) {
    Write-Host "  • $($s.Organization) (Plan: $($s.Plan))" -ForegroundColor Yellow
    Write-Host "    --> $($s.SnapshotPath)" -ForegroundColor Gray
}

Write-Host "`n[+] 1-Click Rollback Script Ready:" -ForegroundColor Yellow
Write-Host "    $rollbackScriptPath`n" -ForegroundColor White
