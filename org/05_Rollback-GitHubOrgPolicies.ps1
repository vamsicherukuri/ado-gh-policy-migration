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
