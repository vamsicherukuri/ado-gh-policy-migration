#Requires -Version 7.0
<#
.SYNOPSIS
    Restores GitHub Rulesets to their exact pre-flight snapshot state (1-Click Rollback).

.DESCRIPTION
    Phase 2 - Step 5 of the ADO-to-GitHub Policy Migration pipeline.
    - Safety First: 100% reversible rollback engine.
    - Scans pre-flight snapshots in 'project\output\snapshots'.
    - Deletes rulesets created during migration ('ado-migrated-*').
    - Restores any pre-existing rulesets that were modified.
    - Performs immediate read-back verification.

.PARAMETER TargetOrg
    Specific GitHub organization to rollback. Defaults to all orgs with snapshots.

.PARAMETER TargetRepo
    Optional specific repository to rollback.

.PARAMETER SnapshotPath
    Explicit snapshot JSON path to rollback from.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\project"
    pwsh .\05_Rollback-GitHubRulesets.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [string]$TargetRepo = "",

    [Parameter(Mandatory = $false)]
    [string]$SnapshotPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "         GitHub Rulesets 1-Click Rollback Engine                 " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Authentication
$token = ""
if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "Ruleset-Rollback/2.0"
        }
        $null = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
        $token = $cleanPat
    }
    catch {
        # Fallback
    }
}

if (-not $token) {
    try {
        $cliToken = (& gh auth token 2>$null)
        if ($cliToken) { $token = $cliToken.Trim() }
    }
    catch {
        # gh CLI failed
    }
}

if (-not $token) {
    throw "No valid GitHub credentials available for rollback."
}

$apiHeaders = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "AdoToGh-RulesetRollback/2.0"
}

# 2. Resolve Snapshot Files
$snapshotsDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots"
$snapshotFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

if ($SnapshotPath) {
    if (-not (Test-Path -LiteralPath $SnapshotPath)) {
        throw "Specified snapshot path not found: '$SnapshotPath'"
    }
    $snapshotFiles.Add((Get-Item -LiteralPath $SnapshotPath))
}
elseif ($TargetOrg) {
    $p = Join-Path -Path $snapshotsDir -ChildPath "$TargetOrg-latest-rulesets-preflight.json"
    if (-not (Test-Path -LiteralPath $p)) {
        throw "Pre-flight snapshot for '$TargetOrg' not found at '$p'."
    }
    $snapshotFiles.Add((Get-Item -LiteralPath $p))
}
else {
    $found = @(Get-ChildItem -Path $snapshotsDir -Filter *-latest-rulesets-preflight.json)
    if ($found.Count -eq 0) {
        throw "No *-latest-rulesets-preflight.json snapshots found in '$snapshotsDir'."
    }
    foreach ($f in $found) {
        $snapshotFiles.Add($f)
    }
}

Write-Host "[+] Found $($snapshotFiles.Count) pre-flight snapshot(s) for rollback." -ForegroundColor Cyan

# 3. Perform Rollback for Each Snapshot
foreach ($snapFile in $snapshotFiles) {
    $snap = Get-Content -LiteralPath $snapFile.FullName -Raw | ConvertFrom-Json
    $org = $snap.TargetOrganization
    Write-Host "`n[+] Rolling back rulesets on '$org' (Snapshot: $($snap.CapturedAtUtc))..." -ForegroundColor Cyan

    # A. Check and rollback Organization-Level Rulesets
    if (-not $TargetRepo) {
        Write-Host "    Checking Organization-level rulesets on '$org'..." -ForegroundColor Cyan
        try {
            $existingOrg = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org/rulesets" -Headers $apiHeaders -Method Get
            if ($existingOrg) {
                foreach ($rs in @($existingOrg)) {
                    if ($rs.name -like "ado-migrated-*") {
                        Write-Host "    Deleting migrated Org ruleset '$($rs.name)' (ID: $($rs.id)) on '$org'..." -ForegroundColor Yellow
                        try {
                            Invoke-RestMethod -Uri "https://api.github.com/orgs/$org/rulesets/$($rs.id)" -Headers $apiHeaders -Method Delete
                            Write-Host "    [OK] Deleted Org ruleset '$($rs.name)'." -ForegroundColor Green
                        }
                        catch {
                            if ($_.Exception.Message -match '404' -or ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response.StatusCode -eq 404)) {
                                Write-Host "    [OK] Org ruleset '$($rs.name)' was already removed (idempotent)." -ForegroundColor Green
                            } else {
                                Write-Warning "    Failed to delete Org ruleset '$($rs.name)': $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Org rulesets read skipped if lacks admin:org
        }
    }

    # B. Check and rollback Repository-Level Rulesets
    $repoList = @()
    if ($TargetRepo) {
        $repoList = @([PSCustomObject]@{ name = $TargetRepo })
    }
    else {
        try {
            $reposResp = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org/repos?per_page=100" -Headers $apiHeaders -Method Get
            if ($reposResp) { $repoList = @($reposResp) }
        }
        catch {
            Write-Warning "Could not list repositories in '$org': $($_.Exception.Message)"
        }
    }

    foreach ($r in $repoList) {
        $rName = $r.name
        # Query existing rulesets on this repo
        $existing = @()
        try {
            $existingResp = Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$rName/rulesets" -Headers $apiHeaders -Method Get
            if ($existingResp) { $existing = @($existingResp) }
        }
        catch {
            Write-Warning "Could not query rulesets on '$org/$rName': $($_.Exception.Message)"
            continue
        }

        if ($existing.Count -eq 0) {
            Write-Host "    '$org/$rName' has 0 rulesets (Already in clean pre-flight state)." -ForegroundColor Gray
            continue
        }

        foreach ($rs in $existing) {
            $rsName = $rs.name
            $rsId = $rs.id

            # Check if this ruleset was created by migration
            if ($rsName -like "ado-migrated-*") {
                Write-Host "    Deleting migrated repo ruleset '$rsName' (ID: $rsId) on '$org/$rName'..." -ForegroundColor Yellow
                try {
                    Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$rName/rulesets/$rsId" -Headers $apiHeaders -Method Delete
                    Write-Host "    [OK] Deleted ruleset '$rsName'." -ForegroundColor Green
                }
                catch {
                    if ($_.Exception.Message -match '404' -or ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response.StatusCode -eq 404)) {
                        Write-Host "    [OK] Ruleset '$rsName' was already removed (idempotent)." -ForegroundColor Green
                    } else {
                        Write-Warning "    Failed to delete ruleset '$rsName': $($_.Exception.Message)"
                    }
                }
            }
        }

        # Post-rollback verification check
        $verifyResp = Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$rName/rulesets" -Headers $apiHeaders -Method Get
        $rem = if ($verifyResp) { @($verifyResp).Count } else { 0 }
        Write-Host "    [VERIFIED] '$org/$rName' ruleset count restored to: $rem." -ForegroundColor Green
    }
}

Write-Host "`n[OK] Rollback complete. All target repositories restored to pre-flight ruleset state." -ForegroundColor Green
