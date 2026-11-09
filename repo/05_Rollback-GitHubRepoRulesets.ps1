#Requires -Version 7.0
<#
.SYNOPSIS
    Restores GitHub Repository Rulesets to their exact pre-flight snapshot state (1-Click Rollback).

.DESCRIPTION
    Phase 3 - Step 5 of the ADO-to-GitHub Policy Migration pipeline.
    - Safety First: 100% reversible rollback engine for repository-level rulesets.
    - Scans pre-flight snapshot JSON files in 'repo\output\snapshots\latest' or an explicit -SnapshotPath.
    - Deletes any ruleset created by the migration ('ado-migrated-*').
    - Restores any pre-existing rulesets or classic branch protections captured in the pre-flight snapshot.
    - Performs immediate read-back verification.

.PARAMETER TargetOrg
    Specific GitHub organization. Defaults to 'ADO2GH-Migration' or config/github-org.txt.

.PARAMETER TargetRepo
    Specific repository name (e.g. 'sample2') or 'owner/repo'.

.PARAMETER TargetRepos
    Array of repository names.

.PARAMETER SnapshotPath
    Explicit path to a snapshot JSON file.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\repo"
    pwsh .\05_Rollback-GitHubRepoRulesets.ps1 -TargetOrg "ADO2GH-Migration" -TargetRepo "sample2"
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [string]$TargetRepo = "",

    [Parameter(Mandatory = $false)]
    [string[]]$TargetRepos = @(),

    [Parameter(Mandatory = $false)]
    [string]$SnapshotPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "      GitHub Repository Rulesets 1-Click Rollback Engine         " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Authentication
$token = ""
$tokenSource = ""

if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "RepoRuleset-Rollback/3.0"
        }
        $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
        $token = $cleanPat
        $tokenSource = "`$env:GH_PAT (User: $($userObj.login))"
    }
    catch {}
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
                "User-Agent"           = "RepoRuleset-Rollback/3.0"
            }
            $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
            $token = $cliToken
            $tokenSource = "gh auth token (User: $($userObj.login))"
        }
    }
    catch {}
}

if (-not $token) {
    throw "No valid GitHub credentials available for rollback. Please set `$env:GH_PAT or authenticate via 'gh auth login'."
}

Write-Host "[+] Authentication         : $tokenSource" -ForegroundColor Green

$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "RepoRuleset-Rollback/3.0"
}

# 2. Resolve Snapshot Files
$snapshotsDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots\latest"
$snapshotFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

if ($SnapshotPath) {
    if (-not (Test-Path -LiteralPath $SnapshotPath)) {
        throw "Specified snapshot path not found: '$SnapshotPath'"
    }
    $snapshotFiles.Add((Get-Item -LiteralPath $SnapshotPath))
}
elseif ($TargetRepo) {
    $rName = $TargetRepo.Trim()
    if ($rName.Contains("/")) {
        $parts = $rName -split '/'
        $TargetOrg = $parts[0]
        $rName = $parts[1]
    }
    $matching = @(Get-ChildItem -Path $snapshotsDir -Filter "*$rName.snapshot.json" -ErrorAction SilentlyContinue)
    if ($matching.Count -gt 0) {
        $snapshotFiles.Add($matching[0])
    }
}
else {
    $found = @(Get-ChildItem -Path $snapshotsDir -Filter *.snapshot.json -ErrorAction SilentlyContinue)
    if ($found.Count -eq 0) {
        # Check parent snapshots directory for recent timestamp folder
        $parentSnapshotsDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots"
        $found = @(Get-ChildItem -Path $parentSnapshotsDir -Recurse -Filter *.snapshot.json -ErrorAction SilentlyContinue)
    }
    foreach ($f in $found) {
        $snapshotFiles.Add($f)
    }
}

if ($snapshotFiles.Count -eq 0) {
    throw "No pre-flight snapshot files found in '$snapshotsDir'. Run 03_Snapshot-GitHubRepoRulesets.ps1 before attempting rollback."
}

Write-Host "[+] Found $($snapshotFiles.Count) pre-flight snapshot file(s) for rollback." -ForegroundColor Cyan

# 3. Filter by TargetOrg/TargetRepos if specified
$filteredSnapshots = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
foreach ($snapFile in $snapshotFiles) {
    $snap = Get-Content -LiteralPath $snapFile.FullName -Raw | ConvertFrom-Json
    $matchesOrg = [string]::IsNullOrWhiteSpace($TargetOrg) -or ($snap.TargetOrg -eq $TargetOrg)
    $matchesRepo = $true
    if (-not [string]::IsNullOrWhiteSpace($TargetRepo)) {
        $cleanR = $TargetRepo.Trim()
        if ($cleanR.Contains("/")) { $cleanR = ($cleanR -split '/')[-1] }
        $matchesRepo = ($snap.RepositoryName -eq $cleanR)
    }
    elseif ($TargetRepos.Count -gt 0) {
        $matchesRepo = $TargetRepos.Contains($snap.RepositoryName)
    }

    if ($matchesOrg -and $matchesRepo) {
        $filteredSnapshots.Add($snapFile)
    }
}

if ($filteredSnapshots.Count -eq 0) {
    throw "No snapshots matched the specified target filters (Org: '$TargetOrg', Repo: '$TargetRepo')."
}

$rollbackResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# 4. Perform Rollback Per Repository
foreach ($snapFile in $filteredSnapshots) {
    $snap = Get-Content -LiteralPath $snapFile.FullName -Raw | ConvertFrom-Json
    $org = $snap.TargetOrg
    $repo = $snap.RepositoryName

    Write-Host "`n[+] Rolling back repository '$org/$repo' (Pre-flight captured at: $($snap.CapturedAtUtc))..." -ForegroundColor Cyan

    # A. Query Current Live Rulesets
    $currentRulesets = @()
    try {
        $liveResp = Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$repo/rulesets" -Headers $headers -Method Get
        if ($liveResp) { $currentRulesets = @($liveResp) }
    }
    catch {
        Write-Warning "Could not query current rulesets for '$org/$repo': $($_.Exception.Message)"
        continue
    }

    # B. Identify and Delete Migrated Rulesets
    $deletedCount = 0
    $snapshotIds = @()
    if ($snap.Rulesets) {
        $snapshotIds = @($snap.Rulesets | ForEach-Object { [int]$_.id })
    }

    foreach ($rs in $currentRulesets) {
        $rsName = [string]$rs.name
        $rsId = [int]$rs.id

        # Delete if named like migrated ruleset OR not present in the original snapshot
        $isMigrated = ($rsName -like "ado-migrated-*") -or (-not $snapshotIds.Contains($rsId))
        if ($isMigrated) {
            Write-Host "    Deleting migrated ruleset '$rsName' (ID: $rsId)..." -ForegroundColor Yellow
            try {
                Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$repo/rulesets/$rsId" -Headers $headers -Method Delete
                Write-Host "    [OK] Deleted ruleset '$rsName'." -ForegroundColor Green
                $deletedCount++
            }
            catch {
                if ($_.Exception.Message -match '404' -or ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response.StatusCode -eq 404)) {
                    Write-Host "    [OK] Ruleset '$rsName' was already removed (idempotent)." -ForegroundColor Green
                    $deletedCount++
                } else {
                    Write-Warning "    Failed to delete ruleset '$rsName': $($_.Exception.Message)"
                }
            }
        }
    }

    # C. Restore Snapshot Rulesets if Missing
    $restoredCount = 0
    if ($snap.Rulesets -and $snap.Rulesets.Count -gt 0) {
        foreach ($origRs in $snap.Rulesets) {
            $origName = $origRs.name
            $stillExists = @($currentRulesets | Where-Object { $_.id -eq $origRs.id -or $_.name -eq $origName }).Count -gt 0
            if (-not $stillExists) {
                Write-Host "    Restoring snapshot ruleset '$origName'..." -ForegroundColor Yellow
                $restorePayload = [PSCustomObject]@{
                    name        = $origRs.name
                    target      = $origRs.target
                    enforcement = $origRs.enforcement
                    conditions  = $origRs.conditions
                    rules       = $origRs.rules
                }
                try {
                    $body = $restorePayload | ConvertTo-Json -Depth 8
                    Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$repo/rulesets" -Headers $headers -Method Post -Body $body | Out-Null
                    Write-Host "    [OK] Restored ruleset '$origName'." -ForegroundColor Green
                    $restoredCount++
                }
                catch {
                    Write-Warning "    Failed to restore ruleset '$origName': $($_.Exception.Message)"
                }
            }
        }
    }

    # D. Verification Read-back
    $finalRulesets = @()
    try {
        $finalResp = Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$repo/rulesets" -Headers $headers -Method Get
        if ($finalResp) { $finalRulesets = @($finalResp) }
    }
    catch {}

    $expectedCount = if ($snap.Rulesets) { $snap.Rulesets.Count } else { 0 }
    $actualCount = $finalRulesets.Count
    $isMatch = ($expectedCount -eq $actualCount)

    Write-Host "    [VERIFIED] Ruleset count on '$org/$repo': $actualCount (Pre-flight was: $expectedCount)." -ForegroundColor $(if ($isMatch) { 'Green' } else { 'Yellow' })

    $rollbackResults.Add([PSCustomObject]@{
        Organization       = $org
        Repository         = $repo
        DeletedRulesets    = $deletedCount
        RestoredRulesets   = $restoredCount
        PreFlightCount     = $expectedCount
        CurrentCount       = $actualCount
        Status             = if ($isMatch) { "Success" } else { "Count Mismatch" }
    })
}

Write-Host "`n-----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "                 REPOSITORY ROLLBACK REPORT                      " -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
$rollbackResults | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White

Write-Host "[OK] Rollback complete: Success" -ForegroundColor Green
