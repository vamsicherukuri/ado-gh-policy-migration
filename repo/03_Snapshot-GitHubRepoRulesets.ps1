#Requires -Version 7.0
<#
.SYNOPSIS
    Captures pre-flight snapshots of existing GitHub Repository Rulesets and branch protections.

.DESCRIPTION
    Phase 3 - Step 3 of the ADO-to-GitHub Policy Migration pipeline.
    - Safety First: Freezes current GitHub repository ruleset and branch protection configurations before any mutations.
    - Captures:
        * Repository Rulesets (/repos/{owner}/{repo}/rulesets) including rules, conditions, enforcement, and bypass actors.
        * Classic Branch Protections (/repos/{owner}/{repo}/branches/{branch}/protection).
        * Core Repository Policy Settings (forking, merge commit types).
    - Writes immutable snapshot JSON files to 'repo\output\snapshots\{timestamp}\' and 'repo\output\snapshots\latest\'.
    - Used by '05_Rollback-GitHubRepoRulesets.ps1' for guaranteed 1-click restoration.

.PARAMETER TargetOrg
    Target GitHub organization. Defaults to 'ADO2GH-Migration' or config/github-org.txt.

.PARAMETER TargetRepo
    Specific GitHub repository name or 'owner/repo'.

.PARAMETER TargetRepos
    Array of repository names.

.PARAMETER ReposFilePath
    Path to text file containing target repositories. Defaults to 'config\repos.txt'.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\repo"
    pwsh .\03_Snapshot-GitHubRepoRulesets.ps1 -TargetOrg "ADO2GH-Migration" -TargetRepo "sample2"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetOrg = "",

    [Parameter(Mandatory = $false)]
    [string]$TargetRepo = "",

    [Parameter(Mandatory = $false)]
    [string[]]$TargetRepos = @(),

    [Parameter(Mandatory = $false)]
    [string]$MappingFilePath = "",

    [Parameter(Mandatory = $false)]
    [string]$ReposFilePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Capture Pre-Flight Snapshot of GitHub Repository Rulesets    " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Target Organization
if ([string]::IsNullOrWhiteSpace($TargetOrg)) {
    $orgFile = Join-Path -Path $PSScriptRoot -ChildPath "config\github-org.txt"
    if (Test-Path -LiteralPath $orgFile) {
        $lines = @(Get-Content -LiteralPath $orgFile | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#")
        })
        if ($lines.Count -gt 0) {
            $TargetOrg = $lines[0].Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($TargetOrg)) {
        $TargetOrg = "ADO2GH-Migration"
    }
}

# 2. Resolve Target Repositories
$repoNames = [System.Collections.Generic.List[string]]::new()

if (-not [string]::IsNullOrWhiteSpace($TargetRepo)) {
    $cleaned = $TargetRepo.Trim()
    if ($cleaned.Contains("/")) {
        $parts = $cleaned -split '/'
        $TargetOrg = $parts[0]
        $cleaned = $parts[1]
    }
    $repoNames.Add($cleaned)
}

if ($TargetRepos -and $TargetRepos.Count -gt 0) {
    foreach ($r in $TargetRepos) {
        $cleaned = $r.Trim()
        if ($cleaned.Contains("/")) {
            $parts = $cleaned -split '/'
            $TargetOrg = $parts[0]
            $cleaned = $parts[1]
        }
        if (-not $repoNames.Contains($cleaned)) {
            $repoNames.Add($cleaned)
        }
    }
}

if ($repoNames.Count -eq 0) {
    if ([string]::IsNullOrWhiteSpace($MappingFilePath)) {
        $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\repo-mapping.csv"
        if (-not (Test-Path -LiteralPath $MappingFilePath)) {
            $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "repo-mapping.csv"
        }
    }

    if (Test-Path -LiteralPath $MappingFilePath) {
        Write-Host "[+] Using Source-to-Target mapping: $MappingFilePath" -ForegroundColor Cyan
        $mappingRows = @(Import-Csv -LiteralPath $MappingFilePath)
        foreach ($m in $mappingRows) {
            $targetRepoName = if ($m.PSObject.Properties['TargetGhRepo'] -and -not [string]::IsNullOrWhiteSpace($m.TargetGhRepo)) { $m.TargetGhRepo.Trim() } else { $m.AdoRepo.Trim() }
            if ($m.PSObject.Properties['TargetGhOrg'] -and -not [string]::IsNullOrWhiteSpace($m.TargetGhOrg)) {
                $TargetOrg = $m.TargetGhOrg.Trim()
            }
            if (-not $repoNames.Contains($targetRepoName)) {
                $repoNames.Add($targetRepoName)
            }
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($ReposFilePath)) {
            $ReposFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\repos.txt"
        }
        if (Test-Path -LiteralPath $ReposFilePath) {
            $lines = @(Get-Content -LiteralPath $ReposFilePath | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#")
            })
            foreach ($l in $lines) {
                $cleaned = $l.Trim()
                # Extract repository name from org/proj/repo or url
                $parts = $cleaned -split '[\/\\]'
                $rName = $parts[-1]
                if (-not [string]::IsNullOrWhiteSpace($rName) -and -not $repoNames.Contains($rName)) {
                    $repoNames.Add($rName)
                }
            }
        }
    }
}

if ($repoNames.Count -eq 0) {
    throw "No target repositories specified. Provide via -TargetRepo, -TargetRepos, or 'config\repos.txt'."
}

Write-Host "[+] Target Organization    : $TargetOrg" -ForegroundColor Cyan
Write-Host "[+] Target Repositories    : $($repoNames.Count) repo(s) -> ($($repoNames -join ', '))" -ForegroundColor Cyan

# 3. Resolve GitHub Authentication
$token = ""
$tokenSource = ""

if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "RepoRuleset-Snapshot/3.0"
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
                "User-Agent"           = "RepoRuleset-Snapshot/3.0"
            }
            $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
            $token = $cliToken
            $tokenSource = "gh auth token (User: $($userObj.login))"
        }
    }
    catch {}
}

if (-not $token) {
    throw "No valid GitHub token found. Please set `$env:GH_PAT or authenticate via 'gh auth login'."
}

Write-Host "[+] Authentication         : $tokenSource" -ForegroundColor Green

$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "RepoRuleset-Snapshot/3.0"
}

function Invoke-GhApi {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = "Get"
    )
    return Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -TimeoutSec 15
}

# 4. Prepare Output Directories
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$snapshotDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots\$timestamp"
$latestDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots\latest"
New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
New-Item -ItemType Directory -Path $latestDir -Force | Out-Null
$logFile = Join-Path -Path $snapshotDir -ChildPath "execution.log"
"" | Set-Content -LiteralPath $logFile -Encoding utf8

$summaryList = [System.Collections.Generic.List[PSCustomObject]]::new()

# 5. Execute Snapshots per Repository
foreach ($repo in $repoNames) {
    Write-Host "`n[+] Capturing pre-flight snapshot for '$TargetOrg/$repo'..." -ForegroundColor Cyan

    # A. Repo Metadata
    $repoMeta = $null
    try {
        $repoMeta = Invoke-GhApi -Uri "https://api.github.com/repos/$TargetOrg/$repo"
    }
    catch {
        Write-Warning "Repository '$TargetOrg/$repo' not found or inaccessible: $($_.Exception.Message)"
        continue
    }

    # B. Fetch Repository Rulesets
    $rulesetsDetailed = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $rulesetList = Invoke-GhApi -Uri "https://api.github.com/repos/$TargetOrg/$repo/rulesets"
        if ($rulesetList) {
            foreach ($rs in $rulesetList) {
                try {
                    $detail = Invoke-GhApi -Uri "https://api.github.com/repos/$TargetOrg/$repo/rulesets/$($rs.id)"
                    $rulesetsDetailed.Add($detail)
                }
                catch {
                    Write-Warning "Failed to fetch ruleset detail for ID $($rs.id): $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Warning "Could not list rulesets for '$TargetOrg/$repo': $($_.Exception.Message)"
    }

    # C. Fetch Classic Branch Protections
    $branchProtections = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $protectedBranches = Invoke-GhApi -Uri "https://api.github.com/repos/$TargetOrg/$repo/branches?protected=true"
        if ($protectedBranches) {
            foreach ($b in $protectedBranches) {
                try {
                    $bProt = Invoke-GhApi -Uri "https://api.github.com/repos/$TargetOrg/$repo/branches/$([Uri]::EscapeDataString($b.name))/protection"
                    $branchProtections.Add([PSCustomObject]@{
                        BranchName = $b.name
                        Protection = $bProt
                    })
                }
                catch {}
            }
        }
    }
    catch {}

    # D. Build Snapshot Object
    $snapshotObj = [PSCustomObject]@{
        SnapshotVersion     = "3.0"
        CapturedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
        TargetOrg           = $TargetOrg
        RepositoryName      = $repo
        DefaultBranch       = $repoMeta.default_branch
        AllowForking        = $repoMeta.allow_forking
        AllowSquashMerge    = $repoMeta.allow_squash_merge
        AllowMergeCommit    = $repoMeta.allow_merge_commit
        AllowRebaseMerge    = $repoMeta.allow_rebase_merge
        RulesetsCount       = $rulesetsDetailed.Count
        Rulesets            = $rulesetsDetailed
        BranchProtections   = $branchProtections
    }

    $safeFileName = "$TargetOrg-$repo.snapshot.json" -replace '[^a-zA-Z0-9_\-\.]', '_'
    $timestampFile = Join-Path -Path $snapshotDir -ChildPath $safeFileName
    $latestFile = Join-Path -Path $latestDir -ChildPath $safeFileName

    $snapshotJson = $snapshotObj | ConvertTo-Json -Depth 15
    Set-Content -LiteralPath $timestampFile -Value $snapshotJson -Encoding utf8
    Set-Content -LiteralPath $latestFile -Value $snapshotJson -Encoding utf8

    Add-Content -LiteralPath $logFile -Value "[$TargetOrg/$repo] Rulesets: $($rulesetsDetailed.Count), ClassicProtections: $($branchProtections.Count) -> $timestampFile" -Encoding utf8
    Write-Host "  [+] Snapshotted $TargetOrg/$repo ($($rulesetsDetailed.Count) rulesets)" -ForegroundColor Gray

    $summaryList.Add([PSCustomObject]@{
        Organization      = $TargetOrg
        Repository        = $repo
        DefaultBranch     = $repoMeta.default_branch
        RulesetsCaptured  = $rulesetsDetailed.Count
        ClassicProtections= $branchProtections.Count
        SnapshotPath      = $timestampFile
    })
}

$summaryTable = $summaryList | Format-Table -AutoSize | Out-String
Add-Content -LiteralPath $logFile -Value "`n=================================================================" -Encoding utf8
Add-Content -LiteralPath $logFile -Value "             PRE-FLIGHT REPOSITORY SNAPSHOT SUMMARY              " -Encoding utf8
Add-Content -LiteralPath $logFile -Value "=================================================================" -Encoding utf8
Add-Content -LiteralPath $logFile -Value $summaryTable -Encoding utf8

$totalRules = ($summaryList | Measure-Object -Property RulesetsCaptured -Sum).Sum
Write-Host "`n[OK] Snapshot complete. Directory: $snapshotDir" -ForegroundColor Green
Write-Host "     Total Rulesets Frozen : $totalRules across $($summaryList.Count) repositories" -ForegroundColor Gray
Write-Host "     Detailed Execution Log: $logFile" -ForegroundColor Cyan
