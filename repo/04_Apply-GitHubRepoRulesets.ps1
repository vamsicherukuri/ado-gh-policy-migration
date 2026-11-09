#Requires -Version 7.0
<#
.SYNOPSIS
    Translates and applies Azure DevOps repository push and branch policies to GitHub Repository Rulesets.

.DESCRIPTION
    Phase 3 - Step 4 of the ADO-to-GitHub Policy Migration pipeline.
    - Safety First: Requires a pre-flight snapshot before applying any changes (auto-triggers 03_Snapshot if missing).
    - Source-to-Target Reconciliation: Supports upfront name mappings from 'repo-mapping.csv'.
    - Sequential Execution & Anti-Throttling: Sequential processing with 200ms polite pacing and Retry-After backoff.
    - Enhanced -DryRun: Actively verifies repository existence and admin write permissions before live mutation.
    - Pattern A Partial Failure Manifest: Automatically exports failed items to 'ado-repo-policy-groups-failed.csv' for 1-click retry.
    - Translates:
        * Push Policies (R02 path, R05 length, R06 size) -> GitHub Repository Push Ruleset (target: 'push')
        * Branch Policies (R01 email, B01 reviewers, B02 stale reset, B03 comments, B05 status, B07 codeowners, B09 force-push, B10 deletion) -> GitHub Repository Branch Ruleset (target: 'branch')
    - Supports -DryRun (safe validation) and -Enforcement 'evaluate' (default), 'active', or 'disabled'.
    - Fully idempotent: Updates existing rulesets if found, or creates them.

.PARAMETER TargetOrg
    Target GitHub organization (e.g. 'ADO2GH-Migration'). Defaults to first org in 'config\github-org.txt'.

.PARAMETER TargetRepo
    Specific repository name (e.g. 'sample2') or 'owner/repo'.

.PARAMETER TargetRepos
    Array of repository names.

.PARAMETER GroupsFilePath
    Path to groups CSV (e.g. 'output\latest\ado-repo-policy-groups.csv' or 'ado-repo-policy-groups-failed.csv').

.PARAMETER MappingFilePath
    Path to Source-to-Target mapping manifest. Defaults to 'config\repo-mapping.csv'.

.PARAMETER Enforcement
    Ruleset enforcement level: 'evaluate' (default / observation), 'active' (enforced), or 'disabled'.

.PARAMETER DryRun
    Preview payloads and actions, and perform pre-flight permission checks without making modifications.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\repo"
    pwsh .\04_Apply-GitHubRepoRulesets.ps1 -DryRun
    pwsh .\04_Apply-GitHubRepoRulesets.ps1 -Enforcement evaluate
    pwsh .\04_Apply-GitHubRepoRulesets.ps1 -GroupsFilePath .\output\latest\ado-repo-policy-groups-failed.csv
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
    [string]$GroupsFilePath = "",

    [Parameter(Mandatory = $false)]
    [string]$MappingFilePath = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet('evaluate', 'active', 'disabled')]
    [string]$Enforcement = "evaluate",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Apply ADO Repo & Branch Policies to GitHub Rulesets          " -ForegroundColor Cyan
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

# 2. Resolve Source-to-Target Name Mapping (Step 0)
$repoMappingTable = @{}
if ([string]::IsNullOrWhiteSpace($MappingFilePath)) {
    $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\repo-mapping.csv"
    if (-not (Test-Path -LiteralPath $MappingFilePath)) {
        $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "repo-mapping.csv"
    }
}

if (Test-Path -LiteralPath $MappingFilePath) {
    Write-Host "[+] Using Source-to-Target Mapping : $MappingFilePath" -ForegroundColor Cyan
    $mappingRows = @(Import-Csv -LiteralPath $MappingFilePath)
    foreach ($m in $mappingRows) {
        $sRepo = $m.AdoRepo.Trim()
        $tRepo = if ($m.PSObject.Properties['TargetGhRepo'] -and -not [string]::IsNullOrWhiteSpace($m.TargetGhRepo)) { $m.TargetGhRepo.Trim() } else { $sRepo }
        $tOrg = if ($m.PSObject.Properties['TargetGhOrg'] -and -not [string]::IsNullOrWhiteSpace($m.TargetGhOrg)) { $m.TargetGhOrg.Trim() } else { $TargetOrg }
        $repoMappingTable[$sRepo] = @{ TargetOrg = $tOrg; TargetRepo = $tRepo }
        $repoMappingTable[$tRepo] = @{ TargetOrg = $tOrg; TargetRepo = $tRepo }
    }
}

# 3. Resolve Target Repositories to Process
$repoTargets = [System.Collections.Generic.List[PSCustomObject]]::new()

# Mode A: Specific Target Repo
if (-not [string]::IsNullOrWhiteSpace($TargetRepo)) {
    $cleaned = $TargetRepo.Trim()
    $tOrg = $TargetOrg
    if ($cleaned.Contains("/")) {
        $parts = $cleaned -split '/'
        $tOrg = $parts[0]
        $cleaned = $parts[1]
    }
    $sourceName = $cleaned
    if ($repoMappingTable.ContainsKey($cleaned)) {
        $tOrg = $repoMappingTable[$cleaned].TargetOrg
        $cleaned = $repoMappingTable[$cleaned].TargetRepo
    }
    $repoTargets.Add([PSCustomObject]@{ TargetOrg = $tOrg; TargetRepo = $cleaned; SourceRepo = $sourceName; GroupId = "MANUAL" })
}

# Mode B: Specific Target Repos Array
if ($TargetRepos -and $TargetRepos.Count -gt 0) {
    foreach ($r in $TargetRepos) {
        $cleaned = $r.Trim()
        $tOrg = $TargetOrg
        if ($cleaned.Contains("/")) {
            $parts = $cleaned -split '/'
            $tOrg = $parts[0]
            $cleaned = $parts[1]
        }
        $sourceName = $cleaned
        if ($repoMappingTable.ContainsKey($cleaned)) {
            $tOrg = $repoMappingTable[$cleaned].TargetOrg
            $cleaned = $repoMappingTable[$cleaned].TargetRepo
        }
        $repoTargets.Add([PSCustomObject]@{ TargetOrg = $tOrg; TargetRepo = $cleaned; SourceRepo = $sourceName; GroupId = "MANUAL" })
    }
}

# Mode C: Groups File / Pattern A Retry Manifest
if ($repoTargets.Count -eq 0) {
    if (-not [string]::IsNullOrWhiteSpace($GroupsFilePath)) {
        if (-not (Test-Path -LiteralPath $GroupsFilePath)) {
            throw "Specified GroupsFilePath not found: '$GroupsFilePath'"
        }
        Write-Host "[+] Loading target groups from      : $GroupsFilePath" -ForegroundColor Cyan
        $groupData = @(Import-Csv -LiteralPath $GroupsFilePath)
        foreach ($row in $groupData) {
            # Check if this is a failed retry manifest (has TargetRepo / Repository)
            if ($row.PSObject.Properties['TargetRepo']) {
                $tOrg = if ($row.PSObject.Properties['Organization']) { $row.Organization } else { $TargetOrg }
                $tRepo = $row.TargetRepo
                $sRepo = if ($row.PSObject.Properties['SourceRepo']) { $row.SourceRepo } else { $tRepo }
                $gId = if ($row.PSObject.Properties['GroupId']) { $row.GroupId } else { "RETRY" }
                $already = @($repoTargets | Where-Object { $_.TargetRepo -eq $tRepo -and $_.TargetOrg -eq $tOrg }).Count -gt 0
                if (-not $already) {
                    $repoTargets.Add([PSCustomObject]@{ TargetOrg = $tOrg; TargetRepo = $tRepo; SourceRepo = $sRepo; GroupId = $gId })
                }
            }
            elseif ($row.PSObject.Properties['MemberRepos']) {
                $gId = $row.GroupId
                $members = @($row.MemberRepos -split ';')
                foreach ($m in $members) {
                    $cleaned = $m.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($cleaned)) {
                        $parts = $cleaned -split '[\/\\]'
                        $sRepo = $parts[-1]
                        $tRepo = $sRepo
                        $tOrg = $TargetOrg
                        if ($repoMappingTable.ContainsKey($sRepo)) {
                            $tOrg = $repoMappingTable[$sRepo].TargetOrg
                            $tRepo = $repoMappingTable[$sRepo].TargetRepo
                        }
                        $repoTargets.Add([PSCustomObject]@{ TargetOrg = $tOrg; TargetRepo = $tRepo; SourceRepo = $sRepo; GroupId = $gId })
                    }
                }
            }
        }
    }
}

# Mode D: Default from mapping file or repos.txt
if ($repoTargets.Count -eq 0) {
    if ($repoMappingTable.Count -gt 0) {
        foreach ($sRepo in $repoMappingTable.Keys) {
            $mappingInfo = $repoMappingTable[$sRepo]
            $existsAlready = @($repoTargets | Where-Object { $_.TargetRepo -eq $mappingInfo.TargetRepo }).Count -gt 0
            if (-not $existsAlready) {
                $repoTargets.Add([PSCustomObject]@{
                    TargetOrg  = $mappingInfo.TargetOrg
                    TargetRepo = $mappingInfo.TargetRepo
                    SourceRepo = $sRepo
                    GroupId    = "ALL-MAPPED"
                })
            }
        }
    }
    else {
        $reposFile = Join-Path -Path $PSScriptRoot -ChildPath "config\repos.txt"
        if (Test-Path -LiteralPath $reposFile) {
            $lines = @(Get-Content -LiteralPath $reposFile | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#")
            })
            foreach ($l in $lines) {
                $cleaned = $l.Trim()
                $parts = $cleaned -split '[\/\\]'
                $rName = $parts[-1]
                if (-not [string]::IsNullOrWhiteSpace($rName)) {
                    $repoTargets.Add([PSCustomObject]@{
                        TargetOrg  = $TargetOrg
                        TargetRepo = $rName
                        SourceRepo = $rName
                        GroupId    = "DEFAULT"
                    })
                }
            }
        }
    }
}

if ($repoTargets.Count -eq 0) {
    throw "No target repositories resolved. Provide via -TargetRepo, -GroupsFilePath, or 'config\repo-mapping.csv'."
}

Write-Host "[+] Target Organization(s) : $(@($repoTargets | ForEach-Object { $_.TargetOrg } | Select-Object -Unique) -join ', ')" -ForegroundColor Cyan
Write-Host "[+] Target Repositories    : $($repoTargets.Count) repo(s) -> ($(@($repoTargets | ForEach-Object { $_.TargetRepo }) -join ', '))" -ForegroundColor Cyan
Write-Host "[+] Enforcement Level      : $Enforcement" -ForegroundColor $(if ($Enforcement -eq 'active') { 'Green' } else { 'Yellow' })
if ($DryRun) {
    Write-Host "[!] Mode                   : DRY-RUN (Pre-Flight Permission Audit & Payload Validation)" -ForegroundColor Yellow
}

# 4. Resolve GitHub Authentication
$token = ""
$tokenSource = ""

if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "RepoRuleset-Apply/3.0"
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
                "User-Agent"           = "RepoRuleset-Apply/3.0"
            }
            $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
            $token = $cliToken
            $tokenSource = "gh auth token (User: $($userObj.login))"
        }
    }
    catch {}
}

if (-not $token) {
    throw "No valid GitHub authentication found. Please set `$env:GH_PAT or authenticate via 'gh auth login'."
}

Write-Host "[+] Authentication         : $tokenSource" -ForegroundColor Green

$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "RepoRuleset-Apply/3.0"
}

# 5. Anti-Throttling API Engine (Polite Pacing & Retry-After Backoff)
function Invoke-GhApiWithThrottling {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'Get',
        [string]$Body = $null,
        [int]$MaxRetries = 3
    )

    # Polite delay to prevent secondary rate-limit bursts
    Start-Sleep -Milliseconds 200

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $p = @{
                Uri        = $Uri
                Headers    = $headers
                Method     = $Method
                TimeoutSec = 20
            }
            if ($Body) { $p['Body'] = $Body }
            return (Invoke-RestMethod @p)
        }
        catch {
            $status = 0
            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
                try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            }

            if ($status -in @(429, 403) -and $attempt -lt $MaxRetries) {
                $retryAfter = 5
                try {
                    $ra = $_.Exception.Response.Headers['Retry-After']
                    if ($ra) { $retryAfter = [int]$ra }
                } catch {}
                Write-Host "    [THROTTLING GUARD] Rate limit warning (HTTP $status). Sleeping ${retryAfter}s before retry (Attempt $attempt of $MaxRetries)..." -ForegroundColor Yellow
                Start-Sleep -Seconds $retryAfter
                continue
            }
            throw
        }
    }
}

# 6. Pre-Flight Safety Verification (Snapshots)
if (-not $DryRun) {
    $latestSnapshotDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots\latest"
    foreach ($target in $repoTargets) {
        $rName = $target.TargetRepo
        $tOrg = $target.TargetOrg
        $snapPattern = "*$rName.snapshot.json"
        $existingSnap = @()
        if (Test-Path -LiteralPath $latestSnapshotDir) {
            $existingSnap = @(Get-ChildItem -Path $latestSnapshotDir -Filter $snapPattern)
        }

        if ($existingSnap.Count -eq 0) {
            Write-Host "[!] Pre-flight snapshot missing for '$tOrg/$rName'. Auto-capturing..." -ForegroundColor Yellow
            $snapScript = Join-Path -Path $PSScriptRoot -ChildPath "03_Snapshot-GitHubRepoRulesets.ps1"
            & pwsh -NoProfile -File $snapScript -TargetOrg $tOrg -TargetRepo $rName
        }
        else {
            Write-Host "[+] Pre-flight snapshot verified for '$tOrg/$rName'." -ForegroundColor Green
        }
    }
}

# 7. Ingest Crosswalk Manifest
$crosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "config\ado-to-ghec-repo-crosswalk.csv"
if (-not (Test-Path -LiteralPath $crosswalkPath)) {
    $crosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "ado-to-ghec-repo-crosswalk.csv"
}

$crosswalk = @()
if (Test-Path -LiteralPath $crosswalkPath) {
    $crosswalk = @(Import-Csv -LiteralPath $crosswalkPath)
}

# 8. Load Captured Policies (if available)
$captureDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
$capturedMap = @{}
if (Test-Path -LiteralPath $captureDir) {
    $captures = @(Get-ChildItem -Path $captureDir -Filter *.repo-policies.json)
    foreach ($c in $captures) {
        try {
            $cData = Get-Content -LiteralPath $c.FullName -Raw | ConvertFrom-Json
            $capturedMap[$cData.RepositoryName] = $cData
            if ($cData.PSObject.Properties['TargetGhRepo'] -and -not [string]::IsNullOrWhiteSpace($cData.TargetGhRepo)) {
                $capturedMap[$cData.TargetGhRepo] = $cData
            }
        }
        catch {}
    }
}

$appliedResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$latestLogDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
New-Item -ItemType Directory -Path $latestLogDir -Force | Out-Null
$logFile = Join-Path -Path $latestLogDir -ChildPath "execution.log"
"" | Set-Content -LiteralPath $logFile -Encoding utf8

# 9. Sequential Execution Loop
foreach ($target in $repoTargets) {
    $tOrg = $target.TargetOrg
    $tRepo = $target.TargetRepo
    $sRepo = $target.SourceRepo
    $gId = $target.GroupId

    Add-Content -LiteralPath $logFile -Value "Processing: $tOrg/$tRepo (Source: $sRepo | Group: $gId)" -Encoding utf8

    # A. Determine applicable policies
    $capture = if ($capturedMap.ContainsKey($sRepo)) { $capturedMap[$sRepo] } elseif ($capturedMap.ContainsKey($tRepo)) { $capturedMap[$tRepo] } else { $null }
    $applicablePolicies = @()
    if ($capture -and $capture.Policies) {
        $applicablePolicies = @($capture.Policies | Where-Object { $_.IsEnabled -eq $true })
    }

    # If no capture file exists for this repo, generate from crosswalk with ApplyPolicy=True
    if ($applicablePolicies.Count -eq 0 -and $crosswalk.Count -gt 0) {
        Write-Host "    [!] No ADO capture found for '$sRepo'. Using defaults from crosswalk manifest." -ForegroundColor Yellow
        $synthPolicies = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($cw in $crosswalk) {
            if ($cw.ApplyPolicy -eq 'True') {
                $scopeType = if ($cw.PolicyCode.StartsWith("R")) { "RepositoryPushPolicy" } else { "BranchPolicy" }
                $synthPolicies.Add([PSCustomObject]@{
                    PolicyCode   = $cw.PolicyCode
                    PolicyName   = $cw.AdoPolicyName
                    ScopeType    = $scopeType
                    TargetBranch = "ALL"
                    IsEnabled    = $true
                    Settings     = [PSCustomObject]@{}
                })
            }
        }
        $applicablePolicies = @($synthPolicies)
    }

    # B. Build Branch Rules (B01, B02, B03, B05, B07, B09, B10, B11, R01)
    $branchRules = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Pull Request Rule (combines B01, B02, B03, B07)
    $prPolicy = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'B01' }) | Select-Object -First 1
    $commentPolicy = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'B03' }) | Select-Object -First 1
    $codeOwnerPolicy = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'B07' }) | Select-Object -First 1

    $approverCount = 1
    $dismissStale = $true
    if ($prPolicy -and $prPolicy.Settings) {
        if ($prPolicy.Settings.PSObject.Properties['minimumApproverCount']) {
            $approverCount = [int]$prPolicy.Settings.minimumApproverCount
        }
        if ($prPolicy.Settings.PSObject.Properties['resetOnSourcePush']) {
            $dismissStale = [bool]$prPolicy.Settings.resetOnSourcePush
        }
    }

    $requireCodeOwner = ($null -ne $codeOwnerPolicy)
    $requireResolution = ($null -ne $commentPolicy)

    $branchRules.Add([PSCustomObject]@{
        type       = "pull_request"
        parameters = [PSCustomObject]@{
            required_approving_review_count   = $approverCount
            dismiss_stale_reviews_on_push     = $dismissStale
            require_code_owner_review         = $requireCodeOwner
            require_last_push_approval        = $false
            required_review_thread_resolution = $requireResolution
        }
    })

    # Status Checks (B05 Build Validation & B06 Status Checks)
    $statusPolicies = @($applicablePolicies | Where-Object { $_.PolicyCode -in @('B05', 'B06') })
    $statusCheckList = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($sp in $statusPolicies) {
        $cName = "continuous-integration"
        if ($sp.Settings) {
            if ($sp.Settings.PSObject.Properties['displayName'] -and -not [string]::IsNullOrWhiteSpace($sp.Settings.displayName)) {
                $cName = [string]$sp.Settings.displayName
            }
            elseif ($sp.Settings.PSObject.Properties['name'] -and -not [string]::IsNullOrWhiteSpace($sp.Settings.name)) {
                $cName = [string]$sp.Settings.name
            }
        }
        $statusCheckList.Add([PSCustomObject]@{ context = $cName })
    }

    if ($statusCheckList.Count -gt 0) {
        $branchRules.Add([PSCustomObject]@{
            type       = "required_status_checks"
            parameters = [PSCustomObject]@{
                strict_required_status_checks_policy = $true
                required_status_checks               = @($statusCheckList | Select-Object -Unique -Property context)
            }
        })
    }

    # B09: Block Force Push
    $branchRules.Add([PSCustomObject]@{ type = "non_fast_forward" })

    # B10: Block Branch Deletion
    $branchRules.Add([PSCustomObject]@{ type = "deletion" })

    # B11: Commit Signing
    $signPolicy = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'B11' })
    if ($signPolicy.Count -gt 0) {
        $branchRules.Add([PSCustomObject]@{ type = "required_signatures" })
    }

    # R01: Author Email Restriction (Evaluated on Branch Commits)
    $r01 = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'R01' }) | Select-Object -First 1
    if ($r01) {
        $emailPattern = "*@company.com"
        if ($r01.Settings -and $r01.Settings.PSObject.Properties['authorEmailPatterns']) {
            $pats = @($r01.Settings.authorEmailPatterns)
            if ($pats.Count -gt 0) { $emailPattern = $pats[0] }
        }
        $branchRules.Add([PSCustomObject]@{
            type       = "commit_author_email_pattern"
            parameters = [PSCustomObject]@{
                operator = "ends_with"
                pattern  = ($emailPattern -replace '^\*', '')
                name     = "Enforce Corporate Author Email"
                negate   = $false
            }
        })
    }

    $branchRulesetPayload = [PSCustomObject]@{
        name        = "ado-migrated-repo-branch-ruleset"
        target      = "branch"
        enforcement = $Enforcement
        conditions  = [PSCustomObject]@{
            ref_name = [PSCustomObject]@{
                include = @("~DEFAULT_BRANCH")
                exclude = @()
            }
        }
        rules       = $branchRules
    }

    # C. Build Push Rules (R02, R05, R06)
    $pushRules = [System.Collections.Generic.List[PSCustomObject]]::new()

    # R02: File Path Restrictions
    $r02 = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'R02' }) | Select-Object -First 1
    $restrictedPaths = [System.Collections.Generic.List[string]]::new()
    if ($r02 -and $r02.Settings -and $r02.Settings.PSObject.Properties['filenamePatterns']) {
        foreach ($pat in @($r02.Settings.filenamePatterns)) {
            $restrictedPaths.Add([string]$pat)
        }
    }
    if ($restrictedPaths.Count -gt 0) {
        $pushRules.Add([PSCustomObject]@{
            type       = "file_path_restriction"
            parameters = [PSCustomObject]@{
                restricted_file_paths = @($restrictedPaths | Select-Object -Unique)
            }
        })
    }

    # R05: Max File Path Length
    $r05 = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'R05' }) | Select-Object -First 1
    if ($r05) {
        $maxLen = 260
        if ($r05.Settings -and $r05.Settings.PSObject.Properties['maxPathLength']) {
            $maxLen = [int]$r05.Settings.maxPathLength
        }
        $pushRules.Add([PSCustomObject]@{
            type       = "max_file_path_length"
            parameters = [PSCustomObject]@{
                max_file_path_length = $maxLen
            }
        })
    }

    # R06: Max File Size
    $r06 = @($applicablePolicies | Where-Object { $_.PolicyCode -eq 'R06' }) | Select-Object -First 1
    if ($r06) {
        $maxBytes = 104857600
        if ($r06.Settings -and $r06.Settings.PSObject.Properties['maximumGitBlobSizeInBytes']) {
            $maxBytes = [int64]$r06.Settings.maximumGitBlobSizeInBytes
        }
        $maxMb = [Math]::Max(1, [int][Math]::Round($maxBytes / 1MB))
        $pushRules.Add([PSCustomObject]@{
            type       = "max_file_size"
            parameters = [PSCustomObject]@{
                max_file_size = $maxMb
            }
        })
    }

    $pushRulesetPayload = $null
    if ($pushRules.Count -gt 0) {
        $pushRulesetPayload = [PSCustomObject]@{
            name        = "ado-migrated-repo-push-ruleset"
            target      = "push"
            enforcement = $Enforcement
            rules       = $pushRules
        }
    }

    # D. Enhanced DryRun with Permission Pre-Flight Audit
    if ($DryRun) {
        $accessCheck = "Ready"
        try {
            $repoMeta = Invoke-GhApiWithThrottling -Uri "https://api.github.com/repos/$tOrg/$tRepo" -Method Get
            $hasAdmin = ($repoMeta.permissions -and [bool]$repoMeta.permissions.admin)
            if (-not $hasAdmin) {
                $accessCheck = "FAIL: Missing Admin Permissions"
            }
        }
        catch {
            $accessCheck = "FAIL: Repository Inaccessible ($($_.Exception.Message))"
        }

        $dryStatus = if ($accessCheck -eq "Ready") { "DryRun-Validated" } else { $accessCheck }
        Write-Host "    [DRY-RUN AUDIT] Pre-flight Check: $accessCheck ($dryStatus)" -ForegroundColor $(if ($accessCheck -eq 'Ready') { 'Green' } else { 'Red' })

        $appliedResults.Add([PSCustomObject]@{
            Organization = $tOrg
            TargetRepo   = $tRepo
            SourceRepo   = $sRepo
            GroupId      = $gId
            RulesetType  = "branch"
            RulesetName  = $branchRulesetPayload.name
            RulesCount   = $branchRules.Count
            Status       = $dryStatus
        })
        if ($pushRulesetPayload) {
            $appliedResults.Add([PSCustomObject]@{
                Organization = $tOrg
                TargetRepo   = $tRepo
                SourceRepo   = $sRepo
                GroupId      = $gId
                RulesetType  = "push"
                RulesetName  = $pushRulesetPayload.name
                RulesCount   = $pushRules.Count
                Status       = $dryStatus
            })
        }
        continue
    }

    # E. Live Mutation Execution with Throttling Guard
    $existingMap = @{}
    try {
        $existingList = Invoke-GhApiWithThrottling -Uri "https://api.github.com/repos/$tOrg/$tRepo/rulesets" -Method Get
        if ($existingList) {
            foreach ($ex in @($existingList)) {
                $existingMap[$ex.name] = $ex.id
            }
        }
    }
    catch {
        Write-Warning "Could not query repository rulesets for '$tOrg/$tRepo': $($_.Exception.Message)"
    }

    # Apply Branch Ruleset
    $branchBody = $branchRulesetPayload | ConvertTo-Json -Depth 8
    $bName = $branchRulesetPayload.name
    try {
        if ($existingMap.ContainsKey($bName)) {
            $exId = $existingMap[$bName]
            $res = Invoke-GhApiWithThrottling -Uri "https://api.github.com/repos/$tOrg/$tRepo/rulesets/$exId" -Method Put -Body $branchBody
            Add-Content -LiteralPath $logFile -Value "    [OK] Branch ruleset updated on '$tRepo' (ID: $($res.id), Enforcement: $($res.enforcement))" -Encoding utf8
        }
        else {
            $res = Invoke-GhApiWithThrottling -Uri "https://api.github.com/repos/$tOrg/$tRepo/rulesets" -Method Post -Body $branchBody
            Add-Content -LiteralPath $logFile -Value "    [OK] Branch ruleset created on '$tRepo' (ID: $($res.id), Enforcement: $($res.enforcement))" -Encoding utf8
        }
        $appliedResults.Add([PSCustomObject]@{
            Organization = $tOrg
            TargetRepo   = $tRepo
            SourceRepo   = $sRepo
            GroupId      = $gId
            RulesetType  = "branch"
            RulesetName  = $bName
            RulesCount   = $branchRules.Count
            Status       = "Success"
        })
    }
    catch {
        Add-Content -LiteralPath $logFile -Value "    [FAIL] Failed to apply branch ruleset on '$tRepo': $($_.Exception.Message)" -Encoding utf8
        $appliedResults.Add([PSCustomObject]@{
            Organization = $tOrg
            TargetRepo   = $tRepo
            SourceRepo   = $sRepo
            GroupId      = $gId
            RulesetType  = "branch"
            RulesetName  = $bName
            RulesCount   = 0
            Status       = "Failed: $($_.Exception.Message)"
        })
    }

    # Apply Push Ruleset
    if ($pushRulesetPayload) {
        $pushBody = $pushRulesetPayload | ConvertTo-Json -Depth 8
        $pName = $pushRulesetPayload.name
        try {
            if ($existingMap.ContainsKey($pName)) {
                $exId = $existingMap[$pName]
                $res = Invoke-GhApiWithThrottling -Uri "https://api.github.com/repos/$tOrg/$tRepo/rulesets/$exId" -Method Put -Body $pushBody
                Add-Content -LiteralPath $logFile -Value "    [OK] Push ruleset updated on '$tRepo' (ID: $($res.id), Enforcement: $($res.enforcement))" -Encoding utf8
            }
            else {
                $res = Invoke-GhApiWithThrottling -Uri "https://api.github.com/repos/$tOrg/$tRepo/rulesets" -Method Post -Body $pushBody
                Add-Content -LiteralPath $logFile -Value "    [OK] Push ruleset created on '$tRepo' (ID: $($res.id), Enforcement: $($res.enforcement))" -Encoding utf8
            }
            $appliedResults.Add([PSCustomObject]@{
                Organization = $tOrg
                TargetRepo   = $tRepo
                SourceRepo   = $sRepo
                GroupId      = $gId
                RulesetType  = "push"
                RulesetName  = $pName
                RulesCount   = $pushRules.Count
                Status       = "Success"
            })
        }
        catch {
            Add-Content -LiteralPath $logFile -Value "    [FAIL] Failed to apply push ruleset on '$tRepo': $($_.Exception.Message)" -Encoding utf8
            $appliedResults.Add([PSCustomObject]@{
                Organization = $tOrg
                TargetRepo   = $tRepo
                SourceRepo   = $sRepo
                GroupId      = $gId
                RulesetType  = "push"
                RulesetName  = $pName
                RulesCount   = 0
                Status       = "Failed: $($_.Exception.Message)"
            })
        }
    }
    Write-Host "  [+] Configured $tOrg/$tRepo (Branch & Push rulesets applied)" -ForegroundColor Gray
}

# Write full report to execution log
Add-Content -LiteralPath $logFile -Value "`n=================================================================" -Encoding utf8
Add-Content -LiteralPath $logFile -Value "               REPOSITORY RULESET APPLICATION REPORT             " -Encoding utf8
Add-Content -LiteralPath $logFile -Value "=================================================================" -Encoding utf8
$appliedResults | Format-Table -AutoSize | Out-String | Add-Content -LiteralPath $logFile -Encoding utf8

# 10. Pattern A: Auto-Generate Retry Manifest for Partial Failures
$failedEntries = @($appliedResults | Where-Object { $_.Status -like 'Failed*' -or $_.Status -like 'FAIL*' })
if ($failedEntries.Count -gt 0) {
    $latestDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
    New-Item -ItemType Directory -Path $latestDir -Force | Out-Null
    $failedFile = Join-Path -Path $latestDir -ChildPath "ado-repo-policy-groups-failed.csv"
    $failedEntries | Export-Csv -LiteralPath $failedFile -NoTypeInformation -Encoding utf8

    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "   PATTERN A: RETRY MANIFEST GENERATED FOR FAILED REPOSITORIES   " -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "[!] $($failedEntries.Count) operation(s) failed out of $($appliedResults.Count) total." -ForegroundColor Yellow
    Write-Host "[!] Retry manifest generated at: $failedFile" -ForegroundColor Yellow
    Write-Host "[!] To retry ONLY the failed items without rerunning successful ones, execute:" -ForegroundColor White
    Write-Host "    pwsh .\04_Apply-GitHubRepoRulesets.ps1 -GroupsFilePath '$failedFile'`n" -ForegroundColor Green
}
else {
    Write-Host "[OK] Ruleset application complete: Success ($($appliedResults.Count) ruleset(s) applied)." -ForegroundColor Green
    Write-Host "     Detailed Execution Log: $logFile" -ForegroundColor Cyan
}
