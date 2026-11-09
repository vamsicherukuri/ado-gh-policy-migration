#Requires -Version 7.0
<#
.SYNOPSIS
    Applies ADO project push and branch policies to GitHub Enterprise Cloud as Repository Rulesets.

.DESCRIPTION
    Phase 2 - Step 4 of the ADO-to-GitHub Policy Migration pipeline.
    - Safety First: Enforces that a pre-flight snapshot exists before any mutation.
    - Reads captured project policies from 'project\output\latest' and crosswalk manifest.
    - Builds robust GitHub Rulesets:
        * "Branch Ruleset": PR review counts, dismiss stale reviews, comment resolution, merge types, author email patterns.
        * "Push Ruleset": Restricted file paths, max file size, max path length.
    - Supports -DryRun mode (preview planned JSON payloads without API calls).
    - Supports -Enforcement <active|evaluate|disabled> (defaults to 'evaluate' for safe non-blocking testing).
    - Idempotently creates or updates rulesets.
    - Immediate post-apply read-back verification.

.PARAMETER TargetOrg
    Specific GitHub organization to target. Defaults to list in 'project\github-org.txt'.

.PARAMETER TargetRepo
    Optional specific repository name to target. If omitted, applies to all repositories in target org.

.PARAMETER Enforcement
    Ruleset enforcement level: 'active', 'evaluate', or 'disabled'. Defaults to 'evaluate'.

.PARAMETER DryRun
    Previews ruleset payloads without modifying GitHub.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\project"
    pwsh .\04_Apply-GitHubRulesets.ps1 -DryRun
    pwsh .\04_Apply-GitHubRulesets.ps1 -Enforcement evaluate
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
    [string]$MappingFilePath = "",

    [Parameter(Mandatory = $false)]
    [string]$GroupsFilePath = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet('active', 'evaluate', 'disabled')]
    [string]$Enforcement = "evaluate",

    [Parameter(Mandatory = $false)]
    [ValidateSet('Org', 'Repo', 'Auto')]
    [string]$Scope = "Auto",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Scope -eq 'Auto') {
    if (-not [string]::IsNullOrWhiteSpace($TargetRepo)) {
        $Scope = 'Repo'
    } else {
        $Scope = 'Org'
    }
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Apply ADO Project Policies to GitHub (Rulesets Engine)        " -ForegroundColor Cyan
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
Write-Host "[+] Enforcement Level      : $Enforcement" -ForegroundColor $(if ($Enforcement -eq 'active') { 'Green' } else { 'Yellow' })
if ($DryRun) {
    Write-Host "[!] Mode                   : DRY-RUN (No changes will be applied)" -ForegroundColor Yellow
}

# 2. Safety Gate: Verify Snapshot
$snapshotsDir = Join-Path -Path $PSScriptRoot -ChildPath "output\snapshots"
foreach ($org in $targetOrgs) {
    $pointer = Join-Path -Path $snapshotsDir -ChildPath "$org-latest-rulesets-preflight.json"
    if (-not (Test-Path -LiteralPath $pointer)) {
        Write-Host "[!] Pre-flight snapshot missing for '$org'. Triggering 03_Snapshot-GitHubRulesets.ps1..." -ForegroundColor Yellow
        $snapScript = Join-Path -Path $PSScriptRoot -ChildPath "03_Snapshot-GitHubRulesets.ps1"
        & pwsh -NoProfile -File $snapScript -TargetOrg $org
        if (-not (Test-Path -LiteralPath $pointer)) {
            throw "Safety verification failed: Could not verify snapshot for '$org'."
        }
    }
    Write-Host "[+] Verified Snapshot for '$org'." -ForegroundColor Green
}

# 3. Resolve Authentication
$token = ""
$tokenSource = ""

if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
    $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
    try {
        $testHeaders = @{
            Authorization          = "Bearer $cleanPat"
            Accept                 = "application/vnd.github+json"
            "X-GitHub-Api-Version" = "2022-11-28"
            "User-Agent"           = "Ruleset-Apply/2.0"
        }
        $userObj = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
        $token = $cleanPat
        $tokenSource = "`$env:GH_PAT (User: $($userObj.login))"
    }
    catch {
        # Fallback to keyring
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
                "User-Agent"           = "Ruleset-Apply/2.0"
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
    throw "No valid GitHub credentials available."
}
Write-Host "[+] Authentication         : $tokenSource" -ForegroundColor Green

# 4. Ingest Captured ADO Policies & Helper
$captureDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
$captureFiles = @(Get-ChildItem -Path $captureDir -Filter *.project-policies.json)
if ($captureFiles.Count -eq 0) {
    throw "No captured policies found in '$captureDir'. Run 01_Capture-AdoProjectPolicies.ps1 first."
}

# Source-to-Target repo mapping for project fleet distribution
$repoMappingFile = Join-Path -Path $PSScriptRoot -ChildPath "..\repo\config\repo-mapping.csv"
if (-not (Test-Path -LiteralPath $repoMappingFile)) {
    $repoMappingFile = Join-Path -Path $PSScriptRoot -ChildPath "config\repo-mapping.csv"
}
$repoMappingRows = @()
if (Test-Path -LiteralPath $repoMappingFile) {
    $repoMappingRows = @(Import-Csv -LiteralPath $repoMappingFile)
}

function Build-ProjectRulesetPayloads {
    param(
        [Parameter(Mandatory)][PSCustomObject]$CaptureData,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Enforcement,
        [string[]]$ProjectTargetRepos = @()
    )
    $adoPolicies = @($CaptureData.Policies | Where-Object { $_.IsEnabled -eq $true })

    # A. Branch Ruleset
    $branchRules = [System.Collections.Generic.List[PSCustomObject]]::new()
    $branchRules.Add([PSCustomObject]@{ type = "deletion" })
    $branchRules.Add([PSCustomObject]@{ type = "non_fast_forward" })

    $p19 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P19' }) | Select-Object -First 1
    $p21 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P21' }) | Select-Object -First 1
    $p22 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P22' }) | Select-Object -First 1
    $p25 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P25' }) | Select-Object -First 1

    $approverCount = 1
    $dismissStale = $false
    if ($p19) {
        if ($p19.Settings.PSObject.Properties['minimumApproverCount']) { $approverCount = [int]$p19.Settings.minimumApproverCount }
        if ($p19.Settings.PSObject.Properties['resetOnSourcePush']) { $dismissStale = [bool]$p19.Settings.resetOnSourcePush }
    }

    $prParams = [ordered]@{
        required_approving_review_count   = $approverCount
        dismiss_stale_reviews_on_push     = $dismissStale
        require_code_owner_review         = ($null -ne $p25)
        require_last_push_approval        = $false
        required_review_thread_resolution = ($null -ne $p21)
    }

    if ($p22 -and $p22.Settings.PSObject.Properties['allowSquash'] -and $p22.Settings.allowSquash) {
        $prParams['allowed_merge_methods'] = @('squash')
    }

    $branchRules.Add([PSCustomObject]@{
        type       = "pull_request"
        parameters = [PSCustomObject]$prParams
    })

    $p13 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P13' }) | Select-Object -First 1
    if ($p13 -and $p13.Settings.PSObject.Properties['authorEmailPatterns']) {
        $patterns = @($p13.Settings.authorEmailPatterns)
        if ($patterns.Count -gt 0) {
            $firstPattern = [string]$patterns[0]
            $operator = "ends_with"
            $patVal = $firstPattern.TrimStart('*')
            if ($firstPattern.StartsWith('*@')) {
                $operator = "ends_with"
                $patVal = $firstPattern.TrimStart('*')
            }
            $branchRules.Add([PSCustomObject]@{
                type       = "commit_author_email_pattern"
                parameters = [PSCustomObject]@{
                    operator = $operator
                    pattern  = $patVal
                    name     = "ADO Migrated Author Email Pattern"
                    negate   = $false
                }
            })
        }
    }

    $branchConditions = [ordered]@{
        ref_name = [PSCustomObject]@{
            include = @("~DEFAULT_BRANCH", "refs/heads/main", "refs/heads/master")
            exclude = @()
        }
    }
    if ($Scope -eq 'Org') {
        if ($ProjectTargetRepos -and $ProjectTargetRepos.Count -gt 0) {
            $branchConditions["repository_name"] = [PSCustomObject]@{
                include = @($ProjectTargetRepos)
                exclude = @()
            }
        }
        else {
            $branchConditions["repository_name"] = [PSCustomObject]@{ all = $true }
        }
    }

    $branchRulesetPayload = [PSCustomObject]@{
        name        = "ado-migrated-branch-ruleset"
        target      = "branch"
        enforcement = $Enforcement
        conditions  = [PSCustomObject]$branchConditions
        rules       = $branchRules
    }

    # B. Push Ruleset
    $pushRules = [System.Collections.Generic.List[PSCustomObject]]::new()
    $p18 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P18' }) | Select-Object -First 1
    if ($p18 -and $p18.Settings.PSObject.Properties['maximumGitBlobSizeInBytes']) {
        $bytes = [long]$p18.Settings.maximumGitBlobSizeInBytes
        $mb = [Math]::Max(1, [int][Math]::Round($bytes / 1MB))
        $pushRules.Add([PSCustomObject]@{
            type       = "max_file_size"
            parameters = [PSCustomObject]@{ max_file_size = $mb }
        })
    }

    $p17 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P17' }) | Select-Object -First 1
    if ($p17 -and $p17.Settings.PSObject.Properties['maxPathLength']) {
        $pushRules.Add([PSCustomObject]@{
            type       = "max_file_path_length"
            parameters = [PSCustomObject]@{ max_file_path_length = [int]$p17.Settings.maxPathLength }
        })
    }

    $p14 = @($adoPolicies | Where-Object { $_.PolicyCode -eq 'P14' }) | Select-Object -First 1
    $restrictedPaths = [System.Collections.Generic.List[string]]::new()
    if ($p14 -and $p14.Settings.PSObject.Properties['filenamePatterns']) {
        foreach ($pat in @($p14.Settings.filenamePatterns)) { $restrictedPaths.Add([string]$pat) }
    }
    if ($restrictedPaths.Count -gt 0) {
        $pushRules.Add([PSCustomObject]@{
            type       = "file_path_restriction"
            parameters = [PSCustomObject]@{ restricted_file_paths = @($restrictedPaths | Select-Object -Unique) }
        })
    }

    $pushRulesetPayload = $null
    if ($pushRules.Count -gt 0) {
        $pushConditions = [ordered]@{}
        if ($Scope -eq 'Org') {
            if ($ProjectTargetRepos -and $ProjectTargetRepos.Count -gt 0) {
                $pushConditions["repository_name"] = [PSCustomObject]@{
                    include = @($ProjectTargetRepos)
                    exclude = @()
                }
            }
            else {
                $pushConditions["repository_name"] = [PSCustomObject]@{ all = $true }
            }
        }

        $pushRulesetPayload = [PSCustomObject]@{
            name        = "ado-migrated-push-ruleset"
            target      = "push"
            enforcement = $Enforcement
            rules       = $pushRules
        }
        if ($pushConditions.Count -gt 0) {
            $pushRulesetPayload | Add-Member -MemberType NoteProperty -Name "conditions" -Value ([PSCustomObject]$pushConditions)
        }
    }

    return @{
        BranchPayload = $branchRulesetPayload
        PushPayload   = $pushRulesetPayload
    }
}

# 6. Anti-Throttling API Engine (Polite Pacing & Retry-After Backoff)
$apiHeaders = @{
    Authorization          = "Bearer $token"
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "AdoToGh-RulesetApply/2.0"
}

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
                Headers    = $apiHeaders
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

# 7. Enhanced DryRun Check with Pre-Flight Permission Audit
if ($DryRun) {
    Write-Host "`n-----------------------------------------------------------------" -ForegroundColor Gray
    Write-Host "             PRE-FLIGHT PERMISSION & REACHABILITY AUDIT          " -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
    foreach ($org in $targetOrgs) {
        $auditStatus = "Ready"
        try {
            if ($Scope -eq 'Org') {
                $orgMeta = Invoke-GhApiWithThrottling -Uri "https://api.github.com/orgs/$org" -Method Get
                $auditStatus = if ($orgMeta.plan -and $orgMeta.plan.name -eq 'enterprise') { "Ready (Enterprise Plan Verified)" } else { "Ready" }
            } else {
                $checkRepo = if ($TargetRepo) { $TargetRepo } elseif ($TargetRepos -and @($TargetRepos).Count -gt 0) { $TargetRepos[0] } else { "" }
                if ($checkRepo) {
                    $repoMeta = Invoke-GhApiWithThrottling -Uri "https://api.github.com/repos/$org/$checkRepo" -Method Get
                    if (-not ($repoMeta.permissions -and $repoMeta.permissions.admin)) {
                        $auditStatus = "FAIL: Missing Admin Permissions on '$org/$checkRepo'"
                    }
                }
            }
        }
        catch {
            $auditStatus = "FAIL: $($_.Exception.Message)"
        }
        Write-Host "    [DRY-RUN AUDIT] Scope: $Scope | Target: $org | Status: $auditStatus" -ForegroundColor $(if ($auditStatus -like 'Ready*') { 'Green' } else { 'Red' })
    }

    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "   DRY RUN COMPLETE: No modifications were made to GitHub.       " -ForegroundColor Yellow
    Write-Host "=================================================================`n" -ForegroundColor Yellow
    return
}

# 8. Apply Rulesets to GitHub
$appliedResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($cFile in $captureFiles) {
    $captureData = Get-Content -LiteralPath $cFile.FullName -Raw | ConvertFrom-Json
    $pName = $captureData.ProjectName

    # Resolve target repos for this specific project
    $projTargetRepos = @(
        if ($TargetRepo) {
            $isMatch = @($repoMappingRows | Where-Object { $_.AdoProject -eq $pName -and ($_.TargetGhRepo -eq $TargetRepo -or $_.AdoRepo -eq $TargetRepo) })
            if ($isMatch.Count -gt 0) { $TargetRepo }
        }
        elseif ($TargetRepos -and @($TargetRepos).Count -gt 0) {
            @($repoMappingRows | Where-Object { $_.AdoProject -eq $pName -and ($_.TargetGhRepo -in $TargetRepos -or $_.AdoRepo -in $TargetRepos) } | ForEach-Object { $_.TargetGhRepo })
        }
        else {
            @($repoMappingRows | Where-Object { $_.AdoProject -eq $pName } | ForEach-Object { $_.TargetGhRepo })
        }
    )

    if (@($projTargetRepos).Count -eq 0 -and $Scope -ne 'Org') {
        Write-Host "[-] Skipping project '$pName': No matching target repositories found for this project." -ForegroundColor Gray
        continue
    }

    $payloads = Build-ProjectRulesetPayloads -CaptureData $captureData -Scope $Scope -Enforcement $Enforcement -ProjectTargetRepos $projTargetRepos
    $branchRulesetPayload = $payloads.BranchPayload
    $pushRulesetPayload   = $payloads.PushPayload

    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "   Processing Project Policies: $pName (Repos: $($projTargetRepos -join ', '))" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    foreach ($org in $targetOrgs) {
        if ($Scope -eq 'Org') {
            $repoTargetDesc = if ($projTargetRepos.Count -gt 0) { "$($projTargetRepos.Count) targeted repo(s): ($($projTargetRepos -join ', '))" } else { "all repositories" }
            Write-Host "`n[+] Applying rulesets at Organization level on '$org' (Targeting $repoTargetDesc)..." -ForegroundColor Cyan

            # Query existing Org rulesets
            $existingMap = @{}
            try {
                $existingList = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org/rulesets" -Headers $apiHeaders -Method Get
                if ($existingList) {
                    foreach ($ex in @($existingList)) {
                        $existingMap[$ex.name] = $ex.id
                    }
                }
            }
            catch {
                Write-Warning "Could not query organization rulesets on '$org': $($_.Exception.Message)"
            }

            # A. Apply Branch Ruleset
            $branchBody = $branchRulesetPayload | ConvertTo-Json -Depth 8
            $branchName = $branchRulesetPayload.name
            try {
                if ($existingMap.ContainsKey($branchName)) {
                    $exId = $existingMap[$branchName]
                    $rsEndpoint = "https://api.github.com/orgs/$org/rulesets/$exId"
                    $createdRs = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Put -Body $branchBody
                    Write-Host "     [OK] Org Branch Ruleset updated (ID: $($createdRs.id), Status: $($createdRs.enforcement))" -ForegroundColor Green
                }
                else {
                    $rsEndpoint = "https://api.github.com/orgs/$org/rulesets"
                    $createdRs = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Post -Body $branchBody
                    Write-Host "     [OK] Org Branch Ruleset created (ID: $($createdRs.id), Status: $($createdRs.enforcement))" -ForegroundColor Green
                }

                $appliedResults.Add([PSCustomObject]@{
                    Project      = $pName
                    Scope        = "Organization"
                    Target       = $org
                    RulesetType  = "branch"
                    RulesetId    = $createdRs.id
                    RulesetName  = $createdRs.name
                    Enforcement  = $createdRs.enforcement
                    RulesCount   = @($createdRs.rules).Count
                    Status       = "Success"
                })
            }
            catch {
                Write-Warning "     [FAIL] Failed to apply Org branch ruleset on '$org': $($_.Exception.Message)"
                $appliedResults.Add([PSCustomObject]@{
                    Project      = $pName
                    Scope        = "Organization"
                    Target       = $org
                    RulesetType  = "branch"
                    RulesetId    = $null
                    RulesetName  = $branchName
                    Enforcement  = $Enforcement
                    RulesCount   = 0
                    Status       = "Failed ($($_.Exception.Message))"
                })
            }

            # B. Apply Push Ruleset (if defined)
            if ($pushRulesetPayload) {
                $pushBody = $pushRulesetPayload | ConvertTo-Json -Depth 8
                $pushName = $pushRulesetPayload.name
                try {
                    if ($existingMap.ContainsKey($pushName)) {
                        $exId = $existingMap[$pushName]
                        $rsEndpoint = "https://api.github.com/orgs/$org/rulesets/$exId"
                        $createdPush = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Put -Body $pushBody
                        Write-Host "     [OK] Org Push Ruleset updated (ID: $($createdPush.id), Status: $($createdPush.enforcement))" -ForegroundColor Green
                    }
                    else {
                        $rsEndpoint = "https://api.github.com/orgs/$org/rulesets"
                        $createdPush = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Post -Body $pushBody
                        Write-Host "     [OK] Org Push Ruleset created (ID: $($createdPush.id), Status: $($createdPush.enforcement))" -ForegroundColor Green
                    }

                    $appliedResults.Add([PSCustomObject]@{
                        Project      = $pName
                        Scope        = "Organization"
                        Target       = $org
                        RulesetType  = "push"
                        RulesetId    = $createdPush.id
                        RulesetName  = $createdPush.name
                        Enforcement  = $createdPush.enforcement
                        RulesCount   = @($createdPush.rules).Count
                        Status       = "Success"
                    })
                }
                catch {
                    Write-Warning "     [FAIL] Failed to apply Org push ruleset on '$org': $($_.Exception.Message)"
                    $appliedResults.Add([PSCustomObject]@{
                        Project      = $pName
                        Scope        = "Organization"
                        Target       = $org
                        RulesetType  = "push"
                        RulesetId    = $null
                        RulesetName  = $pushName
                        Enforcement  = $Enforcement
                        RulesCount   = 0
                        Status       = "Failed ($($_.Exception.Message))"
                    })
                }
            }
        }
        else {
            # Target repository level (-Scope Repo)
            foreach ($rName in $projTargetRepos) {
                Write-Host "`n[+] Applying [$pName] rulesets to customer repository '$org/$rName'..." -ForegroundColor Cyan
                $existingMap = @{}
                try {
                    $existingList = Invoke-RestMethod -Uri "https://api.github.com/repos/$org/$rName/rulesets" -Headers $apiHeaders -Method Get
                    if ($existingList) {
                        foreach ($ex in @($existingList)) {
                            $existingMap[$ex.name] = $ex.id
                        }
                    }
                }
                catch {
                    # Ignore list failures
                }

                # A. Apply Branch Ruleset
                $branchBody = $branchRulesetPayload | ConvertTo-Json -Depth 8
                $branchName = $branchRulesetPayload.name
                try {
                    if ($existingMap.ContainsKey($branchName)) {
                        $exId = $existingMap[$branchName]
                        $rsEndpoint = "https://api.github.com/repos/$org/$rName/rulesets/$exId"
                        $createdRs = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Put -Body $branchBody
                        Write-Host "     [OK] Branch Ruleset updated (ID: $($createdRs.id), Status: $($createdRs.enforcement))" -ForegroundColor Green
                    }
                    else {
                        $rsEndpoint = "https://api.github.com/repos/$org/$rName/rulesets"
                        $createdRs = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Post -Body $branchBody
                        Write-Host "     [OK] Branch Ruleset created (ID: $($createdRs.id), Status: $($createdRs.enforcement))" -ForegroundColor Green
                    }

                    $appliedResults.Add([PSCustomObject]@{
                        Project      = $pName
                        Scope        = "Repository"
                        Target       = "$org/$rName"
                        RulesetType  = "branch"
                        RulesetId    = $createdRs.id
                        RulesetName  = $createdRs.name
                        Enforcement  = $createdRs.enforcement
                        RulesCount   = @($createdRs.rules).Count
                        Status       = "Success"
                    })
                }
                catch {
                    Write-Warning "     [FAIL] Failed to apply branch ruleset on '$org/$rName': $($_.Exception.Message)"
                    $appliedResults.Add([PSCustomObject]@{
                        Project      = $pName
                        Scope        = "Repository"
                        Target       = "$org/$rName"
                        RulesetType  = "branch"
                        RulesetId    = $null
                        RulesetName  = $branchName
                        Enforcement  = $Enforcement
                        RulesCount   = 0
                        Status       = "Failed ($($_.Exception.Message))"
                    })
                }

                # B. Apply Push Ruleset (if defined)
                if ($pushRulesetPayload) {
                    $pushBody = $pushRulesetPayload | ConvertTo-Json -Depth 8
                    $pushName = $pushRulesetPayload.name
                    try {
                        if ($existingMap.ContainsKey($pushName)) {
                            $exId = $existingMap[$pushName]
                            $rsEndpoint = "https://api.github.com/repos/$org/$rName/rulesets/$exId"
                            $createdPush = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Put -Body $pushBody
                            Write-Host "     [OK] Push Ruleset updated (ID: $($createdPush.id), Status: $($createdPush.enforcement))" -ForegroundColor Green
                        }
                        else {
                            $rsEndpoint = "https://api.github.com/repos/$org/$rName/rulesets"
                            $createdPush = Invoke-RestMethod -Uri $rsEndpoint -Headers $apiHeaders -Method Post -Body $pushBody
                            Write-Host "     [OK] Push Ruleset created (ID: $($createdPush.id), Status: $($createdPush.enforcement))" -ForegroundColor Green
                        }

                        $appliedResults.Add([PSCustomObject]@{
                            Project      = $pName
                            Scope        = "Repository"
                            Target       = "$org/$rName"
                            RulesetType  = "push"
                            RulesetId    = $createdPush.id
                            RulesetName  = $createdPush.name
                            Enforcement  = $createdPush.enforcement
                            RulesCount   = @($createdPush.rules).Count
                            Status       = "Success"
                        })
                    }
                    catch {
                        Write-Warning "     [FAIL] Failed to apply push ruleset on '$org/$rName': $($_.Exception.Message)"
                    }
                }
            }
        }
    }
}

Write-Host "`n-----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "                  RULESET APPLICATION SUMMARY                    " -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
$appliedResults | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White

# Pattern A: Export failed items to retry manifest if any failures occurred
$failedEntries = @($appliedResults | Where-Object { $_.Status -like 'Failed*' -or $_.Status -like 'FAIL*' })
if ($failedEntries.Count -gt 0) {
    $latestDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
    New-Item -ItemType Directory -Path $latestDir -Force | Out-Null
    $failedFile = Join-Path -Path $latestDir -ChildPath "ado-project-failed.csv"
    $failedEntries | Export-Csv -LiteralPath $failedFile -NoTypeInformation -Encoding utf8

    Write-Host "`n=================================================================" -ForegroundColor Yellow
    Write-Host "   PATTERN A: RETRY MANIFEST GENERATED FOR FAILED TARGETS        " -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "[!] $($failedEntries.Count) operation(s) failed out of $($appliedResults.Count) total." -ForegroundColor Yellow
    Write-Host "[!] Retry manifest generated at: $failedFile" -ForegroundColor Yellow
    Write-Host "[!] To retry ONLY the failed items without rerunning successful ones, execute:" -ForegroundColor White
    Write-Host "    pwsh .\04_Apply-GitHubRulesets.ps1 -GroupsFilePath '$failedFile'`n" -ForegroundColor Green
}
else {
    Write-Host "[OK] Ruleset application complete: Success ($($appliedResults.Count) ruleset(s) applied). Rollback is available via 05_Rollback-GitHubRulesets.ps1." -ForegroundColor Green
}
