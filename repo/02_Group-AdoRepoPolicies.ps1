#Requires -Version 7.0
<#
.SYNOPSIS
    Groups, analyzes, and matrices Azure DevOps repository and branch policies against GitHub Rulesets.

.DESCRIPTION
    Phase 3 - Step 2 of the ADO-to-GitHub Policy Migration pipeline.
    - Scans captured ADO repo policy JSON files in 'repo\output\latest' (or -CaptureDir).
    - Ingests the authoritative crosswalk manifest 'ado-to-ghec-repo-crosswalk.csv'.
    - Generates:
        * 'ado-repo-policy-matrix.csv' (Clean side-by-side audit matrix of Yes/No policy enforcement per repository).
        * 'ado-repo-policy-details.csv' (Detailed parameter breakdown: approver counts, patterns, limits, branch refs).
        * 'ado-repo-policy-groups.csv' (Clusters repositories sharing identical policy signatures).
    - Robust against Windows Excel file locks with automatic fallback naming.

.PARAMETER CaptureDir
    Directory containing captured .repo-policies.json files. Defaults to '$PSScriptRoot\output\latest'.

.PARAMETER CrosswalkPath
    Path to crosswalk CSV. Defaults to '$PSScriptRoot\config\ado-to-ghec-repo-crosswalk.csv'.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\repo"
    pwsh .\02_Group-AdoRepoPolicies.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CaptureDir = "",

    [Parameter(Mandatory = $false)]
    [string]$CrosswalkPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Save-SafeCsv {
    param(
        [Parameter(Mandatory)][System.Collections.IEnumerable]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )
    try {
        $InputObject | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
        return $Path
    }
    catch [System.IO.IOException] {
        $dir = [System.IO.Path]::GetDirectoryName($Path)
        $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $ext = [System.IO.Path]::GetExtension($Path)
        $fallback = [System.IO.Path]::Combine($dir, "$base-updated$ext")
        Write-Warning "File '$Path' is locked (e.g. open in Excel). Writing to '$fallback' instead."
        $InputObject | Export-Csv -Path $fallback -NoTypeInformation -Encoding utf8
        return $fallback
    }
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Analyze & Matrix ADO Repo Policies for GitHub Rulesets        " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Capture Directory
if ([string]::IsNullOrWhiteSpace($CaptureDir)) {
    $CaptureDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
}

if (-not (Test-Path -LiteralPath $CaptureDir)) {
    throw "Capture directory not found: '$CaptureDir'. Run 01_Capture-AdoRepoPolicies.ps1 first."
}

$captureFiles = @(Get-ChildItem -Path $CaptureDir -Filter *.repo-policies.json)
if ($captureFiles.Count -eq 0) {
    throw "No *.repo-policies.json files found in '$CaptureDir'."
}

Write-Host "[+] Found $($captureFiles.Count) repository capture file(s) in: $CaptureDir" -ForegroundColor Cyan

# 2. Resolve Crosswalk Manifest (Source of Truth)
if ([string]::IsNullOrWhiteSpace($CrosswalkPath)) {
    $CrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "config\ado-to-ghec-repo-crosswalk.csv"
    if (-not (Test-Path -LiteralPath $CrosswalkPath)) {
        $CrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "ado-to-ghec-repo-crosswalk.csv"
    }
}

if (-not (Test-Path -LiteralPath $CrosswalkPath)) {
    throw "Crosswalk file not found: '$CrosswalkPath'."
}

$crosswalk = @(Import-Csv -LiteralPath $CrosswalkPath)
Write-Host "[+] Ingested $($crosswalk.Count) policies from crosswalk manifest." -ForegroundColor Cyan

# 3. Parse Repository Captures
$reposData = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($f in $captureFiles) {
    $raw = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
    $reposData.Add($raw)
}

# 4. Build Side-by-Side Audit Matrix & Details
$matrixRows = [System.Collections.Generic.List[System.Collections.Specialized.OrderedDictionary]]::new()
$detailsRows = [System.Collections.Generic.List[PSCustomObject]]::new()

# Track repository policy signatures for grouping
$repoSignatures = @{}

foreach ($repo in $reposData) {
    $repoKey = "$($repo.Organization)/$($repo.ProjectName)/$($repo.RepositoryName)"
    $activeCodes = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $repo.Policies) {
        if ($p.IsEnabled -and -not $activeCodes.Contains($p.PolicyCode)) {
            $activeCodes.Add($p.PolicyCode)
        }
    }
    $activeCodes.Sort()
    $sig = ($activeCodes -join "|")
    if (-not $repoSignatures.ContainsKey($sig)) {
        $repoSignatures[$sig] = [System.Collections.Generic.List[string]]::new()
    }
    $repoSignatures[$sig].Add($repoKey)
}

foreach ($cw in $crosswalk) {
    $code     = $cw.PolicyCode
    $name     = if ($cw.PSObject.Properties['AdoPolicyName']) { $cw.AdoPolicyName } else { $code }
    $targetGh = $cw.TargetGhPolicyKey
    $implType = if ($cw.PSObject.Properties['ImplementationType']) { $cw.ImplementationType } else { "Repo Ruleset" }
    $apply    = $cw.ApplyPolicy

    $row = [System.Collections.Specialized.OrderedDictionary]::new()
    $row["PolicyCode"] = $code
    $row["AdoPolicyName"] = $name
    $row["TargetGhPolicyKey"] = $targetGh
    $row["ImplementationType"] = $implType
    $row["ApplyToGitHub"] = $apply

    foreach ($repo in $reposData) {
        $repoKey = "$($repo.Organization)/$($repo.ProjectName)/$($repo.RepositoryName)"
        $matched = @($repo.Policies | Where-Object { $_.PolicyCode -eq $code -and $_.IsEnabled -eq $true })
        
        $isEnforced = ($matched.Count -gt 0)
        $row[$repoKey] = if ($isEnforced) { "Yes" } else { "No" }

        # Detailed breakdown
        if ($isEnforced) {
            foreach ($m in $matched) {
                $detailsDesc = ""
                $settings = $m.Settings

                switch ($code) {
                    "R01" {
                        $pats = if ($settings.PSObject.Properties['authorEmailPatterns']) { $settings.authorEmailPatterns -join "; " } else { "None" }
                        $detailsDesc = "Allowed Emails: $pats"
                    }
                    "R02" {
                        $pats = if ($settings.PSObject.Properties['filenamePatterns']) { $settings.filenamePatterns -join "; " } else { "None" }
                        $detailsDesc = "Restricted Paths: $pats"
                    }
                    "R05" {
                        $len = if ($settings.PSObject.Properties['maxPathLength']) { $settings.maxPathLength } else { "Default" }
                        $detailsDesc = "Max Path Length: $len chars"
                    }
                    "R06" {
                        $bytes = if ($settings.PSObject.Properties['maximumGitBlobSizeInBytes']) { $settings.maximumGitBlobSizeInBytes } else { 0 }
                        $mb = [Math]::Round(($bytes / 1MB), 2)
                        $detailsDesc = "Max File Size: $mb MB ($bytes bytes)"
                    }
                    "B01" {
                        $count = if ($settings.PSObject.Properties['minimumApproverCount']) { $settings.minimumApproverCount } else { 1 }
                        $reset = if ($settings.PSObject.Properties['resetOnSourcePush']) { $settings.resetOnSourcePush } else { $false }
                        $detailsDesc = "Approvers: $count | Reset on Push: $reset"
                    }
                    "B03" {
                        $detailsDesc = "Requires unresolved comments to be resolved"
                    }
                    "B04" {
                        $squash = if ($settings.PSObject.Properties['allowSquash']) { $settings.allowSquash } else { $false }
                        $rebase = if ($settings.PSObject.Properties['allowRebase']) { $settings.allowRebase } else { $false }
                        $detailsDesc = "Allowed Strategies -> Squash: $squash, Rebase: $rebase"
                    }
                    "B05" {
                        $buildDef = if ($settings.PSObject.Properties['buildDefinitionId']) { "BuildDefId: $($settings.buildDefinitionId)" } else { "Build Validation" }
                        $detailsDesc = $buildDef
                    }
                    "B06" {
                        $name = if ($settings.PSObject.Properties['name']) { $settings.name } else { "External Service Check" }
                        $detailsDesc = "Status Check: $name"
                    }
                    "B07" {
                        $detailsDesc = "Automatically included required reviewers (CODEOWNERS equivalent)"
                    }
                    "B08" {
                        $detailsDesc = "Work Item Linking Required"
                    }
                    default {
                        $detailsDesc = "Enforced ($($m.ScopeType))"
                    }
                }

                $detailsRows.Add([PSCustomObject]@{
                    Organization       = $repo.Organization
                    ProjectName        = $repo.ProjectName
                    RepositoryName     = $repo.RepositoryName
                    PolicyCode         = $code
                    PolicyName         = $name
                    ScopeType          = $m.ScopeType
                    TargetBranch       = $m.TargetBranch
                    ConfiguredDetails  = $detailsDesc
                    GitHubRuleMapping  = $targetGh
                })
            }
        }
    }
    $matrixRows.Add($row)
}

# 5. Build Grouping Summary
$groupRows = [System.Collections.Generic.List[PSCustomObject]]::new()
$groupIndex = 1
foreach ($sigKey in $repoSignatures.Keys) {
    $members = $repoSignatures[$sigKey]
    $groupRows.Add([PSCustomObject]@{
        GroupId          = "REPO-GRP-$("{0:D2}" -f $groupIndex)"
        RepositoryCount  = $members.Count
        ActivePolicies   = ($sigKey -split '\|').Count
        PolicyCodes      = ($sigKey -replace '\|', ', ')
        MemberRepos      = ($members -join "; ")
    })
    $groupIndex++
}

# 6. Output Results
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$outputDir = Join-Path -Path $PSScriptRoot -ChildPath "output\$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$matrixObjects = @($matrixRows | ForEach-Object { [PSCustomObject]$_ })
$matrixPath = Join-Path -Path $outputDir -ChildPath "ado-repo-policy-matrix.csv"
$detailsPath = Join-Path -Path $outputDir -ChildPath "ado-repo-policy-details.csv"
$groupsPath = Join-Path -Path $outputDir -ChildPath "ado-repo-policy-groups.csv"

$savedMatrix = Save-SafeCsv -InputObject $matrixObjects -Path $matrixPath
$savedDetails = Save-SafeCsv -InputObject $detailsRows -Path $detailsPath
$savedGroups = Save-SafeCsv -InputObject $groupRows -Path $groupsPath

# Copy to latest directory for 04_Apply
$latestDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
New-Item -ItemType Directory -Path $latestDir -Force | Out-Null
$latestGroupsPath = Join-Path -Path $latestDir -ChildPath "ado-repo-policy-groups.csv"
$null = Save-SafeCsv -InputObject $groupRows -Path $latestGroupsPath

# Save full diagnostic tables to execution log
$logFile = Join-Path -Path $outputDir -ChildPath "execution.log"
$latestLog = Join-Path -Path $latestDir -ChildPath "execution.log"
$logContent = @"
=================================================================
             ADO REPO POLICY AUDIT MATRIX (SUMMARY)              
=================================================================
$($matrixObjects | Format-Table -AutoSize | Out-String)

=================================================================
                  REPOSITORY POLICY GROUPS                       
=================================================================
$($groupRows | Format-Table -AutoSize | Out-String)
"@
$logContent | Set-Content -LiteralPath $logFile -Encoding utf8
$logContent | Set-Content -LiteralPath $latestLog -Encoding utf8

Write-Host "`n[OK] Policy analysis & grouping complete ($($captureFiles.Count) repositories across $($groupRows.Count) policy groups)." -ForegroundColor Green
Write-Host "     Matrix CSV    : $savedMatrix" -ForegroundColor Gray
Write-Host "     Groups CSV    : $savedGroups" -ForegroundColor Gray
Write-Host "     Detailed Log  : $logFile" -ForegroundColor Cyan
