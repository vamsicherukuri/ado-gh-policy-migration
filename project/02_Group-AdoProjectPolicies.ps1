#Requires -Version 7.0
<#
.SYNOPSIS
    Groups, analyzes, and matrices Azure DevOps project and branch policies against GitHub Rulesets.

.DESCRIPTION
    Phase 2 - Step 2 of the ADO-to-GitHub Policy Migration pipeline.
    - Scans captured ADO project policy JSON files in 'project\output\latest' (or -CaptureDir).
    - Ingests the authoritative crosswalk manifest 'ado-to-ghec-rulesets-crosswalk.csv'.
    - Generates:
        * 'ado-project-policy-matrix.csv' (Clean side-by-side Excel audit matrix of Yes/No policy enforcement).
        * 'ado-project-policy-details.csv' (Detailed parameter breakdown: approver counts, regexes, path limits).
    - Robust against Windows Excel file locks with automatic fallback naming.

.PARAMETER CaptureDir
    Directory containing captured .project-policies.json files. Defaults to '$PSScriptRoot\output\latest'.

.PARAMETER CrosswalkPath
    Path to crosswalk CSV. Defaults to '$PSScriptRoot\ado-to-ghec-rulesets-crosswalk.csv'.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\project"
    pwsh .\02_Group-AdoProjectPolicies.ps1
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
Write-Host "   Analyze & Matrix ADO Project Policies for GitHub Rulesets     " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Capture Directory
if ([string]::IsNullOrWhiteSpace($CaptureDir)) {
    $CaptureDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
}

if (-not (Test-Path -LiteralPath $CaptureDir)) {
    throw "Capture directory not found: '$CaptureDir'. Run 01_Capture-AdoProjectPolicies.ps1 first."
}

$captureFiles = @(Get-ChildItem -Path $CaptureDir -Filter *.project-policies.json)
if ($captureFiles.Count -eq 0) {
    throw "No *.project-policies.json files found in '$CaptureDir'."
}

Write-Host "[+] Found $($captureFiles.Count) project capture file(s) in: $CaptureDir" -ForegroundColor Cyan

# 2. Resolve Crosswalk Manifest (Source of Truth)
if ([string]::IsNullOrWhiteSpace($CrosswalkPath)) {
    $CrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "config\ado-to-ghec-rulesets-crosswalk.csv"
    if (-not (Test-Path -LiteralPath $CrosswalkPath)) {
        $CrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "ado-to-ghec-rulesets-crosswalk.csv"
    }
}

if (-not (Test-Path -LiteralPath $CrosswalkPath)) {
    throw "Crosswalk file not found: '$CrosswalkPath'."
}

$crosswalk = @(Import-Csv -LiteralPath $CrosswalkPath)
Write-Host "[+] Ingested $($crosswalk.Count) policies from crosswalk manifest." -ForegroundColor Cyan

# 3. Parse Project Captures
$projectsData = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($f in $captureFiles) {
    $raw = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
    $projectsData.Add($raw)
}

# 4. Build Excel Side-by-Side Audit Matrix (Pure Yes/No)
$matrixRows = [System.Collections.Generic.List[System.Collections.Specialized.OrderedDictionary]]::new()
$detailsRows = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($cw in $crosswalk) {
    $code     = $cw.PolicyCode
    $name     = if ($cw.PSObject.Properties['AdoPolicyName']) { $cw.AdoPolicyName } else { $code }
    $targetGh = $cw.TargetGhPolicyKey
    $action   = if ($cw.PSObject.Properties['TargetGhActionHandler']) { $cw.TargetGhActionHandler } else { $targetGh }
    $implType = if ($cw.PSObject.Properties['ImplementationType']) { $cw.ImplementationType } else { "Org Ruleset" }
    $apply    = $cw.ApplyPolicy

    $row = [System.Collections.Specialized.OrderedDictionary]::new()
    $row["PolicyCode"] = $code
    $row["AdoPolicyName"] = $name
    $row["TargetGhPolicyKey"] = $targetGh
    $row["ImplementationType"] = $implType
    $row["ApplyToGitHub"] = $apply

    foreach ($proj in $projectsData) {
        $projKey = "$($proj.Organization)/$($proj.ProjectName)"
        $matched = @($proj.Policies | Where-Object { $_.PolicyCode -eq $code -and $_.IsEnabled -eq $true })
        
        $isEnforced = ($matched.Count -gt 0)
        $row[$projKey] = if ($isEnforced) { "Yes" } else { "No" }

        # Collect detailed parameter breakdown
        if ($isEnforced) {
            foreach ($m in $matched) {
                $detailsDesc = ""
                $settings = $m.Settings

                switch ($code) {
                    "P13" {
                        $pats = if ($settings.PSObject.Properties['authorEmailPatterns']) { $settings.authorEmailPatterns -join "; " } else { "None" }
                        $detailsDesc = "Patterns: $pats"
                    }
                    "P14" {
                        $pats = if ($settings.PSObject.Properties['filenamePatterns']) { $settings.filenamePatterns -join "; " } else { "None" }
                        $detailsDesc = "Restricted Paths: $pats"
                    }
                    "P17" {
                        $len = if ($settings.PSObject.Properties['maxPathLength']) { $settings.maxPathLength } else { "Default" }
                        $detailsDesc = "Max Path Length: $len chars"
                    }
                    "P18" {
                        $bytes = if ($settings.PSObject.Properties['maximumGitBlobSizeInBytes']) { $settings.maximumGitBlobSizeInBytes } else { 0 }
                        $mb = [Math]::Round(($bytes / 1MB), 2)
                        $detailsDesc = "Max File Size: $mb MB ($bytes bytes)"
                    }
                    "P19" {
                        $count = if ($settings.PSObject.Properties['minimumApproverCount']) { $settings.minimumApproverCount } else { 1 }
                        $reset = if ($settings.PSObject.Properties['resetOnSourcePush']) { $settings.resetOnSourcePush } else { $false }
                        $detailsDesc = "Approvers: $count | Reset on Push: $reset"
                    }
                    "P21" {
                        $detailsDesc = "Requires all review comment threads resolved"
                    }
                    "P22" {
                        $squash = if ($settings.PSObject.Properties['allowSquash']) { $settings.allowSquash } else { $false }
                        $rebase = if ($settings.PSObject.Properties['allowRebase']) { $settings.allowRebase } else { $false }
                        $detailsDesc = "Allowed Strategies -> Squash: $squash, Rebase: $rebase"
                    }
                    default {
                        $detailsDesc = "Enforced ($($m.Classification))"
                    }
                }

                $detailsRows.Add([PSCustomObject]@{
                    Organization       = $proj.Organization
                    ProjectName        = $proj.ProjectName
                    PolicyCode         = $code
                    PolicyName         = $name
                    Classification     = $m.Classification
                    BranchPatterns     = ($m.BranchPatterns -join "; ")
                    TargetRepositories = if ($m.TargetRepositories.Count -gt 0) { $m.TargetRepositories -join "; " } else { "All Repositories" }
                    ConfiguredDetails  = $detailsDesc
                    GitHubRuleMapping  = $targetGh
                })
            }
        }
    }
    $matrixRows.Add($row)
}

# 5. Output Results
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$outputDir = Join-Path -Path $PSScriptRoot -ChildPath "output\$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$matrixObjects = @($matrixRows | ForEach-Object { [PSCustomObject]$_ })
$matrixPath = Join-Path -Path $outputDir -ChildPath "ado-project-policy-matrix.csv"
$detailsPath = Join-Path -Path $outputDir -ChildPath "ado-project-policy-details.csv"

$savedMatrix = Save-SafeCsv -InputObject $matrixObjects -Path $matrixPath
$savedDetails = Save-SafeCsv -InputObject $detailsRows -Path $detailsPath

Write-Host "`n-----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "             ADO PROJECT POLICY AUDIT MATRIX (SUMMARY)           " -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
$matrixObjects | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White

Write-Host "[OK] Matrix CSV saved to  : $savedMatrix" -ForegroundColor Green
Write-Host "[OK] Details CSV saved to : $savedDetails" -ForegroundColor Green
