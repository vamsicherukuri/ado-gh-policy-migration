#Requires -Version 7.0
<#
.SYNOPSIS
    Unit and integration tests for the ADO to Safe-Settings transformation engine.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = $PSScriptRoot
$transformDir = Join-Path $scriptRoot "..\scripts\transform"
$testOutput = Join-Path $scriptRoot "..\output\test-safe-settings"

# Load modules
. (Join-Path $transformDir "ConvertTo-Yaml.ps1")

$passCount = 0
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "Assertion Failed: $Message"
    }
    $script:passCount++
}

Write-Host "Running Safe-Settings Transformation Tests..." -ForegroundColor Cyan

# Test 1: YAML Serialization of Special Characters
$yamlTestObj = [ordered]@{
    suborg = [ordered]@{
        name = "test-project"
        repos = @("repo1", "repo2")
    }
    pattern = "@contoso.com"
    wildcard = "*"
    flag = $true
    count = 2
}
$yaml = ConvertTo-Yaml -InputObject $yamlTestObj
Assert-True ($yaml -match 'name: test-project') "YAML contains string"
Assert-True ($yaml -match 'pattern: "@contoso.com"') "YAML quotes strings starting with @"
Assert-True ($yaml -match 'wildcard: "\*"') "YAML quotes asterisks"
Assert-True ($yaml -match 'flag: true') "YAML serializes boolean as true"
Assert-True ($yaml -match 'count: 2') "YAML serializes integers"

# Test 2: End-to-End Snapshot Transformation
$fixture = Get-ChildItem (Join-Path $scriptRoot "..\output\policy-capture") -Filter "*.portable.json" -Recurse |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Assert-True ($null -ne $fixture) "Found portable JSON fixture"

& (Join-Path $transformDir "Convert-AdoToSafeSettings.ps1") `
    -PortableJsonPath $fixture.FullName `
    -OutputDir $testOutput `
    -Enforcement "active"

$settingsFile = Join-Path $testOutput ".github\settings.yml"
$suborgFile = Join-Path $testOutput ".github\suborgs\project1.yml"
$repoFile = Join-Path $testOutput ".github\repos\sample2.yml"
$reportFile = Join-Path $testOutput "MIGRATION-REPORT.md"

Assert-True (Test-Path $settingsFile) ".github/settings.yml created"
Assert-True (Test-Path $suborgFile) ".github/suborgs/project1.yml created"
Assert-True (Test-Path $repoFile) ".github/repos/sample2.yml created"
Assert-True (Test-Path $reportFile) "MIGRATION-REPORT.md created"

# Test 3: Validate Suborg Content
$suborgContent = Get-Content -LiteralPath $suborgFile -Raw
Assert-True ($suborgContent -match 'name: project1') "Suborg has correct project name"
Assert-True ($suborgContent -match '- sample2') "Suborg lists sample2"
Assert-True ($suborgContent -match 'required_approving_review_count: 2') "Branch ruleset has 2 required reviewers"
Assert-True ($suborgContent -match 'dismiss_stale_reviews_on_push: true') "Stale review dismissal mapped"
Assert-True ($suborgContent -match 'required_review_thread_resolution: true') "Conversation resolution mapped"
Assert-True ($suborgContent -match 'allow_squash_merge: true') "Squash merge setting enabled"
Assert-True ($suborgContent -match 'type: non_fast_forward') "Force push protection mapped"
Assert-True ($suborgContent -match 'type: deletion') "Branch deletion protection mapped"
Assert-True ($suborgContent -match 'max_file_path_length: 180') "Path length 180 mapped"
Assert-True ($suborgContent -match 'max_file_size: 1') "Max file size converted to 1 MB"

# Test 4: Validate Repo Overrides Content
$repoContent = Get-Content -LiteralPath $repoFile -Raw
Assert-True ($repoContent -match 'name: sample2') "Repo override targets sample2"
Assert-True ($repoContent -match 'context: policy-lab-sample2') "Repo has specific build pipeline check context"

Write-Host "ALL TESTS PASSED ($passCount assertions)" -ForegroundColor Green
