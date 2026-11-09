#Requires -Version 7.0
<#
.SYNOPSIS
    Master test orchestrator for the ADO to GitHub migration suite.
.DESCRIPTION
    Runs all test files in test_suite/ with rigorous reporting.
    Can be completely purged at the end of the project using Remove-TestSuite.ps1.
.EXAMPLE
    pwsh ./test_suite/Run-AllTests.ps1
.EXAMPLE
    pwsh ./test_suite/Run-AllTests.ps1 -SkipLive
#>
[CmdletBinding()]
param(
    [switch]$SkipLive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   ADO to GitHub Policy Migration - Rigorous Test Suite     " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[+] Working Directory: $PSScriptRoot"
Write-Host "[+] Mode             : $(if ($SkipLive) { 'Offline Unit/Static Only' } else { 'Full Unit + Live API Idempotency' })"

$testFiles = @(Get-ChildItem -Path $PSScriptRoot -Filter *Test*.ps1 | Where-Object { 
    $_.Name -ne 'Test-Framework.ps1' -and 
    $_.Name -ne 'Run-AllTests.ps1' -and 
    $_.Name -ne 'Remove-TestSuite.ps1' 
} | Sort-Object Name)

if ($testFiles.Count -eq 0) {
    Write-Warning "No test files found in $PSScriptRoot."
    exit 0
}

$allPassed = $true
$suiteSw = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($tf in $testFiles) {
    Write-Host "`n>>> Running: $($tf.Name)..." -ForegroundColor Yellow
    
    $argsList = "-NoProfile -File `"$($tf.FullName)`""
    if ($SkipLive) {
        $argsList += " -IncludeLiveApiTests:`$false"
    }

    $p = Start-Process -FilePath 'pwsh' -ArgumentList $argsList -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        $allPassed = $false
        Write-Host ">>> FAILED: $($tf.Name) (ExitCode: $($p.ExitCode))`n" -ForegroundColor Red
    }
    else {
        Write-Host ">>> PASSED: $($tf.Name)`n" -ForegroundColor Green
    }
}

$suiteSw.Stop()
Write-Host "============================================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host " ALL TEST SUITES PASSED ($($suiteSw.Elapsed.TotalSeconds.ToString('F2'))s) " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0
}
else {
    Write-Host " TEST SUITE ENCOUNTERED FAILURES ($($suiteSw.Elapsed.TotalSeconds.ToString('F2'))s) " -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 1
}
