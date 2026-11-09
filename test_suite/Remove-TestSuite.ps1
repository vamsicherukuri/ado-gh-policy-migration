#Requires -Version 7.0
<#
.SYNOPSIS
    Self-destruct / cleanup script for the temporary test suite.
.DESCRIPTION
    Safely removes the test_suite folder upon project completion.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force
)

$targetDir = $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "          TEST SUITE CLEANUP / REMOVAL UTILITY              " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "[+] Target Directory to Remove: $targetDir"

if (-not $Force) {
    $confirm = Read-Host "Are you sure you want to permanently delete the entire test suite folder? (y/N)"
    if ($confirm -notmatch '^[Yy]$') {
        Write-Host "Cleanup aborted by user." -ForegroundColor Gray
        exit 0
    }
}

# Change working directory up one level before deleting current folder
Set-Location (Join-Path $targetDir '..')

Write-Host "[+] Deleting test suite: $targetDir..." -ForegroundColor Yellow
Remove-Item -Path $targetDir -Recurse -Force
Write-Host "[OK] Test suite successfully removed. Workspace is clean!" -ForegroundColor Green
