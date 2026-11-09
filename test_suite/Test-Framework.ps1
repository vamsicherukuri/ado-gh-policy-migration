#Requires -Version 7.0
<#
.SYNOPSIS
    Lightweight, standalone test runner for rigorous testing of ADO to GitHub migration scripts.
.DESCRIPTION
    Provides Describe/It test block assertions, timing, isolated execution, and formatted output.
#>

class TestState {
    [int]$Passed = 0
    [int]$Failed = 0
    [int]$Total = 0
    [System.Collections.Generic.List[string]]$Errors = [System.Collections.Generic.List[string]]::new()
    [System.Diagnostics.Stopwatch]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
}

$global:SuiteState = [TestState]::new()

function Describe {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script
    )
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " SUITE: $Name" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    & $Script
}

function Context {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script
    )
    Write-Host "`n  [$Name]" -ForegroundColor DarkCyan
    & $Script
}

function It {
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Test
    )
    $global:SuiteState.Total++
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Test
        $sw.Stop()
        $global:SuiteState.Passed++
        Write-Host "    [PASS] " -NoNewline -ForegroundColor Green
        Write-Host "$Description " -NoNewline -ForegroundColor White
        Write-Host "($($sw.ElapsedMilliseconds)ms)" -ForegroundColor DarkGray
    }
    catch {
        $sw.Stop()
        $global:SuiteState.Failed++
        $msg = $_.Exception.Message
        $global:SuiteState.Errors.Add("$Description -> $msg")
        Write-Host "    [FAIL] " -NoNewline -ForegroundColor Red
        Write-Host "$Description" -ForegroundColor Yellow
        Write-Host "           Error: $msg" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message = '')
    if ($Actual -ne $Expected) {
        $prefix = if ($Message) { "${Message}: " } else { "" }
        throw "${prefix}Expected '$Expected' but got '$Actual'"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message = 'Condition is not True')
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-False {
    param([bool]$Condition, [string]$Message = 'Condition is not False')
    if ($Condition) {
        throw $Message
    }
}

function Assert-NotNull {
    param($Value, [string]$Message = 'Value was null')
    if ($null -eq $Value) {
        throw $Message
    }
}

function Assert-FileExists {
    param([string]$Path, [string]$Message = '')
    if (-not (Test-Path -LiteralPath $Path)) {
        $prefix = if ($Message) { "${Message}: " } else { "" }
        throw "${prefix}File not found at: $Path"
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)][scriptblock]$Script,
        [string]$ExpectedMessagePattern = ''
    )
    $threw = $false
    try {
        & $Script
    }
    catch {
        $threw = $true
        if ($ExpectedMessagePattern -and ($_.Exception.Message -notmatch $ExpectedMessagePattern)) {
            throw "Expected exception matching '$ExpectedMessagePattern' but caught: $($_.Exception.Message)"
        }
    }
    if (-not $threw) {
        throw "Expected an exception to be thrown, but execution succeeded."
    }
}

function Get-TestReport {
    $global:SuiteState.Timer.Stop()
    Write-Host "`n------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " TEST RUN SUMMARY" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " Total Tests : $($global:SuiteState.Total)"
    Write-Host " Passed      : $($global:SuiteState.Passed)" -ForegroundColor Green
    Write-Host " Failed      : $($global:SuiteState.Failed)" -ForegroundColor $(if ($global:SuiteState.Failed -gt 0) { 'Red' } else { 'Green' })
    Write-Host " Duration    : $($global:SuiteState.Timer.Elapsed.TotalSeconds.ToString('F2'))s"

    if ($global:SuiteState.Failed -gt 0) {
        Write-Host "`n Failures:" -ForegroundColor Red
        foreach ($err in $global:SuiteState.Errors) {
            Write-Host "   - $err" -ForegroundColor Red
        }
        return $false
    }
    return $true
}
