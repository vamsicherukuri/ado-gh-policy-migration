#Requires -Version 7.0
<#
.SYNOPSIS
    Stages transformed safe-settings YAML configurations into a Safe-Settings administrative
    repository, commits the changes to a migration branch, and opens a Pull Request for review.

.DESCRIPTION
    This script implements the GitOps approval gate:
      1. Verifies clean working tree.
      2. Checks out or creates a dedicated migration branch (non-destructively).
      3. Copies .github/ configuration files to the target Safe-Settings repository.
      4. Commits the new/updated policy files.
      5. Pushes safely and opens a Pull Request with MIGRATION-REPORT.md as the body.
      6. Traps all native CLI exit codes immediately to prevent false success reporting.

.EXAMPLE
    .\scripts\pipeline\Submit-SafeSettingsPR.ps1 -AdminRepoPath "..\safe-settings-admin" -ProjectName "project1" -CreatePr
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AdminRepoPath,

    [string]$ProjectName = "project1",

    [string]$StagedDir = (Join-Path $PSScriptRoot "..\..\output\safe-settings"),

    [string]$BranchName = "migration/ado-$ProjectName",

    [switch]$CreatePr,

    [switch]$ForceBranchOverwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-GitCommand {
    param(
        [scriptblock]$Action,
        [string]$ErrorMessage
    )

    $output = & $Action
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "$ErrorMessage (Exit code: $code)"
    }
    return $output
}

if (-not (Test-Path $AdminRepoPath)) {
    throw "Safe-Settings admin repository path not found: $AdminRepoPath"
}

$stagedGithubDir = Join-Path $StagedDir ".github"
if (-not (Test-Path $stagedGithubDir)) {
    throw "Staged safe-settings directory not found at: $stagedGithubDir. Run Convert-AdoToSafeSettings.ps1 first."
}

Write-Host "Target Safe-Settings Admin Repo: $AdminRepoPath" -ForegroundColor Cyan
Push-Location $AdminRepoPath

try {
    # 1. Verify clean working tree
    $status = Invoke-GitCommand { git status --porcelain } "Failed to check git status in admin repo"
    if ($status) {
        throw "Admin repository working directory is not clean. Commit or stash existing changes before staging migration."
    }

    # 2. Safe checkout (avoid unconditional -B overwrite unless explicitly requested)
    Write-Host "Checking out branch: $BranchName" -ForegroundColor Cyan
    $branchExistsLocally = $null
    & git show-ref --verify --quiet "refs/heads/$BranchName"
    if ($LASTEXITCODE -eq 0) {
        $branchExistsLocally = $true
    }

    if ($branchExistsLocally -and -not $ForceBranchOverwrite) {
        Invoke-GitCommand { git checkout $BranchName } "Failed to switch to existing branch '$BranchName'"
    } else {
        $checkoutFlag = if ($ForceBranchOverwrite) { "-B" } else { "-b" }
        Invoke-GitCommand { git checkout $checkoutFlag $BranchName } "Failed to checkout branch '$BranchName'"
    }

    # 3. Copy staged files into the admin repo
    $targetGithubDir = Join-Path $AdminRepoPath ".github"
    $null = New-Item -ItemType Directory -Path $targetGithubDir -Force
    Copy-Item -Path "$stagedGithubDir\*" -Destination $targetGithubDir -Recurse -Force

    # 4. Stage & Commit
    Invoke-GitCommand { git add .github/ } "Failed to stage .github directory"
    $hasDiff = Invoke-GitCommand { git status --porcelain } "Failed to check diff status after staging"
    if (-not $hasDiff) {
        Write-Host "No changes detected. Target repository already has identical policy configurations." -ForegroundColor Yellow
        return
    }

    $commitMsg = "feat(policy): migrate ADO policies for project '$ProjectName'"
    Invoke-GitCommand { git commit -m $commitMsg } "Failed to commit policy changes"
    Write-Host "Committed policy updates: $commitMsg" -ForegroundColor Green

    # 5. Optionally Push & Open Pull Request (Safe push without --force)
    if ($CreatePr) {
        Write-Host "Pushing branch to remote..." -ForegroundColor Cyan
        Invoke-GitCommand { git push -u origin $BranchName } "Failed to push branch '$BranchName' to origin"

        $reportPath = Join-Path $StagedDir "MIGRATION-REPORT.md"
        $prTitle = "Policy Migration: ADO Project '$ProjectName'"
        
        Write-Host "Opening Pull Request..." -ForegroundColor Cyan
        if (Test-Path $reportPath) {
            Invoke-GitCommand { gh pr create --title $prTitle --body-file $reportPath } "Failed to create Pull Request"
        } else {
            Invoke-GitCommand { gh pr create --title $prTitle --body "Automated ADO to GitHub policy migration for project $ProjectName." } "Failed to create Pull Request"
        }
        Write-Host "Pull Request created successfully. Safe-Settings dry-run will evaluate changes." -ForegroundColor Green
    } else {
        Write-Host "`nStaging complete on branch '$BranchName'." -ForegroundColor Yellow
        Write-Host "To push and open PR manually, run:" -ForegroundColor Yellow
        Write-Host "  cd `"$AdminRepoPath`""
        Write-Host "  git push -u origin $BranchName"
        Write-Host "  gh pr create --title `"Policy Migration: $ProjectName`" --body-file `"$StagedDir\MIGRATION-REPORT.md`""
    }
} finally {
    Pop-Location
}
