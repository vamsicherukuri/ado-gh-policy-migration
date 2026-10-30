#Requires -Version 7.0
<#
.SYNOPSIS
    Stages transformed safe-settings YAML configurations into a Safe-Settings administrative
    repository, commits the changes to a migration branch, and opens a Pull Request for review.

.DESCRIPTION
    This script implements the GitOps approval gate:
      1. Copies .github/ configuration files to the target Safe-Settings repository.
      2. Creates a dedicated migration branch.
      3. Commits the new/updated policy files.
      4. Opens a Pull Request with MIGRATION-REPORT.md as the body.
      5. Safe-Settings automatically triggers its Dry-Run check and posts diff comments on the PR.

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

    [switch]$CreatePr
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
    # 1. Ensure working directory is clean
    $status = git status --porcelain
    if ($status) {
        throw "Admin repository working directory is not clean. Commit or stash existing changes before staging migration."
    }

    # 2. Checkout or create migration branch
    Write-Host "Checking out branch: $BranchName" -ForegroundColor Cyan
    git checkout -B $BranchName

    # 3. Copy staged files into the admin repo
    $targetGithubDir = Join-Path $AdminRepoPath ".github"
    $null = New-Item -ItemType Directory -Path $targetGithubDir -Force
    Copy-Item -Path "$stagedGithubDir\*" -Destination $targetGithubDir -Recurse -Force

    # 4. Stage & Commit
    git add .github/
    $hasDiff = git status --porcelain
    if (-not $hasDiff) {
        Write-Host "No changes detected. Target repository already has identical policy configurations." -ForegroundColor Yellow
        return
    }

    $commitMsg = "feat(policy): migrate ADO policies for project '$ProjectName'"
    git commit -m $commitMsg
    Write-Host "Committed policy updates: $commitMsg" -ForegroundColor Green

    # 5. Optionally Push & Open Pull Request
    if ($CreatePr) {
        Write-Host "Pushing branch to remote..." -ForegroundColor Cyan
        git push -u origin $BranchName --force

        $reportPath = Join-Path $StagedDir "MIGRATION-REPORT.md"
        $prTitle = "Policy Migration: ADO Project '$ProjectName'"
        
        Write-Host "Opening Pull Request..." -ForegroundColor Cyan
        if (Test-Path $reportPath) {
            gh pr create --title $prTitle --body-file $reportPath
        } else {
            gh pr create --title $prTitle --body "Automated ADO to GitHub policy migration for project $ProjectName."
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
