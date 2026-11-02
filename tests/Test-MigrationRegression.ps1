#Requires -Version 7.0
<#
.SYNOPSIS
    Regression test suite covering precision mapping edge cases:
      1. Configuration keys (suborgrepos, rulesets)
      2. Multi-repo and ref tuples (Prefix matchKind -> **)
      3. Capture ambiguity detection (rejects unspecific/duplicate matches)
      4. Advisory vs blocking partitioning (isBlocking=false -> evaluate)
      5. Required reviewers marked as Partial with identity details
      6. Commit author email dedicated ref metadata ruleset (~ALL, all patterns)
      7. CLI error trapping (detects failures in git/gh)
      8. Merge-only policy produces required_approving_review_count = 0
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = $PSScriptRoot
$transformDir = Join-Path $scriptRoot "..\scripts\transform"
$pipelineDir = Join-Path $scriptRoot "..\scripts\pipeline"
$testOutput = Join-Path $scriptRoot "..\output\test-regression"

# Load modules
. (Join-Path $transformDir "ConvertTo-Yaml.ps1")

$passCount = 0
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "Assertion Failed: $Message"
    }
    $script:passCount++
}

function Assert-Throws([scriptblock]$Block, [string]$ExpectedMessageSubstring, [string]$Message) {
    $threw = $false
    try {
        & $Block
    } catch {
        $threw = $true
        if ($ExpectedMessageSubstring -and $_.Exception.Message -notlike "*$ExpectedMessageSubstring*") {
            throw "Expected exception containing '$ExpectedMessageSubstring' but got: $($_.Exception.Message)"
        }
    }
    if (-not $threw) {
        throw "Assertion Failed: Expected exception was not thrown. $Message"
    }
    $script:passCount++
}

Write-Host "`nRunning Migration Edge Case Regression Tests..." -ForegroundColor Cyan

# Clean scratch directory
Remove-Item -Recurse -Force $testOutput -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $testOutput -Force

# ---------------------------------------------------------------------------
# Test 1 & 2 & 4 & 5 & 6 & 9: Synthetic Multi-Scope Fixture Transformation
# ---------------------------------------------------------------------------
$syntheticAdo = [ordered]@{
    schemaVersion = "1.0"
    exportedAt = "2026-11-02T12:00:00Z"
    source = [ordered]@{
        organization = "contoso-org"
        project = "project-alpha"
        capturedAt = "2026-11-02T12:00:00Z"
    }
    references = [ordered]@{
        repositories = [ordered]@{
            "repo-1" = [ordered]@{ sourceId = "guid-1" }
            "repo-2" = [ordered]@{ sourceId = "guid-2" }
        }
    }
    policies = @(
        # 1. Blocking Reviewer Policy on Prefix ref refs/heads/policy-lab/
        [ordered]@{
            source = [ordered]@{ policyId = 101 }
            type = [ordered]@{ displayName = "Minimum number of reviewers"; id = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd" }
            isEnabled = $true
            isBlocking = $true
            isDeleted = $false
            scope = @(
                [ordered]@{
                    repository = $null
                    refName = "refs/heads/policy-lab/"
                    matchKind = "Prefix"
                }
            )
            settings = [ordered]@{
                minimumApproverCount = 2
                resetOnSourcePush = $true
            }
        },
        # 2. Advisory (isBlocking: false) status check on Default Branch
        [ordered]@{
            source = [ordered]@{ policyId = 102 }
            type = [ordered]@{ displayName = "Status"; id = "cbdc66da-9728-4af8-aada-9a5a32e4a226" }
            isEnabled = $true
            isBlocking = $false
            isDeleted = $false
            scope = @(
                [ordered]@{
                    repository = [ordered]@{ '$ref' = "repository:repo-1" }
                    refName = "refs/heads/main"
                    matchKind = "Exact"
                }
            )
            settings = [ordered]@{
                genre = "advisory"
                name = "linter"
            }
        },
        # 3. Merge-only policy (NO reviewer requirements)
        [ordered]@{
            source = [ordered]@{ policyId = 103 }
            type = [ordered]@{ displayName = "Require a merge strategy"; id = "fa4e907d-c16b-4a4c-9dfa-4916e5d171ab" }
            isEnabled = $true
            isBlocking = $true
            isDeleted = $false
            scope = @(
                [ordered]@{
                    repository = [ordered]@{ '$ref' = "repository:repo-2" }
                    refName = "refs/heads/release"
                    matchKind = "Exact"
                }
            )
            settings = [ordered]@{
                allowSquash = $true
            }
        },
        # 4. Required Reviewers (Named/Group)
        [ordered]@{
            source = [ordered]@{ policyId = 104 }
            type = [ordered]@{ displayName = "Required reviewers"; id = "fd2167ab-b0be-447a-8ec8-39368250530e" }
            isEnabled = $true
            isBlocking = $true
            isDeleted = $false
            scope = @(
                [ordered]@{
                    repository = [ordered]@{ '$ref' = "repository:repo-1" }
                    refName = "refs/heads/main"
                    matchKind = "Exact"
                }
            )
            settings = [ordered]@{
                requiredReviewerIds = @("user-guid-abc")
                filenamePatterns = @("/critical/*")
            }
        },
        # 5. Commit author email validation with multiple patterns
        [ordered]@{
            source = [ordered]@{ policyId = 105 }
            type = [ordered]@{ displayName = "Commit author email validation"; id = "77ed4bd3-b063-4689-934a-175e4d0a78d7" }
            isEnabled = $true
            isBlocking = $true
            isDeleted = $false
            scope = @(
                [ordered]@{
                    repository = $null
                    refName = $null
                    matchKind = $null
                }
            )
            settings = [ordered]@{
                authorEmailPatterns = @("*@company.com", "service-bot@partner.org")
            }
        }
    )
}

$fixturePath = Join-Path $testOutput "project-alpha.portable.json"
$syntheticAdo | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $fixturePath -Encoding utf8

# Execute transform
& (Join-Path $transformDir "Convert-AdoToSafeSettings.ps1") `
    -PortableJsonPath $fixturePath `
    -OutputDir $testOutput `
    -Enforcement "active"

$suborgFile = Join-Path $testOutput ".github\suborgs\project-alpha.yml"
$repo1File = Join-Path $testOutput ".github\repos\repo-1.yml"
$repo2File = Join-Path $testOutput ".github\repos\repo-2.yml"
$reportFile = Join-Path $testOutput "MIGRATION-REPORT.md"

Assert-True (Test-Path $suborgFile) "Suborg file created"
Assert-True (Test-Path $repo1File) "Repo 1 file created"
Assert-True (Test-Path $repo2File) "Repo 2 file created"

$suborgText = Get-Content -LiteralPath $suborgFile -Raw
$repo1Text = Get-Content -LiteralPath $repo1File -Raw
$repo2Text = Get-Content -LiteralPath $repo2File -Raw
$reportText = Get-Content -LiteralPath $reportFile -Raw

# --- Fix 1: Safe-Settings configuration keys ---
Assert-True ($suborgText -match '(?m)^suborgrepos:') "Suborg uses top-level 'suborgrepos:'"
Assert-True ($suborgText -match '(?m)^rulesets:') "Suborg uses top-level 'rulesets:'"
Assert-True ($suborgText -notmatch 'suborg\.repos') "Suborg does not use invalid suborg.repos"
Assert-True ($suborgText -notmatch 'repository_rulesets:') "Suborg does not use repository_rulesets:"
Assert-True ($repo1Text -match '(?m)^rulesets:') "Repo uses top-level 'rulesets:'"

# --- Fix 2: Source Scope Tuples & Prefix Semantics ---
Assert-True ($suborgText -match 'refs/heads/policy-lab/\*\*') "Prefix match translated to fnmatch '**'"
Assert-True ($repo1Text -match 'refs/heads/main') "Exact match preserved"

# --- Fix 4: Optional Policy Partitioning ---
Assert-True ($repo1Text -match 'enforcement: evaluate') "Advisory (isBlocking=false) policy mapped to ruleset enforcement: evaluate"
Assert-True ($repo1Text -notmatch 'isBlocking') "Rule object does not leak internal isBlocking property"

# --- Fix 5: Required Reviewers Partial Status ---
Assert-True ($reportText -match 'Required reviewers.*Partial / Manual Configuration Required') "Required reviewers categorized as Partial"
Assert-True ($reportText -match 'CODEOWNERS') "Report explains CODEOWNERS prerequisite"

# --- Fix 6: Author Email Ruleset (Branch target, ~ALL, multiple patterns) ---
Assert-True ($suborgText -match 'name:.*email.*|.*commit-metadata.*') "Dedicated metadata ruleset exists"
Assert-True ($suborgText -match 'target: branch') "Email metadata ruleset targets branch (not push)"
Assert-True ($suborgText -match '~ALL') "Email metadata ruleset targets ~ALL"
Assert-True ($suborgText -match '@company\.com' -and $suborgText -match 'service-bot@partner\.org') "Both email patterns preserved"

# --- Fix 9: Merge-Only Zero Approvals ---
Assert-True ($repo2Text -match 'required_approving_review_count: 0') "Merge-only policy explicitly sets approvals to 0"
Assert-True ($reportText -match 'Require a merge strategy.*PR requirement') "Report explains merge method introduces PR requirement"

# ---------------------------------------------------------------------------
# Test 3: Capture Ambiguity Detection
# ---------------------------------------------------------------------------
$ambiguousSummary = [ordered]@{
    captures = @(
        [ordered]@{ organization = "org-dup"; project = "project-dup"; capture = "c:\captures\proj1.capture.json"; repositories = @("r1") },
        [ordered]@{ organization = "org-dup"; project = "project-dup"; capture = "c:\captures\proj2.capture.json"; repositories = @("r2") }
    )
}
$ambiguousSummaryPath = Join-Path $testOutput "capture-summary.json"
$ambiguousSummary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ambiguousSummaryPath -Encoding utf8

$ambiguousPortable = [ordered]@{
    source = [ordered]@{ organization = "org-dup"; project = "project-dup" }
    policies = @()
}
$ambiguousPortablePath = Join-Path $testOutput "ambiguous.portable.json"
$ambiguousPortable | ConvertTo-Json | Set-Content -LiteralPath $ambiguousPortablePath -Encoding utf8

Assert-Throws {
    & (Join-Path $transformDir "Convert-AdoToSafeSettings.ps1") `
        -PortableJsonPath $ambiguousPortablePath `
        -OutputDir (Join-Path $testOutput "out-ambig")
} "Ambiguous" "Ambiguous capture match throws an explicit error"

# ---------------------------------------------------------------------------
# Test 7: CLI Failure Trapping in Submit-SafeSettingsPR.ps1
# ---------------------------------------------------------------------------
$dummyAdminRepo = Join-Path $testOutput "dummy-admin-repo"
$null = New-Item -ItemType Directory -Path $dummyAdminRepo -Force

# Running against a non-git directory must fail immediately
Assert-Throws {
    & (Join-Path $pipelineDir "Submit-SafeSettingsPR.ps1") `
        -AdminRepoPath $dummyAdminRepo `
        -StagedDir $testOutput `
        -ProjectName "project-alpha"
} "" "Submit-SafeSettingsPR fails on git status failure in non-git directory"

# Clean scratch directory
Remove-Item -Recurse -Force $testOutput -ErrorAction SilentlyContinue

Write-Host "`nALL REGRESSION SPEC TESTS PASSED ($passCount assertions)" -ForegroundColor Green
