#Requires -Version 7.0
<#
.SYNOPSIS
    Regression test suite covering precision mapping edge cases:
      1. Configuration keys (suborgrepos, rulesets)
      2. Multi-repo and ref tuples (Prefix matchKind -> pathname-aware patterns)
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
$testOutput = Join-Path ([IO.Path]::GetTempPath()) ("migration-regression-" + [guid]::NewGuid().ToString("N"))

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

try {
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
                statusGenre = "advisory"
                statusName = "linter"
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
                authorEmailPatterns = @("*@company.com", "*@*.partner.org", "bot+ci@ci.net")
            }
        }
    )
}

$fixturePath = Join-Path $testOutput "project-alpha.portable.json"
$syntheticAdo | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $fixturePath -Encoding utf8

$contextMapPath = Join-Path $testOutput "contexts.json"
@{ statuses = @{ "advisory/linter" = "advisory/linter" } } |
    ConvertTo-Json | Set-Content -LiteralPath $contextMapPath

# Dot-source the real transform so helper behavior can also be exercised.
. (Join-Path $transformDir "Convert-AdoToSafeSettings.ps1") `
    -PortableJsonPath $fixturePath `
    -OutputDir $testOutput `
    -CheckContextMapPath $contextMapPath `
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
Assert-True ($suborgText -match 'name:.*metadata') "Dedicated metadata ruleset exists"
Assert-True ($suborgText -match 'target: branch') "Email metadata ruleset targets branch (not push)"
Assert-True ($suborgText -match '~ALL') "Email metadata ruleset targets ~ALL"
Assert-True ($repo1Text -match 'context: advisory/linter') "Native ADO status field names map to the destination context"
$emailRuleset = @($projectBlocks.Rulesets | Where-Object { $_.name -match 'metadata' })[0]
Assert-True ($emailRuleset.rules.Count -eq 1) "Email alternatives emit one rule"
$emailParameters = $emailRuleset.rules[0].parameters
Assert-True ($emailParameters.operator -eq "regex") "Email operator conforms to GitHub schema"
foreach ($email in @("dev@company.com", "ops@sub.partner.org", "bot+ci@ci.net")) {
    Assert-True ([regex]::IsMatch($email, $emailParameters.pattern)) "Email allowlist accepts $email"
}
foreach ($email in @("attacker@fakecompany.com", "dev@company.com.attacker.com", "botxci@ci.net")) {
    Assert-True (-not [regex]::IsMatch($email, $emailParameters.pattern)) "Email allowlist rejects $email"
}

$prefixPatterns = @(Convert-AdoRefToGitHubPattern "refs/heads/release" Prefix "~DEFAULT_BRANCH")
Assert-True (($prefixPatterns -join ',') -eq 'refs/heads/release*,refs/heads/release*/**/*') "String prefix uses the documented recursive fnmatch subset"
$folderPatterns = @(Convert-AdoRefToGitHubPattern "refs/heads/policy-lab/" Prefix "~DEFAULT_BRANCH")
Assert-True (($folderPatterns -join ',') -eq 'refs/heads/policy-lab/**/*') "Folder prefix includes direct and deep descendants"
$matcherDir = Join-Path $testOutput "matcher"
$null = New-Item -ItemType Directory -Path $matcherDir
git -C $matcherDir init --quiet
if ($LASTEXITCODE -ne 0) { throw "Cannot initialize offline wildcard test repository" }
$prefixPatterns | Set-Content (Join-Path $matcherDir ".gitignore")
foreach ($ref in @("release", "release-candidate", "release/v1", "release-candidate/subbranch", "release/2026/01")) {
    git -C $matcherDir check-ignore --no-index --quiet "refs/heads/$ref"
    Assert-True ($LASTEXITCODE -eq 0) "Git pathname wildcard corpus includes $ref"
}
git -C $matcherDir check-ignore --no-index --quiet "refs/heads/not-release/v1"
Assert-True ($LASTEXITCODE -eq 1) "Prefix does not include unrelated branches"
$folderPatterns | Set-Content (Join-Path $matcherDir ".gitignore")
foreach ($ref in @("policy-lab/main", "policy-lab/a/b/c")) {
    git -C $matcherDir check-ignore --no-index --quiet "refs/heads/$ref"
    Assert-True ($LASTEXITCODE -eq 0) "Folder prefix includes $ref"
}
git -C $matcherDir check-ignore --no-index --quiet "refs/heads/policy-lab-candidate/main"
Assert-True ($LASTEXITCODE -eq 1) "Folder prefix preserves its slash boundary"

$items = [Collections.Generic.List[object]]::new()
foreach ($ref in @("refs/heads/release/a", "refs/heads/release-a")) {
    $items.Add(@{ Policy = @{ type = @{ displayName = "Minimum number of reviewers" }; settings = @{ minimumApproverCount = 2 } }; RefPattern = @($ref); IsBlocking = $true })
}
$names = (Build-SafeSettingsScopeBlocks $items "repo").Rulesets.name
Assert-True (@($names | Select-Object -Unique).Count -eq 2) "Different refs have distinct ruleset identities"
$items.Reverse()
$reorderedNames = (Build-SafeSettingsScopeBlocks $items "repo").Rulesets.name
Assert-True ((@($names | Sort-Object) -join ',') -eq (@($reorderedNames | Sort-Object) -join ',')) "Ruleset names are order-independent"
$projectNames = (Build-SafeSettingsScopeBlocks $items "repo" -ScopeKind project).Rulesets.name
Assert-True (@($names + $projectNames | Select-Object -Unique).Count -eq 4) "Project and repository layers cannot collide"
foreach ($counts in @(@(3, 1), @(1, 3), @(0, 0))) {
    $items.Clear()
    foreach ($count in $counts) {
        $items.Add(@{ Policy = @{ type = @{ displayName = "Minimum number of reviewers" }; settings = @{ minimumApproverCount = $count } }; RefPattern = @("refs/heads/main"); IsBlocking = $true })
    }
    $blocks = Build-SafeSettingsScopeBlocks $items "counts"
    Assert-True ($blocks.Rulesets[0].rules[0].parameters.required_approving_review_count -eq ($counts | Measure-Object -Maximum).Maximum) "Reviewer aggregation retains the maximum, including zero"
}
$items[0].Policy.settings.minimumApproverCount = -1
Assert-Throws { Build-SafeSettingsScopeBlocks $items "invalid" } "minimumApproverCount" "Negative reviewer counts fail explicitly"
$items.Clear()
$items.Add(@{
    Policy = @{ type = @{ displayName = "Minimum number of reviewers" }; settings = @{
        minimumApproverCount = 2; prohibitRequesterFromApproving = $true
    } }
    RefPattern = @("refs/heads/main"); IsBlocking = $true
})
$requesterBlocks = Build-SafeSettingsScopeBlocks $items "requester"
Assert-True (-not $requesterBlocks.Rulesets[0].rules[0].parameters.require_last_push_approval) "Requester restrictions do not invent last-pusher restrictions"
$Enforcement = "disabled"
$items[0].IsBlocking = $false
Assert-True ((Build-SafeSettingsScopeBlocks $items "advisory").Rulesets[0].enforcement -eq "disabled") "Explicit disabled overrides optional evaluate"
$Enforcement = "active"

$conversionFixture = @{
    source = @{ organization = "fixture"; project = "conversion" }
    references = @{ repositories = @{ repo = @{} } }
    policies = @(
        @{ type = @{ displayName = "File size restriction" }; settings = @{ maximumGitBlobSizeInBytes = 1500000 } },
        @{ type = @{ displayName = "Build" }; settings = @{ buildDefinitionId = 77 } }
    )
}
$conversionPath = Join-Path $testOutput "conversion.portable.json"
$conversionFixture | ConvertTo-Json -Depth 20 | Set-Content $conversionPath
$conversionOutput = Join-Path $testOutput "conversion"
& (Join-Path $transformDir "Convert-AdoToSafeSettings.ps1") -PortableJsonPath $conversionPath -OutputDir $conversionOutput
$conversionReport = Get-Content (Join-Path $conversionOutput "MIGRATION-REPORT.md") -Raw
$conversionYaml = Get-Content (Join-Path $conversionOutput ".github\suborgs\conversion.yml") -Raw
Assert-True ($conversionReport -match '1500000 bytes.*1048576 bytes') "Persisted report identifies the exact threshold tightening"
Assert-True ($conversionReport -match 'UNVERIFIED.*77') "Persisted report identifies the unresolved build ID"
Assert-True ($conversionYaml -notmatch 'required_status_checks|pipeline-77') "Unmapped builds never become guessed active checks"
$items.Clear()
foreach ($patterns in @(@("a?@company.com", "Z+ci@company.com"), @("*@partner.org"))) {
    $items.Add(@{
        Policy = @{ type = @{ displayName = "Commit author email validation" }; settings = @{ authorEmailPatterns = $patterns } }
        RefPattern = @("~ALL"); IsBlocking = $true
    })
}
$emailPolicies = (Build-SafeSettingsScopeBlocks $items "multiple-email-policies").Rulesets
Assert-True ($emailPolicies.Count -eq 2) "Different source email policies remain separate conjunctive rulesets"
Assert-True (@($emailPolicies | Where-Object { $_.rules.Count -ne 1 }).Count -eq 0) "Each email policy emits exactly one regex rule"
$wildcardRegex = Convert-EmailPatternsToRegex @("a?@company.com", "Z+ci@company.com")
Assert-True ("ab@company.com" -cmatch $wildcardRegex -and "abc@company.com" -cnotmatch $wildcardRegex) "Question-mark wildcards match exactly one character"
Assert-True ($wildcardRegex -ceq '^(Z\+ci@company\.com|a.@company\.com)$') "Regex alternatives use portable ordinal sorting"
Assert-Throws { Convert-EmailPatternsToRegex @("") } "empty patterns" "Empty email patterns are rejected"
$items.Clear()
$items.Add(@{
    Policy = @{ type = @{ displayName = "File size restriction" }; settings = @{ maximumGitBlobSizeInBytes = 500000 } }
    RefPattern = @("~ALL"); IsBlocking = $true
})
Assert-True ((Build-SafeSettingsScopeBlocks $items "small-file-limit").Rulesets.Count -eq 0) "Unrepresentable sub-MiB limits are omitted, not weakened"

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

Write-Host "`nALL REGRESSION SPEC TESTS PASSED ($passCount assertions)" -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $testOutput) { Remove-Item -LiteralPath $testOutput -Recurse -Force }
}
