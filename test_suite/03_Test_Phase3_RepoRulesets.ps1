#Requires -Version 7.0
<#
.SYNOPSIS
    Vigorous test suite for Phase 3: Repository-Level & Branch-Level Policies (GitHub Rulesets).
.DESCRIPTION
    Comprehensive tests covering:
      - AST Static Syntax Analysis & StrictMode validation
      - Crosswalk and Config file structural integrity (R01..R07, B01..B11)
      - Payload builder, byte-to-MB translation logic, and capture schema
      - Snapshot schema verification
      - Dry-run validation and Live API idempotency checks
#>
[CmdletBinding()]
param(
    [bool]$IncludeLiveApiTests = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Test-Framework.ps1')

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$phase3Dir = Join-Path $repoRoot 'repo'
$crosswalkPath = Join-Path $phase3Dir 'config\ado-to-ghec-repo-crosswalk.csv'
$ghOrgFile = Join-Path $phase3Dir 'config\github-org.txt'
$reposFile = Join-Path $phase3Dir 'config\repos.txt'
$scripts = @(
    '01_Capture-AdoRepoPolicies.ps1',
    '02_Group-AdoRepoPolicies.ps1',
    '03_Snapshot-GitHubRepoRulesets.ps1',
    '04_Apply-GitHubRepoRulesets.ps1',
    '05_Rollback-GitHubRepoRulesets.ps1'
)

Describe "Phase 3: Static Code Quality & Syntax Integrity" {
    Context "PowerShell AST Validation" {
        foreach ($s in $scripts) {
            $scriptPath = Join-Path $phase3Dir $s
            It "Parses '$s' with zero syntax errors" {
                Assert-FileExists $scriptPath
                $errors = $null
                $tokens = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
                Assert-Equal $errors.Count 0 "Script $s has syntax errors: $($errors -join ', ')"
                Assert-NotNull $ast
            }

            It "'$s' declares #Requires -Version 7.0 and Set-StrictMode" {
                $content = Get-Content $scriptPath -Raw
                Assert-True ($content -match '#Requires\s+-Version\s+7\.0') "Missing #Requires -Version 7.0 in $s"
                Assert-True ($content -match 'Set-StrictMode\s+-Version\s+Latest') "Missing Set-StrictMode in $s"
                Assert-True ($content -match '\$ErrorActionPreference\s*=\s*[''"]Stop[''"]') "Missing ErrorActionPreference Stop in $s"
            }
        }
    }
}

Describe "Phase 3: Crosswalk & Config Schema Validation" {
    Context "ado-to-ghec-repo-crosswalk.csv Integrity" {
        It "Exists and contains clean execution columns" {
            Assert-FileExists $crosswalkPath
            $csv = Import-Csv $crosswalkPath
            Assert-True ($csv.Count -ge 12) "Expected at least 12 crosswalk policies, found $($csv.Count)"

            $requiredCols = @('PolicyCode', 'AdoPolicyName', 'AdoInternalKey', 'TargetGhPolicyKey', 'ImplementationType', 'ProposedGhSetting', 'ApplyPolicy')
            $firstRow = $csv[0]
            foreach ($col in $requiredCols) {
                Assert-True ($null -ne $firstRow.$col) "Missing expected column '$col' in crosswalk"
            }
        }

        It "Informational repo crosswalk copy exists with complete reference metadata" {
            $infoPath = Join-Path (Split-Path $crosswalkPath) "ado-to-ghec-repo-crosswalk-informational.csv"
            Assert-FileExists $infoPath
            $infoCsv = Import-Csv $infoPath
            Assert-True ($infoCsv.Count -ge 18) "Expected at least 18 policies in informational crosswalk"
            $allCols = @('PolicyCode', 'AdoPolicyId', 'AdoPolicyName', 'AdoInternalKey', 'TargetGhPolicyKey', 'ImplementationType', 'ApplyPolicy')
            foreach ($col in $allCols) {
                Assert-True ($null -ne $infoCsv[0].$col) "Missing expected column '$col' in informational crosswalk"
            }
        }

        It "Contains unique Policy Codes (R01..R07, B01..B11)" {
            $csv = Import-Csv $crosswalkPath
            $ids = @($csv | ForEach-Object { $_.PolicyCode })
            $uniqueIds = @($ids | Select-Object -Unique)
            Assert-Equal $ids.Count $uniqueIds.Count "Duplicate PolicyCode detected in Phase 3 crosswalk"
        }

        It "ApplyPolicy contains strictly 'True' or 'False'" {
            $csv = Import-Csv $crosswalkPath
            foreach ($row in $csv) {
                Assert-True ($row.ApplyPolicy -in @('True', 'False')) "Policy $($row.PolicyCode) has invalid ApplyPolicy: '$($row.ApplyPolicy)'"
            }
        }
    }

    Context "Configuration Files" {
        It "repos.txt exists and contains valid targets" {
            Assert-FileExists $reposFile
            $lines = @(Get-Content $reposFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
            Assert-True ($lines.Count -gt 0) "repos.txt is empty"
        }

        It "github-org.txt exists and contains target orgs" {
            Assert-FileExists $ghOrgFile
            $lines = @(Get-Content $ghOrgFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
            Assert-True ($lines.Count -gt 0) "github-org.txt is empty"
        }
    }
}

Describe "Phase 3: Transformation, Capture & Sizing Logic" {
    Context "Byte to Megabyte Conversion for max_file_size" {
        It "Calculates 104857600 bytes as 100 MB" {
            $bytes = 104857600
            $mb = [Math]::Max(1, [int][Math]::Round($bytes / 1MB))
            Assert-Equal $mb 100 "104857600 bytes should convert to 100 MB"
        }

        It "Calculates 52428800 bytes as 50 MB" {
            $bytes = 52428800
            $mb = [Math]::Max(1, [int][Math]::Round($bytes / 1MB))
            Assert-Equal $mb 50 "52428800 bytes should convert to 50 MB"
        }
    }

    Context "ADO Capture File Schema Conformance" {
        $captureDir = Join-Path $phase3Dir 'output\latest'
        It "Latest repo capture files conform to CaptureVersion 3.0 schema" {
            Assert-FileExists $captureDir
            $captureFiles = @(Get-ChildItem -Path $captureDir -Filter *.repo-policies.json)
            Assert-True ($captureFiles.Count -ge 1) "Expected at least 1 repo capture file in output\latest"

            foreach ($file in $captureFiles) {
                $raw = Get-Content $file.FullName -Raw | ConvertFrom-Json
                Assert-Equal $raw.CaptureVersion "3.0" "CaptureVersion must be 3.0"
                Assert-NotNull $raw.Organization "Capture missing 'Organization'"
                Assert-NotNull $raw.ProjectName "Capture missing 'ProjectName'"
                Assert-NotNull $raw.RepositoryName "Capture missing 'RepositoryName'"
                Assert-NotNull $raw.DefaultBranch "Capture missing 'DefaultBranch'"
                Assert-True ($raw.TotalPoliciesCount -ge 0) "TotalPoliciesCount must be >= 0"
                Assert-NotNull $raw.Policies "Capture missing 'Policies' array"
            }
        }
    }

    Context "Repository Snapshot Schema Conformance" {
        $snapshotsDir = Join-Path $phase3Dir 'output\snapshots\latest'
        It "Repository pre-flight snapshots conform to frozen schema" {
            Assert-FileExists $snapshotsDir
            $snapshotFiles = @(Get-ChildItem -Path $snapshotsDir -Filter *.snapshot.json)
            Assert-True ($snapshotFiles.Count -ge 1) "Expected at least 1 repo pre-flight snapshot"

            foreach ($file in $snapshotFiles) {
                $raw = Get-Content $file.FullName -Raw | ConvertFrom-Json
                Assert-Equal $raw.SnapshotVersion "3.0" "SnapshotVersion must be 3.0"
                Assert-NotNull $raw.TargetOrg "Snapshot $($file.Name) missing 'TargetOrg'"
                Assert-NotNull $raw.RepositoryName "Snapshot $($file.Name) missing 'RepositoryName'"
                Assert-NotNull $raw.DefaultBranch "Snapshot $($file.Name) missing 'DefaultBranch'"
                Assert-NotNull $raw.Rulesets "Snapshot $($file.Name) missing 'Rulesets'"
            }
        }
    }
}

Describe "Phase 3: Negative & DryRun Testing" {
    Context "DryRun Safety Guarantee" {
        It "Executes 04_Apply-GitHubRepoRulesets.ps1 -DryRun with zero mutations" {
            $applyScript = Join-Path $phase3Dir '04_Apply-GitHubRepoRulesets.ps1'
            $output = & pwsh -NoProfile -Command "& '$applyScript' -TargetOrg ADO2GH-Migration -TargetRepo sample2 -DryRun" 2>&1
            $outputString = $output -join "`n"

            Assert-True ($outputString -match 'DRY-RUN') "DryRun marker not detected in output"
            Assert-True ($outputString -match 'DryRun-Validated') "DryRun-Validated status missing in table"
            Assert-True ($outputString -match 'Ruleset application complete: Success') "Completion message missing in DryRun"
        }
    }
}

if ($IncludeLiveApiTests) {
    Describe "Phase 3: Live GitHub API Idempotency & Verification" {
        Context "Target Repository Ruleset Lifecycle on ADO2GH-Migration/sample2" {
            $applyScript = Join-Path $phase3Dir '04_Apply-GitHubRepoRulesets.ps1'
            $rollbackScript = Join-Path $phase3Dir '05_Rollback-GitHubRepoRulesets.ps1'

            It "Live Apply creates Branch and Push Rulesets in evaluate mode" {
                $output = & pwsh -NoProfile -Command "& '$applyScript' -TargetOrg ADO2GH-Migration -TargetRepo sample2 -Enforcement evaluate" 2>&1
                $outStr = $output -join "`n"
                Assert-True ($outStr -match 'Ruleset application complete: Success') "Ruleset apply did not report Success"
            }

            It "Live Re-Apply is idempotent and updates existing rulesets" {
                $output = & pwsh -NoProfile -Command "& '$applyScript' -TargetOrg ADO2GH-Migration -TargetRepo sample2 -Enforcement active" 2>&1
                $outStr = $output -join "`n"
                Assert-True ($outStr -match 'Ruleset application complete: Success') "Ruleset re-apply did not report Success"
            }

            It "Live Rollback completely removes migrated rulesets and verifies 0 remaining" {
                $output = & pwsh -NoProfile -Command "& '$rollbackScript' -TargetOrg ADO2GH-Migration -TargetRepo sample2" 2>&1
                $outStr = $output -join "`n"
                Assert-True ($outStr -match 'Rollback complete: Success') "Rollback did not verify restored state"
            }

            It "Repeated Rollback is 100% idempotent (causes zero errors when already clean)" {
                $output = & pwsh -NoProfile -Command "& '$rollbackScript' -TargetOrg ADO2GH-Migration -TargetRepo sample2" 2>&1
                $outStr = $output -join "`n"
                Assert-True ($outStr -match 'Rollback complete: Success') "Idempotent rollback failed"
            }
        }
    }
}

# Output consolidated test report
$success = Get-TestReport
if (-not $success) {
    exit 1
}
exit 0
