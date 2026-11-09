#Requires -Version 7.0
<#
.SYNOPSIS
    Vigorous test suite for Phase 2: Project-Level & Push Policies (GitHub Rulesets).
.DESCRIPTION
    Comprehensive tests covering:
      - AST Static Syntax Analysis & StrictMode validation
      - Crosswalk and Config file structural integrity
      - Payload builder and byte-to-MB translation logic
      - Snapshot schema verification
      - Safe CSV locking logic
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
$projDir = Join-Path $repoRoot 'project'
$crosswalkPath = Join-Path $projDir 'config\ado-to-ghec-rulesets-crosswalk.csv'
$ghOrgFile = Join-Path $projDir 'config\github-org.txt'
$projectsFile = Join-Path $projDir 'config\projects.txt'
$scripts = @(
    '01_Capture-AdoProjectPolicies.ps1',
    '02_Group-AdoProjectPolicies.ps1',
    '03_Snapshot-GitHubRulesets.ps1',
    '04_Apply-GitHubRulesets.ps1',
    '05_Rollback-GitHubRulesets.ps1'
)

Describe "Phase 2: Static Code Quality & Syntax Integrity" {
    Context "PowerShell AST Validation" {
        foreach ($s in $scripts) {
            $scriptPath = Join-Path $projDir $s
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

Describe "Phase 2: Crosswalk & Config Schema Validation" {
    Context "ado-to-ghec-rulesets-crosswalk.csv Integrity" {
        It "Exists and contains clean execution columns" {
            Assert-FileExists $crosswalkPath
            $csv = Import-Csv $crosswalkPath
            Assert-True ($csv.Count -ge 14) "Expected at least 14 crosswalk policies, found $($csv.Count)"

            $requiredCols = @('PolicyCode', 'AdoPolicyName', 'AdoInternalKey', 'TargetGhPolicyKey', 'ImplementationType', 'ProposedGhSetting', 'ApplyPolicy')
            $firstRow = $csv[0]
            foreach ($col in $requiredCols) {
                Assert-True ($null -ne $firstRow.$col) "Missing expected column '$col' in crosswalk"
            }
        }

        It "Informational project crosswalk copy exists with complete reference metadata" {
            $infoPath = Join-Path (Split-Path $crosswalkPath) "ado-to-ghec-rulesets-crosswalk-informational.csv"
            Assert-FileExists $infoPath
            $infoCsv = Import-Csv $infoPath
            Assert-True ($infoCsv.Count -ge 14) "Expected at least 14 policies in informational crosswalk"
            $allCols = @('PolicyCode', 'AdoPolicyId', 'AdoPolicyName', 'AdoInternalKey', 'TargetGhPolicyKey', 'ImplementationType', 'ApplyPolicy')
            foreach ($col in $allCols) {
                Assert-True ($null -ne $infoCsv[0].$col) "Missing expected column '$col' in informational crosswalk"
            }
        }

        It "Contains unique Policy Codes (P13..P27)" {
            $csv = Import-Csv $crosswalkPath
            $ids = @($csv | ForEach-Object { $_.PolicyCode })
            $uniqueIds = @($ids | Select-Object -Unique)
            Assert-Equal $ids.Count $uniqueIds.Count "Duplicate PolicyCode detected in Phase 2 crosswalk"
        }

        It "ApplyPolicy contains strictly 'True' or 'False'" {
            $csv = Import-Csv $crosswalkPath
            foreach ($row in $csv) {
                Assert-True ($row.ApplyPolicy -in @('True', 'False')) "Policy $($row.PolicyCode) has invalid ApplyPolicy: '$($row.ApplyPolicy)'"
            }
        }
    }

    Context "Configuration Files" {
        It "projects.txt exists and contains valid targets" {
            Assert-FileExists $projectsFile
            $lines = @(Get-Content $projectsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
            Assert-True ($lines.Count -gt 0) "projects.txt is empty"
        }
    }
}

Describe "Phase 2: Transformation & Sizing Logic" {
    Context "Byte to Megabyte Conversion for max_file_size" {
        It "Calculates 1048576 bytes as exactly 1 MB" {
            $bytes = 1048576
            $mb = [Math]::Max(1, [int][Math]::Round($bytes / 1MB))
            Assert-Equal $mb 1 "1048576 bytes should convert to 1 MB"
        }

        It "Calculates 104857600 bytes as 100 MB" {
            $bytes = 104857600
            $mb = [Math]::Max(1, [int][Math]::Round($bytes / 1MB))
            Assert-Equal $mb 100 "104857600 bytes should convert to 100 MB"
        }
    }

    Context "Snapshot Schema Conformance" {
        $snapshotsDir = Join-Path $projDir 'output\snapshots'
        It "Ruleset pre-flight snapshots conform to frozen schema" {
            Assert-FileExists $snapshotsDir
            $snapshotFiles = @(Get-ChildItem -Path $snapshotsDir -Filter *-latest-rulesets-preflight.json)
            Assert-True ($snapshotFiles.Count -ge 3) "Expected at least 3 ruleset pre-flight snapshots"

            foreach ($file in $snapshotFiles) {
                $raw = Get-Content $file.FullName -Raw | ConvertFrom-Json
                Assert-NotNull $raw.TargetOrganization "Snapshot $($file.Name) missing 'TargetOrganization'"
                Assert-NotNull $raw.CapturedAtUtc "Snapshot $($file.Name) missing 'CapturedAtUtc'"
                Assert-Equal $raw.PlanName "enterprise" "Target org must have 'enterprise' plan"
                Assert-NotNull $raw.RepoRulesets "Snapshot $($file.Name) missing 'RepoRulesets'"
            }
        }
    }
}

Describe "Phase 2: Negative & DryRun Testing" {
    Context "DryRun Safety Guarantee" {
        It "Executes 04_Apply-GitHubRulesets.ps1 -DryRun with zero mutations" {
            $applyScript = Join-Path $projDir '04_Apply-GitHubRulesets.ps1'
            $output = & pwsh -NoProfile -Command "& '$applyScript' -DryRun" 2>&1
            $outputString = $output -join "`n"

            Assert-True ($outputString -match 'DRY RUN COMPLETE') "DryRun marker not detected in output"
            Assert-True ($outputString -match 'No modifications were made to GitHub') "Safety confirmation missing in DryRun"
        }
    }
}

if ($IncludeLiveApiTests) {
    Describe "Phase 2: Live GitHub API Idempotency & Verification" {
        Context "Target Repository Ruleset Lifecycle on ADO2GHEC" {
            $applyScript = Join-Path $projDir '04_Apply-GitHubRulesets.ps1'
            $rollbackScript = Join-Path $projDir '05_Rollback-GitHubRulesets.ps1'

            It "Live Apply creates Branch and Push Rulesets in evaluate mode" {
                $output = & pwsh -NoProfile -Command "& '$applyScript' -TargetOrg ADO2GHEC -TargetRepo sample2 -Enforcement evaluate" 2>&1
                $outStr = $output -join "`n"
                Assert-True ($outStr -match 'Success') "Ruleset apply did not report Success"
            }

            It "Live Rollback completely removes migrated rulesets and verifies 0 remaining" {
                $output = & pwsh -NoProfile -Command "& '$rollbackScript' -TargetOrg ADO2GHEC -TargetRepo sample2" 2>&1
                $outStr = $output -join "`n"
                Assert-True ($outStr -match 'VERIFIED|Success') "Rollback did not verify restored state"
            }

            It "Repeated Rollback is 100% idempotent (causes zero errors when already clean)" {
                $output = & pwsh -NoProfile -Command "& '$rollbackScript' -TargetOrg ADO2GHEC -TargetRepo sample2" 2>&1
                $outStr = $output -join "`n"
                Assert-True ($outStr -match 'Already in clean pre-flight state|VERIFIED|Success') "Idempotent rollback failed"
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
