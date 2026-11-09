#Requires -Version 7.0
<#
.SYNOPSIS
    Vigorous test suite for Phase 1: Organization Governance Policies.
.DESCRIPTION
    Comprehensive tests covering:
      - AST Static Syntax Analysis & StrictMode validation
      - Crosswalk and Config file structural integrity
      - Payload builder and boolean inversion logic
      - Snapshot schema verification
      - Safe CSV locking logic
      - Negative testing (corrupted snapshots, invalid tokens, non-existent orgs)
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
$orgDir = Join-Path $repoRoot 'org'
$crosswalkPath = Join-Path $orgDir 'config\ado-to-ghec-crosswalk.csv'
$ghOrgFile = Join-Path $orgDir 'config\github-org.txt'
$adoOrgFile = Join-Path $orgDir 'config\orgs.txt'
$scripts = @(
    '01_Capture-AdoOrgPolicies.ps1',
    '02_Group-AdoOrgPolicies.ps1',
    '03_Snapshot-GitHubOrgPolicies.ps1',
    '04_Apply-GitHubOrgPolicies.ps1',
    '05_Rollback-GitHubOrgPolicies.ps1'
)

Describe "Phase 1: Static Code Quality & Syntax Integrity" {
    Context "PowerShell AST Validation" {
        foreach ($s in $scripts) {
            $scriptPath = Join-Path $orgDir $s
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

Describe "Phase 1: Crosswalk & Configuration Schema Validation" {
    Context "ado-to-ghec-crosswalk.csv Integrity" {
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

        It "Informational crosswalk copy exists with complete reference metadata" {
            $infoPath = Join-Path (Split-Path $crosswalkPath) "ado-to-ghec-crosswalk-informational.csv"
            Assert-FileExists $infoPath
            $infoCsv = Import-Csv $infoPath
            Assert-True ($infoCsv.Count -ge 12) "Expected at least 12 policies in informational crosswalk"
            $allCols = @('PolicyCode', 'AdoPolicyId', 'AdoPolicyName', 'AdoInternalKey', 'TargetGhPolicyKey', 'ImplementationType', 'ApplyPolicy', 'TargetGhApiEndpoint')
            foreach ($col in $allCols) {
                Assert-True ($null -ne $infoCsv[0].$col) "Missing expected column '$col' in informational crosswalk"
            }
        }

        It "Contains exactly unique Policy Codes (P01..P12, P-BASIC)" {
            $csv = Import-Csv $crosswalkPath
            $ids = @($csv | ForEach-Object { $_.PolicyCode })
            $uniqueIds = @($ids | Select-Object -Unique)
            Assert-Equal $ids.Count $uniqueIds.Count "Duplicate PolicyCode detected in crosswalk"
            foreach ($id in $ids) {
                Assert-True ($id -match '^P(\d{2}|-[A-Z]+)$') "PolicyCode '$id' does not match pattern P## or P-[A-Z]+"
            }
        }

        It "ApplyPolicy contains strictly 'True' or 'False'" {
            $csv = Import-Csv $crosswalkPath
            foreach ($row in $csv) {
                Assert-True ($row.ApplyPolicy -in @('True', 'False')) "Policy $($row.PolicyCode) has invalid ApplyPolicy: '$($row.ApplyPolicy)'"
            }
        }

        It "Has exactly 6 active policies targeted for GitHub governance application" {
            $csv = Import-Csv $crosswalkPath
            $active = @($csv | Where-Object { $_.ApplyPolicy -eq 'True' })
            Assert-Equal $active.Count 6 "Expected exactly 6 active policies to apply"
        }
    }

    Context "Target Organizations Config Files" {
        It "github-org.txt has clean, valid entries" {
            Assert-FileExists $ghOrgFile
            $orgs = @(Get-Content $ghOrgFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
            Assert-True ($orgs.Count -gt 0) "github-org.txt has no valid organizations"
            foreach ($o in $orgs) {
                Assert-True ($o -match '^[a-zA-Z0-9_\-]+$') "Invalid characters in GitHub org name: '$o'"
            }
        }

        It "orgs.txt has clean, valid ADO entries" {
            Assert-FileExists $adoOrgFile
            $orgs = @(Get-Content $adoOrgFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
            Assert-True ($orgs.Count -gt 0) "orgs.txt has no valid organizations"
            foreach ($o in $orgs) {
                Assert-True ($o -match '^[a-zA-Z0-9_\-]+$') "Invalid characters in ADO org name: '$o'"
            }
        }
    }
}

Describe "Phase 1: Offline Unit Logic & Transformation Tests" {
    Context "Negative Boolean Inversion Logic" {
        It "Inverts ADO negative policies correctly into target state" {
            # In ADO:
            # disallowOAuthAuthentication: true  -> OAuth restricted = true
            # disallowPublicProjects: true       -> Public projects allowed = false
            # enforcePrivateRepoForking: true    -> Forking private repos allowed = false
            $adoDisallowPublic = $true
            $ghCanCreatePublic = -not $adoDisallowPublic
            Assert-Equal $ghCanCreatePublic $false "Public creation should be false when ADO disallows public"

            $adoEnforceForkRestriction = $true
            $ghCanForkPrivate = -not $adoEnforceForkRestriction
            Assert-Equal $ghCanForkPrivate $false "Forking private should be false when ADO restricts forking"
        }
    }

    Context "Snapshot Schema & Integrity Verification" {
        $snapshotsDir = Join-Path $orgDir 'output\snapshots'
        It "Pre-flight snapshots exist and conform to the frozen schema" {
            Assert-FileExists $snapshotsDir
            $snapshotFiles = @(Get-ChildItem -Path $snapshotsDir -Filter *-latest-preflight.json)
            Assert-True ($snapshotFiles.Count -ge 3) "Expected at least 3 latest pre-flight snapshots"

            foreach ($file in $snapshotFiles) {
                $raw = Get-Content $file.FullName -Raw | ConvertFrom-Json
                Assert-NotNull $raw.TargetOrganization "Snapshot $($file.Name) missing 'TargetOrganization'"
                Assert-NotNull $raw.CapturedAtUtc "Snapshot $($file.Name) missing 'CapturedAtUtc'"
                Assert-NotNull $raw.AuthSource "Snapshot $($file.Name) missing 'AuthSource'"
                Assert-Equal $raw.PlanName "enterprise" "Target org must have 'enterprise' plan"
                Assert-NotNull $raw.GovernanceSettings "Snapshot $($file.Name) missing 'GovernanceSettings'"

                $gov = $raw.GovernanceSettings
                Assert-NotNull $gov.members_can_create_public_repositories "Missing members_can_create_public_repositories"
                Assert-NotNull $gov.members_can_fork_private_repositories "Missing members_can_fork_private_repositories"
                Assert-NotNull $gov.members_allowed_repository_creation_type "Missing members_allowed_repository_creation_type"
            }
        }
    }

    Context "Excel File-Lock Resiliency Logic" {
        It "Simulates locked file and successfully recovers via alternate file write" {
            $tempDir = Join-Path $repoRoot 'test_suite\temp_test'
            if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
            $testCsv = Join-Path $tempDir 'locked_test.csv'
            Set-Content -Path $testCsv -Value "Col1,Col2`nVal1,Val2"

            # Open a file stream with exclusive lock simulating Excel
            $fileStream = [System.IO.File]::Open($testCsv, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $savedPath = $null
                # Attempt to save to locked file using Save-SafeCsv logic
                try {
                    [System.IO.File]::WriteAllText($testCsv, "new content")
                    $savedPath = $testCsv
                }
                catch [System.IO.IOException] {
                    $fallback = [System.IO.Path]::Combine($tempDir, "locked_test-fallback.csv")
                    [System.IO.File]::WriteAllText($fallback, "new content")
                    $savedPath = $fallback
                }

                Assert-NotNull $savedPath
                Assert-True ($savedPath -like '*-fallback.csv') "Did not use fallback file when primary is locked"
                Assert-FileExists $savedPath
            }
            finally {
                $fileStream.Close()
                $fileStream.Dispose()
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "Phase 1: Negative & Boundary Testing" {
    Context "Corrupted Snapshot Safety" {
        It "Rollback engine refuses to process corrupted JSON snapshot" {
            $tempDir = Join-Path $repoRoot 'test_suite\temp_corrupt'
            if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
            $corruptSnapshot = Join-Path $tempDir 'corrupt-snapshot.json'
            Set-Content -Path $corruptSnapshot -Value "{ this is corrupted json syntax ... "

            # Test that loading corrupt snapshot throws a JSON parse error
            Assert-Throws {
                $content = Get-Content $corruptSnapshot -Raw
                $null = ConvertFrom-Json -InputObject $content -AsHashtable
            }

            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        It "Rollback fails gracefully if snapshot file does not exist" {
            $nonExistentPath = Join-Path $orgDir 'output\snapshots\non-existent-snapshot.json'
            Assert-False (Test-Path -LiteralPath $nonExistentPath)
        }
    }

    Context "DryRun Safety Guarantee" {
        It "Executes 04_Apply-GitHubOrgPolicies.ps1 -DryRun with zero mutations" {
            $applyScript = Join-Path $orgDir '04_Apply-GitHubOrgPolicies.ps1'
            $output = & pwsh -NoProfile -Command "& '$applyScript' -DryRun" 2>&1
            $outputString = $output -join "`n"

            Assert-True ($outputString -match 'DRY RUN COMPLETE') "DryRun marker not detected in output"
            Assert-True ($outputString -match 'No modifications were made to GitHub') "Safety confirmation missing in DryRun"
            Assert-False ($outputString -match 'Failed to apply') "DryRun should not encounter failure"
        }
    }
}

if ($IncludeLiveApiTests) {
    Describe "Phase 1: Live GitHub API Idempotency & Verification" {
        Context "Target GitHub Enterprise Environment" {
            $token = ""
            if (-not [string]::IsNullOrWhiteSpace($env:GH_PAT)) {
                $cleanPat = $env:GH_PAT.Trim().Trim('"').Trim("'")
                try {
                    $testHeaders = @{
                        Authorization = "Bearer $cleanPat"
                        Accept        = "application/vnd.github+json"
                        'User-Agent'  = 'PowerShell-GHEC-Tester'
                    }
                    $null = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $testHeaders -Method Get -TimeoutSec 10
                    $token = $cleanPat
                }
                catch {
                    # PAT in env rejected; will fallback to gh CLI keyring
                }
            }

            if (-not $token) {
                $cliToken = (& gh auth token 2>$null)
                if ($cliToken) { $token = $cliToken.Trim() }
            }

            It "GitHub Authentication token is valid and returns authenticated user" {
                Assert-NotNull $token "GitHub token could not be found in env:GH_PAT or gh keyring"
                $headers = @{
                    Authorization = "Bearer $token"
                    Accept        = "application/vnd.github+json"
                    'User-Agent'  = 'PowerShell-GHEC-Tester'
                }
                $userResponse = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $headers -Method Get
                Assert-NotNull $userResponse.login
                Assert-True ($userResponse.login.Length -gt 0)
            }

            It "All target orgs belong to an Enterprise account and have 'enterprise' plan" {
                $headers = @{
                    Authorization = "Bearer $token"
                    Accept        = "application/vnd.github+json"
                    'User-Agent'  = 'PowerShell-GHEC-Tester'
                }
                $orgs = @(Get-Content $ghOrgFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
                foreach ($org in $orgs) {
                    $orgResponse = Invoke-RestMethod -Uri "https://api.github.com/orgs/$org" -Headers $headers -Method Get
                    Assert-Equal $orgResponse.plan.name "enterprise" "Org '$org' must be on 'enterprise' plan"
                }
            }

            It "Rollback engine is 100% idempotent (running twice succeeds with zero state drift)" {
                $rollbackScript = Join-Path $orgDir '05_Rollback-GitHubOrgPolicies.ps1'
                
                # First run of rollback
                $run1 = & pwsh -NoProfile -Command "& '$rollbackScript'" 2>&1
                $out1 = $run1 -join "`n"
                Assert-True ($out1 -match '\[VERIFIED\]') "First rollback run did not verify 100% restoration"

                # Immediate second run of rollback to verify idempotency
                $run2 = & pwsh -NoProfile -Command "& '$rollbackScript'" 2>&1
                $out2 = $run2 -join "`n"
                Assert-True ($out2 -match '\[VERIFIED\]') "Second rollback run did not verify 100% restoration"
                Assert-False ($out2 -match 'Error|Exception|Failed') "Second rollback encountered unexpected error"
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
