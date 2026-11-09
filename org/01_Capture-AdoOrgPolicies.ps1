#Requires -Version 7.0
<#
.SYNOPSIS
    Extracts Azure DevOps Organization-Level Governance Policies (ADO-001 through ADO-012).

.DESCRIPTION
    Extracts the 12 organization governance policies (OAuth, SSH, PAT, Audit, Invites, etc.)
    using Azure DevOps's embedded organization-policies data provider.
    Runs with zero required parameters from the script directory:
      $env:ADO_PAT = "your-pat"
      pwsh .\Capture-AdoOrgPolicies.ps1

    Reads organization names line-by-line from 'orgs.txt' in the same folder, or accepts
    a single organization via '-Org <name>'.

.PARAMETER Org
    Optional: Single Azure DevOps organization name (e.g. 'ado-policy-testing').
    If omitted, reads the list from 'orgs.txt' in the script folder.

.PARAMETER ConfigPath
    Optional: Custom path to a text or CSV file with organization names. Defaults to 'orgs.txt'.

.PARAMETER RunId
    Optional: Custom identifier for the run. Defaults to timestamp (yyyyMMdd-HHmmss).

.PARAMETER OutputDir
    Optional: Custom output directory. Defaults to 'output/<RunId>' inside the script folder.

.PARAMETER Preview
    If specified, performs connection checks and prints discovered orgs without saving files.

.EXAMPLE
    # Typical usage:
    $env:ADO_PAT = "your_personal_access_token"
    pwsh .\Capture-AdoOrgPolicies.ps1

    # Single org:
    pwsh .\Capture-AdoOrgPolicies.ps1 -Org my-org
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Org,

    [string]$ConfigPath = "",

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "",

    [Parameter(Mandatory = $false)]
    [switch]$UseDefaultCredentials,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateCheck,

    [string]$RunId,

    [string]$OutputDir,

    [switch]$Preview
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Known 12 Governance Policy Definitions mapping to Inventory IDs
$script:KnownInventory = [ordered]@{
    'Policy.DisallowOAuthAuthentication'                 = @{ Id = 'ADO-001'; Name = 'Third-party application access through OAuth'; Category = 'applicationConnection'; Inverted = $true; TrueMeaning = 'Blocked'; FalseMeaning = 'Allowed' }
    'Policy.DisallowSecureShell'                         = @{ Id = 'ADO-002'; Name = 'SSH authentication'; Category = 'applicationConnection'; Inverted = $true; TrueMeaning = 'Blocked'; FalseMeaning = 'Allowed' }
    'Policy.ValidateSshKeyExpiration'                    = @{ Id = 'ADO-003'; Name = 'Validate SSH key expiration'; Category = 'applicationConnection'; Inverted = $false; TrueMeaning = 'Enforced'; FalseMeaning = 'Disabled' }
    'Policy.LogAuditEvents'                              = @{ Id = 'ADO-004'; Name = 'Log audit events'; Category = 'security'; Inverted = $false; TrueMeaning = 'Enforced'; FalseMeaning = 'Disabled' }
    'Policy.DisablePATCreation'                          = @{ Id = 'ADO-005'; Name = 'Restrict personal access token (PAT) creation'; Category = 'security'; Inverted = $false; TrueMeaning = 'Restricted'; FalseMeaning = 'Allowed' }
    'Policy.AllowPublicProjects'                         = @{ Id = 'ADO-006'; Name = 'Allow public projects'; Category = 'security'; Inverted = $false; TrueMeaning = 'Allowed'; FalseMeaning = 'Disabled' }
    'Policy.ArtifactsExternalPackageProtectionToken'     = @{ Id = 'ADO-007'; Name = 'Additional protections when using public package registries'; Category = 'security'; Inverted = $false; TrueMeaning = 'Protected'; FalseMeaning = 'Disabled' }
    'Policy.EnforceAADConditionalAccess'                 = @{ Id = 'ADO-008'; Name = 'Enable IP Conditional Access policy validation on non-interactive flows'; Category = 'security'; Inverted = $false; TrueMeaning = 'Enforced'; FalseMeaning = 'Disabled' }
    'Policy.DisallowAadGuestUserAccess'                  = @{ Id = 'ADO-009'; Name = 'External guest access'; Category = 'user'; Inverted = $true; TrueMeaning = 'Blocked'; FalseMeaning = 'Allowed' }
    'Policy.AllowTeamAdminsInvitationsAccessToken'       = @{ Id = 'ADO-010'; Name = 'Allow team and project administrators to invite new users'; Category = 'user'; Inverted = $false; TrueMeaning = 'Allowed'; FalseMeaning = 'Admins Only' }
    'Policy.AllowRequestAccessToken'                     = @{ Id = 'ADO-011'; Name = 'Request access'; Category = 'user'; Inverted = $false; TrueMeaning = 'Allowed'; FalseMeaning = 'Disabled' }
    'Policy.AllowFeedbackCollection'                     = @{ Id = 'ADO-012'; Name = 'Allow Microsoft to collect feedback from users'; Category = 'privacy'; Inverted = $false; TrueMeaning = 'Allowed'; FalseMeaning = 'Disabled' }
    'Policy.AllowExtensionsLocalNetworkAccess'           = @{ Id = 'ADO-EXT'; Name = 'Allow extensions to access resources on the local network'; Category = 'security'; Inverted = $false; TrueMeaning = 'Allowed'; FalseMeaning = 'Disabled' }
}

function Get-AdoAuthHeader {
    param([switch]$AllowDefaultCredentials)

    if ($AllowDefaultCredentials) {
        return @{ Header = $null; Mode = "Windows Integrated Authentication (NTLM/Kerberos)" }
    }

    $pat = [Environment]::GetEnvironmentVariable('ADO_PAT', 'Process')
    if (-not $pat) { $pat = [Environment]::GetEnvironmentVariable('ADO_PAT', 'User') }
    if (-not $pat) { $pat = [Environment]::GetEnvironmentVariable('ADO_PAT', 'Machine') }

    if ($pat) {
        $cleanPat = $pat.Trim().Trim('"').Trim("'")
        $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$cleanPat"))
        return @{ Header = "Basic $b64"; Mode = "ADO_PAT" }
    }

    # Fallback to Azure CLI if logged in
    $az = Get-Command 'az' -ErrorAction SilentlyContinue
    if ($az) {
        $azToken = & az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query "accessToken" -o tsv 2>$null
        if ($azToken) {
            return @{ Header = "Bearer $azToken"; Mode = "Azure CLI (az)" }
        }
    }

    throw "ADO PAT not found. Please set your token in the session using:`n  `$env:ADO_PAT = `"your-personal-access-token`"`nor pass -UseDefaultCredentials for on-premises ADO Server."
}

function Extract-SingleOrgPolicies {
    param(
        [string]$TargetOrg,
        [string]$AuthHeader,
        [string]$BaseServerUrl = "",
        [switch]$UseWinAuth,
        [switch]$SkipCertCheck
    )

    $cleanTarget = $TargetOrg.Trim()
    $url = if ($cleanTarget.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $cleanTarget.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
        "$($cleanTarget.TrimEnd('/'))/_settings/organizationPolicy"
    } elseif ($BaseServerUrl) {
        "$($BaseServerUrl.TrimEnd('/'))/$cleanTarget/_settings/organizationPolicy"
    } else {
        "https://dev.azure.com/$cleanTarget/_settings/organizationPolicy"
    }

    $headers = @{
        Accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    if ($AuthHeader) {
        $headers['Authorization'] = $AuthHeader
    }

    $reqArgs = @{
        Uri                = $url
        Headers            = $headers
        TimeoutSec         = 60
        MaximumRedirection = 3
        SkipHttpErrorCheck = $true
    }
    if ($UseWinAuth) {
        $reqArgs['UseDefaultCredentials'] = $true
    }
    if ($SkipCertCheck) {
        $reqArgs['SkipCertificateCheck'] = $true
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-WebRequest @reqArgs
    } catch {
        throw "Failed to reach ADO Organization/Collection '$cleanTarget' at '$url': $($_.Exception.Message)"
    }

    if ($resp.StatusCode -ne 200) {
        throw "Failed to retrieve organization policies for '$cleanTarget' (HTTP $($resp.StatusCode)) at '$url'. Ensure permissions or credentials are valid."
    }

    $stopwatch.Stop()

    # Parse embedded data provider from the script block
    $match = [regex]::Matches($resp.Content, '<script id="dataProviders"[^>]*>(.*?)</script>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($match.Count -eq 0) {
        throw "No embedded 'dataProviders' found in response for '$TargetOrg'. The page layout or authentication response may have differed."
    }

    $json = $match[0].Groups[1].Value | ConvertFrom-Json
    $provider = $json.data.'ms.vss-admin-web.organization-policies-data-provider'
    if ($null -eq $provider) {
        throw "Data provider 'ms.vss-admin-web.organization-policies-data-provider' was not returned for '$TargetOrg'. Check permissions."
    }

    $invertedList = @($provider.invertedPolicies)
    $policies = $provider.policies

    $extracted = [ordered]@{
        adoOrganization = $TargetOrg
        capturedAt = [DateTime]::UtcNow.ToString('o')
        durationMs = $stopwatch.ElapsedMilliseconds
        hostId = $provider.hostId
        requestAccessUrl = $provider.requestAccessUrl
        permissionBits = $provider.permissionBits
        isGuestUser = $provider.isGuestUser
        policies = [ordered]@{}
    }

    foreach ($cat in @('applicationConnection', 'security', 'user', 'privacy')) {
        if ($policies.$cat) {
            foreach ($item in $policies.$cat) {
                $p = $item.policy
                $pName = $p.name

                $meta = if ($script:KnownInventory.Contains($pName)) { $script:KnownInventory[$pName] } else {
                    @{ Id = 'CUSTOM'; Name = $item.description; Category = $cat; Inverted = ($pName -in $invertedList); TrueMeaning = 'Enabled'; FalseMeaning = 'Disabled' }
                }

                $effVal = [bool]$p.effectiveValue
                $cfgVal = $p.value
                $parentVal = $p.parentPolicy.value

                # Compute Human Meaning
                $humanVal = if ($meta.Inverted) {
                    if ($effVal) { $meta.TrueMeaning } else { $meta.FalseMeaning }
                } else {
                    if ($effVal) { $meta.TrueMeaning } else { $meta.FalseMeaning }
                }

                $props = if ($p.PSObject.Properties.Match('properties').Count) { $p.properties } else { $null }

                $extracted.policies[$pName] = [ordered]@{
                    inventoryId     = $meta.Id
                    policyName      = $meta.Name
                    category        = $meta.Category
                    internalName    = $pName
                    description     = $item.description
                    effectiveValue  = $effVal
                    configuredValue = $cfgVal
                    parentValue     = $parentVal
                    humanMeaning    = $humanVal
                    isInverted      = ($pName -in $invertedList)
                    learnMoreLink   = $item.learnMoreLink
                    properties      = $props
                }
            }
        }
    }

    return $extracted
}

# --- Resolve Target Organizations ---
$targetOrgs = [System.Collections.Generic.List[string]]::new()

if ($Org -and -not [string]::IsNullOrWhiteSpace($Org)) {
    $targetOrgs.Add($Org.Trim())
} else {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path $PSScriptRoot "config\orgs.txt"
        if (-not (Test-Path -LiteralPath $ConfigPath)) {
            $ConfigPath = Join-Path $PSScriptRoot "orgs.txt"
        }
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "No organizations provided and config file not found: $ConfigPath`nCreate an 'orgs.txt' file listing your ADO organizations (one per line) or specify '-Org <name>'."
    }

    # Support simple text file (one org per line) or CSV
    if ($ConfigPath.EndsWith('.csv', [StringComparison]::OrdinalIgnoreCase)) {
        $rows = Import-Csv -LiteralPath $ConfigPath
        foreach ($r in $rows) {
            $val = if ($r.Organization) { $r.Organization } else { ($r.PSObject.Properties | Select-Object -First 1).Value }
            if ($val -and -not [string]::IsNullOrWhiteSpace($val) -and ($val.Trim() -notin $targetOrgs)) {
                $targetOrgs.Add($val.Trim())
            }
        }
    } else {
        # Plain text file (one org per line, ignore empty lines and lines starting with #)
        $lines = Get-Content -LiteralPath $ConfigPath
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -and -not $trimmed.StartsWith('#') -and ($trimmed -notin $targetOrgs)) {
                $targetOrgs.Add($trimmed)
            }
        }
    }
}

if ($targetOrgs.Count -eq 0) { throw "No valid organization names found to extract." }

# Setup Paths & RunId
if (-not $RunId) { $RunId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') }
if (-not $OutputDir) { $OutputDir = Join-Path $PSScriptRoot "output\$RunId" }

$authInfo = Get-AdoAuthHeader -AllowDefaultCredentials:$UseDefaultCredentials

# Header
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Azure DevOps Organization Governance Extractor" -ForegroundColor Cyan
Write-Host " Run ID        : $RunId" -ForegroundColor White
Write-Host " Target Orgs   : $($targetOrgs.Count) org(s) -> ($($targetOrgs -join ', '))" -ForegroundColor White
Write-Host " Auth Source   : $($authInfo.Mode)" -ForegroundColor White
Write-Host " Output Dir    : $OutputDir" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan

if ($Preview) {
    Write-Host "[PREVIEW ONLY] Target organizations verified. No files will be written." -ForegroundColor Yellow
    return
}

$null = New-Item -ItemType Directory -Path $OutputDir -Force

$allOrgResults = [ordered]@{}
$matrixRows = [System.Collections.Generic.List[object]]::new()

foreach ($orgName in $targetOrgs) {
    $cleanOrg = $orgName.Trim()
    $safeOrgName = if ($cleanOrg.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $cleanOrg.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
        ($cleanOrg.TrimEnd('/') -split '/')[-1] -replace '[^a-zA-Z0-9_\-]', '_'
    } else {
        $cleanOrg -replace '[^a-zA-Z0-9_\-]', '_'
    }

    Write-Host "Extracting policies for org: $cleanOrg..." -NoNewline
    try {
        $result = Extract-SingleOrgPolicies -TargetOrg $cleanOrg -AuthHeader $authInfo.Header -BaseServerUrl $ServerUrl -UseWinAuth:$UseDefaultCredentials -SkipCertCheck:$SkipCertificateCheck
        $allOrgResults[$cleanOrg] = $result
        
        # Save individual Org JSON snapshot
        $orgJsonPath = Join-Path $OutputDir "$safeOrgName.org-policies.json"
        $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $orgJsonPath -Encoding utf8
        Write-Host " [OK] ($($result.durationMs) ms, $($result.policies.Count) policies)" -ForegroundColor Green
    } catch {
        Write-Host " [FAILED]" -ForegroundColor Red
        Write-Warning "Failed org $cleanOrg`: $($_.Exception.Message)"
        $allOrgResults[$cleanOrg] = @{ error = $_.Exception.Message }
    }
}

# --- Generate Governance Comparison Matrix across all Orgs ---
Write-Host "`nBuilding Organization Governance Matrix..." -ForegroundColor Cyan

# Gather union of all policy internal names
$allPolicyKeys = [System.Collections.Generic.HashSet[string]]::new()
foreach ($oName in $allOrgResults.Keys) {
    $res = $allOrgResults[$oName]
    if ($res -is [System.Collections.IDictionary] -and $res.Contains('policies') -and $null -ne $res['policies']) {
        foreach ($k in $res['policies'].Keys) { [void]$allPolicyKeys.Add($k) }
    }
}

# Sort policy keys in inventory order (ADO-001 -> ADO-012)
$sortedKeys = @($allPolicyKeys | Sort-Object {
    if ($script:KnownInventory.Contains($_)) { $script:KnownInventory[$_].Id } else { "ZZZ-$_" }
})

foreach ($k in $sortedKeys) {
    $meta = if ($script:KnownInventory.Contains($k)) { $script:KnownInventory[$k] } else {
        @{ Id = 'CUSTOM'; Name = $k; Category = 'other' }
    }

    $row = [ordered]@{
        'Inventory ID'        = $meta.Id
        'Policy Description'  = $meta.Name
        'Category'            = $meta.Category
        'Internal Name'       = $k
    }

    $orgValues = [System.Collections.Generic.List[string]]::new()
    foreach ($oName in $targetOrgs) {
        $orgRes = $allOrgResults[$oName]
        if ($orgRes -is [System.Collections.IDictionary] -and $orgRes.Contains('policies') -and $orgRes['policies'] -and $orgRes['policies'].Contains($k)) {
            $val = $orgRes['policies'][$k].humanMeaning
            $row[$oName] = $val
            $orgValues.Add($val)
        } else {
            $row[$oName] = 'Not Captured'
            $orgValues.Add('Not Captured')
        }
    }

    # Detect Consensus vs. Conflict across orgs
    $distinctVals = @($orgValues | Select-Object -Unique)
    if ($distinctVals.Count -eq 1) {
        $row['Consensus Status'] = "MATCH ($($distinctVals[0]))"
    } else {
        $row['Consensus Status'] = "CONFLICT ($($distinctVals -join ' vs '))"
    }

    $matrixRows.Add([PSCustomObject]$row)
}

# Write matrix CSV
$matrixCsvPath = Join-Path $OutputDir "org-governance-matrix.csv"
$matrixRows | Export-Csv -LiteralPath $matrixCsvPath -NoTypeInformation -Encoding utf8
Write-Host "Created: $matrixCsvPath" -ForegroundColor Green

# Write execution summary JSON
$summaryPath = Join-Path $OutputDir "capture-summary.json"
$summaryObj = [ordered]@{
    runId = $RunId
    capturedAt = [DateTime]::UtcNow.ToString('o')
    organizationsScanned = $targetOrgs.Count
    organizationsSuccess = @($allOrgResults.Values | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('policies') }).Count
    organizationsFailed = @($allOrgResults.Values | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('error') }).Count
    totalPoliciesInventoried = $matrixRows.Count
    conflictsDetected = @($matrixRows | Where-Object { $_.'Consensus Status' -like 'CONFLICT*' }).Count
    artifacts = [ordered]@{
        matrixCsv = $matrixCsvPath
        orgJsonSnapshots = @($targetOrgs | ForEach-Object {
            $s = if ($_.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $_.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
                ($_.TrimEnd('/') -split '/')[-1] -replace '[^a-zA-Z0-9_\-]', '_'
            } else {
                $_ -replace '[^a-zA-Z0-9_\-]', '_'
            }
            Join-Path $OutputDir "$s.org-policies.json"
        })
    }
}
$summaryObj | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $summaryPath -Encoding utf8
Write-Host "Created: $summaryPath" -ForegroundColor Green

Write-Host "`nCapture completed successfully!" -ForegroundColor Green
Write-Host "Review matrix: $matrixCsvPath" -ForegroundColor White
