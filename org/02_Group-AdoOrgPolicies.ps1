#Requires -Version 7.0
<#
.SYNOPSIS
    Groups Azure DevOps organizations by policy configuration fingerprints and generates
    an Excel-ready comparison matrix and an editable ADO-to-GHEC crosswalk manifest.

.DESCRIPTION
    Step 2 of the ADO-to-GitHub Org Governance migration pipeline.
    - Scans captured ADO org policy JSON files.
    - Groups organizations with identical policy profiles together.
    - Sorts groups from least restrictive (fewer policies active) to most restrictive (most policies active).
    - Generates 'ado-org-policy-groups.csv' (Excel side-by-side view of all groups and their orgs).
    - Generates 'ado-to-ghec-crosswalk.csv' (Source of truth manifest editable by the user before GitHub apply).
    - Clearly highlights:
        * ⚠️ Semantically Similar: Allowed SSH Key types & SSH CAs (ADO-002)
        * 🏛️ Architectural: SAML Single Sign-On / Enterprise Managed Users (EMU) (ADO-008/AAD)
        * 🚫 Deprecated in GitHub: Basic Authentication natively blocked (ADO-BasicAuth)

.PARAMETER InputDir
    Directory containing the captured <org>.org-policies.json files.
    Defaults to the latest subfolder under '$PSScriptRoot\output'.

.PARAMETER TargetOutputDir
    Directory where grouping and crosswalk files should be saved.
    Defaults to the same directory as InputDir.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\org"
    pwsh .\Group-AdoOrgPolicies.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$InputDir = "",

    [Parameter(Mandatory = $false)]
    [string]$TargetOutputDir = "",

    [Parameter(Mandatory = $false)]
    [string]$SelectGroup = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   ADO Organization Policy Grouping & Crosswalk Generator" -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Input Directory
if ([string]::IsNullOrWhiteSpace($InputDir)) {
    $outputBase = Join-Path -Path $PSScriptRoot -ChildPath "output"
    if (Test-Path -Path $outputBase) {
        $latestSubdir = Get-ChildItem -Path $outputBase -Directory |
            Where-Object {
                $_.Name -ne "snapshots" -and @(Get-ChildItem -Path $_.FullName -Filter "*.org-policies.json" -File).Count -gt 0
            } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($null -ne $latestSubdir) {
            $InputDir = $latestSubdir.FullName
        }
    }

    if ([string]::IsNullOrWhiteSpace($InputDir) -or -not (Test-Path -Path $InputDir)) {
        $InputDir = $PSScriptRoot
    }
}

if (-not (Test-Path -Path $InputDir)) {
    throw "Input directory not found: '$InputDir'"
}

Write-Host "[+] Reading captured ADO organization policies from:" -ForegroundColor Gray
Write-Host "    $InputDir`n" -ForegroundColor Yellow

$jsonFiles = @(Get-ChildItem -Path $InputDir -Filter "*.org-policies.json" -File)
if ($jsonFiles.Count -eq 0) {
    throw "No '*.org-policies.json' files found in '$InputDir'. Please run Step 1 (Capture-AdoOrgPolicies.ps1) first."
}

if ([string]::IsNullOrWhiteSpace($TargetOutputDir)) {
    $TargetOutputDir = $InputDir
}
if (-not (Test-Path -Path $TargetOutputDir)) {
    [System.IO.Directory]::CreateDirectory($TargetOutputDir) | Out-Null
}

# 2. Master Policy Catalog & Metadata Mapping
# Loads predefined static Crosswalk (Source of Truth) from $PSScriptRoot\config\ado-to-ghec-crosswalk.csv
$staticCrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "config\ado-to-ghec-crosswalk.csv"
if (-not (Test-Path -LiteralPath $staticCrosswalkPath)) {
    $staticCrosswalkPath = Join-Path -Path $PSScriptRoot -ChildPath "ado-to-ghec-crosswalk.csv"
}
$MasterCrosswalkDefinitions = [ordered]@{}

if (Test-Path -Path $staticCrosswalkPath) {
    Write-Host "[+] Loaded predefined Crosswalk configuration (Source of Truth):" -ForegroundColor Gray
    Write-Host "    $staticCrosswalkPath`n" -ForegroundColor Yellow
    $csvDefs = Import-Csv -Path $staticCrosswalkPath

    foreach ($entry in $csvDefs) {
        $pKey = $entry.AdoInternalKey
        $short = switch ($entry.PolicyCode) {
            "P01" { "OAuth-Restrictions" }
            "P02" { "SSH-Block" }
            "P03" { "SSH-Key-Expiration" }
            "P04" { "Audit-Logging" }
            "P05" { "PAT-Restrictions" }
            "P06" { "Package-Protections" }
            "P07" { "Conditional-Access-IP" }
            "P08" { "Guest-Access-Block" }
            "P09" { "Team-Admin-Invite" }
            "P10" { "Request-Access" }
            "P11" { "Public-Projects" }
            "P12" { "Forking-Restrictions" }
            default { $entry.PolicyCode }
        }

        $MasterCrosswalkDefinitions[$pKey] = @{
            PolicyCode         = $entry.PolicyCode
            InventoryId        = if ($entry.PSObject.Properties['AdoPolicyId']) { $entry.AdoPolicyId } else { $entry.PolicyCode }
            PolicyName         = if ($entry.PSObject.Properties['AdoPolicyName']) { $entry.AdoPolicyName } else { $short }
            ShortLabel         = $short
            TargetGhPolicyKey  = $entry.TargetGhPolicyKey
            ImplementationType = if ($entry.PSObject.Properties['ImplementationType']) { $entry.ImplementationType } else { "Direct Org API" }
            TargetGhAction     = if ($entry.PSObject.Properties['TargetGhActionHandler']) { $entry.TargetGhActionHandler } else { "" }
            GhEndpoint         = if ($entry.PSObject.Properties['TargetGhApiEndpoint']) { $entry.TargetGhApiEndpoint } else { "" }
            DefaultApply       = [bool]::Parse($entry.ApplyPolicy)
            ActiveWhen         = if ($entry.PSObject.Properties['DefaultAdoActiveState']) { $entry.DefaultAdoActiveState } else { "Enforced" }
            Notes              = if ($entry.PSObject.Properties['ImplementationGuidance']) { $entry.ImplementationGuidance } else { "" }
        }
    }
}
else {
    Write-Warning "Static crosswalk not found at '$staticCrosswalkPath'. Using internal defaults."
}

# 3. Ingest Policy Files & Build Organization State Profiles
$orgProfiles = @{}
$allDiscoveredPolicies = [System.Collections.Generic.HashSet[string]]::new()

foreach ($file in $jsonFiles) {
    try {
        $raw = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        $orgName = $raw.adoOrganization

        $policies = @{}
        if ($null -ne $raw.policies) {
            foreach ($prop in $raw.policies.PSObject.Properties) {
                $pName = $prop.Name
                $pValue = $prop.Value
                $meaning = if ($null -ne $pValue.humanMeaning) { $pValue.humanMeaning } else { "$($pValue.effectiveValue)" }
                $effective = [bool]$pValue.effectiveValue
                $configured = if ($null -ne $pValue.configuredValue) { [bool]$pValue.configuredValue } else { $effective }

                $policies[$pName] = [PSCustomObject]@{
                    InternalName    = $pName
                    InventoryId     = if ($null -ne $pValue.inventoryId) { $pValue.inventoryId } else { "CUSTOM" }
                    PolicyName      = if ($null -ne $pValue.policyName) { $pValue.policyName } else { $pName }
                    HumanMeaning    = $meaning
                    EffectiveValue  = $effective
                    ConfiguredValue = $configured
                }
                [void]$allDiscoveredPolicies.Add($pName)
            }
        }

        # Calculate a "Security/Policy Strictness Score"
        # Points awarded for active governance controls (e.g. Blocked unsecure access, Enforced audit, Restricted PATs)
        $activePolicyCount = 0
        foreach ($pKey in $policies.Keys) {
            $m = $policies[$pKey].HumanMeaning
            if ($m -in @("Blocked", "Enforced", "Protected", "Disabled", "Restricted")) {
                # In ADO: DisallowOAuth=Blocked, DisallowSSH=Blocked, DisablePAT=Enforced/Restricted, LogAudit=Enforced
                $activePolicyCount++
            }
        }

        $orgProfiles[$orgName] = [PSCustomObject]@{
            OrgName           = $orgName
            Policies          = $policies
            ActivePolicyCount = $activePolicyCount
            Fingerprint       = ""
        }
    }
    catch {
        Write-Warning "Failed to parse '$($file.Name)': $_"
    }
}

$orgCount = $orgProfiles.Count
Write-Host "[+] Ingested policies from $orgCount Azure DevOps organization(s)." -ForegroundColor Green

# 4. Generate Deterministic Fingerprint for Each Org
# Sort policy keys alphabetically so comparison is order-independent
$sortedPolicyKeys = @($allDiscoveredPolicies | Sort-Object)

foreach ($orgName in $orgProfiles.Keys) {
    $prof = $orgProfiles[$orgName]
    $sigParts = [System.Collections.Generic.List[string]]::new()
    foreach ($pKey in $sortedPolicyKeys) {
        if ($prof.Policies.ContainsKey($pKey)) {
            $meaning = $prof.Policies[$pKey].HumanMeaning
            $sigParts.Add("$pKey=$meaning")
        }
        else {
            $sigParts.Add("$pKey=NotCaptured")
        }
    }
    $fingerprint = ($sigParts -join "|")
    $prof.Fingerprint = $fingerprint
}

# 5. Group Organizations by Exact Policy Fingerprint
$groupLookup = @{}
foreach ($orgName in $orgProfiles.Keys) {
    $prof = $orgProfiles[$orgName]
    $fp = $prof.Fingerprint
    if (-not $groupLookup.ContainsKey($fp)) {
        $groupLookup[$fp] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $groupLookup[$fp].Add($prof)
}

# 6. Sort Groups: Least Policies to Most Policies Active
# Group-1 = Least active policies (most permissive)
# Group-N = Most active policies (most restrictive / highest security)
$sortedGroups = @($groupLookup.Values | Sort-Object {
    $firstOrg = $_[0]
    $firstOrg.ActivePolicyCount
})

$groupedProfilesList = [System.Collections.Generic.List[PSCustomObject]]::new()
$groupIndex = 1

foreach ($orgList in $sortedGroups) {
    $sampleOrg = $orgList[0]
    $memberOrgs = @($orgList.OrgName | Sort-Object)
    $activeCount = $sampleOrg.ActivePolicyCount

    # Label groups with friendly intuitive names
    $profileLabel = if ($sortedGroups.Count -eq 1) {
        "Baseline Profile"
    }
    elseif ($groupIndex -eq 1) {
        "Profile A (Least Policies Active)"
    }
    elseif ($groupIndex -eq $sortedGroups.Count) {
        "Profile $([char](64 + $groupIndex)) (Most Policies Active)"
    }
    else {
        "Profile $([char](64 + $groupIndex))"
    }

    $groupObj = [PSCustomObject]@{
        GroupNumber       = $groupIndex
        GroupId           = "Group-$groupIndex"
        Label             = $profileLabel
        ActivePolicyCount = $activeCount
        TotalTracked      = $sortedPolicyKeys.Count
        OrgCount          = $memberOrgs.Count
        Organizations     = $memberOrgs
        SamplePolicies    = $sampleOrg.Policies
        Fingerprint       = $sampleOrg.Fingerprint
    }
    $groupedProfilesList.Add($groupObj)
    $groupIndex++
}

# 8. Build Human-Readable Organization-Policy Matrix ('ado-org-policy-matrix.csv')
# Track policy definitions in consistent P01..P12 order
$masterPolicyList = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($pKey in $MasterCrosswalkDefinitions.Keys) {
    if ($allDiscoveredPolicies.Contains($pKey)) {
        $def = $MasterCrosswalkDefinitions[$pKey]
        $masterPolicyList.Add([PSCustomObject]@{
            InternalName       = $pKey
            PolicyCode         = $def.PolicyCode
            PolicyName         = $def.PolicyName
            ShortLabel         = $def.ShortLabel
            ActiveWhen         = $def.ActiveWhen
            TargetGhPolicyKey  = $def.TargetGhPolicyKey
            ImplementationType = $def.ImplementationType
            TargetGhAction     = $def.TargetGhAction
            GhEndpoint         = $def.GhEndpoint
            DefaultApply       = $def.DefaultApply
            Notes              = $def.Notes
        })
    }
}

# Any other discovered policies not in master catalog
$otherPolicies = $allDiscoveredPolicies | Where-Object { -not $MasterCrosswalkDefinitions.Contains($_) }
$customIdx = 13
foreach ($pKey in $otherPolicies) {
    $code = "P$customIdx"
    $masterPolicyList.Add([PSCustomObject]@{
        InternalName       = $pKey
        PolicyCode         = $code
        PolicyName         = $pKey
        ShortLabel         = $pKey
        ActiveWhen         = "Enforced"
        TargetGhPolicyKey  = "GH-CUSTOM"
        ImplementationType = "Custom / Review"
        TargetGhAction     = "ManualReview"
        GhEndpoint         = "N/A"
        DefaultApply       = $false
        Notes              = "Discovered custom policy."
    })
    $customIdx++
}

# Construct the Matrix Rows (Rows = Organizations)
$matrixRows = [System.Collections.Generic.List[PSCustomObject]]::new()
$sortedOrgNames = @($orgProfiles.Keys | Sort-Object)

foreach ($orgName in $sortedOrgNames) {
    $prof = $orgProfiles[$orgName]
    $row = [ordered]@{
        "Organization" = $orgName
    }

    $yesCount = 0
    foreach ($pMeta in $masterPolicyList) {
        $pKey = $pMeta.InternalName
        $colName = "$($pMeta.PolicyCode) ($($pMeta.ShortLabel))"
        $isYes = $false

        if ($prof.Policies.ContainsKey($pKey)) {
            $m = $prof.Policies[$pKey].HumanMeaning
            if ($m -eq $pMeta.ActiveWhen -or $m -in @("Blocked", "Enforced", "Protected", "Disabled", "Restricted")) {
                $isYes = $true
            }
        }

        if ($isYes) {
            $row[$colName] = "Yes"
            $yesCount++
        }
        else {
            $row[$colName] = "No"
        }
    }

    $matrixRows.Add([PSCustomObject]$row)
}

# Add Summary Statistics Rows
$summaryYesRow = [ordered]@{ "Organization" = "TOTAL YES COUNT" }
$summaryNoRow  = [ordered]@{ "Organization" = "TOTAL NO COUNT" }
$summaryConsensusRow = [ordered]@{ "Organization" = "CONSENSUS STATUS" }

foreach ($pMeta in $masterPolicyList) {
    $colName = "$($pMeta.PolicyCode) ($($pMeta.ShortLabel))"
    $yCount = 0
    $nCount = 0

    foreach ($r in $matrixRows) {
        if ($r.$colName -eq "Yes") { $yCount++ } else { $nCount++ }
    }

    $summaryYesRow[$colName] = $yCount
    $summaryNoRow[$colName]  = $nCount

    if ($nCount -eq 0) {
        $summaryConsensusRow[$colName] = "MATCH (100% Yes)"
    }
    elseif ($yCount -eq 0) {
        $summaryConsensusRow[$colName] = "MATCH (100% No)"
    }
    else {
        $summaryConsensusRow[$colName] = "⚠️ CONFLICT ($yCount Yes / $nCount No)"
    }
}

function Save-SafeCsv {
    param($Data, [string]$Path)
    try {
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
        Write-Host "    --> Created: $Path" -ForegroundColor Green
    }
    catch [System.IO.IOException] {
        Write-Warning "Could not overwrite '$([System.IO.Path]::GetFileName($Path))' because it is currently open in Excel or another application."
        $alt = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($Path), "$([System.IO.Path]::GetFileNameWithoutExtension($Path))-updated.csv")
        $Data | Export-Csv -Path $alt -NoTypeInformation -Encoding utf8
        Write-Host "    --> Saved to fallback file: $alt" -ForegroundColor Yellow
        Write-Host "    (Tip: Close the file in Excel to allow overwriting the primary file)" -ForegroundColor Gray
    }
}

# Save pure organization matrix (only organization rows, no summary rows)
$matrixCsvPath = Join-Path -Path $TargetOutputDir -ChildPath "ado-org-policy-matrix.csv"
Save-SafeCsv -Data $matrixRows -Path $matrixCsvPath

# 9. Summary JSON for Downstream Pipeline Consumption
$dominantGroup = $groupedProfilesList | Sort-Object OrgCount -Descending | Select-Object -First 1

$summaryData = [PSCustomObject]@{
    GeneratedAt          = [System.DateTime]::UtcNow.ToString("o")
    SourceDirectory      = $InputDir
    TotalOrgsAnalyzed    = $orgCount
    DistinctGroupsCount  = $groupedProfilesList.Count
    DefaultDominantGroup = $dominantGroup.GroupId
    Groups               = $groupedProfilesList | ForEach-Object {
        [PSCustomObject]@{
            GroupId           = $_.GroupId
            Label             = $_.Label
            OrgCount          = $_.OrgCount
            ActivePolicyCount = $_.ActivePolicyCount
            Organizations     = $_.Organizations
        }
    }
    StaticCrosswalkFile  = $staticCrosswalkPath
    GeneratedFiles       = @{
        OrgPolicyMatrixCsv = $matrixCsvPath
    }
}
$summaryJsonPath = Join-Path -Path $TargetOutputDir -ChildPath "grouping-summary.json"
$summaryData | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryJsonPath -Encoding utf8

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                     EXECUTION COMPLETE                          " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[+] Generated Organization-Policy Matrix (Yes/No Grid):" -ForegroundColor Green
Write-Host "    $matrixCsvPath`n" -ForegroundColor Yellow
Write-Host "[i] Static Crosswalk Config (Source of Truth):" -ForegroundColor Gray
Write-Host "    $staticCrosswalkPath`n" -ForegroundColor White
