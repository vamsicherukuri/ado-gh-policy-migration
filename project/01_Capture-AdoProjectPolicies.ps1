#Requires -Version 7.0
<#
.SYNOPSIS
    Captures Azure DevOps project-level push policies and cross-repository branch policies.

.DESCRIPTION
    Phase 2 - Step 1 of the ADO-to-GitHub Policy Migration pipeline.
    - Queries ADO Project API (_apis/policy/configurations) to extract:
        * Project Push Policies (Author email patterns, max file size, max path length, reserved names)
        * Cross-Repository Branch Policies (PR review counts, comment resolution, merge types, builds, status checks)
        * Repository-Specific Policies
    - Classifies each policy by scope, target branch/ref patterns, and enablement status.
    - Exports clean, structured JSON captures for grouping and GitHub Ruleset translation.

.PARAMETER ProjectsFilePath
    Path to text file containing target projects in 'org/project' format. Defaults to '$PSScriptRoot\projects.txt'.

.PARAMETER Org
    Direct ADO organization name. If supplied with -Project, bypasses projects.txt.

.PARAMETER Project
    Direct ADO project name.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\project"
    pwsh .\01_Capture-AdoProjectPolicies.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProjectsFilePath = "",

    [Parameter(Mandatory = $false)]
    [string]$Org = "",

    [Parameter(Mandatory = $false)]
    [string]$Project = "",

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "",

    [Parameter(Mandatory = $false)]
    [switch]$UseDefaultCredentials,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   Capture ADO Project-Level & Cross-Repo Branch Policies         " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Targets
$targetList = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($ServerUrl -and $Project) {
    $cleanBase = $ServerUrl.TrimEnd('/')
    $collectionName = ($cleanBase -split '/')[-1]
    $targetList.Add([PSCustomObject]@{ BaseUrl = $cleanBase; Org = $collectionName; Project = $Project.Trim() })
}
elseif ($Org -and $Project) {
    $cleanOrg = $Org.Trim()
    $base = if ($cleanOrg.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $cleanOrg.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
        $cleanOrg.TrimEnd('/')
    } else {
        "https://dev.azure.com/$cleanOrg"
    }
    $collectionName = ($base -split '/')[-1]
    $targetList.Add([PSCustomObject]@{ BaseUrl = $base; Org = $collectionName; Project = $Project.Trim() })
}
else {
    if ([string]::IsNullOrWhiteSpace($ProjectsFilePath)) {
        $ProjectsFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\projects.txt"
        if (-not (Test-Path -LiteralPath $ProjectsFilePath)) {
            $ProjectsFilePath = Join-Path -Path $PSScriptRoot -ChildPath "projects.txt"
        }
    }

    if (-not (Test-Path -LiteralPath $ProjectsFilePath)) {
        throw "Projects file not found at: '$ProjectsFilePath'. Create it or provide -Org and -Project."
    }

    $lines = @(Get-Content -LiteralPath $ProjectsFilePath | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#")
    })

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $trimmed.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
            $lastSlash = $trimmed.LastIndexOf('/')
            $base = $trimmed.Substring(0, $lastSlash)
            $pName = $trimmed.Substring($lastSlash + 1)
            $collectionName = ($base.TrimEnd('/') -split '/')[-1]
            $targetList.Add([PSCustomObject]@{ BaseUrl = $base; Org = $collectionName; Project = $pName })
        }
        elseif ($trimmed.Contains('/')) {
            $parts = $trimmed -split '/'
            $targetList.Add([PSCustomObject]@{ BaseUrl = "https://dev.azure.com/$($parts[0].Trim())"; Org = $parts[0].Trim(); Project = $parts[1].Trim() })
        }
        else {
            # Single project name; check if orgs.txt exists in org directory
            $defaultOrgFile = Join-Path -Path $PSScriptRoot -ChildPath "..\org\config\orgs.txt"
            if (-not (Test-Path -LiteralPath $defaultOrgFile)) {
                $defaultOrgFile = Join-Path -Path $PSScriptRoot -ChildPath "..\org\orgs.txt"
            }
            $defaultOrg = "ado-policy-testing"
            if (Test-Path -LiteralPath $defaultOrgFile) {
                $orgLines = @(Get-Content -LiteralPath $defaultOrgFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#") })
                if ($orgLines.Count -gt 0) { $defaultOrg = $orgLines[0].Trim() }
            }
            $base = if ($defaultOrg.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $defaultOrg.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
                $defaultOrg.TrimEnd('/')
            } else {
                "https://dev.azure.com/$defaultOrg"
            }
            $collectionName = ($base -split '/')[-1]
            $targetList.Add([PSCustomObject]@{ BaseUrl = $base; Org = $collectionName; Project = $trimmed })
        }
    }
}

if ($targetList.Count -eq 0) {
    throw "No target projects specified in '$ProjectsFilePath'."
}

Write-Host "[+] Target Projects        : $($targetList.Count) project(s)" -ForegroundColor Cyan
foreach ($t in $targetList) {
    Write-Host "    - $($t.Org)/$($t.Project)" -ForegroundColor Gray
}

# 2. Resolve Authentication (PAT, Windows Auth, or Azure CLI)
$authHeader = @{ Accept = "application/json" }
$authSource = ""

if ($UseDefaultCredentials) {
    $authSource = "Windows Integrated Authentication (NTLM/Kerberos)"
}
elseif (-not [string]::IsNullOrWhiteSpace($env:ADO_PAT)) {
    $cleanPat = $env:ADO_PAT.Trim().Trim('"').Trim("'")
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$cleanPat"))
    $authHeader["Authorization"] = "Basic $b64"
    $authSource = "`$env:ADO_PAT"
}
elseif (Get-Command az -ErrorAction SilentlyContinue) {
    try {
        $tokenJson = & az account get-access-token --resource '499b84ac-1321-427f-aa17-267ca6975798' --output json 2>$null
        if ($LASTEXITCODE -eq 0 -and $tokenJson) {
            $tokenObj = ($tokenJson -join "`n") | ConvertFrom-Json
            $authHeader["Authorization"] = "Bearer $($tokenObj.accessToken)"
            $authSource = "Azure CLI (az account)"
        }
    }
    catch {
        # Az CLI token acquisition failed
    }
}

if (-not $UseDefaultCredentials -and -not $authHeader.ContainsKey("Authorization")) {
    throw "No valid ADO authentication found. Please set `$env:ADO_PAT, run 'az login', or use -UseDefaultCredentials for on-premise ADO Server."
}

function Invoke-AdoRest {
    param([string]$Url)
    $invokeArgs = @{
        Uri     = $Url
        Headers = $authHeader
        Method  = 'Get'
    }
    if ($UseDefaultCredentials) { $invokeArgs['UseDefaultCredentials'] = $true }
    if ($SkipCertificateCheck) { $invokeArgs['SkipCertificateCheck'] = $true }
    return Invoke-RestMethod @invokeArgs
}

Write-Host "[+] Authentication         : $authSource" -ForegroundColor Green

# 3. Output Directory Setup
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$outputDir = Join-Path -Path $PSScriptRoot -ChildPath "output\$timestamp"
$latestDir = Join-Path -Path $PSScriptRoot -ChildPath "output\latest"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
New-Item -ItemType Directory -Path $latestDir -Force | Out-Null

# 4. Known Policy Type Mappings (GUID to Policy Code)
$knownTypes = @{
    '77ed4bd3-b063-4689-934a-175e4d0a78d7' = @{ Code = 'P13'; Name = 'Commit author email validation'; Scope = 'branch' }
    '51c78909-e838-41a2-9496-c647091e3c61' = @{ Code = 'P14'; Name = 'File name restriction'; Scope = 'push' }
    '7ed39669-655c-494e-b4a0-a08b4da0fcce' = @{ Code = 'P15'; Name = 'Git repository settings'; Scope = 'push' }
    'db2b9b4c-180d-4529-9701-01541d19f36b' = @{ Code = 'P16'; Name = 'Reserved names restriction'; Scope = 'push' }
    '001a79cf-fda1-4c4e-9e7c-bac40ee5ead8' = @{ Code = 'P17'; Name = 'Path Length restriction'; Scope = 'push' }
    '2e26e725-8201-4edd-8bf5-978563c34a80' = @{ Code = 'P18'; Name = 'File size restriction'; Scope = 'push' }
    'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd' = @{ Code = 'P19'; Name = 'Minimum number of reviewers'; Scope = 'branch' }
    '40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e' = @{ Code = 'P20'; Name = 'Work item linking'; Scope = 'branch' }
    'c6a1889d-b943-4856-b76f-9e46bb6b0df2' = @{ Code = 'P21'; Name = 'Comment requirements'; Scope = 'branch' }
    'fa4e907d-c16b-4a4c-9dfa-4916e5d171ab' = @{ Code = 'P22'; Name = 'Require a merge strategy'; Scope = 'branch' }
    '0609b952-1397-4640-95ec-e00a01b2c241' = @{ Code = 'P23'; Name = 'Build'; Scope = 'branch' }
    'cbdc66da-9728-4af8-aada-9a5a32e4a226' = @{ Code = 'P24'; Name = 'Status'; Scope = 'branch' }
    'fd2167ab-b0be-447a-8ec8-39368250530e' = @{ Code = 'P25'; Name = 'Required reviewers'; Scope = 'branch' }
}

$summaryList = [System.Collections.Generic.List[PSCustomObject]]::new()

# 5. Capture Project Policies
foreach ($target in $targetList) {
    $org = $target.Org
    $proj = $target.Project
    $baseUrl = $target.BaseUrl
    Write-Host "`n[+] Capturing policies for '$org/$proj' ($baseUrl)..." -ForegroundColor Cyan

    # A. Fetch Project Info
    $projUrl = "$baseUrl/_apis/projects/$([Uri]::EscapeDataString($proj))?api-version=7.0"
    $projData = $null
    try {
        $projData = Invoke-AdoRest $projUrl
    }
    catch {
        Write-Warning "Failed to query project '$proj' in org '$org': $($_.Exception.Message)"
        continue
    }

    # B. Fetch Repositories in Project
    $reposUrl = "$baseUrl/$([Uri]::EscapeDataString($proj))/_apis/git/repositories?api-version=7.0"
    $repoList = @()
    try {
        $reposData = Invoke-AdoRest $reposUrl
        if ($reposData.value) { $repoList = @($reposData.value) }
    }
    catch {
        Write-Warning "Could not fetch repositories for '$proj': $($_.Exception.Message)"
    }

    $repoMap = @{}
    foreach ($r in $repoList) {
        $repoMap[$r.id] = $r.name
    }

    # C. Fetch Policy Configurations
    $configsUrl = "$baseUrl/$([Uri]::EscapeDataString($proj))/_apis/policy/configurations?api-version=7.0"
    $configs = @()
    try {
        $configsData = Invoke-AdoRest $configsUrl
        if ($configsData.value) { $configs = @($configsData.value) }
    }
    catch {
        Write-Warning "Failed to fetch policy configurations for '$proj': $($_.Exception.Message)"
        continue
    }

    Write-Host "    Found $($configs.Count) raw policy configuration(s) across $($repoList.Count) repository(ies)." -ForegroundColor Gray

    # D. Classify and Normalize Policies
    $normalizedPolicies = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($cfg in $configs) {
        $typeGuid = [string]$cfg.type.id
        $typeName = [string]$cfg.type.displayName
        $policyCode = "UNKNOWN"
        $defaultScope = "unknown"

        if ($knownTypes.ContainsKey($typeGuid)) {
            $policyCode = $knownTypes[$typeGuid].Code
            $defaultScope = $knownTypes[$typeGuid].Scope
        }

        # Analyze Scopes
        $scopes = @()
        if ($cfg.settings.PSObject.Properties['scope']) {
            $scopes = @($cfg.settings.scope)
        }

        $isProjectScope = $false
        $isCrossRepoBranch = $false
        $targetRepoNames = [System.Collections.Generic.List[string]]::new()
        $branchPatterns = [System.Collections.Generic.List[string]]::new()

        if ($scopes.Count -eq 0) {
            $isProjectScope = $true
        }
        else {
            foreach ($s in $scopes) {
                $repoId = if ($s.PSObject.Properties['repositoryId']) { [string]$s.repositoryId } else { $null }
                $refName = if ($s.PSObject.Properties['refName']) { [string]$s.refName } else { $null }
                
                if ([string]::IsNullOrWhiteSpace($repoId)) {
                    if ([string]::IsNullOrWhiteSpace($refName)) {
                        $isProjectScope = $true
                    }
                    else {
                        $isCrossRepoBranch = $true
                        $branchPatterns.Add($refName)
                    }
                }
                else {
                    $rName = if ($repoMap.ContainsKey($repoId)) { $repoMap[$repoId] } else { $repoId }
                    $targetRepoNames.Add($rName)
                    if (-not [string]::IsNullOrWhiteSpace($refName)) {
                        $branchPatterns.Add($refName)
                    }
                }
            }
        }

        $classification = "ProjectPushPolicy"
        if ($isCrossRepoBranch) {
            $classification = "ProjectCrossRepoBranchPolicy"
        }
        elseif ($targetRepoNames.Count -gt 0) {
            $classification = "RepositoryScopedPolicy"
        }

        $normalizedPolicies.Add([PSCustomObject]@{
            Id                  = $cfg.id
            PolicyCode          = $policyCode
            PolicyName          = $typeName
            TypeGuid            = $typeGuid
            IsEnabled           = [bool]$cfg.isEnabled
            IsBlocking          = [bool]$cfg.isBlocking
            Classification      = $classification
            TargetRepositories  = @($targetRepoNames | Select-Object -Unique)
            BranchPatterns      = @($branchPatterns | Select-Object -Unique)
            Settings            = $cfg.settings
            RawUrl              = $cfg.url
        })
    }

    # E. Construct Project Capture Object
    $captureObj = [PSCustomObject]@{
        CaptureVersion       = "2.0"
        CapturedAtUtc        = (Get-Date).ToUniversalTime().ToString("o")
        Organization         = $org
        ProjectName          = $projData.name
        ProjectId            = $projData.id
        RepositoryCount      = $repoList.Count
        TotalPoliciesCount   = $normalizedPolicies.Count
        PushPoliciesCount    = @($normalizedPolicies | Where-Object { $_.Classification -eq 'ProjectPushPolicy' }).Count
        CrossRepoBranchCount = @($normalizedPolicies | Where-Object { $_.Classification -eq 'ProjectCrossRepoBranchPolicy' }).Count
        RepoScopedCount      = @($normalizedPolicies | Where-Object { $_.Classification -eq 'RepositoryScopedPolicy' }).Count
        Policies             = $normalizedPolicies
    }

    # F. Save to Disk
    $safeName = "$org-$proj" -replace '[^a-zA-Z0-9_\-]', '_'
    $outFile = Join-Path -Path $outputDir -ChildPath "$safeName.project-policies.json"
    $latestFile = Join-Path -Path $latestDir -ChildPath "$safeName.project-policies.json"

    $captureObj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outFile -Encoding utf8
    $captureObj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $latestFile -Encoding utf8

    Write-Host "    [SAVED] $outFile" -ForegroundColor Green

    $summaryList.Add([PSCustomObject]@{
        Organization = $org
        Project      = $projData.name
        Repos        = $repoList.Count
        Total        = $normalizedPolicies.Count
        ProjectPush  = $captureObj.PushPoliciesCount
        CrossRepo    = $captureObj.CrossRepoBranchCount
        RepoScoped   = $captureObj.RepoScopedCount
    })
}

Write-Host "`n-----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "                  CAPTURE SUMMARY BY PROJECT                     " -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
$summaryList | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White

Write-Host "[OK] Project policies successfully captured in: $outputDir" -ForegroundColor Green
