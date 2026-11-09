#Requires -Version 7.0
<#
.SYNOPSIS
    Captures Azure DevOps repository-level push policies and branch policies.

.DESCRIPTION
    Phase 3 - Step 1 of the ADO-to-GitHub Policy Migration pipeline.
    - Queries ADO Git & Policy APIs (_apis/git/repositories, _apis/policy/configurations) to extract:
        * Repository Push Policies (Author emails, max file size, max path length, reserved names, case enforcement)
        * Branch Policies (Reviewer requirements, comment resolution, merge types, build validation, status checks)
    - Supports both Azure DevOps Services (Cloud) and Azure DevOps Server 2022.1 (On-Premises).
    - Classifies policies by scope type (Push vs Branch) and ref pattern (e.g. refs/heads/main).
    - Exports clean, structured JSON captures for grouping and GitHub Ruleset translation.

.PARAMETER ReposFilePath
    Path to text file containing target repositories in 'org/project/repository' format. Defaults to 'config\repos.txt'.

.PARAMETER Org
    Direct ADO organization name.

.PARAMETER Project
    Direct ADO project name.

.PARAMETER Repo
    Direct ADO repository name.

.PARAMETER ServerUrl
    Base URL for Azure DevOps Server (e.g. 'https://server/tfs/DefaultCollection').

.PARAMETER UseDefaultCredentials
    Use Windows Integrated Authentication (NTLM/Kerberos) for on-premise ADO Server.

.PARAMETER SkipCertificateCheck
    Bypass SSL/TLS certificate validation for internal CAs or self-signed certificates.

.EXAMPLE
    cd "c:\Users\vcherukuri\factory\ado to gh branch policies\repo"
    pwsh .\01_Capture-AdoRepoPolicies.ps1
    pwsh .\01_Capture-AdoRepoPolicies.ps1 -Org "ado-policy-testing" -Project "project1" -Repo "sample2"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$MappingFilePath = "",

    [Parameter(Mandatory = $false)]
    [string]$ReposFilePath = "",

    [Parameter(Mandatory = $false)]
    [string]$Org = "",

    [Parameter(Mandatory = $false)]
    [string]$Project = "",

    [Parameter(Mandatory = $false)]
    [string]$Repo = "",

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
Write-Host "   Capture ADO Repository & Branch-Level Policies               " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Resolve Targets
$targetList = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($ServerUrl -and $Project -and $Repo) {
    $cleanBase = $ServerUrl.TrimEnd('/')
    $collectionName = ($cleanBase -split '/')[-1]
    $targetList.Add([PSCustomObject]@{
        BaseUrl = $cleanBase
        Org     = $collectionName
        Project = $Project.Trim()
        Repo    = $Repo.Trim()
    })
}
elseif ($Org -and $Project -and $Repo) {
    $cleanOrg = $Org.Trim()
    $base = if ($cleanOrg.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $cleanOrg.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
        $cleanOrg.TrimEnd('/')
    } else {
        "https://dev.azure.com/$cleanOrg"
    }
    $collectionName = ($base -split '/')[-1]
    $targetList.Add([PSCustomObject]@{
        BaseUrl = $base
        Org     = $collectionName
        Project = $Project.Trim()
        Repo    = $Repo.Trim()
    })
}
else {
    # Check for upfront Source-to-Target mapping manifest first
    if ([string]::IsNullOrWhiteSpace($MappingFilePath)) {
        $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\repo-mapping.csv"
        if (-not (Test-Path -LiteralPath $MappingFilePath)) {
            $MappingFilePath = Join-Path -Path $PSScriptRoot -ChildPath "repo-mapping.csv"
        }
    }

    if (Test-Path -LiteralPath $MappingFilePath) {
        Write-Host "[+] Using Source-to-Target mapping: $MappingFilePath" -ForegroundColor Cyan
        $mappingRows = @(Import-Csv -LiteralPath $MappingFilePath)
        foreach ($m in $mappingRows) {
            $cleanOrg = $m.AdoOrg.Trim()
            $base = if ($cleanOrg.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $cleanOrg.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
                $cleanOrg.TrimEnd('/')
            } else {
                "https://dev.azure.com/$cleanOrg"
            }
            $targetList.Add([PSCustomObject]@{
                BaseUrl      = $base
                Org          = ($base -split '/')[-1]
                Project      = $m.AdoProject.Trim()
                Repo         = $m.AdoRepo.Trim()
                TargetGhOrg  = if ($m.PSObject.Properties['TargetGhOrg']) { $m.TargetGhOrg.Trim() } else { "ADO2GH-Migration" }
                TargetGhRepo = if ($m.PSObject.Properties['TargetGhRepo']) { $m.TargetGhRepo.Trim() } else { $m.AdoRepo.Trim() }
            })
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($ReposFilePath)) {
            $ReposFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\repos.txt"
            if (-not (Test-Path -LiteralPath $ReposFilePath)) {
                $ReposFilePath = Join-Path -Path $PSScriptRoot -ChildPath "repos.txt"
            }
        }

        if (-not (Test-Path -LiteralPath $ReposFilePath)) {
            throw "Repositories config file not found at: '$ReposFilePath' or '$MappingFilePath'. Create it or provide -Org, -Project, and -Repo."
        }

        $lines = @(Get-Content -LiteralPath $ReposFilePath | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#")
        })

        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("http://", [StringComparison]::OrdinalIgnoreCase) -or $trimmed.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
                # On-premises Server format: http(s)://server/tfs/collection/project/_git/repo
                $gitIndex = $trimmed.IndexOf('/_git/')
                if ($gitIndex -gt 0) {
                    $baseProj = $trimmed.Substring(0, $gitIndex)
                    $rName = $trimmed.Substring($gitIndex + 6).Trim('/')
                    $lastSlash = $baseProj.LastIndexOf('/')
                    $base = $baseProj.Substring(0, $lastSlash)
                    $pName = $baseProj.Substring($lastSlash + 1)
                    $colName = ($base.TrimEnd('/') -split '/')[-1]
                    $targetList.Add([PSCustomObject]@{ BaseUrl = $base; Org = $colName; Project = $pName; Repo = $rName; TargetGhOrg = ""; TargetGhRepo = $rName })
                }
                else {
                    # Standard slash separated URL
                    $parts = $trimmed.TrimEnd('/') -split '/'
                    $rName = $parts[-1]
                    $pName = $parts[-2]
                    $base = ($parts[0..($parts.Length - 3)]) -join '/'
                    $colName = ($base -split '/')[-1]
                    $targetList.Add([PSCustomObject]@{ BaseUrl = $base; Org = $colName; Project = $pName; Repo = $rName; TargetGhOrg = ""; TargetGhRepo = $rName })
                }
            }
            elseif ($trimmed.Contains('/')) {
                $parts = $trimmed -split '/'
                if ($parts.Count -ge 3) {
                    $targetList.Add([PSCustomObject]@{
                        BaseUrl      = "https://dev.azure.com/$($parts[0].Trim())"
                        Org          = $parts[0].Trim()
                        Project      = $parts[1].Trim()
                        Repo         = $parts[2].Trim()
                        TargetGhOrg  = ""
                        TargetGhRepo = $parts[2].Trim()
                    })
                }
                elseif ($parts.Count -eq 2) {
                    $targetList.Add([PSCustomObject]@{
                        BaseUrl      = "https://dev.azure.com/ado-policy-testing"
                        Org          = "ado-policy-testing"
                        Project      = $parts[0].Trim()
                        Repo         = $parts[1].Trim()
                        TargetGhOrg  = ""
                        TargetGhRepo = $parts[1].Trim()
                    })
                }
            }
        }
    }
}

if ($targetList.Count -eq 0) {
    throw "No target repositories specified in '$ReposFilePath'."
}

Write-Host "[+] Target Repositories    : $($targetList.Count) repo(s)" -ForegroundColor Cyan
foreach ($t in $targetList) {
    Write-Host "    - $($t.Org)/$($t.Project)/$($t.Repo)" -ForegroundColor Gray
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
    catch {}
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
$logFile = Join-Path -Path $outputDir -ChildPath "execution.log"
$latestLog = Join-Path -Path $latestDir -ChildPath "execution.log"
"" | Set-Content -LiteralPath $logFile -Encoding utf8
"" | Set-Content -LiteralPath $latestLog -Encoding utf8

function Log-Message {
    param([string]$Text, [switch]$Console, [string]$Color = 'White')
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')] $Text"
    Add-Content -LiteralPath $logFile -Value $line -Encoding utf8
    Add-Content -LiteralPath $latestLog -Value $line -Encoding utf8
    if ($Console) {
        Write-Host $Text -ForegroundColor $Color
    }
}

# 4. Known Policy Type Mappings (GUID to Policy Code)
$knownTypes = @{
    # Push Policies
    '77ed4bd3-b063-4689-934a-175e4d0a78d7' = @{ Code = 'R01'; Name = 'Commit author email validation'; ScopeType = 'RepositoryPushPolicy' }
    '51c78909-e838-41a2-9496-c647091e3c61' = @{ Code = 'R02'; Name = 'File path validation'; ScopeType = 'RepositoryPushPolicy' }
    '7ed39669-655c-494e-b4a0-a08b4da0fcce' = @{ Code = 'R03'; Name = 'Case enforcement'; ScopeType = 'RepositoryPushPolicy' }
    'db2b9b4c-180d-4529-9701-01541d19f36b' = @{ Code = 'R04'; Name = 'Reserved names'; ScopeType = 'RepositoryPushPolicy' }
    '001a79cf-fda1-4c4e-9e7c-bac40ee5ead8' = @{ Code = 'R05'; Name = 'Maximum path length'; ScopeType = 'RepositoryPushPolicy' }
    '2e26e725-8201-4edd-8bf5-978563c34a80' = @{ Code = 'R06'; Name = 'Maximum file size'; ScopeType = 'RepositoryPushPolicy' }

    # Branch Policies
    'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd' = @{ Code = 'B01'; Name = 'Require a minimum number of reviewers'; ScopeType = 'BranchPolicy' }
    'c6a1889d-b943-4856-b76f-9e46bb6b0df2' = @{ Code = 'B03'; Name = 'Check for comment resolution'; ScopeType = 'BranchPolicy' }
    'fa4e907d-c16b-4a4c-9dfa-4916e5d171ab' = @{ Code = 'B04'; Name = 'Limit merge types'; ScopeType = 'BranchPolicy' }
    '0609b952-1397-4640-95ec-e00a01b2c241' = @{ Code = 'B05'; Name = 'Build validation'; ScopeType = 'BranchPolicy' }
    'cbdc66da-9728-4af8-aada-9a5a32e4a226' = @{ Code = 'B06'; Name = 'Status checks (External services)'; ScopeType = 'BranchPolicy' }
    'fd2167ab-b0be-447a-8ec8-39368250530e' = @{ Code = 'B07'; Name = 'Automatically included reviewers'; ScopeType = 'BranchPolicy' }
    '40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e' = @{ Code = 'B08'; Name = 'Check for linked work items'; ScopeType = 'BranchPolicy' }
}

$summaryList = [System.Collections.Generic.List[PSCustomObject]]::new()

# 5. Capture Repository Policies
foreach ($target in $targetList) {
    $org = $target.Org
    $proj = $target.Project
    $repo = $target.Repo
    $baseUrl = $target.BaseUrl
    Write-Host "`n[+] Capturing policies for repository '$org/$proj/$repo' ($baseUrl)..." -ForegroundColor Cyan

    # A. Fetch Repository Metadata
    $repoUrl = "$baseUrl/$([Uri]::EscapeDataString($proj))/_apis/git/repositories/$([Uri]::EscapeDataString($repo))?api-version=7.0"
    $repoData = $null
    try {
        $repoData = Invoke-AdoRest $repoUrl
    }
    catch {
        Write-Warning "Failed to query repository '$repo' in project '$proj': $($_.Exception.Message)"
        continue
    }

    $repoId = $repoData.id
    $defaultBranch = if ($repoData.defaultBranch) { $repoData.defaultBranch } else { "refs/heads/main" }
    Log-Message "[$org/$proj/$repo] Repository ID: $repoId, Default Branch: $defaultBranch"

    # B. Fetch Policy Configurations in Project
    $configsUrl = "$baseUrl/$([Uri]::EscapeDataString($proj))/_apis/policy/configurations?api-version=7.0"
    $configs = @()
    try {
        $configsData = Invoke-AdoRest $configsUrl
        if ($configsData.value) { $configs = @($configsData.value) }
    }
    catch {
        Write-Warning "Failed to fetch policy configurations for project '$proj': $($_.Exception.Message)"
        continue
    }

    # C. Filter and Classify Policies for THIS Repository
    $repoPolicies = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($cfg in $configs) {
        $typeGuid = [string]$cfg.type.id
        $typeName = [string]$cfg.type.displayName
        $policyCode = "UNKNOWN"
        $scopeType = "BranchPolicy"

        if ($knownTypes.ContainsKey($typeGuid)) {
            $policyCode = $knownTypes[$typeGuid].Code
            $typeName = $knownTypes[$typeGuid].Name
            $scopeType = $knownTypes[$typeGuid].ScopeType
        }

        # Check Scopes
        $scopes = @($cfg.settings.scope)
        $isMatch = $false
        $targetRef = $null
        $isCrossRepo = $false

        if ($scopes.Count -eq 0) {
            # Project-wide push policy applies to all repos
            $isMatch = $true
            $targetRef = "ALL"
            $scopeType = "RepositoryPushPolicy"
        }
        else {
            foreach ($s in $scopes) {
                $sRepoId = if ($s.PSObject.Properties['repositoryId']) { [string]$s.repositoryId } else { $null }
                $sRef = if ($s.PSObject.Properties['refName']) { [string]$s.refName } else { $null }

                if ([string]::IsNullOrWhiteSpace($sRepoId)) {
                    # Cross-repo policy applying to matching refName
                    $isMatch = $true
                    $isCrossRepo = $true
                    $targetRef = if ($sRef) { $sRef } else { "ALL" }
                }
                elseif ($sRepoId -eq $repoId) {
                    # Specifically scoped to this repository
                    $isMatch = $true
                    $targetRef = if ($sRef) { $sRef } else { "ALL" }
                }
            }
        }

        if (-not $isMatch) {
            continue
        }

        if ($targetRef -eq "ALL" -or [string]::IsNullOrWhiteSpace($targetRef)) {
            $scopeType = "RepositoryPushPolicy"
        }

        $repoPolicies.Add([PSCustomObject]@{
            Id            = $cfg.id
            PolicyCode    = $policyCode
            PolicyName    = $typeName
            TypeGuid      = $typeGuid
            ScopeType     = $scopeType
            TargetBranch  = $targetRef
            IsCrossRepo   = $isCrossRepo
            IsEnabled     = [bool]$cfg.isEnabled
            IsBlocking    = [bool]$cfg.isBlocking
            Settings      = $cfg.settings
            RawUrl        = $cfg.url
        })
    }

    Log-Message "Found $($repoPolicies.Count) applicable policies for '$org/$proj/$($repoData.name)'."

    # D. Construct Repository Capture Object
    $targetGhOrg = if ($target.PSObject.Properties['TargetGhOrg'] -and -not [string]::IsNullOrWhiteSpace($target.TargetGhOrg)) { $target.TargetGhOrg } else { "" }
    $targetGhRepo = if ($target.PSObject.Properties['TargetGhRepo'] -and -not [string]::IsNullOrWhiteSpace($target.TargetGhRepo)) { $target.TargetGhRepo } else { $repoData.name }

    $captureObj = [PSCustomObject]@{
        CaptureVersion      = "3.0"
        CapturedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
        Organization        = $org
        ProjectName         = $proj
        RepositoryName      = $repoData.name
        TargetGhOrg         = $targetGhOrg
        TargetGhRepo        = $targetGhRepo
        RepositoryId        = $repoId
        DefaultBranch       = $defaultBranch
        TotalPoliciesCount  = $repoPolicies.Count
        PushPoliciesCount   = @($repoPolicies | Where-Object { $_.ScopeType -eq 'RepositoryPushPolicy' }).Count
        BranchPoliciesCount = @($repoPolicies | Where-Object { $_.ScopeType -eq 'BranchPolicy' }).Count
        Policies            = $repoPolicies
    }

    # E. Save to Disk
    $safeName = "$org-$proj-$($repoData.name)" -replace '[^a-zA-Z0-9_\-]', '_'
    $outFile = Join-Path -Path $outputDir -ChildPath "$safeName.repo-policies.json"
    $latestFile = Join-Path -Path $latestDir -ChildPath "$safeName.repo-policies.json"

    $captureObj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outFile -Encoding utf8
    $captureObj | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $latestFile -Encoding utf8

    Log-Message "Saved JSON snapshot to: $outFile"
    Write-Host "  [+] Captured $org/$proj/$($repoData.name) ($($repoPolicies.Count) policies)" -ForegroundColor Gray

    $summaryList.Add([PSCustomObject]@{
        Organization   = $org
        Project        = $proj
        Repository     = $repoData.name
        DefaultBranch  = $defaultBranch
        TotalPolicies  = $repoPolicies.Count
        PushPolicies   = $captureObj.PushPoliciesCount
        BranchPolicies = $captureObj.BranchPoliciesCount
    })
}

# Write full summary table to execution log
$summaryTable = $summaryList | Format-Table -AutoSize | Out-String
Log-Message "`n-----------------------------------------------------------------"
Log-Message "                  CAPTURE SUMMARY BY REPOSITORY                  "
Log-Message "-----------------------------------------------------------------"
Log-Message "`n$summaryTable"

Write-Host "`n[OK] Repository policies successfully captured in: $outputDir" -ForegroundColor Green
Write-Host "     Detailed Execution Log: $logFile" -ForegroundColor Cyan
