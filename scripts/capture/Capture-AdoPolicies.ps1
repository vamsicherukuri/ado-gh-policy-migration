#Requires -Version 7.0
<#
.SYNOPSIS
Captures ADO repository and branch policies using GET requests only.
.EXAMPLE
.\scripts\capture\Capture-AdoPolicies.ps1 -Org ado-policy-testing -Project project1 -Auth az
.EXAMPLE
.\scripts\capture\Capture-AdoPolicies.ps1
.EXAMPLE
.\scripts\capture\Capture-AdoPolicies.ps1 -Preview
.NOTES
Does not capture tenant/organization security switches, permissions, or pipeline variables.
Defaults to config\ado-policy-config.csv relative to the workspace, not the current directory.
Missing, empty, or invalid configuration stops the scan; -ConfigPath selects a different CSV.
Config must identify exactly one organization. PAT values come exclusively from
ADO_PAT in user/process environment variables, never from config or script parameters.
#>
[CmdletBinding(DefaultParameterSetName = 'Config')]
param(
    [Parameter(ParameterSetName = 'Config')]
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\ado-policy-config.csv'),
    [Parameter(Mandatory, ParameterSetName = 'Direct')]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]*$')][string]$Org,
    [Parameter(Mandatory, ParameterSetName = 'Direct')][ValidateNotNullOrEmpty()][string]$Project,
    [Parameter(ParameterSetName = 'Direct')][string[]]$Repos,
    [ValidatePattern('^[A-Za-z0-9-]{6,40}$')][string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    [ValidateSet('pat', 'az')][string]$Auth = 'pat',
    [Parameter(ParameterSetName = 'Config')][switch]$Preview,
    [Parameter(ParameterSetName = 'Direct')]
    [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')][string]$PatEnvironmentVariable = 'ADO_PAT',
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\..\output\policy-capture')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AdoAuthorization {
    param([string]$Mode, [string]$EnvironmentVariable = 'ADO_PAT')
    if ($Mode -eq 'pat') {
        $pat = [Environment]::GetEnvironmentVariable($EnvironmentVariable, 'User')
        if (-not $pat) { $pat = [Environment]::GetEnvironmentVariable($EnvironmentVariable, 'Process') }
        if (-not $pat) { throw "Environment variable $EnvironmentVariable is not set. Set it or use Azure CLI authentication." }
        return 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(":$pat"))
    }
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI is not installed. Install it and run 'az login', or use -Auth pat."
    }
    $tokenJson = & az account get-access-token --resource '499b84ac-1321-427f-aa17-267ca6975798' --output json 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Could not obtain an ADO token. Run 'az login' first." }
    $token = ($tokenJson -join "`n") | ConvertFrom-Json -AsHashtable
    if (-not $token.accessToken) { throw 'Azure CLI returned no access token.' }
    return "Bearer $($token.accessToken)"
}

function Invoke-AdoGet {
    param([hashtable]$Client, [string]$Url, [hashtable]$Query = @{}, [int[]]$Allow = @())
    $parameters = @{ 'api-version' = '7.1' }
    foreach ($key in $Query.Keys) { $parameters[$key] = $Query[$key] }
    $encoded = foreach ($key in $parameters.Keys) {
        '{0}={1}' -f [Uri]::EscapeDataString($key), [Uri]::EscapeDataString([string]$parameters[$key])
    }
    $Client.gets++
    try {
        $response = Invoke-WebRequest -Uri ($Url + '?' + ($encoded -join '&')) -Method Get `
            -Headers @{ Authorization = $Client.authorization; Accept = 'application/json' } `
            -TimeoutSec 90 -MaximumRedirection 0 -SkipHttpErrorCheck
    }
    catch {
        # Do not propagate HTTP exception details that could contain authentication material.
        throw "GET $Url failed at the transport layer. Check connectivity, TLS, and proxy configuration."
    }
    $status = [int]$response.StatusCode
    if ($status -in $Allow) {
        Write-Warning "GET $Url returned HTTP $status; the reference will be marked unresolved."
        return @{ body = $null; headers = $response.Headers }
    }
    if ($status -lt 200 -or $status -ge 300) {
        throw "GET $Url returned HTTP $status. Check credentials, read permissions, and resource names."
    }
    if ([string]$response.Headers['Content-Type'] -notmatch 'json') {
        throw "GET $Url returned non-JSON content. The token may be invalid or expired."
    }
    return @{
        body = (ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 100)
        headers = $response.Headers
    }
}

function Get-AdoCollection {
    param([hashtable]$Client, [string]$Url, [hashtable]$Query = @{})
    $queryCopy = $Query.Clone()
    $seen = [Collections.Generic.HashSet[string]]::new()
    do {
        $response = Invoke-AdoGet $Client $Url $queryCopy
        if (-not $response.body.Contains('value')) { throw "GET $Url returned no collection value." }
        foreach ($item in $response.body.value) { $item }
        $continuation = [string]($response.headers['x-ms-continuationtoken'] | Select-Object -First 1)
        if ($continuation) {
            if (-not $seen.Add($continuation)) { throw "GET $Url repeated a continuation token." }
            $queryCopy.continuationToken = $continuation
        }
    } while ($continuation)
}

function Invoke-PolicyCapture {
    param(
        [string]$Org = $script:Org, [string]$Project = $script:Project,
        [string[]]$Repos = $script:Repos, [string]$RunId = $script:RunId,
        [string]$Auth = $script:Auth, [string]$OutputRoot = $script:OutputRoot,
        [string]$PatEnvironmentVariable = $script:PatEnvironmentVariable,
        [string]$TargetPath
    )
    $runRoot = Join-Path $OutputRoot $RunId
    if ($TargetPath) {
        if (Test-Path -LiteralPath $TargetPath) { throw "Capture already exists: $TargetPath. Use a new -RunId." }
    }
    elseif (Test-Path -LiteralPath $runRoot) { throw "Capture already exists: $runRoot. Use a new -RunId." }
    $client = @{ organization = $Org; authorization = (Get-AdoAuthorization $Auth $PatEnvironmentVariable); gets = 0 }
    $projectPath = [Uri]::EscapeDataString($Project)
    $api = "https://dev.azure.com/$Org/$projectPath/_apis"
    $projectInfo = (Invoke-AdoGet $client "https://dev.azure.com/$Org/_apis/projects/$projectPath").body
    $target = $TargetPath
    if (-not $target) { $target = Join-Path $runRoot ((Get-CaptureFileStem $projectInfo.name $projectInfo.id) + '.capture.json') }
    $repositories = @{}
    foreach ($repository in @(Get-AdoCollection $client "$api/git/repositories")) {
        $repositories[$repository.name] = $repository
    }
    $selected = @($repositories.Keys | Sort-Object)
    if ($Repos) {
        $selected = @($Repos | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
        foreach ($name in $selected) {
            if (-not $repositories.ContainsKey($name)) { throw "Repository not found in ${Org}/${Project}: $name" }
        }
    }
    $selectedIds = @($selected | ForEach-Object { $repositories[$_].id })
    $policies = @(Get-AdoCollection $client "$api/policy/configurations" @{ '$top' = 100 } |
        Where-Object {
            $scopes = @($_.settings['scope'] | Where-Object { $null -ne $_ })
            if (-not $scopes.Count) { $true }
            else { @($scopes | Where-Object { -not $_['repositoryId'] -or $_['repositoryId'] -in $selectedIds }).Count -gt 0 }
        } | Sort-Object { [long]$_.id })
    $snapshot = [ordered]@{
        captureVersion = '1.0'; capturedAt = [DateTime]::UtcNow.ToString('o')
        adoOrganization = $Org; adoProject = $projectInfo.name; projectId = $projectInfo.id
        authMode = $Auth; selectedRepositories = $selected; policies = $policies
        repositories = @{}; identities = @{}; pipelines = @{}; warnings = @()
    }
    foreach ($name in $selected) {
        $repository = $repositories[$name]
        $refs = @{}
        $effective = @{}
        if ($repository['isDisabled']) {
            $snapshot.warnings += "${name}: repository is disabled; refs/branches not captured"
        }
        else {
            $repoApi = "$api/git/repositories/$($repository.id)"
            foreach ($prefix in @('heads/', 'tags/')) {
                foreach ($ref in @(Get-AdoCollection $client "$repoApi/refs" @{ filter = $prefix; '$top' = 1000 })) {
                    $refs[$ref.name] = $ref.objectId
                }
            }
            foreach ($ref in @($refs.Keys | Where-Object { $_.StartsWith('refs/heads/') } | Sort-Object)) {
                $found = @(Get-AdoCollection $client "$api/git/policy/configurations" @{
                    repositoryId = $repository.id; refName = $ref
                })
                if ($found.Count) {
                    $effective[$ref.Substring(11)] = @($found | ForEach-Object {
                        @{ id = $_.id; type = $_.type.displayName; isEnabled = $_.isEnabled; isBlocking = $_.isBlocking }
                    })
                }
            }
        }
        $snapshot.repositories[$name] = @{ repository = $repository; refs = $refs; effectivePolicies = $effective }
    }
    $identityIds = [Collections.Generic.HashSet[string]]::new()
    $pipelineIds = [Collections.Generic.HashSet[string]]::new()
    foreach ($policy in $policies) {
        foreach ($id in @($policy.settings['requiredReviewerIds'])) { if ($id) { [void]$identityIds.Add($id) } }
        if ($policy.settings['authorId']) { [void]$identityIds.Add($policy.settings.authorId) }
        if ($null -ne $policy.settings['buildDefinitionId']) { [void]$pipelineIds.Add([string]$policy.settings.buildDefinitionId) }
    }
    if ($identityIds.Count) {
        $body = (Invoke-AdoGet $client "https://vssps.dev.azure.com/$Org/_apis/identities" @{
            identityIds = (($identityIds | Sort-Object) -join ','); queryMembership = 'None'
        } -Allow @(401, 403)).body
        if ($body) {
            foreach ($identity in $body.value) {
                if (-not $identity) { continue }
                $principal = $null
                $mail = $null
                if ($identity['properties'] -and $identity.properties['Account']) {
                    $principal = $identity.properties.Account['$value']
                }
                if ($identity['properties'] -and $identity.properties['Mail']) {
                    $mail = $identity.properties.Mail['$value']
                }
                if (-not $principal) { $principal = $mail }
                if (-not $principal) { $principal = $identity.providerDisplayName }
                $display = $identity['customDisplayName']
                if (-not $display) { $display = $identity.providerDisplayName }
                $snapshot.identities[$identity.id] = @{
                    principalName = $principal; displayName = $display; mail = $mail
                    isGroup = [bool]$identity['isContainer']; descriptor = $identity['descriptor']
                }
            }
        }
        foreach ($id in $identityIds) {
            if (-not $snapshot.identities.ContainsKey($id)) {
                $snapshot.identities[$id] = @{
                    principalName = $null; unresolved = $true
                    reason = 'Identity not returned (deleted, or token lacks Identity read)'
                }
            }
        }
    }
    foreach ($id in $pipelineIds) {
        $body = (Invoke-AdoGet $client "$api/build/definitions/$id" -Allow @(401, 403, 404)).body
        $snapshot.pipelines[$id] = if ($body) {
            $repoName = $null
            $yaml = $null
            if ($body['repository']) { $repoName = $body.repository['name'] }
            if ($body['process']) { $yaml = $body.process['yamlFilename'] }
            @{ name = $body.name; path = $body['path']; repository = $repoName; yamlFilename = $yaml }
        } else {
            @{ name = $null; unresolved = $true; reason = 'Pipeline not found or token lacks Build read' }
        }
    }
    foreach ($kind in @('identities', 'pipelines')) {
        foreach ($id in $snapshot[$kind].Keys) {
            if ($snapshot[$kind][$id]['unresolved']) {
                $snapshot.warnings += "$kind ${id}: $($snapshot[$kind][$id].reason)"
            }
        }
    }
    $json = ConvertTo-Json -InputObject $snapshot -Depth 100 -WarningAction Stop
    [void][IO.Directory]::CreateDirectory((Split-Path $target))
    $temporary = "$target.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary, $target)
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
        $client.authorization = $null
    }
    foreach ($warning in $snapshot.warnings) { Write-Warning $warning }
    $counts = @{ project = 0; repository = 0; crossRepoBranch = 0; repositoryBranch = 0; mixed = 0 }
    foreach ($policy in $policies) {
        $scopes = @($policy.settings['scope'] | Where-Object { $null -ne $_ })
        $levels = @(foreach ($scope in $scopes) {
            if ($scope['refName']) {
                if ($scope['repositoryId']) { 'repositoryBranch' } else { 'crossRepoBranch' }
            }
            else {
                if ($scope['repositoryId']) { 'repository' } else { 'project' }
            }
        })
        $levels = @($levels | Select-Object -Unique)
        $level = 'project'
        if ($levels.Count -eq 1) { $level = $levels[0] }
        elseif ($levels.Count -gt 1) { $level = 'mixed' }
        $counts[$level]++
    }
    [ordered]@{
        capture = [IO.Path]::GetFullPath($target); organization = $Org; project = $projectInfo.name
        repositories = $selected; policies = $policies.Count; getRequests = $client.gets
        warnings = $snapshot.warnings
        policyCounts = $counts
        next = ".\scripts\capture\Export-AdoPolicies.ps1 -Capture `"$([IO.Path]::GetFullPath($target))`""
    } | ConvertTo-Json -Depth 10
}

function Get-CaptureFileStem {
    param([string]$Name, [string]$Id)
    $safe = $Name -replace '[<>:"/\\|?*\x00-\x1f]', '_'
    $safe = $safe.TrimEnd('.', ' ')
    if ($safe.Length -gt 100) { $safe = $safe.Substring(0, 100) }
    if (-not $safe -or $safe -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') { $safe = 'project' }
    if ($safe -cne $Name) { $safe += "-$Id" }
    return $safe
}

function Read-CaptureConfig {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'No capture target supplied. Specify -ConfigPath with ado-policy-config.csv, or -Org and -Project. No scan was started.'
    }
    $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new([IO.Path]::GetFullPath($Path), [Text.Encoding]::UTF8, $true)
    $parser.SetDelimiters(',')
    $parser.HasFieldsEnclosedInQuotes = $true
    $rows = [Collections.Generic.List[object]]::new()
    try {
        if ($parser.EndOfData) { throw 'Config is empty. No scan was started.' }
        $header = $parser.ReadFields()
        if (($header -join ',') -cne 'Organization,Project,Repository') {
            throw 'CSV header must be exactly Organization,Project,Repository. Never include credentials in config.'
        }
        while (-not $parser.EndOfData) {
            $fields = $parser.ReadFields()
            if ($fields.Count -ne 3) { throw 'Each CSV row must have exactly three fields.' }
            $orgName, $projectName, $repoName = $fields
            if ($orgName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]*$') { throw 'Each row needs an organization name, not a URL.' }
            if ([string]::IsNullOrWhiteSpace($projectName) -or [string]::IsNullOrWhiteSpace($repoName)) {
                throw 'Project and Repository are required. Use * explicitly for all; blanks never mean all.'
            }
            if ($projectName -eq '*' -and $repoName -ne '*') { throw 'Project * requires Repository *.' }
            foreach ($name in @($projectName, $repoName)) {
                if ($name -ne '*' -and $name.Contains('*')) { throw 'Only standalone * is supported, not wildcard patterns.' }
            }
            if ($repoName.Contains(';')) { throw 'Use one repository per CSV row, not a semicolon-separated list.' }
            $rows.Add(@{ organization = $orgName; project = $projectName; repo = $repoName })
        }
    }
    finally { $parser.Dispose() }
    if (-not $rows.Count) { throw 'Config has no selections. No scan was started.' }
    $organization = @{ name = $rows[0].organization; auth = $script:Auth; patEnvironmentVariable = 'ADO_PAT' }
    if (@($rows | Where-Object { $_.organization -ne $organization.name }).Count) {
        throw 'Config must contain exactly one organization. Use a separate run for each organization.'
    }
    $orgRows = @($rows | Where-Object project -eq '*')
    if ($orgRows.Count) {
        if ($rows.Count -ne 1) { throw 'Organization scope cannot overlap any other selection.' }
    }
    else {
        $projects = [Collections.Generic.List[object]]::new()
        foreach ($group in @($rows | Group-Object project)) {
            $projectRows = @($group.Group)
            $selection = @{ name = $group.Name }
            if (@($projectRows | Where-Object repo -eq '*').Count) {
                if ($projectRows.Count -ne 1) { throw 'Project scope cannot overlap another selection in the same project.' }
            }
            else {
                $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($row in $projectRows) {
                    if (-not $seen.Add($row.repo)) { throw 'Duplicate repository selection in config.' }
                    if ($row.repo.Contains(',')) { throw 'Use one repository per CSV row, not a comma-separated list.' }
                }
                $selection.repos = @($projectRows | ForEach-Object { $_.repo })
            }
            $projects.Add($selection)
        }
        $organization.projects = @($projects.ToArray())
    }
    return @{ organizations = @($organization) }
}

function Invoke-ConfiguredCapture {
    param([string]$Path = $script:ConfigPath, [string]$RunId = $script:RunId,
        [string]$OutputRoot = $script:OutputRoot, [switch]$Preview = $script:Preview)
    $config = Read-CaptureConfig $Path
    $batchRoot = Join-Path $OutputRoot $RunId
    if (Test-Path -LiteralPath $batchRoot) { throw "Capture run already exists: $batchRoot. Use a new -RunId." }
    $results = [Collections.Generic.List[object]]::new()
    foreach ($organization in $config.organizations) {
        $client = @{
            authorization = (Get-AdoAuthorization $organization.auth $organization.patEnvironmentVariable)
            gets = 0
        }
        try {
            $api = "https://dev.azure.com/$($organization.name)/_apis"
            $projects = @()
            if ($organization.Contains('projects')) {
                $projects = @(
                    foreach ($selection in $organization.projects) {
                        $encoded = [Uri]::EscapeDataString($selection.name)
                        $info = (Invoke-AdoGet $client "$api/projects/$encoded").body
                        @{ id = $info.id; name = $info.name; repos = $selection['repos'] }
                    }
                )
            }
            else {
                $projects = @(Get-AdoCollection $client "$api/projects" @{ '$top' = 100 } |
                    ForEach-Object { @{ id = $_.id; name = $_.name; repos = $null } })
                if (-not $projects.Count) { throw "No accessible projects returned for $($organization.name)." }
            }
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $stems = @{}
            foreach ($selection in $projects) {
                $stem = Get-CaptureFileStem $selection.name $selection.id
                $stems[[string]$selection.id] = $stem
            }
            $collisions = @($stems.Values | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
            foreach ($id in @($stems.Keys)) {
                if ($stems[$id] -in $collisions) { $stems[$id] += "-$id" }
            }
            foreach ($selection in $projects) {
                $id = [string]$selection.id
                if ($id -notmatch '^[A-Za-z0-9-]+$') { throw 'ADO returned an invalid project ID.' }
                if (-not $seen.Add($id)) { throw 'Selections resolve to the same project ID more than once.' }
                if ($Preview) {
                    $encoded = [Uri]::EscapeDataString($id)
                    $repositories = @(Get-AdoCollection $client "https://dev.azure.com/$($organization.name)/$encoded/_apis/git/repositories")
                    $names = @($repositories | ForEach-Object { $_.name } | Sort-Object)
                    if ($selection.repos) {
                        foreach ($name in $selection.repos) {
                            if ($name -notin $names) { throw 'Selected repository not found during preview.' }
                        }
                        $names = @($selection.repos)
                    }
                    $results.Add(@{ organization = $organization.name; projectId = $id; repositories = $names })
                    continue
                }
                $result = Invoke-PolicyCapture -Org $organization.name -Project $id -Repos $selection.repos `
                    -Auth $organization.auth -PatEnvironmentVariable $organization.patEnvironmentVariable `
                    -RunId $RunId -OutputRoot $OutputRoot `
                    -TargetPath (Join-Path $batchRoot ($stems[$id] + '.capture.json')) |
                    ConvertFrom-Json -AsHashtable
                $results.Add($result)
            }
            if ($Preview) {
                return (ConvertTo-Json -InputObject @{ status = 'preview'; selections = @($results.ToArray()) } -Depth 20)
            }
        }
        finally { $client.authorization = $null }
    }
    # A summary is written only after every configured project completes successfully.
    $summary = @{ runId = $RunId; captures = @($results.ToArray()); status = 'complete' }
    $json = ConvertTo-Json -InputObject $summary -Depth 20 -WarningAction Stop
    [void][IO.Directory]::CreateDirectory($batchRoot)
    [IO.File]::WriteAllText((Join-Path $batchRoot 'capture-summary.json'), $json, [Text.UTF8Encoding]::new($false))
    $json
}

function Format-CaptureSummary {
    param([Collections.IDictionary]$Summary)
    $previewMode = $Summary['status'] -eq 'preview'
    $captures = @($Summary['captures'])
    if ($previewMode) { $captures = @($Summary.selections) }
    $orgCount = @($captures | ForEach-Object { $_.organization } | Select-Object -Unique).Count
    $repoCount = 0
    foreach ($capture in $captures) { $repoCount += $capture.repositories.Count }
    "Organizations: $orgCount | Projects: $($captures.Count) | Repositories: $repoCount"
    if ($previewMode) {
        'Preview only: policy counts not collected; no files written.'
        return
    }
    $total = 0
    $counts = @{ project = 0; repository = 0; crossRepoBranch = 0; repositoryBranch = 0; mixed = 0 }
    foreach ($capture in $captures) {
        $total += $capture.policies
        foreach ($key in @($counts.Keys)) { $counts[$key] += $capture.policyCounts[$key] }
    }
    "Policies captured: $total"
    "Project-wide: $($counts.project) | Repository-wide: $($counts.repository)"
    "Cross-repo branch: $($counts.crossRepoBranch) | Repository branch: $($counts.repositoryBranch) | Mixed scope: $($counts.mixed)"
    'Organization security policies: not captured.'
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($PSCmdlet.ParameterSetName -eq 'Config') {
        $result = Invoke-ConfiguredCapture | ConvertFrom-Json -AsHashtable
    }
    else {
        $capture = Invoke-PolicyCapture | ConvertFrom-Json -AsHashtable
        $result = @{ status = 'complete'; captures = @($capture) }
    }
    Format-CaptureSummary $result
    if ($result.status -eq 'complete') {
        "Output: $([IO.Path]::GetFullPath((Join-Path $OutputRoot $RunId)))"
    }
}
