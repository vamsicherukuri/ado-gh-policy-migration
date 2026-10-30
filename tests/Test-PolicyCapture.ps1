#Requires -Version 7.0
# Offline regression tests: no credentials, network access, or additional modules required.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$captureScript = Join-Path $root 'scripts\capture\Capture-AdoPolicies.ps1'
$exportScript = Join-Path $root 'scripts\capture\Export-AdoPolicies.ps1'
$fixture = Join-Path $root 'output\ado2gh-migration\20261023Ado2GhMigration01\ado-baseline.json'
$baseline = Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json -AsHashtable
$legacy = Get-Content -LiteralPath (Join-Path $root 'output\_archive\policy-export\20261023Ado2GhMigration01\ado-policies.portable.json') -Raw |
    ConvertFrom-Json -AsHashtable
$membership = Get-Content -LiteralPath (Join-Path $root 'output\ado-policy-testing-project1\reviewer-membership.json') -Raw |
    ConvertFrom-Json -AsHashtable
$state = Get-Content -LiteralPath (Join-Path $root 'output\ado-policy-testing-project1\policy-state.json') -Raw |
    ConvertFrom-Json -AsHashtable
$testDir = Join-Path ([IO.Path]::GetTempPath()) ('ado-policy-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testDir)
$checks = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAILED: $Message" }
    $script:checks++
}

function ConvertTo-Canonical {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [Collections.IDictionary]) {
        $parts = foreach ($key in @($Value.Keys | Sort-Object -CaseSensitive)) {
            (ConvertTo-Json -InputObject ([string]$key) -Compress) + ':' + (ConvertTo-Canonical $Value[$key])
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [array]) {
        $parts = foreach ($item in $Value) { ConvertTo-Canonical $item }
        return '[' + ($parts -join ',') + ']'
    }
    ConvertTo-Json -InputObject $Value -Compress -Depth 100
}

try {
    . $captureScript -Org fixture-org -Project fixture-project -RunId Offline01 -OutputRoot $testDir
    $envName = 'ADO_POLICY_TEST_' + [Guid]::NewGuid().ToString('N')
    [Environment]::SetEnvironmentVariable($envName, 'offline-test-value', 'Process')
    try {
        $header = Get-AdoAuthorization pat $envName
        Assert-True ($header -eq ('Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(':offline-test-value')))) 'PAT is read from the named environment variable'
    }
    finally { [Environment]::SetEnvironmentVariable($envName, $null, 'Process') }
    $script:authVariables = [Collections.Generic.List[string]]::new()
    function Get-AdoAuthorization {
        param($Mode, $EnvironmentVariable)
        $script:authVariables.Add($EnvironmentVariable)
        'Basic offline-placeholder'
    }
    $script:requestCount = 0
    $script:failIdentities = $false
    $script:emptyPolicies = $false
    $script:badContent = $false
    $script:failStatus = 0
    function Invoke-WebRequest {
        param($Uri, $Method, $Headers, $TimeoutSec, $MaximumRedirection, [switch]$SkipHttpErrorCheck)
        Assert-True ($Method -eq 'Get') 'Capture only issues GET requests'
        Assert-True ($MaximumRedirection -eq 0) 'Authenticated requests cannot follow redirects'
        $script:requestCount++
        $url = [Uri]$Uri
        $query = [System.Web.HttpUtility]::ParseQueryString($url.Query)
        $headersOut = @{ 'Content-Type' = 'application/json' }
        $status = 200
        $body = @{}
        if ($url.AbsolutePath -match '/_apis/projects$') {
            if (-not $query['continuationToken']) {
                $body = @{ value = @(@{ name = 'project1'; id = 'fixture-project' }) }
                $headersOut['x-ms-continuationtoken'] = 'project-page-2'
            }
            else { $body = @{ value = @(@{ name = 'project2'; id = 'second-project' }) } }
        }
        elseif ($url.AbsolutePath -match '/_apis/projects/') {
            $body = @{ name = 'project1'; id = 'fixture-project' }
            if ($url.AbsolutePath.EndsWith('/project2')) { $body = @{ name = 'project2'; id = 'second-project' } }
        }
        elseif ($url.AbsolutePath -match '/git/repositories$') {
            $body = @{ value = @($baseline.repositories.Values | ForEach-Object { $_.repository }) }
        }
        elseif ($url.AbsolutePath -match '/_apis/policy/configurations$') {
            if ($script:emptyPolicies) { $body = @{ value = @() } }
            elseif (-not $query['continuationToken']) {
                $body = @{ value = @($baseline.policies | Select-Object -First 10) }
                $headersOut['x-ms-continuationtoken'] = 'next-page'
            } else { $body = @{ value = @($baseline.policies | Select-Object -Skip 10) } }
        }
        elseif ($url.AbsolutePath -match '/git/repositories/([^/]+)/refs$') {
            $id = $Matches[1]
            $repo = @($baseline.repositories.Values | Where-Object { $_.repository.id -eq $id })[0]
            $body = @{ value = @(
                foreach ($name in $repo.refs.Keys) {
                    if ($name.StartsWith('refs/' + $query['filter'])) { @{ name = $name; objectId = $repo.refs[$name] } }
                }
            ) }
        }
        elseif ($url.AbsolutePath -match '/git/policy/configurations$') {
            $repo = @($baseline.repositories.Values | Where-Object { $_.repository.id -eq $query['repositoryId'] })[0]
            $branch = $query['refName'] -replace '^refs/heads/', ''
            $body = @{ value = @(
                foreach ($policy in $repo.effectivePolicies[$branch]) {
                    @{
                        id = $policy.id; type = @{ displayName = $policy.type }
                        isEnabled = $policy.isEnabled; isBlocking = $policy.isBlocking
                    }
                }
            ) }
        }
        elseif ($url.AbsolutePath -match '/_apis/identities$') {
            if ($script:failIdentities) { $status = 403 }
            $body = @{ value = @(
                foreach ($principal in $membership.identities.Keys) {
                    @{
                        id = $membership.identities[$principal]; providerDisplayName = $principal
                        properties = @{ Account = @{ '$value' = $principal } }
                    }
                }
            ) }
        }
        elseif ($url.AbsolutePath -match '/build/definitions/(\d+)$') {
            $id = [long]$Matches[1]
            $pipeline = @($state.pipelines.Values | Where-Object { $_.id -eq $id })[0]
            $body = @{ name = $pipeline.name }
        }
        else { throw "Unexpected fixture request: $Uri" }
        if ($script:badContent) { $headersOut['Content-Type'] = 'text/html' }
        if ($script:failStatus) { $status = $script:failStatus }
        @{
            StatusCode = $status; Headers = $headersOut
            Content = (ConvertTo-Json -InputObject $body -Depth 100)
        }
    }
    $summary = Invoke-PolicyCapture | ConvertFrom-Json -AsHashtable
    Assert-True ($summary.policies -eq 26) 'Capture retains all 26 policies across pagination'
    Assert-True ($summary.policyCounts.project -eq 6 -and $summary.policyCounts.repository -eq 6 -and
        $summary.policyCounts.crossRepoBranch -eq 7 -and $summary.policyCounts.repositoryBranch -eq 7 -and
        $summary.policyCounts.mixed -eq 0) 'Policy levels count unique configurations without branch duplication'
    $console = @(Format-CaptureSummary @{ status = 'complete'; captures = @($summary) }) -join "`n"
    Assert-True ($console -match 'Organizations: 1 \| Projects: 1' -and
        $console -match 'Policies captured: 26' -and $console -notmatch '"captures"|getRequests') 'Console shows counts rather than detailed JSON'
    Assert-True ($summary.getRequests -eq $script:requestCount) 'GET count is accurate'
    Assert-True ([IO.Path]::GetFileName($summary.capture) -eq 'project1.capture.json') 'Direct capture uses a readable flat filename'
    $snapshot = Get-Content -LiteralPath $summary.capture -Raw | ConvertFrom-Json -AsHashtable
    Assert-True ((ConvertTo-Canonical $snapshot.policies) -eq (ConvertTo-Canonical $baseline.policies)) 'Raw policy settings are lossless'
    foreach ($name in $baseline.repositories.Keys) {
        Assert-True ((ConvertTo-Canonical $snapshot.repositories[$name].refs) -eq
            (ConvertTo-Canonical $baseline.repositories[$name].refs)) "Refs preserved for $name"
        foreach ($branch in $baseline.repositories[$name].effectivePolicies.Keys) {
            $expected = @($baseline.repositories[$name].effectivePolicies[$branch] | ForEach-Object {
                @{ id = $_.id; type = $_.type; isEnabled = $_.isEnabled; isBlocking = $_.isBlocking }
            })
            Assert-True ((ConvertTo-Canonical $snapshot.repositories[$name].effectivePolicies[$branch]) -eq
                (ConvertTo-Canonical $expected)) "Effective branch policies preserved for $name/$branch"
        }
    }
    $before = $script:requestCount
    $refused = $false
    try { Invoke-PolicyCapture | Out-Null } catch { $refused = $_.Exception.Message -like 'Capture already exists*' }
    Assert-True ($refused -and $script:requestCount -eq $before) 'Existing capture is refused before authentication/API requests'

    $baselineOut = Join-Path $testDir 'baseline-export'
    $result = & $exportScript -RunId 20261023Ado2GhMigration01 -OutputDir $baselineOut | ConvertFrom-Json -AsHashtable
    $portable = Get-Content -LiteralPath $result.portableJson -Raw | ConvertFrom-Json -AsHashtable
    Assert-True ($result.csvRows -eq 100 -and $result.unresolvedIdReferences -eq 0) 'Legacy export produces 100 rows and resolved references'
    Assert-True ((ConvertTo-Canonical $portable.policies) -eq (ConvertTo-Canonical $legacy.policies)) 'Portable policy schema/values match Python export'
    Assert-True ((ConvertTo-Canonical $portable.references) -eq (ConvertTo-Canonical $legacy.references)) 'Legacy reference mappings match Python export'
    $oldRows = @(Import-Csv -LiteralPath (Join-Path $root 'output\_archive\policy-export\20261023Ado2GhMigration01\ado-policies-review.csv'))
    $newRows = @(Import-Csv -LiteralPath $result.reviewCsv)
    foreach ($old in $oldRows) {
        $new = @($newRows | Where-Object { $_.'Source policy ID' -eq $old.'Source policy ID' -and $_.Setting -eq $old.Setting })
        Assert-True ($new.Count -eq 1) 'CSV setting key retained'
        foreach ($column in @('Inventory ID', 'Level', 'Applies to', 'Policy type', 'Enabled', 'Blocking', 'Meaning', 'Value source')) {
            Assert-True ($new[0].$column -eq $old.$column) "CSV $column matches for $($old.'Source policy ID')/$($old.Setting): '$($new[0].$column)' vs '$($old.$column)'"
        }
        $a = $old.'Raw value'; $b = $new[0].'Raw value'
        if ($a -and $a -notmatch '^(identity|pipeline|repository):') {
            $a = ConvertTo-Canonical (ConvertFrom-Json -InputObject $a -AsHashtable -NoEnumerate)
            $b = ConvertTo-Canonical (ConvertFrom-Json -InputObject $b -AsHashtable -NoEnumerate)
        }
        Assert-True ($a -eq $b) 'CSV raw value preserved'
    }
    $captureResult = & $exportScript -Capture $summary.capture | ConvertFrom-Json -AsHashtable
    Assert-True ($captureResult.policies -eq 26 -and $captureResult.unresolvedIdReferences -eq 0) 'Fresh capture exports without legacy name resolution'
    Assert-True ((Split-Path $captureResult.reviewCsv) -eq (Split-Path $summary.capture) -and
        [IO.Path]::GetFileName($captureResult.reviewCsv) -eq 'project1.review.csv') 'New review CSV sits beside the capture'
    Assert-True ((Get-CaptureFileStem 'unsafe/name' 'fixture-id') -eq 'unsafe_name-fixture-id') 'Unsafe project names receive a safe ID-suffixed filename'
    $refused = $false
    try { & $exportScript -Capture $summary.capture | Out-Null } catch { $refused = $_.Exception.Message -like 'Export already exists*' }
    Assert-True $refused 'Existing export is not overwritten'

    $script:RunId = 'Subset01'; $script:Repos = @('sample2')
    $subset = Invoke-PolicyCapture | ConvertFrom-Json -AsHashtable
    $subsetSnapshot = Get-Content -LiteralPath $subset.capture -Raw | ConvertFrom-Json -AsHashtable
    Assert-True ($subsetSnapshot.repositories.Count -eq 1 -and $subsetSnapshot.policies.Count -eq 26) 'Subset retains project-wide and selected-repo policies'
    $script:RunId = 'Unresolved01'; $script:failIdentities = $true
    $unresolvedSummary = Invoke-PolicyCapture 3>$null | ConvertFrom-Json -AsHashtable
    Assert-True ($unresolvedSummary.warnings.Count -gt 0) 'Permission-limited identities generate persistent warnings'
    $unresolvedResult = & $exportScript -Capture $unresolvedSummary.capture 3>$null | ConvertFrom-Json -AsHashtable
    Assert-True ($unresolvedResult.unresolvedIdReferences -eq 2) 'Unresolved identity IDs remain explicit and distinct'

    $script:RunId = 'EmptyPolicy01'; $script:emptyPolicies = $true
    $empty = Invoke-PolicyCapture | ConvertFrom-Json -AsHashtable
    $emptyResult = & $exportScript -Capture $empty.capture | ConvertFrom-Json -AsHashtable
    Assert-True ($emptyResult.policies -eq 0 -and $emptyResult.csvRows -eq 0) 'Empty snapshots retain empty policy arrays'
    Assert-True ((Get-Content -LiteralPath $emptyResult.reviewCsv -TotalCount 1) -like '*"Raw value"*') 'Empty CSV still has column headers'

    $synthetic = Get-Content -LiteralPath $summary.capture -Raw | ConvertFrom-Json -AsHashtable
    $synthetic.policies = @($synthetic.policies[0])
    $synthetic.policies[0].type.displayName = '=1+1'
    $synthetic.policies[0].settings = @{
        scope = @(@{ repositoryId = $null }); message = '=1+1'
        custom = @{ nullValue = $null; falseValue = $false; emptyArray = @(); nested = @(@{ value = 9223372036854775807 }) }
        requiredReviewerIds = @(); buildDefinitionId = $null; authorId = $null
    }
    $syntheticPath = Join-Path $testDir 'synthetic.json'
    ConvertTo-Json -InputObject $synthetic -Depth 100 | Set-Content -LiteralPath $syntheticPath -Encoding utf8
    $syntheticResult = & $exportScript -Capture $syntheticPath | ConvertFrom-Json -AsHashtable
    $syntheticExport = Get-Content -LiteralPath $syntheticResult.portableJson -Raw | ConvertFrom-Json -AsHashtable
    $syntheticRows = @(Import-Csv -LiteralPath $syntheticResult.reviewCsv)
    Assert-True ($syntheticExport.policies[0].settings.message -eq '=1+1') 'Portable JSON does not change formula-like strings'
    Assert-True ($syntheticRows[0].'Policy type'.StartsWith("'=")) 'Review CSV neutralizes formula prefixes'
    Assert-True ((ConvertTo-Canonical $syntheticExport.policies[0].settings.custom) -eq
        (ConvertTo-Canonical $synthetic.policies[0].settings.custom)) 'Unknown nested settings, nulls, booleans, empty arrays and 64-bit integers survive'
    Assert-True ($null -eq $syntheticExport.policies[0].settings.buildDefinitionId -and
        $syntheticExport.policies[0].settings.requiredReviewerIds.Count -eq 0) 'Null and empty reference settings remain null/empty'
    $script:badContent = $true
    $refused = $false
    try { Invoke-AdoGet @{ gets = 0; authorization = 'offline' } 'https://dev.azure.com/test/_apis/projects/test' | Out-Null }
    catch { $refused = $_.Exception.Message -like '*non-JSON*' }
    Assert-True $refused 'Non-JSON authentication responses fail explicitly'
    $script:badContent = $false; $script:failStatus = 401
    $refused = $false
    try { Invoke-AdoGet @{ gets = 0; authorization = 'offline' } 'https://dev.azure.com/test/_apis/projects/test' | Out-Null }
    catch { $refused = $_.Exception.Message -like '*HTTP 401*' }
    Assert-True $refused 'Authentication failures do not become successful captures'
    $script:failStatus = 0; $script:emptyPolicies = $false; $script:failIdentities = $false
    . $captureScript -RunId DefaultConfig01 -OutputRoot $testDir
    Assert-True ([IO.Path]::GetFullPath($script:ConfigPath) -eq
        (Join-Path $root 'config\ado-policy-config.csv')) 'Default config path resolves relative to the script workspace'
    $defaultPreview = Invoke-ConfiguredCapture -Preview | ConvertFrom-Json -AsHashtable
    Assert-True ($defaultPreview.status -eq 'preview' -and $defaultPreview.selections.Count -eq 2) 'Omitted ConfigPath loads the supplied CSV'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $testDir 'DefaultConfig01'))) 'Default config preview writes no output'
    $configPath = Join-Path $testDir 'ado-policy-config.csv'
    $csvHeader = 'Organization,Project,Repository'
    @($csvHeader, 'first-org,*,*') | Set-Content -LiteralPath $configPath
    $batch = Invoke-ConfiguredCapture -Path $configPath -RunId ConfigAll01 -OutputRoot $testDir |
        ConvertFrom-Json -AsHashtable
    Assert-True ($batch.captures.Count -eq 2) 'All paginated projects in the single organization are captured'
    Assert-True (@($batch.captures | Where-Object { (Split-Path $_.capture) -ne (Join-Path $testDir 'ConfigAll01') }).Count -eq 0) 'Multi-project captures share one flat run directory'
    foreach ($entry in $batch.captures) {
        $flatExport = & $exportScript -Capture $entry.capture | ConvertFrom-Json -AsHashtable
        Assert-True ((Split-Path $flatExport.reviewCsv) -eq (Split-Path $entry.capture)) 'Multiple project exports do not collide or create subdirectories'
    }
    Assert-True (@($batch.captures | Where-Object { $_.repositories.Count -ne $baseline.repositories.Count }).Count -eq 0) 'Omitted repo selection includes all repositories'
    Assert-True ($script:authVariables.Contains('ADO_PAT')) 'CSV capture reads the standard ADO_PAT environment variable'
    Assert-True (Test-Path -LiteralPath (Join-Path $testDir 'ConfigAll01\capture-summary.json')) 'Successful batch persists a completion summary'
    $before = $script:requestCount
    $refused = $false
    try { Invoke-ConfiguredCapture -Path $configPath -RunId ConfigAll01 -OutputRoot $testDir | Out-Null }
    catch { $refused = $_.Exception.Message -like 'Capture run already exists*' }
    Assert-True ($refused -and $before -eq $script:requestCount) 'Existing batch cannot overwrite captures'
    @($csvHeader, 'selected-org,project1,sample2') | Set-Content -LiteralPath $configPath
    $batch = Invoke-ConfiguredCapture -Path $configPath -RunId ConfigSelected01 -OutputRoot $testDir |
        ConvertFrom-Json -AsHashtable
    Assert-True ($batch.captures.Count -eq 1 -and $batch.captures[0].repositories.Count -eq 1 -and
        $batch.captures[0].repositories[0] -eq 'sample2') 'Selected config captures only the requested org/project/repo'
    $selectedText = Get-Content -LiteralPath $batch.captures[0].capture -Raw
    Assert-True (-not $selectedText.Contains('offline-placeholder') -and -not $selectedText.Contains('SELECTED_PAT')) 'Capture does not contain authorization material or credential configuration'
    @($csvHeader, 'first-org,project1,sample2', 'first-org,project2,nonexistent-repo') |
        Set-Content -LiteralPath $configPath
    $refused = $false
    try { Invoke-ConfiguredCapture -Path $configPath -RunId PartialBatch01 -OutputRoot $testDir | Out-Null }
    catch { $refused = $_.Exception.Message -like 'Repository not found*' }
    Assert-True ($refused -and -not (Test-Path -LiteralPath (Join-Path $testDir 'PartialBatch01\capture-summary.json'))) 'Partial failures never produce a complete batch summary'
    Assert-True (Test-Path -LiteralPath (Join-Path $testDir 'PartialBatch01\project1.capture.json')) 'Completed project captures survive a subsequent project failure'
    @($csvHeader, 'first-org,*,*') | Set-Content -LiteralPath $configPath
    $defaultConfig = Read-CaptureConfig $configPath
    Assert-True ($defaultConfig.organizations.Count -eq 1 -and -not $defaultConfig.organizations[0].Contains('projects')) 'Default config selects all accessible projects in one organization'
    $before = $script:requestCount
    $authBefore = $script:authVariables.Count
    $refused = $false
    try { Invoke-ConfiguredCapture -Path '' -RunId NoInput01 -OutputRoot $testDir | Out-Null }
    catch { $refused = $_.Exception.Message -like 'No capture target supplied*' }
    Assert-True ($refused -and $before -eq $script:requestCount -and $authBefore -eq $script:authVariables.Count) 'Missing input fails before authentication or API calls'
    @($csvHeader,
        'selected-org,project1,sample2',
        'selected-org,project1,sample3',
        'selected-org,project2,sample2',
        'selected-org,project2,sample4') | Set-Content -LiteralPath $configPath
    $previewResult = Invoke-ConfiguredCapture -Path $configPath -RunId Preview01 -OutputRoot $testDir -Preview |
        ConvertFrom-Json -AsHashtable
    Assert-True ($previewResult.selections.Count -eq 2 -and
        $previewResult.selections[0].repositories.Count -eq 2 -and
        $previewResult.selections[1].repositories.Count -eq 2) 'Two projects with two repositories each resolve correctly'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $testDir 'Preview01'))) 'Preview writes no captures or output directories'
    $previewConsole = @(Format-CaptureSummary $previewResult) -join "`n"
    Assert-True ($previewConsole -match 'Projects: 2 \| Repositories: 4' -and
        $previewConsole -match 'policy counts not collected') 'Preview counts selections without implying policy capture'
    $batch = Invoke-ConfiguredCapture -Path $configPath -RunId FourRepos01 -OutputRoot $testDir |
        ConvertFrom-Json -AsHashtable
    Assert-True ($batch.captures.Count -eq 2 -and
        @($batch.captures | Where-Object { $_.repositories.Count -ne 2 }).Count -eq 0) 'Two-project/four-repository capture stays within selections'
    @($csvHeader, 'selected-org,project1,*') | Set-Content -LiteralPath $configPath
    $projectConfig = Read-CaptureConfig $configPath
    Assert-True (-not $projectConfig.organizations[0].projects[0].Contains('repos')) 'Project scope explicitly includes all repositories'
    $projectPreview = Invoke-ConfiguredCapture -Path $configPath -RunId ProjectPreview01 -OutputRoot $testDir -Preview |
        ConvertFrom-Json -AsHashtable
    Assert-True ($projectPreview.selections.Count -eq 1 -and
        $projectPreview.selections[0].repositories.Count -eq $baseline.repositories.Count) 'Project wildcard resolves all repositories'
    @($csvHeader, 'selected-org,"Project with, comma",sample2') | Set-Content -LiteralPath $configPath
    Assert-True ((Read-CaptureConfig $configPath).organizations[0].projects[0].name -eq 'Project with, comma') 'Quoted CSV project names are parsed correctly'
    foreach ($invalid in @(
        '',
        $csvHeader,
        "$csvHeader`n,*,*",
        "$csvHeader`nfirst-org,project1,",
        "$csvHeader`nfirst-org,,sample2",
        "$csvHeader`nfirst-org, ,sample2",
        "$csvHeader`nfirst-org,*,sample2",
        "$csvHeader`nfirst-org,project-*,*",
        "$csvHeader`nfirst-org,project1,repo-*",
        "$csvHeader`nfirst-org,project1,sample2;sample3",
        "$csvHeader`nfirst-org,*,*`nsecond-org,*,*",
        "$csvHeader`nfirst-org,*,*`nfirst-org,project1,*",
        "$csvHeader`nfirst-org,project1,*`nfirst-org,project1,sample2",
        "$csvHeader`nfirst-org,project1,sample2`nfirst-org,PROJECT1,SAMPLE2",
        "$csvHeader`nfirst-org,*,*`nfirst-org,*,*",
        "$csvHeader`nfirst-org,project1,*`nfirst-org,project1,*",
        "$csvHeader,Token`nfirst-org,*,*,not-a-token",
        "$csvHeader`nfirst-org,*,*,extra",
        "$csvHeader`nfirst-org,project1",
        "$csvHeader`nfirst-org,project1,`"unterminated",
        "$csvHeader`nhttps://dev.azure.com/test,*,*",
        "Organization,Scope,Project,Repository`nfirst-org,Organization,,"
    )) {
        Set-Content -LiteralPath $configPath -Value $invalid
        $before = $script:requestCount; $authBefore = $script:authVariables.Count; $refused = $false
        try { Invoke-ConfiguredCapture -Path $configPath -RunId Invalid01 -OutputRoot $testDir | Out-Null }
        catch { $refused = $true }
        Assert-True ($refused -and $before -eq $script:requestCount -and
            $authBefore -eq $script:authVariables.Count) 'Invalid CSV is rejected before authentication or network requests'
    }
    Write-Output "PASS: $checks assertions; offline capture, pagination, refs, schema/CSV parity, subset, unresolved references, empty data, and error handling."
}
finally {
    Remove-Item -LiteralPath $testDir -Recurse -Force
}
