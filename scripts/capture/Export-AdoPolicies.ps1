#Requires -Version 7.0
<#
.SYNOPSIS
Exports a policy snapshot as portable JSON and a one-row-per-setting review CSV, without API calls.
.EXAMPLE
.\scripts\capture\Export-AdoPolicies.ps1 -Capture .\output\policy-capture\MyCapture01\ado-policy-capture.json
.EXAMPLE
.\scripts\capture\Export-AdoPolicies.ps1 -RunId 20261023Ado2GhMigration01
.NOTES
Unresolved references retain their source ID and are explicitly flagged. This is not a restore tool.
#>
[CmdletBinding(DefaultParameterSetName = 'Capture')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Capture')][string]$Capture,
    [Parameter(Mandatory, ParameterSetName = 'Baseline')]
    [ValidatePattern('^[A-Za-z0-9-]{6,64}$')][string]$RunId,
    [string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))

function Read-PolicyJson {
    param([string]$Path)
    Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 100
}

function Format-PolicyValue {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'None' }
    if ($Value -is [Collections.IDictionary] -and $Value.Contains('$ref')) {
        $kind, $name = $Value['$ref'] -split ':', 2
        return "$($kind.Substring(0, 1).ToUpperInvariant())$($kind.Substring(1)) '$name'"
    }
    if ($Value -is [bool]) { if ($Value) { return 'Yes' }; return 'No' }
    if ($Value -is [array]) { return (($Value | ForEach-Object { Format-PolicyValue $_ }) -join ', ') }
    if ($Value -is [double]) {
        $text = $Value.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
        if ($text -notmatch '[.eE]') { $text += '.0' }
        return $text
    }
    return [string]$Value
}

function New-PolicyReference {
    param([string]$Kind, $Id)
    $sourceId = [string]$Id
    $name = $referenceNames[$Kind][$sourceId]
    if (-not $name) {
        $name = $sourceId
        $unresolved["${Kind}:$sourceId"] = @{
            kind = $Kind; sourceId = $Id; reason = 'Name unavailable; map this source ID explicitly before restore.'
        }
    }
    $record = @{ sourceId = $Id }
    if ($Kind -eq 'identity' -and $identityDetails.Contains($sourceId)) {
        foreach ($key in $identityDetails[$sourceId].Keys) { $record[$key] = $identityDetails[$sourceId][$key] }
    }
    $group = @{ repository = 'repositories'; identity = 'identities'; pipeline = 'pipelines' }[$Kind]
    if ($references[$group].Contains($name) -and
        [string]$references[$group][$name].sourceId -ne $sourceId) {
        throw "Ambiguous ${Kind} name '$name' refers to multiple source IDs. Resolve the collision before exporting."
    }
    $references[$group][$name] = $record
    return @{ '$ref' = "${Kind}:$name" }
}

if ($PSCmdlet.ParameterSetName -eq 'Baseline') {
    $Capture = Join-Path $root "output\ado2gh-migration\$RunId\ado-baseline.json"
    if (-not $OutputDir) { $OutputDir = Join-Path $root "output\policy-export\$RunId" }
}
elseif (-not $OutputDir) {
    $OutputDir = Split-Path ([IO.Path]::GetFullPath($Capture))
    if (-not $Capture.EndsWith('.capture.json', [StringComparison]::OrdinalIgnoreCase)) {
        $OutputDir = Join-Path $OutputDir 'export'
    }
}
$base = Read-PolicyJson $Capture
if (-not $base.Contains('policies') -or -not $base.Contains('repositories') -or
    -not $base['adoOrganization'] -or -not $base['adoProject'] -or -not $base['capturedAt']) {
    throw 'Input is not a supported ADO policy snapshot.'
}
$referenceNames = @{ repository = @{}; identity = @{}; pipeline = @{} }
$identityDetails = @{}
$inventory = @{}
foreach ($repo in $base.repositories.Values) {
    $referenceNames.repository[[string]$repo.repository.id] = $repo.repository.name
}
if ($PSCmdlet.ParameterSetName -eq 'Baseline') {
    # Legacy migration baselines kept name resolution in separate lab state files.
    $state = Read-PolicyJson (Join-Path $root 'output\ado-policy-testing-project1\policy-state.json')
    $membership = Read-PolicyJson (Join-Path $root 'output\ado-policy-testing-project1\reviewer-membership.json')
    foreach ($principal in $membership.identities.Keys) {
        $id = [string]$membership.identities[$principal]
        $member = @($membership.members.Values | Where-Object { $_.principalName -eq $principal })
        $details = @{ principalName = $principal; displayName = $null; origin = $null; subjectKind = $null }
        if ($member.Count) {
            foreach ($key in @('displayName', 'origin', 'subjectKind')) { $details[$key] = $member[0][$key] }
        }
        $identityDetails[$id] = $details
        $referenceNames.identity[$id] = $principal
    }
    foreach ($pipeline in $state.pipelines.Values) {
        $referenceNames.pipeline[[string]$pipeline.id] = $pipeline.name
    }
    foreach ($key in $state.policies.Keys) { $inventory[[string]$state.policies[$key].id] = $key }
}
foreach ($kind in @('identities', 'pipelines')) {
    if (-not $base.Contains($kind)) { continue }
    foreach ($id in $base[$kind].Keys) {
        $details = $base[$kind][$id]
        if ($kind -eq 'identities') {
            $identityDetails[$id] = $details
            $referenceNames.identity[$id] = $details['principalName']
        }
        else { $referenceNames.pipeline[$id] = $details['name'] }
    }
}
$references = @{ repositories = @{}; identities = @{}; pipelines = @{} }
$unresolved = @{}
$policies = @(
    foreach ($raw in $base.policies) {
        $settings = [ordered]@{}
        foreach ($key in $raw.settings.Keys) {
            if ($key -ne 'scope') { $settings[$key] = $raw.settings[$key] }
        }
        if ($settings.Contains('requiredReviewerIds') -and $null -ne $settings['requiredReviewerIds']) {
            $settings.requiredReviewerIds = @(
                foreach ($id in $settings.requiredReviewerIds) { New-PolicyReference identity $id }
            )
        }
        if ($settings.Contains('buildDefinitionId') -and $null -ne $settings['buildDefinitionId']) {
            $settings.buildDefinitionId = New-PolicyReference pipeline $settings.buildDefinitionId
        }
        if ($settings['authorId']) { $settings.authorId = New-PolicyReference identity $settings.authorId }
        $scope = @(
            foreach ($s in $raw.settings['scope']) {
                $repository = $null
                if ($null -ne $s['repositoryId']) { $repository = New-PolicyReference repository $s.repositoryId }
                [ordered]@{ repository = $repository; refName = $s['refName']; matchKind = $s['matchKind'] }
            }
        )
        $creator = $null
        if ($raw['createdBy']) { $creator = $raw.createdBy['uniqueName'] }
        [ordered]@{
            inventoryId = $inventory[[string]$raw.id]
            source = @{ policyId = $raw.id; revision = $raw.revision; createdDate = $raw['createdDate']; createdBy = $creator }
            type = @{ id = $raw.type.id; displayName = $raw.type.displayName }
            isEnabled = $raw.isEnabled; isBlocking = $raw.isBlocking; isDeleted = [bool]$raw['isDeleted']
            scope = $scope; settings = $settings
        }
    }
)
$export = [ordered]@{
    schemaVersion = '1.0'; exportedAt = [DateTime]::UtcNow.ToString('o')
    source = @{ organization = $base.adoOrganization; project = $base.adoProject; capturedAt = $base.capturedAt }
    howToApply = "Resolve every {'`$ref': 'kind:name'} to a destination ID. Stop on unresolved or ambiguous references. Rebuild settings.scope using repositoryId, refName, matchKind (null repositoryId means all repositories). POST {isEnabled,isBlocking,type:{id},settings} to https://dev.azure.com/{org}/{project}/_apis/policy/configurations?api-version=7.1. Review isDeleted before applying; never recreate deleted policies blindly."
    references = $references; policies = $policies
    unresolvedReferences = @($unresolved.Values)
}
$labels = @{
    authorEmailPatterns = 'Allowed commit author email pattern(s)'
    filenamePatterns = 'Blocked file path pattern(s)'
    enforceConsistentCase = 'Block case-only path conflicts'
    maxPathLength = 'Maximum path length (characters)'
    maximumGitBlobSizeInBytes = 'Maximum file size (bytes)'
    useUncompressedSize = 'Measure uncompressed size'
    minimumApproverCount = 'Minimum approvals required'
    creatorVoteCounts = "PR creator's vote counts"
    allowDownvotes = "Allow completion with 'waiting'/'rejected' votes"
    resetOnSourcePush = 'Reset all votes on new push'
    resetRejectionsOnSourcePush = 'Reset rejections on new push'
    requireVoteOnLastIteration = 'Require approval on latest iteration'
    requireVoteOnEachIteration = 'Require approval on each iteration'
    blockLastPusherVote = 'Last pusher cannot approve'
    allowNoFastForward = 'Allow basic merge (no fast-forward)'
    allowSquash = 'Allow squash merge'; allowRebase = 'Allow rebase and fast-forward'
    allowRebaseMerge = 'Allow rebase with merge commit'; buildDefinitionId = 'Build pipeline'
    displayName = 'Policy display name'; validDuration = 'Build expiration (minutes; 0 = never)'
    manualQueueOnly = 'Manual trigger only'; queueOnSourceUpdateOnly = 'Queue only when source updates'
    statusName = 'Status name'; statusGenre = 'Status genre'; authorId = 'Authorized status author'
    invalidateOnSourceUpdate = 'Reset status on new push'; defaultDisplayName = 'Status display name'
    policyApplicability = 'Applicability (0 = always, 1 = only when status posted)'
    requiredReviewerIds = 'Required reviewer'; message = 'Message shown to PR author'
}
$noSettings = @{
    'Reserved names restriction' = 'Blocks reserved file/folder names (no parameters)'
    'Work item linking' = 'PR must link a work item (no parameters)'
    'Comment requirements' = 'All PR comments must be resolved (no parameters)'
}
$rows = @(
    foreach ($policy in $policies) {
        $first = @{}
        if ($policy.scope.Count) { $first = $policy.scope[0] }
        $level = if ($first['refName']) {
            if ($first['repository']) { 'Branch' } else { 'Project (cross-repo branch)' }
        } else {
            if ($first['repository']) { 'Repository' } else { 'Project (all repositories)' }
        }
        $applies = @(
            foreach ($s in $policy.scope) {
                $name = 'All repositories'
                if ($s.repository) { $name = ($s.repository['$ref'] -split ':', 2)[1] }
                if ($s.refName) {
                    $branch = $s.refName -replace '^refs/heads/', ''
                    if ($s.matchKind -eq 'Prefix') { $branch += '*' }
                    "$name > $branch ($($s.matchKind))"
                } else { $name }
            }
        ) -join '; '
        if (-not $policy.scope.Count) { $applies = 'All repositories' }
        $common = [ordered]@{
            'Inventory ID' = $policy.inventoryId; 'Source policy ID' = $policy.source.policyId
            Level = $level; 'Applies to' = $applies; 'Policy type' = $policy.type.displayName
            Enabled = Format-PolicyValue $policy.isEnabled; Blocking = Format-PolicyValue $policy.isBlocking
        }
        if (-not $policy.settings.Count) {
            $meaning = $noSettings[$policy.type.displayName]
            if (-not $meaning) { $meaning = 'No parameters' }
            $row = [ordered]@{}
            foreach ($column in $common.Keys) { $row[$column] = $common[$column] }
            $row.Setting = '(none)'; $row['Raw value'] = ''; $row.Meaning = $meaning; $row['Value source'] = 'On/off only'
            [pscustomobject]$row
        }
        foreach ($key in $policy.settings.Keys) {
            $value = $policy.settings[$key]
            $values = [Collections.Generic.List[object]]::new()
            if ($key -eq 'requiredReviewerIds' -and $null -ne $value) {
                foreach ($item in $value) { $values.Add($item) }
            } else { $values.Add($value) }
            for ($i = 0; $i -lt $values.Count; $i++) {
                $item = $values[$i]
                $setting = $key
                if ($key -eq 'requiredReviewerIds' -and $null -ne $value) { $setting = "$key[$i]" }
                $label = $labels[$key]
                if (-not $label) { $label = $key }
                $rawValue = 'null'; $meaning = "${label}: not set"; $source = 'ADO default'
                if ($null -ne $item) {
                    $rawValue = ConvertTo-Json -InputObject $item -Depth 100 -Compress -WarningAction Stop
                    if ($item -is [Collections.IDictionary] -and $item.Contains('$ref')) { $rawValue = $item['$ref'] }
                    $meaning = "${label}: $(Format-PolicyValue $item)"; $source = 'Set'
                }
                $row = [ordered]@{}
                foreach ($column in $common.Keys) { $row[$column] = $common[$column] }
                $row.Setting = $setting; $row['Raw value'] = $rawValue; $row.Meaning = $meaning; $row['Value source'] = $source
                [pscustomobject]$row
            }
        }
    }
)
$json = ConvertTo-Json -InputObject $export -Depth 100 -WarningAction Stop
[void][IO.Directory]::CreateDirectory($OutputDir)
$jsonPath = Join-Path $OutputDir 'ado-policies.portable.json'
$csvPath = Join-Path $OutputDir 'ado-policies-review.csv'
if ($PSCmdlet.ParameterSetName -eq 'Capture' -and $Capture.EndsWith('.capture.json', [StringComparison]::OrdinalIgnoreCase)) {
    $stem = [IO.Path]::GetFileName($Capture)
    $stem = $stem.Substring(0, $stem.Length - '.capture.json'.Length)
    $jsonPath = Join-Path $OutputDir "$stem.portable.json"
    $csvPath = Join-Path $OutputDir "$stem.review.csv"
}
if ((Test-Path -LiteralPath $jsonPath) -or (Test-Path -LiteralPath $csvPath)) {
    throw "Export already exists in $OutputDir. Choose a new -OutputDir."
}
$suffix = ".$([Guid]::NewGuid().ToString('N')).tmp"
try {
    [IO.File]::WriteAllText(($jsonPath + $suffix), $json, [Text.UTF8Encoding]::new($false))
    # The CSV is for review, not replay. Escape formula prefixes for spreadsheet safety.
    $safeRows = @(foreach ($row in $rows) {
        $safe = [ordered]@{}
        foreach ($property in $row.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string] -and $value -match '^[\s]*[=+@\-\t\r\n]') { $value = "'" + $value }
            $safe[$property.Name] = $value
        }
        [pscustomobject]$safe
    })
    if ($safeRows.Count) {
        $safeRows | Export-Csv -LiteralPath ($csvPath + $suffix) -NoTypeInformation -Encoding utf8BOM
    }
    else {
        $empty = [ordered]@{}
        foreach ($column in @('Inventory ID', 'Source policy ID', 'Level', 'Applies to', 'Policy type',
            'Enabled', 'Blocking', 'Setting', 'Raw value', 'Meaning', 'Value source')) { $empty[$column] = '' }
        [pscustomobject]$empty | ConvertTo-Csv -NoTypeInformation | Select-Object -First 1 |
            Set-Content -LiteralPath ($csvPath + $suffix) -Encoding utf8BOM
    }
    [IO.File]::Move(($jsonPath + $suffix), $jsonPath)
    [IO.File]::Move(($csvPath + $suffix), $csvPath)
}
finally {
    foreach ($path in @(($jsonPath + $suffix), ($csvPath + $suffix))) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
}
foreach ($reference in $unresolved.Values) {
    Write-Warning "Unresolved $($reference.kind) reference $($reference.sourceId). Map it explicitly before restore."
}
@{
    policies = $policies.Count; csvRows = $rows.Count; unresolvedIdReferences = $unresolved.Count
    portableJson = [IO.Path]::GetFullPath($jsonPath); reviewCsv = [IO.Path]::GetFullPath($csvPath)
} | ConvertTo-Json
