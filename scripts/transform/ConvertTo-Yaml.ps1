#Requires -Version 7.0
<#
.SYNOPSIS
    Converts a PowerShell object / OrderedDictionary / Hashtable into formatted YAML.
    Self-contained: requires no external YAML modules.
#>

function ConvertTo-Yaml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $InputObject,

        [int]$Indent = 0,
        [int]$IndentSize = 2
    )

    process {
        Format-YamlNode -Node $InputObject -CurrentIndent $Indent -IndentSize $IndentSize
    }
}

function Test-YamlQuoteNeeded {
    param([string]$S)
    if ($S -eq '') { return $true }
    if ($S -match '^[0-9]+$') { return $true }
    if ($S -match '^(true|false|yes|no|null|~)$') { return $true }
    if ($S.StartsWith(' ') -or $S.EndsWith(' ')) { return $true }
    if ($S.Contains("`n") -or $S.Contains("`r") -or $S.Contains(':') -or $S.Contains('#')) { return $true }
    if ($S.Contains('*') -or $S.Contains('?') -or $S.Contains('&') -or $S.Contains('!')) { return $true }
    if ($S.Contains('[') -or $S.Contains(']') -or $S.Contains('{') -or $S.Contains('}')) { return $true }
    if ($S.Contains('~') -or $S.Contains('|') -or $S.Contains('>') -or $S.Contains('"')) { return $true }
    if ($S.StartsWith('-') -or $S.StartsWith('@') -or $S.StartsWith('%') -or $S.StartsWith('`')) { return $true }
    return $false
}

function Format-YamlNode {
    param($Node, [int]$CurrentIndent, [int]$IndentSize)

    $indentSpaces = ' ' * $CurrentIndent

    if ($null -eq $Node) {
        return 'null'
    }

    if ($Node -is [bool]) {
        return $(if ($Node) { 'true' } else { 'false' })
    }

    if ($Node -is [byte] -or $Node -is [int] -or $Node -is [long] -or $Node -is [double] -or $Node -is [decimal]) {
        return "$Node"
    }

    if ($Node -is [string]) {
        if (Test-YamlQuoteNeeded $Node) {
            $escaped = $Node.Replace('\', '\\').Replace('"', '\"')
            return "`"$escaped`""
        }
        return $Node
    }

    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Count -eq 0) {
            return '{}'
        }
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $Node.Keys) {
            $val = $Node[$key]
            if ($val -is [System.Collections.IDictionary]) {
                if ($val.Count -eq 0) {
                    $lines.Add("${indentSpaces}${key}: {}")
                } else {
                    $lines.Add("${indentSpaces}${key}:")
                    $lines.Add((Format-YamlNode -Node $val -CurrentIndent ($CurrentIndent + $IndentSize) -IndentSize $IndentSize))
                }
            } elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                $count = 0
                foreach ($item in $val) { $count++ }
                if ($count -eq 0) {
                    $lines.Add("${indentSpaces}${key}: []")
                } else {
                    $lines.Add("${indentSpaces}${key}:")
                    $lines.Add((Format-YamlNode -Node $val -CurrentIndent ($CurrentIndent + $IndentSize) -IndentSize $IndentSize))
                }
            } else {
                $formattedVal = Format-YamlNode -Node $val -CurrentIndent 0 -IndentSize $IndentSize
                $lines.Add("${indentSpaces}${key}: ${formattedVal}")
            }
        }
        return ($lines -join "`n")
    }

    if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        $lines = [System.Collections.Generic.List[string]]::new()
        $hasItems = $false
        foreach ($item in $Node) {
            $hasItems = $true
            if ($item -is [System.Collections.IDictionary]) {
                if ($item.Count -eq 0) {
                    $lines.Add("${indentSpaces}- {}")
                } else {
                    $first = $true
                    foreach ($k in $item.Keys) {
                        $v = $item[$k]
                        $itemIndent = $CurrentIndent + $IndentSize
                        $itemSpaces = ' ' * $itemIndent
                        if ($first) {
                            $prefix = "${indentSpaces}- ${k}:"
                            $first = $false
                        } else {
                            $prefix = "${itemSpaces}${k}:"
                        }

                        if ($v -is [System.Collections.IDictionary]) {
                            if ($v.Count -eq 0) {
                                $lines.Add("${prefix} {}")
                            } else {
                                $lines.Add($prefix)
                                $lines.Add((Format-YamlNode -Node $v -CurrentIndent ($itemIndent + $IndentSize) -IndentSize $IndentSize))
                            }
                        } elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                            $cnt = 0
                            foreach ($sub in $v) { $cnt++ }
                            if ($cnt -eq 0) {
                                $lines.Add("${prefix} []")
                            } else {
                                $lines.Add($prefix)
                                $lines.Add((Format-YamlNode -Node $v -CurrentIndent ($itemIndent + $IndentSize) -IndentSize $IndentSize))
                            }
                        } else {
                            $fmt = Format-YamlNode -Node $v -CurrentIndent 0 -IndentSize $IndentSize
                            $lines.Add("${prefix} ${fmt}")
                        }
                    }
                }
            } elseif ($item -is [System.Collections.IEnumerable] -and $item -isnot [string]) {
                $lines.Add("${indentSpaces}-")
                $lines.Add((Format-YamlNode -Node $item -CurrentIndent ($CurrentIndent + $IndentSize) -IndentSize $IndentSize))
            } else {
                $valStr = Format-YamlNode -Node $item -CurrentIndent 0 -IndentSize $IndentSize
                $lines.Add("${indentSpaces}- ${valStr}")
            }
        }
        if (-not $hasItems) {
            return '[]'
        }
        return ($lines -join "`n")
    }

    return "$Node"
}
