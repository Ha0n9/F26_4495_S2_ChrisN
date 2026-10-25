<#
.SYNOPSIS
    Wrapper the local API server invokes to run a scan.

.DESCRIPTION
    The server spawns this with -File and plain string arguments rather than
    building a -Command string. That matters: a command string has to survive
    Node's argument handling, cmd.exe quoting and PowerShell parsing, and a
    domain name or path containing a space or a quote would either break the
    command or, worse, change what it runs. Passing discrete arguments to a
    file on disk removes that whole class of problem.

    It prints nothing but the path of the file it wrote, so the server has a
    single unambiguous line to read on success.

.PARAMETER ModulePath
    Path to ADSecurityAudit.psd1.

.PARAMETER OutputPath
    Where to write the scan result.

.PARAMETER DomainName
    Optional. Defaults to the domain this computer is joined to.

.PARAMETER NewAccountGraceDays
    Passed through to the stale account check. Defaults to -1, meaning do not
    override the check's own default.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ModulePath,
    [Parameter(Mandatory)] [string] $OutputPath,
    [string] $DomainName,
    [int]    $NewAccountGraceDays = -1
)

$ErrorActionPreference = 'Stop'

Import-Module $ModulePath -Force

$arguments = @{ OutputPath = $OutputPath }
if ($DomainName) { $arguments['DomainName'] = $DomainName }
if ($NewAccountGraceDays -ge 0) {
    $arguments['CheckParameter'] = @{
        'AD.ACCOUNT.STALE_ENABLED' = @{ NewAccountGraceDays = $NewAccountGraceDays }
    }
}

# Warnings from the aggregator (checks that did not run) go to the warning
# stream, which the server captures separately from stdout. Keeping stdout to
# one line means the server never has to guess which line is the result.
Invoke-ADSecurityAudit @arguments | Out-Null

Write-Output $OutputPath
