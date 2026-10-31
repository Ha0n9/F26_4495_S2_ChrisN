<#
    Verification for Invoke-ADSecurityAudit, the aggregator.

    This covers the decision the aggregator makes about every check: whether
    it completed, failed, or completed over only part of its ground. That
    decision had no test before, because the aggregator called
    WindowsIdentity.GetCurrent directly and so could not run anywhere but
    Windows. The identity lookup now lives in Get-AuditExecutionContext,
    which this file replaces with a stub, and the rest runs on any platform.

    No domain, no RSAT and no Windows are required.

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        .\Tests\verify-aggregator.ps1
#>

$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Public\Invoke-ADSecurityAudit.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

$SID = 'S-1-5-21-1111111111-2222222222-3333333333'

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

function Get-ADDomain {
    param($Identity, $Current, $Server, $ErrorAction)
    [pscustomobject]@{
        DNSRoot       = 'auditlab.test'
        NetBIOSName   = 'AUDITLAB'
        DomainMode    = 'Windows2016Domain'
        PDCEmulator   = 'DC01.auditlab.test'
        DomainSID     = [pscustomobject]@{ Value = $SID }
    }
}

# Stands in for the one part of the aggregator that is Windows only.
function Get-AuditExecutionContext {
    param($Domain)
    [pscustomobject]@{ account = 'AUDITLAB\audit_user'; hadDomainAdminRights = $false }
}

function Get-Module {
    param($Name, $ListAvailable, $ErrorAction)
    [pscustomobject]@{ Version = [version]'0.1.0' }
}

# The aggregator resolves check functions through its own registry, so the
# tests redefine the real check names rather than inventing new ones.
function Test-WeakPasswordPolicy {
    param($DomainName)
    New-AuditFinding -CheckId 'AD.POLICY.WEAK_PASSWORD' -Severity 'High' -DomainName $DomainName `
        -AffectedObjects @() -Evidence @{ summary = 'stub' }
}

$script:staleBehaviour = 'finding'
function Test-StaleEnabledAccount {
    param($DomainName, $NewAccountGraceDays)
    switch ($script:staleBehaviour) {
        'throw'   { throw 'Access is denied' }
        'nothing' { return }
        default   {
            New-AuditFinding -CheckId 'AD.ACCOUNT.STALE_ENABLED' -Severity 'High' -DomainName $DomainName `
                -AffectedObjects @() -Evidence @{ summary = 'stub'; grace = $NewAccountGraceDays }
        }
    }
}

$script:adminBehaviour = 'finding'
function Test-ExcessiveAdminMembership {
    param($DomainName, $MaxNestingDepth)
    if ($script:adminBehaviour -in @('finding', 'both')) {
        New-AuditFinding -CheckId 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP' -Severity 'Critical' `
            -DomainName $DomainName -AffectedObjects @() -Evidence @{ summary = 'stub' }
    }
    if ($script:adminBehaviour -in @('partial', 'both')) {
        New-AuditPartialResult -CheckId 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP' `
            -Reason 'Nested membership was not followed beyond 2 levels.'
    }
}

function Test-KerberoastableAccount {
    param($DomainName)
    return
}

$outFile = Join-Path ([System.IO.Path]::GetTempPath()) "aggregator-test-$([guid]::NewGuid()).json"

function Run {
    param([hashtable] $Extra = @{})
    Invoke-ADSecurityAudit -OutputPath $outFile -PassThru -WarningAction SilentlyContinue @Extra
}

# ---------------------------------------------------------------------------
"`nA clean run"
$script:adminBehaviour = 'finding'
$script:staleBehaviour = 'finding'
$r = Run
A ($r.scan.checksRequested.Count -eq 4)              'requests every registered check'
A ($r.scan.checksCompleted.Count -eq 4)              'all four complete'
A (@($r.scan.checksFailed).Count -eq 0)              'nothing failed'
A (@($r.scan.checksPartial).Count -eq 0)             'nothing partial'
A ($r.findings.Count -eq 3)                          'collects the findings'
A ($r.scan.executedBy.hadDomainAdminRights -eq $false) 'records the privilege it ran with'

# ---------------------------------------------------------------------------
"`nA check that throws"
$script:staleBehaviour = 'throw'
$r = Run
A (@($r.scan.checksFailed).Count -eq 1)              'the failure is recorded'
A ($r.scan.checksFailed[0].checkId -ceq 'AD.ACCOUNT.STALE_ENABLED') 'with its check id'
A ($r.scan.checksFailed[0].errorMessage -match 'denied') 'and its message'
A (-not ($r.scan.checksCompleted -contains 'AD.ACCOUNT.STALE_ENABLED')) 'and is not also completed'
A ($r.scan.checksCompleted.Count -eq 3)              'the other checks still ran'
$script:staleBehaviour = 'finding'

# ---------------------------------------------------------------------------
"`nA check that returns a partial result"
# The defect: a check that walked only part of its ground was recorded the
# same way as one that walked all of it, so the dashboard had no way to know
# the difference and presented an unexamined branch as a clean one.
$script:adminBehaviour = 'partial'
$r = Run
A (@($r.scan.checksPartial).Count -eq 1)             'the partial result is recorded'
A ($r.scan.checksPartial[0].checkId -ceq 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP') 'with its check id'
A ($r.scan.checksPartial[0].reason -match 'beyond 2 levels') 'with the reason it was truncated'
A ($r.scan.checksCompleted -contains 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP') 'still counted as completed, because it ran without error'
A (-not ($r.scan.checksFailed.checkId -contains 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP')) 'and not counted as failed, which would discard its findings'

# ---------------------------------------------------------------------------
"`nA partial result alongside real findings"
$script:adminBehaviour = 'both'
$r = Run
A ($r.findings.Count -eq 3)                          'the marker is not mistaken for a finding'
A (@($r.findings | Where-Object { $_.PSObject.Properties.Name -contains 'reason' }).Count -eq 0) 'no marker leaked into findings'
A (@($r.scan.checksPartial).Count -eq 1)             'and is still recorded as partial'
$ids = @($r.findings.checkId)
A ($ids -contains 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP') 'the truncated check keeps the findings it did produce'

# ---------------------------------------------------------------------------
"`nThe written file carries it too"
$written = Get-Content -LiteralPath $outFile -Raw | ConvertFrom-Json
A ($null -ne $written.scan.checksPartial)            'checksPartial survives the JSON round trip'
A ($written.scan.checksPartial[0].reason -match 'beyond 2 levels') 'with its reason intact'

# ---------------------------------------------------------------------------
"`nPer-check parameters still reach the check"
$script:adminBehaviour = 'finding'
$r = Run @{ CheckParameter = @{ 'AD.ACCOUNT.STALE_ENABLED' = @{ NewAccountGraceDays = 0 } } }
$stale = $r.findings | Where-Object checkId -eq 'AD.ACCOUNT.STALE_ENABLED'
A ($stale.evidence.grace -eq 0)                      'the parameter is passed through'

"`nA single requested check"
$r = Run @{ CheckId = @('AD.POLICY.WEAK_PASSWORD') }
A ($r.scan.checksRequested.Count -eq 1)              'only the requested check is run'
A ($r.findings.Count -eq 1)                          'and only its findings are collected'

Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
