$ErrorActionPreference = 'Stop'

# Resolve the module root whether this script sits inside the module folder
# or in a Tests subfolder beside it.
$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module. Put this script in the module folder or in a Tests folder beside Private\." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Private\Checks\Test-StaleEnabledAccount.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

$now = Get-Date
$script:users = @()
function Get-ADUser { param($Filter, $Properties, $Server, $ErrorAction) $script:users }

function U {
    param(
        [string] $Name,
        [Nullable[datetime]] $LastLogon = $null,
        [datetime] $Created = $now.AddYears(-2),
        [string] $OU = 'OU=Staff,DC=auditlab,DC=test'
    )
    [pscustomobject]@{
        SamAccountName    = $Name
        Enabled           = $true
        LastLogonDate     = $LastLogon
        whenCreated       = $Created
        PasswordLastSet   = $Created
        DistinguishedName = "CN=$Name,$OU"
    }
}

"`nAll accounts active"
$script:users = @( (U -Name 'alice' -LastLogon $now.AddDays(-2)), (U -Name 'bob' -LastLogon $now.AddDays(-30)) )
A ($null -eq (Test-StaleEnabledAccount -DomainName 'auditlab.test')) 'returns nothing'

"`nNever signed in"
$script:users = @( (U -Name 'svc_old' -Created $now.AddYears(-3)) )
$r = Test-StaleEnabledAccount -DomainName 'auditlab.test'
A (@($r).Count -eq 1)                                  'one finding'
A ($r.affectedObjects[0].name -eq 'svc_old')           'flags the account'
A ($null -eq $r.affectedObjects[0].attributes.lastLogonDate)  'lastLogonDate is null, not a date'
A ($null -eq $r.affectedObjects[0].attributes.daysInactive)   'daysInactive is null'
A ($r.evidence.neverSignedInCount -eq 1)               'counts it as never signed in'
A ($r.checkId -ceq 'AD.ACCOUNT.STALE_ENABLED')         'check id exact'
A ($r.severity -eq 'High')                             'severity High'

"`nIncludeNeverLoggedOn false"
A ($null -eq (Test-StaleEnabledAccount -DomainName 'auditlab.test' -IncludeNeverLoggedOn $false)) 'excluded'

"`nNew account inside the grace window"
$script:users = @( (U -Name 'new_hire' -Created $now.AddDays(-5)) )
A ($null -eq (Test-StaleEnabledAccount -DomainName 'auditlab.test')) 'not flagged with the default 30 day grace'
A ($null -ne (Test-StaleEnabledAccount -DomainName 'auditlab.test' -NewAccountGraceDays 0)) 'flagged when grace is 0'

"`nFreshly seeded lab accounts (created minutes ago)"
$script:users = @( (U -Name 'stale_user_1' -Created $now.AddMinutes(-20)) )
A ($null -eq (Test-StaleEnabledAccount -DomainName 'auditlab.test')) 'skipped by default, as designed'
$r = Test-StaleEnabledAccount -DomainName 'auditlab.test' -NewAccountGraceDays 0
A ($null -ne $r -and $r.affectedObjects[0].name -eq 'stale_user_1') 'detected with -NewAccountGraceDays 0'

"`nInactive beyond threshold"
$script:users = @( (U -Name 'jdoe' -LastLogon $now.AddDays(-200)), (U -Name 'recent' -LastLogon $now.AddDays(-10)) )
$r = Test-StaleEnabledAccount -DomainName 'auditlab.test' -InactiveDays 90
A ($r.affectedObjects.name -contains 'jdoe')           'flags the inactive account'
A (-not ($r.affectedObjects.name -contains 'recent'))  'leaves the recent one alone'
A ($r.affectedObjects[0].attributes.daysInactive -ge 199) 'records days inactive'
A ($r.evidence.inactiveCount -eq 1)                    'counts it as inactive'
A ($null -eq (Test-StaleEnabledAccount -DomainName 'auditlab.test' -InactiveDays 365)) 'respects a larger threshold'

"`nExcluded OU"
$script:users = @( (U -Name 'archived' -Created $now.AddYears(-3) -OU 'OU=Archive,DC=auditlab,DC=test') )
A ($null -eq (Test-StaleEnabledAccount -DomainName 'auditlab.test' -ExcludedOrganizationalUnits @('OU=Archive,DC=auditlab,DC=test'))) 'skipped'
A ($null -ne (Test-StaleEnabledAccount -DomainName 'auditlab.test')) 'flagged when not excluded'

"`nShape of the result"
$script:users = @(
    (U -Name 'stale_user_1' -Created $now.AddYears(-3)),
    (U -Name 'stale_user_2' -Created $now.AddYears(-3)),
    (U -Name 'stale_user_3' -LastLogon $now.AddDays(-400))
)
$r = Test-StaleEnabledAccount -DomainName 'auditlab.test'
A (@($r).Count -eq 1)                                   'one finding, not one per account'
A ($r.affectedObjects.Count -eq 3)                      'carries all three'
A ($r.affectedObjectCount -eq $r.affectedObjects.Count) 'count matches array'
A ($r.evidence.parametersUsed.inactiveDays -eq 90)      'records the threshold'
A ($r.evidence.neverSignedInCount -eq 2)                'two never signed in'
A ($r.evidence.inactiveCount -eq 1)                     'one inactive'
A ($r.findingId -like 'AD.ACCOUNT.STALE_ENABLED:auditlab.test:*') 'finding id format'
A (($r.affectedObjects | Where-Object { -not $_.distinguishedName }).Count -eq 0) 'every object has a DN'
A ($r.evidence.summary -match 'never signed in')        'summary mentions both cases'

"`nJSON round trip"
$json = $r | ConvertTo-Json -Depth 10
$back = $json | ConvertFrom-Json
A ($back.affectedObjects.Count -eq 3)                   'survives ConvertTo-Json'
A ($null -eq $back.affectedObjects[0].attributes.lastLogonDate) 'null survives as null'

"`nError propagation"
function Get-ADUser { param($Filter, $Properties, $Server, $ErrorAction) throw 'Access is denied' }
$threw = $false
try { Test-StaleEnabledAccount -DomainName 'auditlab.test' } catch { $threw = $true }
A $threw 'error reaches the caller'

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
