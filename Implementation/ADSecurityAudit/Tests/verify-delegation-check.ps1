<#
    Verification for Test-UnconstrainedDelegation.

    Runs against stubbed ActiveDirectory cmdlets, so it works on any machine
    and never touches a domain. The stubs are defined whether or not RSAT is
    present, which serves two purposes: without RSAT the script could not run
    at all, and with RSAT a unit test able to reach a live domain is a unit
    test that might accidentally query one.

    Run from the module root or from this folder:

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        .\Tests\verify-delegation-check.ps1
#>

$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Private\Checks\Test-UnconstrainedDelegation.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

# userAccountControl values, built from the flags rather than written as
# magic numbers, so a reader can see what each fixture actually is.
$UAC_DISABLED        = 0x2
$UAC_WORKSTATION     = 0x1000
$UAC_SERVER_TRUST    = 0x2000      # domain controller
$UAC_DELEGATION      = 0x80000
$UAC_NORMAL_ACCOUNT  = 0x200

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

$script:computers       = @()
$script:users           = @()
$script:computerFilter  = $null
$script:userFilter      = $null
$script:properties      = @()
$script:usedPlainFilter = $false

function Get-ADComputer {
    param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $SearchBase, $ErrorAction)
    if ($Filter) { $script:usedPlainFilter = $true }
    $script:computerFilter = [string] $LDAPFilter
    $script:properties     = @($Properties)
    return $script:computers
}

function Get-ADUser {
    param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $SearchBase, $ErrorAction)
    if ($Filter) { $script:usedPlainFilter = $true }
    $script:userFilter = [string] $LDAPFilter
    return $script:users
}

function C {
    param(
        [string] $Name,
        [int]    $Uac = ($UAC_WORKSTATION -bor $UAC_DELEGATION),
        [bool]   $Enabled = $true,
        [string] $Os = 'Windows Server 2022 Standard',
        $LastLogon = (Get-Date).AddDays(-3),
        [string[]] $Spns = @(),
        [string[]] $AllowedToDelegateTo = @()
    )
    [pscustomobject]@{
        SamAccountName             = "$Name`$"
        DistinguishedName          = "CN=$Name,OU=Servers,DC=auditlab,DC=test"
        userAccountControl         = $Uac
        Enabled                    = $Enabled
        OperatingSystem            = $Os
        LastLogonDate              = $LastLogon
        DNSHostName                = "$Name.auditlab.test"
        ServicePrincipalName       = $Spns
        'msDS-AllowedToDelegateTo' = $AllowedToDelegateTo
    }
}

function U {
    param(
        [string] $Name,
        [int]    $Uac = ($UAC_NORMAL_ACCOUNT -bor $UAC_DELEGATION),
        [bool]   $Enabled = $true,
        $LastLogon = (Get-Date).AddDays(-10),
        [string[]] $Spns = @('HTTP/app01.auditlab.test')
    )
    [pscustomobject]@{
        SamAccountName             = $Name
        DistinguishedName          = "CN=$Name,OU=Services,DC=auditlab,DC=test"
        userAccountControl         = $Uac
        Enabled                    = $Enabled
        OperatingSystem            = $null
        LastLogonDate              = $LastLogon
        DNSHostName                = $null
        ServicePrincipalName       = $Spns
        'msDS-AllowedToDelegateTo' = @()
    }
}

function Reset-Fixture {
    $script:computers       = @()
    $script:users           = @()
    $script:computerFilter  = $null
    $script:userFilter      = $null
    $script:properties      = @()
    $script:usedPlainFilter = $false
}

function Run {
    param([hashtable] $Extra = @{})
    Test-UnconstrainedDelegation -DomainName 'auditlab.test' @Extra
}

# ---------------------------------------------------------------------------
"`nThe query itself"
Reset-Fixture
$script:computers = @( (C 'SRV01') )
Run | Out-Null
A ($script:computerFilter -match '1\.2\.840\.113556\.1\.4\.803')  'asks the directory with the LDAP bitwise matching rule'
A ($script:computerFilter -match '524288')                        'matches the TRUSTED_FOR_DELEGATION bit'
A ($script:userFilter -eq $script:computerFilter)                 'applies the same filter to user accounts'
A (-not $script:usedPlainFilter)                                  'uses an LDAP filter rather than -Filter'
A ($script:properties -contains 'userAccountControl')             'requests userAccountControl so the flags can be checked here too'
A ($script:properties -contains 'msDS-AllowedToDelegateTo')       'requests the constrained delegation attribute'

# ---------------------------------------------------------------------------
"`nNothing to report"
Reset-Fixture
A ($null -eq (Run))                                               'a domain with no delegation produces no finding'

Reset-Fixture
# Every writable domain controller carries this flag by design. Reporting
# them would open every scan of every domain with noise nobody can act on.
$script:computers = @( (C 'DC01' -Uac ($UAC_SERVER_TRUST -bor $UAC_DELEGATION)) )
A ($null -eq (Run))                                               'a domain controller alone produces no finding'

Reset-Fixture
$script:computers = @( (C 'SRV01' -Uac ($UAC_WORKSTATION -bor $UAC_DELEGATION -bor $UAC_DISABLED) -Enabled $false) )
A ($null -eq (Run))                                               'a disabled account is not reported by default'

Reset-Fixture
$script:computers = @( (C 'SRV01') )
A ($null -eq (Run @{ ExcludedAccountNames = @('SRV01$') }))       'an explicitly excused account is dropped'

Reset-Fixture
# The filter asked for the flag, but a check that trusts a filter it never
# evaluated cannot notice when the filter is wrong.
$script:computers = @( (C 'SRV01' -Uac $UAC_WORKSTATION) )
A ($null -eq (Run))                                               'an account without the flag is rejected even if the query returned it'

# ---------------------------------------------------------------------------
"`nOne delegating server"
Reset-Fixture
$script:computers = @( (C 'SRV01') )
$r = Run
A (@($r).Count -eq 1)                                             'one finding covering the domain'
A ($r.checkId -ceq 'AD.PRIVILEGE.UNCONSTRAINED_DELEGATION')       'check id exact'
A ($r.severity -eq 'Critical')                                    'an enabled delegating host is Critical'
A ($r.affectedObjectCount -eq 1)                                  'one affected object'
A ($r.affectedObjects[0].name -eq 'SRV01$')                       'reports the account'
A ($r.affectedObjects[0].objectClass -eq 'computer')              'records what kind of object it is'
A ($r.affectedObjects[0].attributes.operatingSystem -match 'Windows Server') 'carries operatingSystem, a dictionary key attribute'
A ($null -ne $r.affectedObjects[0].attributes.lastLogonDate)      'carries lastLogonDate, the other key attribute'
A ($r.affectedObjects[0].attributes.lastLogonDate -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') 'as the UTC format the contract requires'
A ($r.affectedObjects[0].attributes.enabled -eq $true)            'records whether it is enabled'
A ($r.evidence.domainControllersSkipped -eq 0)                    'counts the domain controllers it skipped'

# ---------------------------------------------------------------------------
"`nDomain controllers are skipped but counted"
Reset-Fixture
$script:computers = @(
    (C 'DC01' -Uac ($UAC_SERVER_TRUST -bor $UAC_DELEGATION))
    (C 'DC02' -Uac ($UAC_SERVER_TRUST -bor $UAC_DELEGATION))
    (C 'SRV01')
)
$r = Run
A ($r.affectedObjectCount -eq 1)                                  'only the non-controller is reported'
A (-not ($r.affectedObjects.name -contains 'DC01$'))              'the controller is left out'
A ($r.evidence.domainControllersSkipped -eq 2)                    'and the number skipped is recorded rather than hidden'
A ($r.evidence.summary -match 'besides the domain controllers')   'the summary says the controllers were excluded'

# ---------------------------------------------------------------------------
"`nUser accounts, not just computers"
Reset-Fixture
$script:users = @( (U 'svc_app') )
$r = Run
A ($r.affectedObjectCount -eq 1)                                  'a delegating user account is reported'
A ($r.affectedObjects[0].objectClass -eq 'user')                  'marked as a user'
A ($r.evidence.userAccountCount -eq 1)                            'counted separately in the evidence'
A ($r.evidence.summary -match 'user accounts rather than computers') 'and called out in the summary, because it is unusual'
A ($null -eq $r.affectedObjects[0].attributes.operatingSystem)    'a user has no operating system, reported as null not blank'

# ---------------------------------------------------------------------------
"`nDisabled accounts"
Reset-Fixture
$script:computers = @( (C 'SRV_OLD' -Uac ($UAC_WORKSTATION -bor $UAC_DELEGATION -bor $UAC_DISABLED) -Enabled $false) )
$r = Run @{ IncludeDisabledAccounts = $true }
A ($r.affectedObjectCount -eq 1)                                  'included on request'
A ($r.severity -eq 'High')                                        'latent rather than live exposure, so High not Critical'
A ($r.evidence.enabledCount -eq 0)                                'none are enabled'
A ($r.affectedObjects[0].attributes.enabled -eq $false)           'recorded per object'

Reset-Fixture
$script:computers = @(
    (C 'SRV01')
    (C 'SRV_OLD' -Uac ($UAC_WORKSTATION -bor $UAC_DELEGATION -bor $UAC_DISABLED) -Enabled $false)
)
$r = Run @{ IncludeDisabledAccounts = $true }
A ($r.severity -eq 'Critical')                                    'one enabled account is enough to make it Critical'
A ($r.evidence.enabledCount -eq 1)                                'the enabled count is right'
A ($r.evidence.summary -match '1 of them are enabled')            'the summary states how many are live'

# ---------------------------------------------------------------------------
"`nConstrained delegation alongside it"
Reset-Fixture
$script:computers = @( (C 'SRV01' -AllowedToDelegateTo @('CIFS/files01.auditlab.test')) )
$r = Run
A ($r.affectedObjects[0].attributes.alsoHasConstrainedDelegation -eq $true) 'flagged on the object'
A ($r.evidence.alsoConstrainedCount -eq 1)                        'counted in the evidence'
A ($r.evidence.summary -match 'migration')                        'the summary reads it as an unfinished migration'

Reset-Fixture
$script:computers = @( (C 'SRV01') )
A ((Run).affectedObjects[0].attributes.alsoHasConstrainedDelegation -eq $false) 'false when the attribute is empty'

# ---------------------------------------------------------------------------
"`nSeveral at once"
Reset-Fixture
$script:computers = @(
    (C 'DC01' -Uac ($UAC_SERVER_TRUST -bor $UAC_DELEGATION))
    (C 'SRV01')
    (C 'SRV02' -Os 'Windows Server 2019 Standard')
)
$script:users = @( (U 'svc_app') )
$r = Run
A (@($r).Count -eq 1)                                             'still one finding, not one per account'
A ($r.affectedObjectCount -eq 3)                                  'two servers and one user, controller excluded'
A ($r.evidence.exposedAccountCount -eq 3)                         'evidence agrees with the object count'

# ---------------------------------------------------------------------------
"`nEvidence records how the check ran"
Reset-Fixture
$script:computers = @( (C 'SRV01') )
$r = Run @{ ExcludedAccountNames = @('OTHER$') }
A ($r.evidence.parametersUsed.excludedAccountNames -contains 'OTHER$') 'records the exclusions it ran with'
A ($r.evidence.query -match '524288')                             'records the query'
A ($r.evidence.note -match 'SERVER_TRUST_ACCOUNT')                'explains how controllers are identified'
A ($r.evidence.limitation -match 'authenticated')                 'states that it reports the condition, not a captured ticket'

# ---------------------------------------------------------------------------
"`nJSON round trip"
Reset-Fixture
$script:computers = @( (C 'SRV01') )
$back = (Run) | ConvertTo-Json -Depth 10 | ConvertFrom-Json
A ($back.affectedObjects[0].attributes.operatingSystem -match 'Windows Server') 'survives ConvertTo-Json'

# ---------------------------------------------------------------------------
"`nError propagation"
function Get-ADComputer { param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $SearchBase, $ErrorAction) throw 'Access is denied' }
$threw = $false
try { Run | Out-Null } catch { $threw = $true }
A $threw                                                          'a hard failure reaches the caller'

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
