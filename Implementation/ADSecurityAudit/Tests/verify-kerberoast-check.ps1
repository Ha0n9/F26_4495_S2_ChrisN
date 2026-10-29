<#
    Verification for Test-KerberoastableAccount.

    Runs against stubbed ActiveDirectory cmdlets, so it works on any machine
    and never touches a domain. The stubs are defined whether or not RSAT is
    present, which serves two purposes: without RSAT the script could not run
    at all, and with RSAT a unit test able to reach a live domain is a unit
    test that might accidentally query one.

    Run from the module root or from this folder:

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        .\Tests\verify-kerberoast-check.ps1
#>

$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Private\Checks\Test-KerberoastableAccount.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

$SID = 'S-1-5-21-1111111111-2222222222-3333333333'

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

$script:users            = @()
$script:lastFilter       = $null
$script:lastProperties   = @()
$script:usedPlainFilter  = $false

function Get-ADUser {
    param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $SearchBase, $ErrorAction)
    if ($Filter) { $script:usedPlainFilter = $true }
    $script:lastFilter     = [string] $LDAPFilter
    $script:lastProperties = @($Properties)
    return $script:users
}

<#
    Builds one stubbed account.

    EncTypes is passed as a string so that "unset" and "zero" stay distinct:
    $null means the attribute is absent from the directory, 0 means it is
    present and empty. The check must treat both as RC4 permitted, and the
    tests below assert that separately for each.
#>
function U {
    param(
        [string] $Name,
        [string] $Rid,
        [string[]] $Spns = @('MSSQLSvc/db01.auditlab.test:1433'),
        $EncTypes = $null,
        $PasswordLastSet = (Get-Date).AddDays(-30),
        [bool] $Enabled = $true,
        [bool] $PasswordNeverExpires = $false,
        $AdminCount = $null
    )
    [pscustomobject]@{
        SamAccountName                  = $Name
        DistinguishedName               = "CN=$Name,OU=Services,DC=auditlab,DC=test"
        SID                             = [pscustomobject]@{ Value = "$SID-$Rid" }
        ServicePrincipalName            = $Spns
        'msDS-SupportedEncryptionTypes' = $EncTypes
        PasswordLastSet                 = $PasswordLastSet
        PasswordNeverExpires            = $PasswordNeverExpires
        Enabled                         = $Enabled
        adminCount                      = $AdminCount
    }
}

function Reset-Fixture {
    $script:users           = @()
    $script:lastFilter      = $null
    $script:lastProperties  = @()
    $script:usedPlainFilter = $false
}

function Run {
    param([hashtable] $Extra = @{})
    Test-KerberoastableAccount -DomainName 'auditlab.test' @Extra
}

# ---------------------------------------------------------------------------
"`nThe query itself"
Reset-Fixture
$script:users = @( (U 'svc_sql' '1401') )
Run | Out-Null
A ($script:lastFilter -like '*objectCategory=person*')      'pins objectCategory to person, which excludes computers and gMSAs'
A ($script:lastFilter -like '*servicePrincipalName=`**')    'asks only for accounts that have an SPN'
A (-not $script:usedPlainFilter)                            'uses an LDAP filter rather than -Filter'
A ($script:lastProperties -contains 'msDS-SupportedEncryptionTypes') 'requests the encryption type attribute'
A ($script:lastProperties -contains 'PasswordLastSet')      'requests PasswordLastSet'
A ($script:lastProperties -contains 'adminCount')           'requests adminCount'

# ---------------------------------------------------------------------------
"`nNothing to report"
Reset-Fixture
$script:users = @()
A ($null -eq (Run))                                         'no SPN accounts means no finding'

Reset-Fixture
$script:users = @( (U 'krbtgt' '502') )
A ($null -eq (Run))                                         'krbtgt alone produces no finding'

Reset-Fixture
$script:users = @( (U 'svc_old' '1402' -Enabled $false) )
A ($null -eq (Run))                                         'a disabled account is not roastable by default'

Reset-Fixture
$script:users = @( (U 'svc_sql' '1401') )
A ($null -eq (Run @{ ExcludedAccountNames = @('svc_sql') })) 'an explicitly excused account is dropped'

Reset-Fixture
$script:users = @( (U 'svc_nospn' '1403' -Spns @()) )
A ($null -eq (Run))                                         'an account whose SPN list is empty is skipped'

# ---------------------------------------------------------------------------
"`nOne ordinary service account"
Reset-Fixture
$script:users = @( (U 'svc_sql' '1401' -EncTypes 0x18) )    # AES128 + AES256
$r = Run
A (@($r).Count -eq 1)                                       'one finding covering the domain'
A ($r.checkId -ceq 'AD.PRIVILEGE.KERBEROASTING')            'check id exact'
A ($r.affectedObjectCount -eq 1)                            'one affected object'
A ($r.affectedObjects[0].name -eq 'svc_sql')                'reports the account'
A ($r.affectedObjects[0].objectClass -eq 'user')            'object class is user'
A ($r.affectedObjects[0].attributes.spnCount -eq 1)         'counts the SPNs'
A ($r.severity -eq 'Medium')                                'AES only and fresh password is Medium, not High'
A ($r.affectedObjects[0].attributes.rc4Permitted -eq $false) 'AES-only account does not permit RC4'
A ($r.affectedObjects[0].attributes.encryptionTypes -like '*AES256*') 'names the encryption types'

# ---------------------------------------------------------------------------
"`nRC4, including the cases that look safe"
Reset-Fixture
$script:users = @( (U 'svc_a' '1401' -EncTypes $null) )
$r = Run
A ($r.affectedObjects[0].attributes.rc4Permitted -eq $true) 'an absent attribute is RC4 permitted, not safety'
A ($r.affectedObjects[0].attributes.encryptionTypes -eq 'not set') 'and is reported as not set'
A ($r.severity -eq 'High')                                  'RC4 raises severity to High'

Reset-Fixture
$script:users = @( (U 'svc_b' '1401' -EncTypes 0) )
A ((Run).affectedObjects[0].attributes.rc4Permitted -eq $true) 'a zero value is also RC4 permitted'

Reset-Fixture
$script:users = @( (U 'svc_c' '1401' -EncTypes 0x04) )
A ((Run).affectedObjects[0].attributes.rc4Permitted -eq $true) 'the RC4 bit set explicitly is detected'

Reset-Fixture
$script:users = @( (U 'svc_d' '1401' -EncTypes 0x14) )      # RC4 + AES256
$r = Run
A ($r.affectedObjects[0].attributes.rc4Permitted -eq $true) 'RC4 alongside AES still counts as permitted'
A ($r.evidence.rc4PermittedCount -eq 1)                     'counted in the evidence'

# ---------------------------------------------------------------------------
"`nPassword age"
Reset-Fixture
$script:users = @( (U 'svc_stale' '1401' -EncTypes 0x18 -PasswordLastSet (Get-Date).AddDays(-900)) )
$r = Run
A ($r.affectedObjects[0].attributes.passwordAgeDays -ge 899) 'computes the age in days'
A ($r.evidence.stalePasswordCount -eq 1)                    'counts it as stale'
A ($r.severity -eq 'High')                                  'a stale password raises severity even with AES'

Reset-Fixture
$script:users = @( (U 'svc_never' '1401' -EncTypes 0x18 -PasswordLastSet $null) )
$r = Run
A ($null -eq $r.affectedObjects[0].attributes.passwordAgeDays) 'a password never set is null, not zero'
A ($null -eq $r.affectedObjects[0].attributes.passwordLastSet) 'and the timestamp stays null'
A ($r.evidence.stalePasswordCount -eq 0)                    'and is not counted as stale, which would be a guess'

Reset-Fixture
$script:users = @( (U 'svc_fresh' '1401' -EncTypes 0x18 -PasswordLastSet (Get-Date).AddDays(-400)) )
A ((Run @{ StalePasswordDays = 500 }).evidence.stalePasswordCount -eq 0) 'the threshold is honoured'

Reset-Fixture
$script:users = @( (U 'svc_ts' '1401' -EncTypes 0x18 -PasswordLastSet ([datetime]'2025-03-04T09:15:00Z')) )
A ((Run).affectedObjects[0].attributes.passwordLastSet -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') 'timestamp is the UTC format the contract requires'

# ---------------------------------------------------------------------------
"`nPrivileged service accounts"
Reset-Fixture
$script:users = @( (U 'svc_admin' '1401' -EncTypes 0x18 -AdminCount 1) )
$r = Run
A ($r.affectedObjects[0].attributes.isPrivileged -eq $true) 'adminCount 1 marks the account privileged'
A ($r.severity -eq 'Critical')                              'a privileged service account is Critical'
A ($r.evidence.privilegedCount -eq 1)                       'counted in the evidence'
A ($r.evidence.limitation -like '*adminCount*')             'the stickiness of adminCount is recorded as a limitation'

# ---------------------------------------------------------------------------
"`nSeveral accounts at once"
Reset-Fixture
$script:users = @(
    (U 'krbtgt'    '502')
    (U 'svc_sql'   '1401' -EncTypes 0x18)
    (U 'svc_web'   '1402' -EncTypes $null -Spns @('HTTP/web01.auditlab.test', 'HTTP/intranet.auditlab.test'))
    (U 'svc_gone'  '1403' -Enabled $false)
)
$r = Run
A (@($r).Count -eq 1)                                       'still one finding, not one per account'
A ($r.affectedObjectCount -eq 2)                            'krbtgt and the disabled account are both left out'
A (($r.affectedObjects | Where-Object { $_.name -eq 'svc_web' }).attributes.spnCount -eq 2) 'counts multiple SPNs on one account'
A (($r.affectedObjects | Where-Object { $_.name -eq 'svc_web' }).attributes.servicePrincipalNames -like '*; *') 'joins multiple SPNs for display'
A ($r.evidence.exposedAccountCount -eq 2)                   'evidence agrees with the object count'
A ($r.evidence.summary -like '*RC4*')                       'summary mentions RC4 when present'

Reset-Fixture
$script:users = @( (U 'svc_gone' '1403' -Enabled $false -EncTypes 0x18) )
A ((Run @{ IncludeDisabledAccounts = $true }).affectedObjectCount -eq 1) 'disabled accounts are included on request'

# ---------------------------------------------------------------------------
"`nEvidence records how the check ran"
Reset-Fixture
$script:users = @( (U 'svc_sql' '1401' -EncTypes 0x18) )
$r = Run @{ StalePasswordDays = 90 }
A ($r.evidence.parametersUsed.stalePasswordDays -eq 90)     'records the threshold it ran with'
A ($r.evidence.parametersUsed.excludedRids -contains 502)   'records the exclusions'
A ($r.evidence.query -like '*objectCategory=person*')       'records the query'
A ($r.evidence.note -like '*krbtgt*')                       'explains the exclusions'

# ---------------------------------------------------------------------------
""
"  $script:p passed, $script:f failed"
""
if ($script:f -gt 0) { exit 1 }
