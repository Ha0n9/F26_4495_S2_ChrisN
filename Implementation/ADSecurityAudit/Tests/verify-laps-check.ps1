<#
    Verification for Test-LapsDeployment.

    Runs against stubbed Get-ADRootDSE, Get-ADObject and Get-ADComputer, so it
    needs no domain and no LAPS installation. The stubs record what was asked
    for, which is what makes the central assertion of this suite possible: that
    no query this check issues ever names a LAPS password attribute.

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        .\Tests\verify-laps-check.ps1
#>

$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Private\Checks\Test-LapsDeployment.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

$LEGACY_EXPIRY  = 'ms-Mcs-AdmPwdExpirationTime'
$WINDOWS_EXPIRY = 'msLAPS-PasswordExpirationTime'

# Every attribute of either generation that holds, or has ever held, a
# password. If one of these reaches a query, this check has stopped being a
# tool that needs no trust with credentials.
$PASSWORD_ATTRIBUTES = @(
    'ms-Mcs-AdmPwd'
    'msLAPS-Password'
    'msLAPS-EncryptedPassword'
    'msLAPS-EncryptedPasswordHistory'
    'msLAPS-EncryptedDSRMPassword'
    'msLAPS-EncryptedDSRMPasswordHistory'
)

# The same names as regexes that will not match inside a longer attribute
# name, so ms-Mcs-AdmPwdExpirationTime does not read as ms-Mcs-AdmPwd.
$BOUNDED = @{}
foreach ($attribute in $PASSWORD_ATTRIBUTES) {
    $BOUNDED[$attribute] = '(?<![A-Za-z0-9-])' + [regex]::Escape($attribute) + '(?![A-Za-z0-9-])'
}
# The guard has to fail on the real thing and pass on the lookalike, or it
# proves nothing about the runs below.
A ('(lDAPDisplayName=ms-Mcs-AdmPwd)' -match $BOUNDED['ms-Mcs-AdmPwd'])                 'the leak guard catches a real password attribute'
A (-not ('(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' -match $BOUNDED['ms-Mcs-AdmPwd'])) 'and does not fire on the expiration attribute'
A (-not ('msLAPS-PasswordExpirationTime' -match $BOUNDED['msLAPS-Password']))          'nor on the Windows LAPS expiration attribute'
A ('"msLAPS-Password": "x"' -match $BOUNDED['msLAPS-Password'])                        'but does catch the Windows LAPS password attribute'

$UAC_WORKSTATION = 0x1000
$UAC_SERVER      = 0x2000      # a writable domain controller

# ---------------------------------------------------------------------------
# Stubs. Everything asked of the directory is recorded.
# ---------------------------------------------------------------------------

$script:legacyInSchema  = $false
$script:windowsInSchema = $false
$script:computers       = @()
$script:asked           = @()     # every property name requested, ever
$script:schemaFilters   = @()
$script:lastServer      = $null
$script:rootDse         = $null

function Get-ADRootDSE {
    param($Server, $ErrorAction)
    $script:lastServer = [string] $Server
    if ($null -ne $script:rootDse) { return $script:rootDse }
    return [pscustomobject]@{
        schemaNamingContext   = 'CN=Schema,CN=Configuration,DC=auditlab,DC=test'
        defaultNamingContext  = 'DC=auditlab,DC=test'
    }
}

function Get-ADObject {
    param($Identity, $Filter, $LDAPFilter, $SearchBase, $Properties, $Server, $ErrorAction)
    $script:schemaFilters += [string] $LDAPFilter
    if ($Properties) { $script:asked += @($Properties) }
    if ([string] $LDAPFilter -match [regex]::Escape($WINDOWS_EXPIRY)) {
        if ($script:windowsInSchema) { return @([pscustomobject]@{ Name = $WINDOWS_EXPIRY }) }
        return @()
    }
    if ([string] $LDAPFilter -match [regex]::Escape($LEGACY_EXPIRY)) {
        if ($script:legacyInSchema) { return @([pscustomobject]@{ Name = $LEGACY_EXPIRY }) }
        return @()
    }
    return @()
}

function Get-ADComputer {
    param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $ErrorAction)
    if ($Properties) { $script:asked += @($Properties) }
    return $script:computers
}

<#
    One computer. Expiration times are given as DateTime for readability and
    converted to the FILETIME the directory would hold, so the stub returns
    what the real attribute returns rather than what is convenient.
#>
function C {
    param(
        [string] $Name,
        $WindowsExpiry = $null,
        $LegacyExpiry  = $null,
        [int]    $Uac  = $UAC_WORKSTATION,
        $Enabled       = $true,
        [string] $OperatingSystem = 'Windows 11 Enterprise',
        $LastLogon     = $null,
        $RawWindows,                     # set instead of WindowsExpiry to inject a raw value
        [switch] $AsString               # return the FILETIME as a string, as some modules do
    )
    $toFileTime = {
        param($d)
        if ($null -eq $d) { return $null }
        $t = ([datetime] $d).ToFileTimeUtc()
        if ($AsString) { return [string] $t }
        return $t
    }
    $obj = [pscustomobject]@{
        Name              = $Name
        SamAccountName    = "$Name`$"
        DistinguishedName = "CN=$Name,OU=Workstations,DC=auditlab,DC=test"
        ObjectClass       = 'computer'
        userAccountControl = $Uac
        Enabled           = $Enabled
        OperatingSystem   = $OperatingSystem
        LastLogonDate     = $LastLogon
    }
    $w = if ($PSBoundParameters.ContainsKey('RawWindows')) { $RawWindows } else { & $toFileTime $WindowsExpiry }
    $obj | Add-Member -NotePropertyName $WINDOWS_EXPIRY -NotePropertyValue $w
    $obj | Add-Member -NotePropertyName $LEGACY_EXPIRY  -NotePropertyValue (& $toFileTime $LegacyExpiry)
    return $obj
}

function Reset-Fixture {
    param([switch] $Windows, [switch] $Legacy)
    $script:legacyInSchema  = [bool] $Legacy
    $script:windowsInSchema = [bool] $Windows
    $script:computers       = @()
    $script:asked           = @()
    $script:schemaFilters   = @()
    $script:lastServer      = $null
    $script:rootDse         = $null
}

function Run {
    param([hashtable] $Extra = @{})
    Test-LapsDeployment -DomainName 'auditlab.test' @Extra
}

$future = (Get-Date).ToUniversalTime().AddDays(20)
$recent = (Get-Date).ToUniversalTime().AddDays(-2)     # inside the default 7 day grace
$stale  = (Get-Date).ToUniversalTime().AddDays(-90)

# ---------------------------------------------------------------------------
"`nThe FILETIME helper on its own"
A ($null -eq (ConvertFrom-LapsFileTime -Value $null))        'no value gives no date'
A ($null -eq (ConvertFrom-LapsFileTime -Value ''))           'an empty string gives no date'
A ($null -eq (ConvertFrom-LapsFileTime -Value '   '))        'whitespace gives no date'
A ($null -eq (ConvertFrom-LapsFileTime -Value 0))            'zero is not a date in 1601'
A ($null -eq (ConvertFrom-LapsFileTime -Value '0'))          'nor is zero as a string'
A ($null -eq (ConvertFrom-LapsFileTime -Value -5))           'a negative value gives no date'
A ($null -eq (ConvertFrom-LapsFileTime -Value 'not a time')) 'junk gives no date rather than throwing'
A ($null -eq (ConvertFrom-LapsFileTime -Value '99999999999999999999')) 'a value too large for Int64 gives no date'
A ($null -eq (ConvertFrom-LapsFileTime -Value 2650467744000000000))    'a value past the FILETIME ceiling gives no date'
$known = [datetime]::SpecifyKind([datetime]'2026-06-01T12:00:00', [DateTimeKind]::Utc)
A ((ConvertFrom-LapsFileTime -Value $known.ToFileTimeUtc()) -eq $known)          'an Int64 round trips'
A ((ConvertFrom-LapsFileTime -Value ([string] $known.ToFileTimeUtc())) -eq $known) 'a string round trips, which is how some module versions return it'
A ((ConvertFrom-LapsFileTime -Value @($known.ToFileTimeUtc())) -eq $known)       'a single-element collection round trips'

"`nTelling an absent value from a malformed one"
A (-not (Test-LapsExpiryValuePresent -Value $null))        'no value is absent'
A (-not (Test-LapsExpiryValuePresent -Value ''))           'an empty string is absent'
A (-not (Test-LapsExpiryValuePresent -Value '  '))         'whitespace is absent'
A (-not (Test-LapsExpiryValuePresent -Value 0))            'zero is absent, because LAPS writes it before a password exists'
A (-not (Test-LapsExpiryValuePresent -Value '0'))          'and so is zero as a string'
A (-not (Test-LapsExpiryValuePresent -Value -1))           'a negative value is absent'
A (-not (Test-LapsExpiryValuePresent -Value @()))          'an empty collection is absent'
A (Test-LapsExpiryValuePresent -Value 'garbage')           'junk is present, so it can be counted as unreadable'
A (Test-LapsExpiryValuePresent -Value $known.ToFileTimeUtc()) 'a real FILETIME is present'
A (Test-LapsExpiryValuePresent -Value '99999999999999999999') 'a value too large for Int64 is present and therefore unreadable, not absent'

# ---------------------------------------------------------------------------
"`nThe password attributes are never requested"
# The point of the whole check. Run it through every path that queries the
# directory and assert the deny list never appears.
foreach ($case in @(
    @{ Label = 'no LAPS in the schema';  Windows = $false; Legacy = $false }
    @{ Label = 'Windows LAPS only';      Windows = $true;  Legacy = $false }
    @{ Label = 'legacy LAPS only';       Windows = $false; Legacy = $true  }
    @{ Label = 'both generations';       Windows = $true;  Legacy = $true  }
)) {
    Reset-Fixture -Windows:$case.Windows -Legacy:$case.Legacy
    $script:computers = @(
        (C 'WS01' -WindowsExpiry $future)
        (C 'WS02')
        (C 'WS03' -LegacyExpiry $stale)
    )
    $r = Run
    $leaked = @($script:asked | Where-Object { $PASSWORD_ATTRIBUTES -contains $_ })
    A ($leaked.Count -eq 0) "no password attribute requested with $($case.Label)"
    # Matched on whole attribute names. Every password attribute is a prefix
    # of an expiration attribute (ms-Mcs-AdmPwd of ms-Mcs-AdmPwdExpirationTime,
    # msLAPS-Password of msLAPS-PasswordExpirationTime), so a substring search
    # reports a leak on every correct run.
    $filterLeak = @($script:schemaFilters | Where-Object { $ff = $_; @($PASSWORD_ATTRIBUTES | Where-Object { $ff -match $BOUNDED[$_] }).Count -gt 0 })
    A ($filterLeak.Count -eq 0) "no password attribute named in a schema filter with $($case.Label)"
    if ($r) {
        $json = $r | ConvertTo-Json -Depth 12
        $inOutput = @($PASSWORD_ATTRIBUTES | Where-Object { $json -match $BOUNDED[$_] })
        A ($inOutput.Count -eq 0) "no password attribute name reaches the output with $($case.Label)"
    }
}

Reset-Fixture -Windows -Legacy
$script:computers = @( (C 'WS01') )
$r = Run
A ($r.evidence.propertiesRequested -contains $WINDOWS_EXPIRY) 'the expiration attribute is recorded as requested'
A (-not ($r.evidence.propertiesRequested | Where-Object { $PASSWORD_ATTRIBUTES -contains $_ })) 'and the recorded list holds no password attribute'
A ($r.evidence.note -match 'No password attribute is requested') 'the evidence states this in words a reader can check'

# ---------------------------------------------------------------------------
"`nLAPS is not installed at all"
Reset-Fixture
$r = Run
A (@($r).Count -eq 1)                                  'one finding'
A ($r.checkId -ceq 'AD.ACCOUNT.LAPS_MISSING')          'check id exact'
A ($r.severity -eq 'High')                             'High, not Critical, because a missing control is not an active exposure'
A ($r.affectedObjectCount -eq 1)                       'one affected object'
A ($r.affectedObjects[0].objectClass -eq 'domainDNS')  'and it is the domain, not a computer'
A ($r.affectedObjects[0].name -eq 'auditlab.test')     'named by the domain'
A ($r.affectedObjects[0].distinguishedName -eq 'DC=auditlab,DC=test') 'with the default naming context as its dn'
A ($r.evidence.schemaExtended -eq $false)              'the evidence says the schema is not extended'
A ($r.evidence.computersExamined -eq 0)                'no computer was examined'
A ($r.evidence.note -match 'not enumerated')           'and explains why they were not'
A (@($r.evidence.generationsInSchema).Count -eq 0)     'no generation is listed'

Reset-Fixture
$script:computers = @( (C 'WS01'), (C 'WS02'), (C 'WS03') )
$r = Run
A ($r.evidence.computersExamined -eq 0)                'computers are not read even when the directory has them'
A (-not ($script:asked -contains 'userAccountControl')) 'and Get-ADComputer is never called'

# ---------------------------------------------------------------------------
"`nThe schema probe"
Reset-Fixture -Windows
Run | Out-Null
A ($script:lastServer -eq 'auditlab.test')             'the root DSE is read from the domain being scanned'
A (@($script:schemaFilters | Where-Object { $_ -match 'lDAPDisplayName' }).Count -eq 2) 'both generations are probed by lDAPDisplayName'

Reset-Fixture -Windows
$script:rootDse = [pscustomobject]@{ schemaNamingContext = ''; defaultNamingContext = 'DC=auditlab,DC=test' }
$threw = $false
try { Run | Out-Null } catch { $threw = $true }
A $threw                                               'a directory with no schema naming context fails rather than guessing'

# ---------------------------------------------------------------------------
"`nNothing to report"
Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $future), (C 'WS02' -WindowsExpiry $future) )
A ($null -eq (Run))                                    'every computer managed and current produces no finding'

Reset-Fixture -Legacy
$script:computers = @( (C 'WS01' -LegacyExpiry $future) )
A ($null -eq (Run))                                    'legacy LAPS alone is still managed'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $recent) )
A ($null -eq (Run))                                    'a password a little past its time is inside the grace'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $future -AsString) )
A ($null -eq (Run))                                    'a FILETIME returned as a string is read the same way'

# ---------------------------------------------------------------------------
"`nA computer with no expiration time"
Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $future), (C 'WS02') )
$r = Run
A (@($r).Count -eq 1)                                  'one finding, not one per computer'
A ($r.severity -eq 'Medium')                           'Medium while some of the estate is managed'
A ($r.affectedObjectCount -eq 1)                       'only the unmanaged computer is named'
A ($r.affectedObjects[0].name -eq 'WS02$')             'by its sam account name'
A ($r.affectedObjects[0].attributes.issue -eq 'Not managed by LAPS') 'the issue is named'
A ($null -eq $r.affectedObjects[0].attributes.lapsGeneration)        'with no generation, because none manages it'
A ($null -eq $r.affectedObjects[0].attributes.passwordExpires)       'and no expiry'
A ($r.affectedObjects[0].attributes.detail -match 'organizational unit') 'the detail names the usual cause'
A ($r.evidence.computersUnmanaged -eq 1)               'counted as unmanaged'
A ($r.evidence.computersManaged -eq 1)                 'and the managed one is counted too'
A ($r.evidence.computersExamined -eq 2)                'both were examined'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01'), (C 'WS02'), (C 'WS03') )
$r = Run
A ($r.severity -eq 'High')                             'High when the schema exists and nothing at all is managed'
A ($r.evidence.computersUnmanaged -eq 3)               'all three counted'

# ---------------------------------------------------------------------------
"`nA password that has fallen out of rotation"
Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $future), (C 'WS02' -WindowsExpiry $stale) )
$r = Run
A (@($r).Count -eq 1)                                  'reported'
A ($r.severity -eq 'Low')                              'Low: LAPS reached this machine once, which is a different problem from never'
A ($r.affectedObjects[0].attributes.issue -eq 'LAPS password overdue for rotation') 'the issue is named'
A ($r.affectedObjects[0].attributes.lapsGeneration -eq 'windows') 'the generation that was managing it is recorded'
A ($null -ne $r.affectedObjects[0].attributes.passwordExpires)    'with the date it expired'
A ($r.affectedObjects[0].attributes.detail -match 'agent is not running') 'and what that means'
A ($r.evidence.computersExpired -eq 1)                 'counted as expired'
A ($r.evidence.computersUnmanaged -eq 0)               'not as unmanaged'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $stale) )
$r = Run @{ ExpiredGraceDays = 365 }
A ($null -eq $r)                                       'a wide enough grace clears it'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $recent) )
$r = Run @{ ExpiredGraceDays = 0 }
A (@($r).Count -eq 1)                                  'a zero grace reports it'
A ($r.evidence.parametersUsed.expiredGraceDays -eq 0)  'and the grace used is recorded'

# ---------------------------------------------------------------------------
"`nSeverity is graded by the worst thing found"
Reset-Fixture -Windows
$script:computers = @( (C 'WS01'), (C 'WS02' -WindowsExpiry $stale) )
$r = Run
A ($r.severity -eq 'Medium')                           'unmanaged outranks overdue'
A ($r.affectedObjectCount -eq 2)                       'both are named'
A ($r.evidence.issueCount -eq 2)                       'and both counted'

# ---------------------------------------------------------------------------
"`nWhat is left out of scope"
Reset-Fixture -Windows
# A domain controller's local account is the restore mode account, which is a
# different thing with a different fix.
$script:computers = @( (C 'DC01' -Uac $UAC_SERVER), (C 'WS01' -WindowsExpiry $future) )
$r = Run
A ($null -eq $r)                                       'a domain controller with no LAPS value is not a finding'
Reset-Fixture -Windows
$script:computers = @( (C 'DC01' -Uac $UAC_SERVER), (C 'WS01') )
$r = Run
A ($r.evidence.domainControllersSkipped -eq 1)         'and is counted as skipped'
A ($r.evidence.computersExamined -eq 1)                'not as examined'
A (-not ($r.affectedObjects.name -contains 'DC01$'))   'and never appears as an affected object'

Reset-Fixture -Windows
$script:computers = @( (C 'OLD01' -Enabled $false), (C 'WS01' -WindowsExpiry $future) )
A ($null -eq (Run))                                    'a disabled computer is skipped by default'
Reset-Fixture -Windows
$script:computers = @( (C 'OLD01' -Enabled $false) )
$out = @(Run @{ IncludeDisabledComputers = $true })
# The only computer is unmanaged, so the no-readable-value ambiguity applies
# here too and a partial result comes back with the finding.
$finding = @($out | Where-Object { $_.PSObject.TypeNames -notcontains 'ADSecurityAudit.PartialResult' })
A ($finding.Count -eq 1)                                'and reported when asked for'
A ($finding[0].affectedObjects[0].attributes.enabled -eq $false) 'with its state recorded'

Reset-Fixture -Windows
$script:computers = @( (C 'APPLIANCE01'), (C 'WS01' -WindowsExpiry $future) )
A ($null -eq (Run @{ ExcludedComputerNames = @('APPLIANCE01$') })) 'an excused computer is dropped'
Reset-Fixture -Windows
$script:computers = @( (C 'APPLIANCE01'), (C 'WS01') )
$r = Run @{ ExcludedComputerNames = @('APPLIANCE01$') }
A ($r.evidence.excludedComputersSkipped -eq 1)         'and counted as excluded'
A ($r.evidence.parametersUsed.excludedComputerNames -contains 'APPLIANCE01$') 'with the exclusion recorded'

# ---------------------------------------------------------------------------
"`nA migration with both generations in the schema"
Reset-Fixture -Windows -Legacy
$script:computers = @( (C 'WS01' -WindowsExpiry $future -LegacyExpiry $stale) )
A ($null -eq (Run))                                    'Windows LAPS wins where both are set, so a stale legacy value is not a finding'

Reset-Fixture -Windows -Legacy
$script:computers = @( (C 'WS01' -WindowsExpiry $stale -LegacyExpiry $future) )
$r = Run
A (@($r).Count -eq 1)                                  'and an expired Windows value is reported even with a current legacy one'
A ($r.affectedObjects[0].attributes.lapsGeneration -eq 'both') 'with both recorded'

Reset-Fixture -Windows -Legacy
$script:computers = @( (C 'WS01') )
$r = Run
A (@($r.evidence.generationsInSchema).Count -eq 2)     'both generations are listed in the evidence'
A ($r.evidence.summary -match 'migration')             'and the summary says what that usually means'

Reset-Fixture -Legacy
$script:computers = @( (C 'WS01' -LegacyExpiry $stale) )
$r = Run
A ($r.affectedObjects[0].attributes.lapsGeneration -eq 'legacy') 'legacy alone is recorded as legacy'
A (-not ($r.evidence.propertiesRequested -contains $WINDOWS_EXPIRY)) 'and the attribute missing from the schema is not requested'

# ---------------------------------------------------------------------------
"`nAn expiration value that is present but unreadable"
Reset-Fixture -Windows
# Treated as unmanaged, which is the cautious reading, and counted separately
# so the reader can tell the two apart.
$script:computers = @( (C 'WS01' -RawWindows 'garbage'), (C 'WS02' -WindowsExpiry $future) )
$r = Run
A (@($r).Count -eq 1)                                  'reported'
A ($r.evidence.unreadableExpiryValues -eq 1)           'counted as unreadable'
A ($r.evidence.computersUnmanaged -eq 1)               'and as unmanaged'
A ($r.affectedObjects[0].attributes.detail -match 'could not be read as a time') 'the object says why'
A ($r.evidence.summary -match 'could not be read')     'and so does the summary'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -RawWindows 0), (C 'WS02' -WindowsExpiry $future) )
$r = Run
A ($r.evidence.unreadableExpiryValues -eq 0)           'a zero is absent rather than unreadable'
A ($r.evidence.computersUnmanaged -eq 1)               'and still unmanaged'

# ---------------------------------------------------------------------------
"`nThe schema says LAPS exists and nothing answers"
# The ambiguity the third contract state was built for: no computer managed,
# or no read access to the attribute. Both look identical from here.
Reset-Fixture -Windows
$script:computers = @( (C 'WS01'), (C 'WS02') )
$out = @(Run)
A ($out.Count -eq 2)                                   'a finding and a partial result are both returned'
$finding = @($out | Where-Object { $_.PSObject.TypeNames -notcontains 'ADSecurityAudit.PartialResult' })
$partial = @($out | Where-Object { $_.PSObject.TypeNames -contains 'ADSecurityAudit.PartialResult' })
A ($finding.Count -eq 1)                               'exactly one finding'
A ($partial.Count -eq 1)                               'exactly one partial result'
A ($partial[0].checkId -ceq 'AD.ACCOUNT.LAPS_MISSING') 'the partial result carries the same check id'
A ($partial[0].reason -match 'lost read access')       'and names the other explanation'
A ($partial[0].reason -match [regex]::Escape($WINDOWS_EXPIRY)) 'naming the attribute to check'
A ($partial[0].reason -match 'more dangerous reading') 'and says which way the finding leans'
A ($finding[0].severity -eq 'High')                    'the finding is still reported rather than withheld'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01'), (C 'WS02' -WindowsExpiry $future) )
$out = @(Run)
A ($out.Count -eq 1)                                   'one readable value is enough to remove the ambiguity'
A (-not ($out[0].PSObject.TypeNames -contains 'ADSecurityAudit.PartialResult')) 'and what comes back is a finding'

Reset-Fixture
$out = @(Run)
A ($out.Count -eq 1)                                   'an unextended schema returns no partial result, because there is no ambiguity'

# ---------------------------------------------------------------------------
"`nEvidence records how the check ran"
Reset-Fixture -Windows
$script:computers = @( (C 'WS01'), (C 'DC01' -Uac $UAC_SERVER), (C 'OLD01' -Enabled $false) )
$r = @(Run)[0]
A ($r.evidence.computersTotal -eq 3)                   'every computer object is counted'
A ($r.evidence.computersExamined -eq 1)                'only the eligible one is examined'
A (($r.evidence.computersUnmanaged + $r.evidence.computersExpired + $r.evidence.computersManaged) -eq $r.evidence.computersExamined) 'and the three outcomes add up to what was examined'
A ($r.evidence.query -match 'Get-ADComputer')          'the query is recorded'
A ($r.evidence.limitation -match 'cannot see whether the local administrator passwords') 'the limitation says what it cannot prove'
A ($r.evidence.note -match 'directory services restore mode') 'and why domain controllers are out of scope'

# ---------------------------------------------------------------------------
"`nJSON round trip"
Reset-Fixture -Windows
$script:computers = @( (C 'WS01' -WindowsExpiry $stale -LastLogon ([datetime]'2026-10-01T08:00:00')), (C 'WS02' -WindowsExpiry $future) )
# Asserted against the JSON text, not against what ConvertFrom-Json hands
# back. PowerShell 7 parses an ISO-8601 string into a DateTime on the way in,
# so a regex over the deserialized object tests the deserializer rather than
# the contract, and would behave differently on 5.1. The dashboard reads the
# text, so the text is what this checks.
$json = (@(Run)[0]) | ConvertTo-Json -Depth 12
$back = $json | ConvertFrom-Json
A ($back.checkId -ceq 'AD.ACCOUNT.LAPS_MISSING')       'survives ConvertTo-Json'
A ($json -match '"passwordExpires":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') 'with the expiry as a UTC contract timestamp'
A ($json -match '"lastLogonDate":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"')   'and the last logon likewise'

Reset-Fixture -Windows
$script:computers = @( (C 'WS01') )
$json = (@(Run)[0]) | ConvertTo-Json -Depth 12
A ($json -match '"passwordExpires":\s*null') 'an absent expiry stays null rather than becoming an empty string'

# ---------------------------------------------------------------------------
"`nError propagation"
function Get-ADRootDSE { param($Server, $ErrorAction) throw 'Access is denied' }
$threw = $false
try { Run | Out-Null } catch { $threw = $true }
A $threw                                               'a root DSE failure reaches the caller rather than reading as no LAPS'

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
