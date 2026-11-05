<#
    Verification for Initialize-VulnerableLab.ps1, the seeding script.

    It runs the real script against stubbed ActiveDirectory cmdlets, with a
    fake directory held in memory, so the behaviour that matters can be
    checked without a domain: that -WhatIf changes nothing while still
    showing the whole plan, that a second run is idempotent, that a missing
    account does not end the run after earlier sections have already changed
    the directory, and that ground-truth.json describes what was actually
    created rather than what the script set out to create.

    That last point is why this file exists. Ground truth is what detection
    accuracy is measured against. A ground truth file that overstates what
    was seeded turns a correct scan into measured false negatives, and the
    error would look like a fault in the scanner.

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        .\Tests\verify-lab-seeding.ps1
#>

$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

$labScript = Join-Path (Split-Path $moduleRoot -Parent) 'Lab\Initialize-VulnerableLab.ps1'
if (-not (Test-Path $labScript)) { throw "Cannot find $labScript" }

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

$SID = 'S-1-5-21-1111111111-2222222222-3333333333'

# ---------------------------------------------------------------------------
# A directory held in memory, plus a log of everything that changed it. The
# log is what proves -WhatIf wrote nothing.
# ---------------------------------------------------------------------------

<#
    One global, deliberately.

    Invoking the lab script with & gives it a script scope of its own, so a
    $script: variable read inside a stub resolves to the lab script rather
    than to this file and comes back as $null. The first version of this
    harness did exactly that, and "no directory write of any kind is
    performed" passed because $null.Count is 0, not because nothing was
    written. A global is the one store both scopes agree on.
#>
$global:LabProbe = @{
    Dir    = @{}
    Ous    = @{}
    Groups = @{}
    Writes = [System.Collections.Generic.List[string]]::new()
    KdsKey = $null
}

function Reset-Directory {
    $global:LabProbe.Dir    = @{}
    $global:LabProbe.Ous    = @{}
    $global:LabProbe.Groups = @{}
    $global:LabProbe.Writes = [System.Collections.Generic.List[string]]::new()
    $global:LabProbe.KdsKey = $null
}

function Add-FakeAccount {
    param([string] $Sam, [string] $Class, [string] $Container = 'OU=LabServiceAccounts,DC=auditlab,DC=test')
    $global:LabProbe.Dir[$Sam] = [pscustomobject]@{
        Name               = $Sam.TrimEnd('$')
        SamAccountName     = $Sam
        ObjectClass        = $Class
        DistinguishedName  = "CN=$($Sam.TrimEnd('$')),$Container"
        userAccountControl = 0x200
        Enabled            = $true
    }
}

function Import-Module { param([Parameter(ValueFromRemainingArguments)] $Rest) }

function Get-ADDomain {
    param([Parameter(ValueFromRemainingArguments)] $Rest)
    [pscustomobject]@{
        DNSRoot           = 'auditlab.test'
        NetBIOSName       = 'AUDITLAB'
        DistinguishedName = 'DC=auditlab,DC=test'
        DomainSID         = [pscustomobject]@{ Value = $SID }
    }
}

function Get-ADOrganizationalUnit {
    param($Filter, [Parameter(ValueFromRemainingArguments)] $Rest)
    if ($Filter -and $Filter -match "'([^']+)'" -and $global:LabProbe.Ous.ContainsKey($Matches[1])) {
        return $global:LabProbe.Ous[$Matches[1]]
    }
    return $null
}
function New-ADOrganizationalUnit {
    param([string] $Name, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("New-ADOrganizationalUnit:$Name")
    $global:LabProbe.Ous[$Name] = [pscustomobject]@{ Name = $Name }
}

function Get-ADDefaultDomainPasswordPolicy {
    param([Parameter(ValueFromRemainingArguments)] $Rest)
    [pscustomobject]@{
        MinPasswordLength           = 7
        ComplexityEnabled           = $true
        LockoutThreshold            = 0
        MaxPasswordAge              = [timespan]::FromDays(42)
        MinPasswordAge              = [timespan]::FromDays(1)
        PasswordHistoryCount        = 24
        ReversibleEncryptionEnabled = $false
    }
}
function Set-ADDefaultDomainPasswordPolicy {
    param([Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add('Set-ADDefaultDomainPasswordPolicy')
}

function Find-FakeBySam {
    param([string] $Filter, [string] $LDAPFilter)
    foreach ($text in @($Filter, $LDAPFilter)) {
        if (-not $text) { continue }
        if ($text -match "'([^']+)'") { $name = $Matches[1] }
        elseif ($text -match '=\s*([^)\s]+)\)?\s*$') { $name = $Matches[1] }
        else { continue }

        if ($global:LabProbe.Dir.ContainsKey($name)) { return $global:LabProbe.Dir[$name] }
        if ($global:LabProbe.Dir.ContainsKey("$name`$")) { return $global:LabProbe.Dir["$name`$"] }
        foreach ($value in $global:LabProbe.Dir.Values) { if ($value.Name -eq $name) { return $value } }
    }
    return $null
}

function Get-ADUser {
    param($Identity, $Filter, $LDAPFilter, [Parameter(ValueFromRemainingArguments)] $Rest)
    $found = Find-FakeBySam -Filter $Filter -LDAPFilter $LDAPFilter
    if ($found -and $found.ObjectClass -eq 'user') { return $found }
    return $null
}
function Get-ADComputer {
    param($Identity, $Filter, $LDAPFilter, [Parameter(ValueFromRemainingArguments)] $Rest)
    $found = Find-FakeBySam -Filter $Filter -LDAPFilter $LDAPFilter
    if ($found -and $found.ObjectClass -eq 'computer') { return $found }
    return $null
}
function Get-ADServiceAccount {
    param($Identity, $Filter, $LDAPFilter, [Parameter(ValueFromRemainingArguments)] $Rest)
    $found = Find-FakeBySam -Filter $Filter -LDAPFilter $LDAPFilter
    if ($found -and $found.ObjectClass -like 'msDS-*') { return $found }
    return $null
}
function Get-ADObject {
    param($Identity, $Filter, $LDAPFilter, [Parameter(ValueFromRemainingArguments)] $Rest)
    return (Find-FakeBySam -Filter $Filter -LDAPFilter $LDAPFilter)
}

function New-ADUser {
    param([string] $Name, [string] $SamAccountName, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("New-ADUser:$SamAccountName")
    Add-FakeAccount -Sam $SamAccountName -Class 'user'
}
function New-ADComputer {
    param([string] $Name, [string] $SamAccountName, [switch] $PassThru, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("New-ADComputer:$SamAccountName")
    Add-FakeAccount -Sam $SamAccountName -Class 'computer'
    # -PassThru has to work, because a script may capture the new object and
    # pass it straight to another cmdlet. A stub that silently returned
    # nothing would make that script look broken when it is not.
    if ($PassThru) { return $global:LabProbe.Dir[$SamAccountName] }
}
function New-ADServiceAccount {
    param([string] $Name, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("New-ADServiceAccount:$Name")
    Add-FakeAccount -Sam "$Name`$" -Class 'msDS-GroupManagedServiceAccount'
}

function Get-ADGroup {
    param($Identity, $Filter, [Parameter(ValueFromRemainingArguments)] $Rest)
    if ($Identity -and "$Identity" -match '-512$') {
        return [pscustomobject]@{ Name = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins,DC=auditlab,DC=test' }
    }
    if ($Filter -and $Filter -match "'([^']+)'" -and $global:LabProbe.Groups.ContainsKey($Matches[1])) {
        return $global:LabProbe.Groups[$Matches[1]]
    }
    return $null
}
function New-ADGroup {
    param([string] $Name, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("New-ADGroup:$Name")
    $global:LabProbe.Groups[$Name] = [pscustomobject]@{ Name = $Name; DistinguishedName = "CN=$Name,DC=auditlab,DC=test" }
}
function Get-ADGroupMember { param([Parameter(ValueFromRemainingArguments)] $Rest) return @() }
function Add-ADGroupMember {
    param([Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add('Add-ADGroupMember')
}
function Set-ADUser {
    param($Identity, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("Set-ADUser:$Identity")
}

function Set-ADAccountControl {
    param($Identity, [Parameter(ValueFromRemainingArguments)] $Rest)
    # The real cmdlet throws when the identity does not resolve, and the
    # seeding script calls it with -ErrorAction Stop. A stub that accepted
    # anything could not tell a script that checks the account exists from
    # one that assumes it does.
    # -Identity accepts a distinguished name, a SAM account name or an AD
    # object, and all three have to resolve here. A stub that only understood
    # strings would fail a script that passes the object it just fetched,
    # which the real cmdlet accepts.
    $key =
        if ($Identity -and $Identity.PSObject.Properties.Name -contains 'DistinguishedName') {
            [string] $Identity.DistinguishedName
        }
        else { "$Identity" }

    $known = @($global:LabProbe.Dir.Values | Where-Object { $_.DistinguishedName -eq $key -or $_.SamAccountName -eq $key })
    if ($known.Count -eq 0) { throw "Cannot find an object with identity: '$key'." }
    $global:LabProbe.Writes.Add("Set-ADAccountControl:$key")
}

function Get-KdsRootKey { param([Parameter(ValueFromRemainingArguments)] $Rest) return $global:LabProbe.KdsKey }

# ---------------------------------------------------------------------------

function Invoke-Lab {
    param([hashtable] $Extra = @{})
    $path = Join-Path ([System.IO.Path]::GetTempPath()) "lab-truth-$([guid]::NewGuid()).json"
    $warnings = @()
    & $labScript -GroundTruthPath $path -WarningAction SilentlyContinue -WarningVariable warnings @Extra | Out-Null
    $truth = if (Test-Path $path) { Get-Content -LiteralPath $path -Raw | ConvertFrom-Json } else { $null }
    Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Truth = $truth; Warnings = @($warnings) }
}

# ---------------------------------------------------------------------------
"`n-WhatIf changes nothing"
Reset-Directory
$result = Invoke-Lab @{ WhatIf = $true }
A ($global:LabProbe.Writes.Count -eq 0)                        'no directory write of any kind is performed'
A ($null -eq $result.Truth)                           'and no ground truth file is written'

# ---------------------------------------------------------------------------
"`nThe delegation step is not gated on having just created the account"
Reset-Directory
# An earlier version only reached the delegation step inside the branch that
# created the account, so an account that already existed was never given the
# flag, and a -WhatIf preview never showed the step at all. Seeding the
# directory first makes that regression visible: no creation runs, and the
# flag must still be set.
#
# The -WhatIf preview text itself is not asserted. ShouldProcess writes it
# straight to the host rather than to a capturable stream, so it cannot be
# read from inside this process.
Add-FakeAccount -Sam 'LAB-APP01$' -Class 'computer'
Add-FakeAccount -Sam 'lab_svc_portal' -Class 'user'
$result = Invoke-Lab
A (-not ($global:LabProbe.Writes -contains 'New-ADComputer:LAB-APP01$')) 'the existing computer is not created again'
A (-not ($global:LabProbe.Writes -contains 'New-ADUser:lab_svc_portal')) 'nor the existing user'
A (@($global:LabProbe.Writes | Where-Object { $_ -like 'Set-ADAccountControl:*' }).Count -eq 2) 'and both are still given the delegation flag'
A (@($result.Truth.expected.'AD.PRIVILEGE.UNCONSTRAINED_DELEGATION'.objects).Count -eq 2) 'ground truth names both'

# ---------------------------------------------------------------------------
"`nA normal run"
Reset-Directory
$result = Invoke-Lab
A (($global:LabProbe.Writes | Where-Object { $_ -eq 'New-ADComputer:LAB-APP01$' }).Count -eq 1) 'creates the delegating computer'
A (($global:LabProbe.Writes | Where-Object { $_ -eq 'New-ADUser:lab_svc_portal' }).Count -eq 1) 'creates the delegating user'
A (($global:LabProbe.Writes | Where-Object { $_ -like 'Set-ADAccountControl:*' }).Count -eq 2)  'flags exactly those two accounts'
A ($null -ne $result.Truth)                           'writes ground truth'

$delegation = $result.Truth.expected.'AD.PRIVILEGE.UNCONSTRAINED_DELEGATION'
A ($delegation.shouldDetect -eq $true)                'ground truth expects a detection'
A (@($delegation.objects).Count -eq 2)                'and names both accounts'
A ($delegation.objects -contains 'LAB-APP01$')        'the computer by its SAM name'
A ($delegation.objects -contains 'lab_svc_portal')    'and the user'
A ($delegation.mustNotDetect -contains 'DC01$')       'and records that a controller must not be reported'
A ($delegation.managedServiceAccountSeeded -eq $false) 'and says the managed service account was not seeded'
A ($null -ne $delegation.notSeeded)                   'with a note saying how to seed it'

$kerberoast = $result.Truth.expected.'AD.PRIVILEGE.KERBEROASTING'
A ($kerberoast.objects -contains 'lab_svc_portal')    'the delegating user is expected by the Kerberoasting check too, because it holds an SPN'

# ---------------------------------------------------------------------------
"`nRunning it twice"
Reset-Directory
Invoke-Lab | Out-Null
$writesAfterFirst = $global:LabProbe.Writes.Count
$creationsBefore = @($global:LabProbe.Writes | Where-Object { $_ -like 'New-AD*' }).Count
$result = Invoke-Lab
$creationsAfter = @($global:LabProbe.Writes | Where-Object { $_ -like 'New-AD*' }).Count
A ($creationsAfter -eq $creationsBefore)              'a second run creates nothing that already exists'
A (@($result.Truth.expected.'AD.PRIVILEGE.UNCONSTRAINED_DELEGATION'.objects).Count -eq 2) 'and ground truth still names both accounts'

# ---------------------------------------------------------------------------
"`nAn account that cannot be created"
Reset-Directory
# Set-ADAccountControl runs with -ErrorAction Stop. Without an existence
# check in front of it, a declined or failed creation ends the whole script
# here, after sections 1 to 4 have already changed the directory.
function New-ADComputer { param([string] $Name, [string] $SamAccountName, [Parameter(ValueFromRemainingArguments)] $Rest) $global:LabProbe.Writes.Add("New-ADComputer:$SamAccountName") }
function New-ADUser { param([string] $Name, [string] $SamAccountName, [Parameter(ValueFromRemainingArguments)] $Rest) $global:LabProbe.Writes.Add("New-ADUser:$SamAccountName") }
$threw = $false
$result = $null
try { $result = Invoke-Lab } catch { $threw = $true }
A (-not $threw)                                       'the run finishes instead of dying part way through'
A (-not (@($global:LabProbe.Writes) -like 'Set-ADAccountControl:*LAB-APP01*')) 'and does not try to flag an account that is not there'
$delegation = $result.Truth.expected.'AD.PRIVILEGE.UNCONSTRAINED_DELEGATION'
A (-not ($delegation.objects -contains 'LAB-APP01$')) 'ground truth leaves out the computer that was never created'
A (-not ($delegation.objects -contains 'lab_svc_portal')) 'and leaves out the user as well'
A (@($delegation.objects).Count -eq 0)                'so it claims no detections at all'
A ($delegation.shouldDetect -eq $false)               'and says so explicitly rather than expecting two'

# Restore the working stubs.
function New-ADComputer {
    param([string] $Name, [string] $SamAccountName, [switch] $PassThru, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("New-ADComputer:$SamAccountName")
    Add-FakeAccount -Sam $SamAccountName -Class 'computer'
    # -PassThru has to work, because a script may capture the new object and
    # pass it straight to another cmdlet. A stub that silently returned
    # nothing would make that script look broken when it is not.
    if ($PassThru) { return $global:LabProbe.Dir[$SamAccountName] }
}
function New-ADUser {
    param([string] $Name, [string] $SamAccountName, [Parameter(ValueFromRemainingArguments)] $Rest)
    $global:LabProbe.Writes.Add("New-ADUser:$SamAccountName")
    Add-FakeAccount -Sam $SamAccountName -Class 'user'
}

# ---------------------------------------------------------------------------
"`nThe managed service account fixture"
Reset-Directory
$result = Invoke-Lab
A (-not ($global:LabProbe.Writes -like 'New-ADServiceAccount:*')) 'is not seeded unless it is asked for'

Reset-Directory
$global:LabProbe.KdsKey = $null
$result = Invoke-Lab @{ IncludeManagedServiceAccount = $true }
A (-not ($global:LabProbe.Writes -like 'New-ADServiceAccount:*')) 'is not created when the forest has no KDS root key'
A (($result.Warnings -join ' ') -match 'KDS root\s+key')  'and the missing prerequisite is stated'
A (($result.Warnings -join ' ') -match 'Add-KdsRootKey') 'with the command that creates it'
A (-not ($global:LabProbe.Writes -like '*KdsRootKey*'))           'the script does not create forest-wide configuration itself'

Reset-Directory
$global:LabProbe.KdsKey = [pscustomobject]@{ KeyId = [guid]::NewGuid() }
$result = Invoke-Lab @{ IncludeManagedServiceAccount = $true }
A (($global:LabProbe.Writes | Where-Object { $_ -eq 'New-ADServiceAccount:lab_gmsa_app' }).Count -eq 1) 'is created when the key exists'
A (($global:LabProbe.Writes | Where-Object { $_ -like 'Set-ADAccountControl:*' }).Count -eq 3)          'and is flagged alongside the other two'
$delegation = $result.Truth.expected.'AD.PRIVILEGE.UNCONSTRAINED_DELEGATION'
A ($delegation.objects -contains 'lab_gmsa_app$')      'ground truth names it'
A ($delegation.managedServiceAccountSeeded -eq $true)  'and records that the path was covered'

# ---------------------------------------------------------------------------
"`nNo secret is written to ground truth"
Reset-Directory
$result = Invoke-Lab
$asText = $result.Truth | ConvertTo-Json -Depth 10
A ($asText -notmatch '(?i)password\s*"?\s*[:=]\s*"[^"]{4,}') 'no password value appears in the file'

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
