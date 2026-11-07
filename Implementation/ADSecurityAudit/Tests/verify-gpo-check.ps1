<#
    Verification for Test-RiskyGroupPolicy.

    Unlike the other check tests, this one does not stub a filesystem. The
    check takes the policy store as a parameter, so each case builds a real
    directory of real policy files in a temporary folder and lets the check
    read them. The parsing is the part most likely to be wrong, and parsing
    is exactly what a mocked filesystem would not exercise.

    No domain, no RSAT and no Windows are required.

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        .\Tests\verify-gpo-check.ps1
#>

$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Private\Checks\Test-RiskyGroupPolicy.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

function Findings { param($r) @($r) | Where-Object { $_ -and -not ($_.PSObject.TypeNames -contains 'ADSecurityAudit.PartialResult') } }
function Partials { param($r) @($r) | Where-Object { $_ -and ($_.PSObject.TypeNames -contains 'ADSecurityAudit.PartialResult') } }

$SID        = 'S-1-5-21-1111111111-2222222222-3333333333'
$GUID_A     = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
$GUID_B     = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'

# ---------------------------------------------------------------------------
# A policy store on disk
# ---------------------------------------------------------------------------

$script:root = $null

function New-PolicyStore {
    if ($script:root -and (Test-Path -LiteralPath $script:root)) {
        Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue
    }
    $script:root = Join-Path ([System.IO.Path]::GetTempPath()) "sysvol-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $script:root -Force | Out-Null
    return $script:root
}

function Add-PolicyFile {
    param(
        [Parameter(Mandatory)] [string] $Guid,
        [Parameter(Mandatory)] [string] $RelativePath,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Content
    )
    $full = Join-Path (Join-Path $script:root $Guid) $RelativePath
    New-Item -ItemType Directory -Path (Split-Path $full -Parent) -Force | Out-Null
    Set-Content -LiteralPath $full -Value $Content -Encoding UTF8
    return $full
}

function Add-GptTmpl {
    param([Parameter(Mandatory)] [string] $Guid, [Parameter(Mandatory)] [string] $Body)
    Add-PolicyFile -Guid $Guid -RelativePath 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf' -Content $Body | Out-Null
}

# A real Groups.xml, trimmed. The cpassword is the published example value.
function Add-GroupsXml {
    param([Parameter(Mandatory)] [string] $Guid, [string] $CPassword = 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ')
    Add-PolicyFile -Guid $Guid -RelativePath 'Machine/Preferences/Groups/Groups.xml' -Content @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)">
    <Properties action="U" newName="" fullName="" description="" cpassword="$CPassword" changeLogon="0" userName="Administrator (built-in)"/>
  </User>
</Groups>
"@ | Out-Null
}

function Get-ADObject {
    param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $ErrorAction)
    if ($LDAPFilter -match '\(cn=(.+)\)$') {
        $cn = $Matches[1]
        if ($script:gpoNames.ContainsKey($cn)) {
            return [pscustomobject]@{ displayName = $script:gpoNames[$cn] }
        }
    }
    return $null
}

function Get-ADDomain {
    param($Identity, $Server, $ErrorAction)
    [pscustomobject]@{ DNSRoot = 'auditlab.test'; DomainSID = $SID }
}

$script:gpoNames = @{ $GUID_A = 'Default Domain Policy'; $GUID_B = 'Workstation Hardening' }

function Run {
    param([hashtable] $Extra = @{})
    Test-RiskyGroupPolicy -DomainName 'auditlab.test' -SysvolPath $script:root -DomainSid $SID @Extra
}

# ---------------------------------------------------------------------------
"`nA policy store with nothing wrong in it"
New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_A -Body @'
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 14
EnableGuestAccount = 0
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeNetworkLogonRight = *S-1-5-11
'@
A ($null -eq (Run))                                   'reports nothing'

# ---------------------------------------------------------------------------
"`nA password stored in Group Policy Preferences"
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
$r = Findings (Run)
A (@($r).Count -eq 1)                                 'one finding'
A ($r.checkId -ceq 'AD.POLICY.RISKY_GPO')             'check id exact'
A ($r.severity -eq 'Critical')                        'a decryptable password in SYSVOL is Critical'
A ($r.affectedObjectCount -eq 1)                      'one affected object'
A ($r.affectedObjects[0].name -eq 'Default Domain Policy') 'named by its display name, not its GUID'
A ($r.affectedObjects[0].objectClass -eq 'groupPolicyContainer') 'object class recorded'
A ($r.affectedObjects[0].attributes.issue -eq 'Stored password') 'the kind of problem is on the object'
A ($r.affectedObjects[0].attributes.policyGuid -eq $GUID_A) 'and so is the GUID, for finding the folder'
A ($r.evidence.storedPasswordCount -eq 1)             'counted in the evidence'
A ($r.evidence.summary -match 'any domain user can decrypt') 'the summary says why it matters'
# The decrypted value is never recorded. A report that quoted the password
# would turn the audit output into the very thing it is reporting.
A ($r.affectedObjects[0].attributes.detail -notmatch 'edBSHOwhZ') 'the password itself is not copied into the finding'
A (($r | ConvertTo-Json -Depth 10) -notmatch 'edBSHOwhZ') 'nor anywhere else in the finding'

New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A -CPassword ''
A ($null -eq (Run))                                   'an empty cpassword sets no password, so it is not a finding'

New-PolicyStore | Out-Null
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Services/Services.xml' -Content @'
<?xml version="1.0" encoding="utf-8"?>
<NTServices>
  <NTService><Properties cpassword="AAAA" accountName="svc_a"/></NTService>
  <NTService><Properties cpassword="BBBB" accountName="svc_b"/></NTService>
</NTServices>
'@ | Out-Null
$r = Findings (Run)
A ($r.evidence.storedPasswordCount -eq 2)             'every password in one file is reported, not just the first'

# ---------------------------------------------------------------------------
"`nA dangerous privilege granted to everybody"
New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_B -Body @'
[Privilege Rights]
SeDebugPrivilege = *S-1-5-11
'@
$r = Findings (Run)
A (@($r).Count -eq 1)                                 'one finding'
A ($r.severity -eq 'High')                            'High, not Critical, with no stored password'
A ($r.affectedObjects[0].name -eq 'Workstation Hardening') 'names the policy'
A ($r.affectedObjects[0].attributes.setting -eq 'SeDebugPrivilege') 'records which privilege'
A ($r.affectedObjects[0].attributes.detail -match 'Authenticated Users') 'and which principal, by its well-known name'
A ($r.evidence.dangerousRightCount -eq 1)             'counted in the evidence'

New-PolicyStore | Out-Null
# Administrators already hold these privileges. Reporting them would make
# the check cry wolf on every domain that exists.
Add-GptTmpl -Guid $GUID_B -Body @'
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20
'@
A ($null -eq (Run))                                   'the same privilege held by Administrators is not reported'

New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_B -Body "[Privilege Rights]`nSeDebugPrivilege = *$SID-513"
A ((Findings (Run)).affectedObjects[0].attributes.detail -match 'Domain Users') 'Domain Users is recognised from the domain SID'

New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_B -Body "[Privilege Rights]`nSeDebugPrivilege = *$SID-512"
A ($null -eq (Run))                                   'Domain Admins is not treated as a broad group'

New-PolicyStore | Out-Null
# A privilege that is not on the dangerous list, granted to everybody. Normal
# on most domains and not what this check is about.
Add-GptTmpl -Guid $GUID_B -Body @'
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-11
SeInteractiveLogonRight = *S-1-5-11
'@
A ($null -eq (Run))                                   'an ordinary privilege granted broadly is not reported'

New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_B -Body @'
[Privilege Rights]
SeDebugPrivilege = *S-1-5-11,*S-1-1-0,*S-1-5-32-544
'@
$r = Findings (Run)
A ($r.affectedObjectCount -eq 2)                      'each broad principal on one line is reported separately'
A (-not (($r.affectedObjects.attributes.detail -join ' ') -match 'S-1-5-32-544')) 'and the narrow one on the same line is left out'

New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_B -Body @'
[Privilege Rights]
SeDebugPrivilege = *S-1-5-11
'@
A ($null -eq (Run @{ RiskyPrivileges = @('SeTcbPrivilege') })) 'the dangerous privilege list is overridable'

# ---------------------------------------------------------------------------
"`nThe guest account"
New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_A -Body @'
[System Access]
EnableGuestAccount = 1
'@
$r = Findings (Run)
A (@($r).Count -eq 1)                                 'reported'
A ($r.severity -eq 'Medium')                          'Medium on its own, so it does not drown out the serious findings'
A ($r.evidence.guestAccountCount -eq 1)               'counted in the evidence'

New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_A -Body "[System Access]`nEnableGuestAccount = 0"
A ($null -eq (Run))                                   'switched off is not a finding'

# ---------------------------------------------------------------------------
"`nSeverity is graded by the worst thing found"
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-GptTmpl  -Guid $GUID_B -Body @'
[System Access]
EnableGuestAccount = 1
[Privilege Rights]
SeImpersonatePrivilege = *S-1-5-11
'@
$r = Findings (Run)
A ($r.severity -eq 'Critical')                        'a stored password outranks everything else'
A ($r.evidence.issueCount -eq 3)                      'all three issues are reported'
A ($r.evidence.storedPasswordCount -eq 1)             'counted by kind: passwords'
A ($r.evidence.dangerousRightCount -eq 1)             'privileges'
A ($r.evidence.guestAccountCount -eq 1)               'and the guest account'
A ($r.evidence.policiesTotal -eq 2)                   'both policies were examined'
A (@($r.affectedObjects.name | Sort-Object -Unique).Count -eq 2) 'findings span both policies'

# ---------------------------------------------------------------------------
"`nParsing oddities"
New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_A -Body @'
; a comment that mentions SeDebugPrivilege = *S-1-5-11
[Privilege Rights]
   SeDebugPrivilege   =   *S-1-5-11
'@
$r = Findings (Run)
A (@($r).Count -eq 1)                                 'whitespace around the setting is tolerated'
A ($r.evidence.dangerousRightCount -eq 1)             'and a commented-out line is not counted'

New-PolicyStore | Out-Null
# The same privilege name outside the Privilege Rights section means
# something else entirely, so the section has to be tracked.
Add-GptTmpl -Guid $GUID_A -Body @'
[Registry Values]
SeDebugPrivilege = *S-1-5-11
'@
A ($null -eq (Run))                                   'a setting in the wrong section is ignored'

New-PolicyStore | Out-Null
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf' -Content '' | Out-Null
A ($null -eq (Run))                                   'an empty policy file is not an error'

New-PolicyStore | Out-Null
$script:gpoNames = @{}
Add-GroupsXml -Guid $GUID_A
A ((Findings (Run)).affectedObjects[0].name -eq $GUID_A) 'falls back to the GUID when the directory has no display name'
$script:gpoNames = @{ $GUID_A = 'Default Domain Policy'; $GUID_B = 'Workstation Hardening' }

# ---------------------------------------------------------------------------
"`nA policy folder that cannot be read"
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-GptTmpl -Guid $GUID_B -Body "[System Access]`nEnableGuestAccount = 0"

# A low-privilege scan will meet folders it cannot open. File permissions
# cannot reproduce that here, because the test may be running as a user who
# bypasses them, so the enumeration itself is made to fail for one folder.
$blocked = Join-Path $script:root $GUID_B
function Get-ChildItem {
    # No [Parameter()] attribute and no ErrorAction here. Either one turns
    # this into an advanced function, which then declares the common
    # parameters itself and collides with the ErrorAction the caller passes.
    param($Path, $LiteralPath, [switch] $Directory, [switch] $File, [switch] $Recurse, $Filter)
    if ($LiteralPath -eq $blocked) { throw [System.UnauthorizedAccessException]::new("Access to the path '$blocked' is denied.") }
    $forward = @{ LiteralPath = $LiteralPath }
    if ($Directory) { $forward['Directory'] = $true }
    if ($File)      { $forward['File']      = $true }
    if ($Recurse)   { $forward['Recurse']   = $true }
    Microsoft.PowerShell.Management\Get-ChildItem @forward
}

$result = Run
$r = Findings $result
$partial = Partials $result
A (@($r).Count -eq 1)                                 'what could be read is still reported'
A ($r.evidence.storedPasswordCount -eq 1)             'including the password in the readable policy'
A (@($partial).Count -eq 1)                           'and the unreadable folder is reported as a partial result'
A ($partial[0].checkId -ceq 'AD.POLICY.RISKY_GPO')    'the marker carries the check id'
A ($partial[0].reason -match 'Workstation Hardening') 'the reason names the policy that was skipped'
A ($partial[0].reason -match 'read access')           'and says what would fix it'
A ($r.evidence.policiesExamined -eq 1)                'the evidence counts what was examined'
A ($r.evidence.policiesTotal -eq 2)                   'separately from what was there'

Remove-Item Function:\Get-ChildItem -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
"`nA store that cannot be reached at all"
$threw = $false
$message = $null
try { Test-RiskyGroupPolicy -DomainName 'auditlab.test' -SysvolPath (Join-Path ([System.IO.Path]::GetTempPath()) 'definitely-not-there') -DomainSid $SID | Out-Null }
catch { $threw = $true; $message = $_.Exception.Message }
A $threw                                              'fails rather than reporting a clean domain'
A ($message -match 'SYSVOL')                          'and says what it could not reach'

# ---------------------------------------------------------------------------
"`nThe domain SID is looked up when it is not supplied"
New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_A -Body "[Privilege Rights]`nSeDebugPrivilege = *$SID-513"
$r = Findings (Test-RiskyGroupPolicy -DomainName 'auditlab.test' -SysvolPath $script:root)
A (@($r).Count -eq 1)                                 'Domain Users is still recognised'
A ($r.affectedObjects[0].attributes.detail -match 'Domain Users') 'using the SID from Get-ADDomain'

# ---------------------------------------------------------------------------
"`nJSON round trip"
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
$back = (Findings (Run)) | ConvertTo-Json -Depth 10 | ConvertFrom-Json
A ($back.affectedObjects[0].attributes.issue -eq 'Stored password') 'survives ConvertTo-Json'
A ($back.evidence.limitation -match 'unlinked')       'the scope limitation is recorded'

if ($script:root -and (Test-Path -LiteralPath $script:root)) {
    Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue
}

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
