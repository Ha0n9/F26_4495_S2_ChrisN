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

<#
    Two values with the shape of real Group Policy Preferences ciphertext:
    Base64, padding stripped as GPP writes it, decoding to a whole number of
    16 byte AES blocks. Neither is a working credential for anything; what
    matters to the check is the format, which it never decrypts.
#>
$CIPHER_A   = 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
$CIPHER_B   = 'RI133B2Wl2CiI0Cau1DtrtTe3wdFwzCiWB5PSAxXMDstchJt3bL0Uie0BaZ/7rdQjugTonF3ZWAKa1iRvd4JGQ'
$GUID_A     = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
$GUID_B     = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
$GUID_C     = '{0F4A1B2C-3D4E-5F60-7182-93A4B5C6D7E8}'

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
    param([Parameter(Mandatory)] [string] $Guid, [AllowEmptyString()] [string] $CPassword = 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ')
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

$script:gpoNames = @{ $GUID_A = 'Default Domain Policy'; $GUID_B = 'Workstation Hardening'; $GUID_C = 'Legacy Drive Mappings' }

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
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Services/Services.xml' -Content @"
<?xml version="1.0" encoding="utf-8"?>
<NTServices>
  <NTService><Properties cpassword="$CIPHER_A" accountName="svc_a"/></NTService>
  <NTService><Properties cpassword="$CIPHER_B" accountName="svc_b"/></NTService>
</NTServices>
"@ | Out-Null
$r = Findings (Run)
A ($r.evidence.storedPasswordCount -eq 2)             'every password in one file is reported, not just the first'
A ($r.affectedObjectCount -eq 2)                      'one affected object each'

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
$script:gpoNames = @{ $GUID_A = 'Default Domain Policy'; $GUID_B = 'Workstation Hardening'; $GUID_C = 'Legacy Drive Mappings' }

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

# ===========================================================================
# Regression cases for the defects found in the first implementation.
# Each block names the defect it guards against.
# ===========================================================================

# Access failures cannot be reproduced with file permissions here, because
# the tests may run as a user who bypasses them. The two enumeration cmdlets
# are shadowed instead, and consult these lists. Both stay empty unless a
# case fills them, so the stubs are transparent the rest of the time.
$script:blockedFolders = @()
$script:blockedFiles   = @()

function Get-ChildItem {
    # No [Parameter()] attribute and no ErrorAction: either one makes this an
    # advanced function, which then declares the common parameters itself and
    # collides with the ErrorAction the caller passes.
    param($Path, $LiteralPath, [switch] $Directory, [switch] $File, [switch] $Recurse, $Filter)
    $leaf = if ($LiteralPath) { Split-Path $LiteralPath -Leaf } else { '' }
    if ($script:blockedFolders -contains $leaf) {
        throw [System.UnauthorizedAccessException]::new("Access to the path '$LiteralPath' is denied.")
    }
    $forward = @{ LiteralPath = $LiteralPath }
    if ($Directory) { $forward['Directory'] = $true }
    if ($File)      { $forward['File']      = $true }
    if ($Recurse)   { $forward['Recurse']   = $true }
    Microsoft.PowerShell.Management\Get-ChildItem @forward
}

function Get-Content {
    param($Path, $LiteralPath, [switch] $Raw, $Encoding)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($script:blockedFiles -contains (Split-Path $target -Leaf)) {
        throw [System.UnauthorizedAccessException]::new("Access to the path '$target' is denied.")
    }
    Microsoft.PowerShell.Management\Get-Content -LiteralPath $target -Raw:$Raw
}

function Reset-Blocks { $script:blockedFolders = @(); $script:blockedFiles = @() }

# ---------------------------------------------------------------------------
"`nDefect 1: the ADMX Central Store was treated as a group policy object"
Reset-Blocks
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
# The Central Store holds thousands of ADMX and ADML files. It is not a
# policy object, it has no GUID name, and the first implementation walked
# every file in it and counted it as a GPO.
Add-PolicyFile -Guid 'PolicyDefinitions' -RelativePath 'inetres.admx' -Content '<policyDefinitions revision="1.0"/>' | Out-Null
Add-PolicyFile -Guid 'PolicyDefinitions' -RelativePath 'en-US/inetres.adml' -Content '<policyDefinitionResources/>' | Out-Null
$r = Findings (Run)
A ($r.evidence.policiesTotal -eq 1)                   'the Central Store is not counted as a policy'
A ($r.evidence.policiesExamined -eq 1)                'nor as one that was examined'
A ($r.evidence.nonPolicyDirectoriesSkipped -contains 'PolicyDefinitions') 'it is named as skipped, rather than passed over silently'
A ($r.affectedObjectCount -eq 1)                      'the real finding is unaffected'
A (@(Partials (Run)).Count -eq 0)                     'and it produces no partial result'

New-PolicyStore | Out-Null
# An ADMX file that happens to contain the text, and a malformed one. The
# first implementation read both, because it recursed into this directory.
Add-PolicyFile -Guid 'PolicyDefinitions' -RelativePath 'bogus.xml' -Content "<a cpassword='$CIPHER_A'/>" | Out-Null
Add-PolicyFile -Guid 'PolicyDefinitions' -RelativePath 'broken.xml' -Content '<a unclosed=' | Out-Null
$result = Run
A ($null -eq $result)                                 'nothing inside the Central Store is read at all'

New-PolicyStore | Out-Null
Add-PolicyFile -Guid '31B2F340-016D-11D2-945F-00C04FB984F9' -RelativePath 'Machine/Preferences/Groups/Groups.xml' -Content "<Groups><User><Properties cpassword='$CIPHER_A'/></User></Groups>" | Out-Null
A ($null -eq (Run))                                   'a GUID without braces is not a policy folder name'

New-PolicyStore | Out-Null
# Lower case is as valid as upper case in a GUID folder name, and a pattern
# that only accepted one would quietly skip real policies.
Add-GroupsXml -Guid '{aabbccdd-1122-3344-5566-778899aabbcc}'
$r = Findings (Run)
A ($r.evidence.policiesTotal -eq 1)                   'a lower case GUID folder is a policy'
A ($r.affectedObjectCount -eq 1)                      'and is examined'

# ---------------------------------------------------------------------------
"`nDefect 2: unreadable folders and unreadable files shared one counter"
Reset-Blocks
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-GptTmpl  -Guid $GUID_B -Body "[System Access]`nEnableGuestAccount = 0"
$r = Findings (Run)
A ($r.evidence.policiesTotal -eq 2)                   'all readable: both policies counted'
A ($r.evidence.policiesExamined -eq 2)                'both examined'
A ($r.evidence.policiesFullyExamined -eq 2)           'both fully'
A ($r.evidence.policiesPartiallyExamined -eq 0)       'none partially'
A ($r.evidence.policiesNotExamined -eq 0)             'none missed'
A (@(Partials (Run)).Count -eq 0)                     'and no partial result'

# One inaccessible folder.
Reset-Blocks
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-GptTmpl  -Guid $GUID_B -Body "[System Access]`nEnableGuestAccount = 1"
$script:blockedFolders = @($GUID_B)
$result = Run
$r = Findings $result
$partial = Partials $result
A ($r.evidence.policiesTotal -eq 2)                   'one blocked folder: both still counted'
A ($r.evidence.policiesExamined -eq 1)                'one examined'
A ($r.evidence.policiesNotExamined -eq 1)             'one not examined'
A ($r.affectedObjectCount -eq 1)                      'what was readable is still reported'
A (@($partial).Count -eq 1)                           'one partial result'
A ($partial[0].reason -match 'could not be opened')   'worded as a folder nobody could open'

# One inaccessible file inside an otherwise readable policy. The policy is
# still examined; the first implementation subtracted it as if it were not.
Reset-Blocks
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Drives/Drives.xml' -Content '<Drives/>' | Out-Null
$script:blockedFiles = @('Drives.xml')
$result = Run
$r = Findings $result
$partial = Partials $result
A ($r.evidence.policiesExamined -eq 1)                'the policy still counts as examined'
A ($r.evidence.policiesFullyExamined -eq 0)           'but not as fully examined'
A ($r.evidence.policiesPartiallyExamined -eq 1)       'it is counted as partially examined'
A ($r.evidence.policiesNotExamined -eq 0)             'and not as missed'
A ($r.evidence.unreadableFileCount -eq 1)             'the file is counted as a file'
A ($r.affectedObjectCount -eq 1)                      'the password in the readable file is still found'
A (@($partial).Count -eq 1)                           'one partial result'
A ($partial[0].reason -match 'individual file')       'worded as a file, not a policy'
A ($partial[0].reason -match 'The rest of each policy was examined') 'and says the rest was covered'

# Several inaccessible files in the same policy. One policy, not three.
Reset-Blocks
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
foreach ($name in 'a.xml', 'b.xml', 'c.xml') {
    Add-PolicyFile -Guid $GUID_A -RelativePath "Machine/Preferences/Extra/$name" -Content '<x/>' | Out-Null
}
$script:blockedFiles = @('a.xml', 'b.xml', 'c.xml')
$r = Findings (Run)
A ($r.evidence.policiesExamined -eq 1)                'still one policy examined'
A ($r.evidence.policiesPartiallyExamined -eq 1)       'counted once, not once per file'
A ($r.evidence.unreadableFileCount -eq 3)             'while the files are counted individually'
A ($r.evidence.policiesExamined -ge 0)                'the count cannot go negative, which it did before'

# Several inaccessible folders.
Reset-Blocks
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-GptTmpl  -Guid $GUID_B -Body "[Privilege Rights]`nSeDebugPrivilege = *S-1-5-11"
Add-GroupsXml -Guid $GUID_C
$script:blockedFolders = @($GUID_B, $GUID_C)
$result = Run
$r = Findings $result
A ($r.evidence.policiesTotal -eq 3)                   'three policies present'
A ($r.evidence.policiesExamined -eq 1)                'one examined'
A ($r.evidence.policiesNotExamined -eq 2)             'two not examined'
A ((Partials $result)[0].reason -match '2 of 3')      'the partial result says how many of how many'

# A mixture: one blocked folder, one blocked file elsewhere.
Reset-Blocks
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Drives/Drives.xml' -Content '<Drives/>' | Out-Null
Add-GptTmpl  -Guid $GUID_B -Body "[System Access]`nEnableGuestAccount = 1"
$script:blockedFolders = @($GUID_B)
$script:blockedFiles   = @('Drives.xml')
$result = Run
$r = Findings $result
$partial = Partials $result
A ($r.evidence.policiesTotal -eq 2)                   'both counted'
A ($r.evidence.policiesExamined -eq 1)                'one examined'
A ($r.evidence.policiesPartiallyExamined -eq 1)       'that one only partially'
A ($r.evidence.policiesFullyExamined -eq 0)           'so none fully'
A ($r.evidence.policiesNotExamined -eq 1)             'and one not at all'
A (@($partial).Count -eq 2)                           'two partial results, one per kind'
A ((($partial.reason) -join ' ') -match 'could not be opened') 'the folder is described as unopened'
A ((($partial.reason) -join ' ') -match 'individual file')     'and the file as a file'

Reset-Blocks

# ---------------------------------------------------------------------------
"`nDefect 3: any non-empty cpassword was claimed to be decryptable"
New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A -CPassword $CIPHER_A
$r = Findings (Run)
A ($r.severity -eq 'Critical')                        'a value shaped like real ciphertext is Critical'
A ($r.affectedObjects[0].attributes.issue -eq 'Stored password') 'and is called a stored password'
A ($r.affectedObjects[0].attributes.detail -match 'published by Microsoft') 'with the claim that it can be decrypted'
A ($r.evidence.storedPasswordCount -eq 1)             'counted as a stored password'
A ($r.evidence.unverifiedCpasswordCount -eq 0)        'and not as an unverified one'

foreach ($case in @(
    @{ Value = 'LAB-PLACEHOLDER-NOT-REAL-CIPHERTEXT'; Label = 'a placeholder with characters Base64 does not use' }
    @{ Value = 'not base64 at all!';                  Label = 'a value with spaces and punctuation' }
    @{ Value = 'AAAA';                                Label = 'valid Base64 that is only 3 bytes, not a whole AES block' }
    @{ Value = 'AAAAAAAAAAAAAAAAAAAAA';               Label = 'valid Base64 of 15 bytes, one short of a block' }
)) {
    New-PolicyStore | Out-Null
    Add-GroupsXml -Guid $GUID_A -CPassword $case.Value
    $r = Findings (Run)
    A ($r.severity -eq 'High')                        "$($case.Label): High, not Critical"
    A ($r.affectedObjects[0].attributes.issue -eq 'Stored password (format not recognised)') "$($case.Label): named as unrecognised"
    A ($r.affectedObjects[0].attributes.detail -match 'cannot say it is a recoverable password') "$($case.Label): the claim is withdrawn"
    A ($r.evidence.unverifiedCpasswordCount -eq 1)    "$($case.Label): counted separately"
    A ($r.evidence.storedPasswordCount -eq 0)         "$($case.Label): not counted as a confirmed password"
}

New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A -CPassword ''
A ($null -eq (Run))                                   'an empty value is still not a finding'

New-PolicyStore | Out-Null
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Groups/Groups.xml' -Content "<Groups><User><Properties cpassword='$CIPHER_A'/></User><User><Properties cpassword='AAAA'/></User></Groups>" | Out-Null
$r = Findings (Run)
A ($r.evidence.storedPasswordCount -eq 1)             'a file with one of each is counted as one of each'
A ($r.evidence.unverifiedCpasswordCount -eq 1)        'both kinds reported'
A ($r.severity -eq 'Critical')                        'and the confirmed one sets the severity'

New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A -CPassword $CIPHER_A
$r = Findings (Run)
A ($r.affectedObjects[0].attributes.valueLength -eq $CIPHER_A.Length) 'the length of the value is recorded'
$serialised = $r | ConvertTo-Json -Depth 10
A ($serialised -notmatch [regex]::Escape($CIPHER_A))  'but the encrypted value never appears in the finding'
A ($serialised -notmatch 'Local\*8')                  'and no decrypted password appears either, because nothing is decrypted'

New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A -CPassword 'LAB-PLACEHOLDER-NOT-REAL-CIPHERTEXT'
A (((Findings (Run)) | ConvertTo-Json -Depth 10) -notmatch 'LAB-PLACEHOLDER') 'an unrecognised value is not quoted back either'

# ---------------------------------------------------------------------------
"`nDefect 4: XML was matched with a regular expression"
New-PolicyStore | Out-Null
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Groups/Groups.xml' -Content "<Groups><User><Properties cpassword='$CIPHER_A'/></User></Groups>" | Out-Null
$r = Findings (Run)
A (@($r).Count -eq 1)                                 'a single-quoted attribute is found'
A ($r.severity -eq 'Critical')                        'and judged the same as a double-quoted one'

New-PolicyStore | Out-Null
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Groups/Groups.xml' -Content @"
<?xml version="1.0" encoding="utf-8"?>
<Groups>
  <User name="a"><Properties action="U"    cpassword = "$CIPHER_A"   changeLogon="0"/></User>
  <User name="b"><Properties action='U' cpassword='$CIPHER_B' changeLogon='0'/></User>
</Groups>
"@ | Out-Null
$r = Findings (Run)
A ($r.evidence.storedPasswordCount -eq 2)             'whitespace, mixed quoting and other attributes are all handled'

New-PolicyStore | Out-Null
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Tasks/ScheduledTasks.xml' -Content @"
<ScheduledTasks>
  <Task><Properties runAs="svc_a" cpassword="$CIPHER_A"/></Task>
  <ImmediateTask><Properties runAs="svc_b" cpassword="$CIPHER_B"/></ImmediateTask>
</ScheduledTasks>
"@ | Out-Null
A ((Findings (Run)).evidence.storedPasswordCount -eq 2) 'several different elements in one file are all inspected'

New-PolicyStore | Out-Null
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Groups/Groups.xml' -Content '<Groups><User><Properties cpassword=' | Out-Null
$result = Run
A ($null -eq (Findings $result))                      'malformed XML yields no finding'
A (@(Partials $result).Count -eq 1)                   'but it is reported as unexamined'
A ((Partials $result)[0].reason -match 'could not be parsed') 'worded as a parse failure'
A ((Partials $result)[0].reason -match 'not evidence that it holds nothing') 'and says why that matters'

New-PolicyStore | Out-Null
Add-GroupsXml -Guid $GUID_A
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Drives/Drives.xml' -Content '<Drives><Drive><Properties cpassword=' | Out-Null
$result = Run
$r = Findings $result
A ($r.evidence.storedPasswordCount -eq 1)             'a readable file beside a malformed one is still inspected'
A ($r.evidence.unparsableFileCount -eq 1)             'and the malformed one is counted'
A ($r.evidence.policiesPartiallyExamined -eq 1)       'the policy counts as partially examined'

New-PolicyStore | Out-Null
# Only .xml files are parsed as XML. A text file mentioning the attribute is
# not a Group Policy Preferences file.
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/notes.txt' -Content "remember to remove cpassword=`"$CIPHER_A`" from Groups.xml" | Out-Null
A ($null -eq (Run))                                   'a non-XML file is not parsed and not reported'

New-PolicyStore | Out-Null
# An untrusted file from a share must not be able to make the parser fetch
# anything. The resolver is disabled, so the entity simply does not resolve.
Add-PolicyFile -Guid $GUID_A -RelativePath 'Machine/Preferences/Groups/Groups.xml' -Content @'
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:9/pwn">]>
<Groups><User><Properties cpassword="&xxe;"/></User></Groups>
'@ | Out-Null
$threw = $false
try { $result = Run } catch { $threw = $true }
A (-not $threw)                                       'an external entity does not crash the check'
A ((@(Findings $result).Count + @(Partials $result).Count) -ge 1) 'and the file is accounted for one way or the other'

# ---------------------------------------------------------------------------
"`nDefect 5: guest groups were described as every account in the domain"
foreach ($case in @(
    @{ Sid = 'S-1-5-11';          Name = 'Authenticated Users'; Scope = 'everyone'; Match = 'every account in the domain' }
    @{ Sid = "$SID-513";          Name = 'Domain Users';        Scope = 'everyone'; Match = 'every account in the domain' }
    @{ Sid = 'S-1-5-32-545';      Name = 'Users \(built-in\)';  Scope = 'everyone'; Match = 'Domain Users is a member of it' }
    @{ Sid = 'S-1-1-0';           Name = 'Everyone';            Scope = 'everyone'; Match = 'every account in the domain' }
    @{ Sid = 'S-1-5-7';           Name = 'Anonymous Logon';     Scope = 'guest';    Match = 'unauthenticated access, with no account at all' }
    @{ Sid = 'S-1-5-32-546';      Name = 'Guests \(built-in\)'; Scope = 'guest';    Match = 'guest access' }
    @{ Sid = "$SID-514";          Name = 'Domain Guests';       Scope = 'guest';    Match = 'guest access' }
)) {
    New-PolicyStore | Out-Null
    Add-GptTmpl -Guid $GUID_A -Body "[Privilege Rights]`nSeDebugPrivilege = *$($case.Sid)"
    $r = Findings (Run)
    $detail = $r.affectedObjects[0].attributes.detail
    A (@($r).Count -eq 1)                             "$($case.Name -replace '\\','') is still detected"
    A ($detail -match $case.Name)                     "$($case.Name -replace '\\','') is named"
    A ($detail -match $case.Match)                    "$($case.Name -replace '\\','') is described accurately"
    A ($r.affectedObjects[0].attributes.principalScope -eq $case.Scope) "$($case.Name -replace '\\','') is classified as $($case.Scope)"
    if ($case.Scope -eq 'guest') {
        # The defect: a guest group is not everybody, and saying so made the
        # finding overstate its own scope.
        A ($detail -notmatch 'every account in the domain') "$($case.Name -replace '\\','') is not called every account in the domain"
    }
}

New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_A -Body "[Privilege Rights]`nSeDebugPrivilege = *$SID-512"
A ($null -eq (Run))                                   'Domain Admins is still not treated as broad'

New-PolicyStore | Out-Null
Add-GptTmpl -Guid $GUID_A -Body "[Privilege Rights]`nSeDebugPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20"
A ($null -eq (Run))                                   'nor are Administrators and the service accounts'

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
