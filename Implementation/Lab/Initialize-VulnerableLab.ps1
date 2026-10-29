<#
.SYNOPSIS
    Seeds the AD lab with known-bad configurations and records what it did.

.DESCRIPTION
    Run this on the lab domain controller to create the misconfigurations the
    auditing module is meant to detect. It also writes ground-truth.json, a
    list of exactly what was seeded.

    That file is the point. Detection accuracy in the project proposal is
    measured by comparing the tool's findings against known ground truth, and
    ground truth recorded by the script that created it is trustworthy in a
    way that a list written from memory three weeks later is not.

    Seeding by script rather than by hand also means the lab can be rebuilt
    after a bad experiment, and the seeding itself is reproducible evidence
    for the report.

.PARAMETER StaleAccountCount
    How many never-signed-in accounts to create.

.PARAMETER GroundTruthPath
    Where to write the record of what was seeded.

.PARAMETER AccountPassword
    Optional password for the seeded accounts, as a SecureString. Leave it
    unset and each account gets its own random password that is never
    written down. The seeded accounts exist to be found by the auditing
    module, not to be signed into, so not knowing their passwords costs
    nothing.

    Supply one only if you have a reason to sign in as a seeded account:

        $p = Read-Host -AsSecureString 'Lab account password'
        .\Initialize-VulnerableLab.ps1 -AccountPassword $p

.PARAMETER WhatIf
    Supported throughout. Run it once with -WhatIf before touching the lab.

.EXAMPLE
    .\Initialize-VulnerableLab.ps1 -WhatIf

.EXAMPLE
    .\Initialize-VulnerableLab.ps1 -Verbose

.NOTES
    DELIBERATELY INSECURE. This script weakens a domain on purpose. Run it
    only against an isolated lab, never against anything else. Take a VM
    checkpoint first: lowering the password policy is easy to reverse, but
    rebuilding a domain you broke another way is not.

    No password is hardcoded here, and none is written to ground-truth.json.
    A literal password in source gets committed, then stays in the git
    history after it is edited out, which is why secret scanners flag it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]          $StaleAccountCount = 3,
    [string]       $GroundTruthPath   = './ground-truth.json',
    [securestring] $AccountPassword
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

function New-LabPassword {
    <#
    .SYNOPSIS
        Returns a random password as a SecureString.

    .DESCRIPTION
        Built from a cryptographic RNG rather than Get-Random, which is
        seeded predictably and is not meant for anything security related.

        One character is taken from each class first so the result always
        satisfies AD complexity, even while this script is in the middle of
        turning complexity off. The plain text is assembled in a char array
        and cleared straight after, so it is not left sitting in a string
        that the garbage collector may keep around.
    #>
    [CmdletBinding()]
    [OutputType([securestring])]
    param([int] $Length = 24)

    # Ambiguous characters left out, so anything read off a console is
    # unambiguous if it ever does have to be typed.
    $classes = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!@#$%^&*()-_=+'
    )

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $pick = {
            param([string] $Set)
            $bytes = [byte[]]::new(4)
            $rng.GetBytes($bytes)
            # Mask off the sign bit, then reduce modulo the set size.
            $value = [BitConverter]::ToUInt32($bytes, 0) % $Set.Length
            $Set[$value]
        }

        $chars = [System.Collections.Generic.List[char]]::new()
        foreach ($class in $classes) { $chars.Add((& $pick $class)) }

        $all = -join $classes
        while ($chars.Count -lt $Length) { $chars.Add((& $pick $all)) }

        # Shuffle, so the first four characters are not one per class in order.
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $bytes = [byte[]]::new(4)
            $rng.GetBytes($bytes)
            $j = [BitConverter]::ToUInt32($bytes, 0) % ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }

        $secure = [securestring]::new()
        foreach ($c in $chars) { $secure.AppendChar($c) }
        $secure.MakeReadOnly()

        return $secure
    }
    finally {
        if ($chars) { for ($i = 0; $i -lt $chars.Count; $i++) { $chars[$i] = [char]0 } }
        $rng.Dispose()
    }
}

function Get-SeedPassword {
    # Honour an explicitly supplied password, otherwise a fresh random one
    # per account so that compromising one seeded account tells you nothing
    # about the others.
    if ($AccountPassword) { return $AccountPassword }
    return New-LabPassword
}

$domain = Get-ADDomain -Current LocalComputer
$root   = $domain.DistinguishedName

Write-Warning "This weakens the security of $($domain.DNSRoot). Lab domains only."

# Recorded as the script goes, so the file cannot drift from what happened.
$groundTruth = [ordered]@{
    seededAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    domain     = $domain.DNSRoot
    expected   = [ordered]@{}
}

# ---------------------------------------------------------------------------
# Organizational units
# ---------------------------------------------------------------------------

function New-LabOU {
    param([string] $Name)

    $dn = "OU=$Name,$root"
    if (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) {
        Write-Verbose "OU $Name already exists"
        return $dn
    }
    if ($PSCmdlet.ShouldProcess($dn, 'Create OU')) {
        # Protection off so the lab can be torn down without extra steps.
        New-ADOrganizationalUnit -Name $Name -Path $root -ProtectedFromAccidentalDeletion $false
        Write-Verbose "Created OU $Name"
    }
    return $dn
}

$staffOu    = New-LabOU -Name 'LabStaff'
$serviceOu  = New-LabOU -Name 'LabServiceAccounts'
$groupsOu   = New-LabOU -Name 'LabGroups'

# ---------------------------------------------------------------------------
# 1. Stale accounts
#
# These are created and never signed in, so LastLogonDate stays null. That is
# the "never signed in" case. Simulating "signed in 300 days ago" is harder:
# lastLogonTimestamp is replicated by the DC rather than set by hand, so the
# check is written around never-signed-in plus account age instead.
# ---------------------------------------------------------------------------

$staleCreated = @()

foreach ($i in 1..$StaleAccountCount) {
    $name = "stale_user_$i"
    if (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue) {
        Write-Verbose "$name already exists"
        $staleCreated += $name
        continue
    }
    if ($PSCmdlet.ShouldProcess($name, 'Create never-signed-in account')) {
        New-ADUser -Name $name `
            -SamAccountName $name `
            -UserPrincipalName "$name@$($domain.DNSRoot)" `
            -Path $staffOu `
            -AccountPassword (Get-SeedPassword) `
            -Enabled $true `
            -Description 'Lab: deliberately stale, never signed in'
        Write-Verbose "Created stale account $name"
    }
    $staleCreated += $name
}

$groundTruth.expected['AD.ACCOUNT.STALE_ENABLED'] = [ordered]@{
    shouldDetect = $true
    objects      = $staleCreated
    note         = 'Enabled, never signed in, so LastLogonDate is null.'
}

# ---------------------------------------------------------------------------
# 2. Weak password policy
#
# Capture the current values first so the change can be undone.
# ---------------------------------------------------------------------------

$before = Get-ADDefaultDomainPasswordPolicy

$groundTruth['originalPasswordPolicy'] = [ordered]@{
    minPasswordLength    = $before.MinPasswordLength
    complexityEnabled    = [bool] $before.ComplexityEnabled
    lockoutThreshold     = $before.LockoutThreshold
    passwordHistoryCount = $before.PasswordHistoryCount
}

if ($PSCmdlet.ShouldProcess($domain.DNSRoot, 'Weaken the default domain password policy')) {
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
        -MinPasswordLength 6 `
        -ComplexityEnabled $false `
        -LockoutThreshold 0 `
        -PasswordHistoryCount 3
    Write-Verbose 'Weakened the default domain password policy'
}

$groundTruth.expected['AD.POLICY.WEAK_PASSWORD'] = [ordered]@{
    shouldDetect   = $true
    objects        = @('Default Domain Policy')
    failedControls = @('minPasswordLength', 'complexityEnabled', 'lockoutThreshold')
}

# ---------------------------------------------------------------------------
# 3. Excessive privileged membership
#
# Two shapes on purpose: one ordinary user added directly, and one group
# nested two levels deep. The nested case is the one a naive check misses,
# and it is the case worth demonstrating.
# ---------------------------------------------------------------------------

$directUser = 'lab_overprivileged'
if (-not (Get-ADUser -Filter "SamAccountName -eq '$directUser'" -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($directUser, 'Create ordinary user for direct Domain Admins membership')) {
        New-ADUser -Name $directUser `
            -SamAccountName $directUser `
            -UserPrincipalName "$directUser@$($domain.DNSRoot)" `
            -Path $staffOu `
            -AccountPassword (Get-SeedPassword) `
            -Enabled $true `
            -Description 'Lab: ordinary user deliberately placed in Domain Admins'
    }
}

# Resolve Domain Admins by SID rather than by name. The name is localized,
# the RID is not, and portability is an evaluation criterion.
$domainAdminsSid = '{0}-512' -f $domain.DomainSID.Value
$domainAdmins    = Get-ADGroup -Identity $domainAdminsSid

if ($PSCmdlet.ShouldProcess($directUser, "Add to $($domainAdmins.Name)")) {
    Add-ADGroupMember -Identity $domainAdmins -Members $directUser -ErrorAction SilentlyContinue
}

# Nested chain: Domain Admins <- LabITSupport <- LabHelpdeskL1 <- members
foreach ($groupName in @('LabITSupport', 'LabHelpdeskL1')) {
    if (-not (Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($groupName, 'Create group')) {
            New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $groupsOu
        }
    }
}

$helpdeskMembers = @()
foreach ($i in 1..4) {
    $name = "lab_helpdesk_$i"
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$name'" -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($name, 'Create help desk user')) {
            New-ADUser -Name $name `
                -SamAccountName $name `
                -UserPrincipalName "$name@$($domain.DNSRoot)" `
                -Path $staffOu `
                -AccountPassword (Get-SeedPassword) `
                -Enabled $true `
                -Description 'Lab: inherits Domain Admins through nested groups'
        }
    }
    $helpdeskMembers += $name
}

if ($PSCmdlet.ShouldProcess('LabHelpdeskL1', 'Add members and nest under LabITSupport, then Domain Admins')) {
    Add-ADGroupMember -Identity 'LabHelpdeskL1' -Members $helpdeskMembers -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity 'LabITSupport'  -Members 'LabHelpdeskL1'  -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity $domainAdmins   -Members 'LabITSupport'   -ErrorAction SilentlyContinue
}

$groundTruth.expected['AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP'] = [ordered]@{
    shouldDetect = $true
    objects      = @($directUser) + $helpdeskMembers
    note         = 'One direct member, plus 4 users inheriting through Domain Admins <- LabITSupport <- LabHelpdeskL1.'
}

# ---------------------------------------------------------------------------
# 4. Kerberoastable service accounts
#
# Three shapes, because the check grades them differently and a lab that only
# seeds the worst case never proves the grading works.
#
#   lab_svc_sql     service principal name, encryption types left unset, so
#                   the key distribution centre still offers RC4
#   lab_svc_web     two service principal names, AES only, which is the
#                   configuration the remediation advice asks for
#   lab_svc_backup  service principal name and Domain Admins membership, the
#                   case where one cracked password is the whole domain
#
# One thing this cannot seed is an old password. PasswordLastSet is
# maintained by the directory and cannot be written, so the stale-password
# path is covered by the unit tests rather than here. The same limit applies
# to lastLogonTimestamp in section 1, and for the same reason.
# ---------------------------------------------------------------------------

function New-LabServiceAccount {
    param(
        [string]   $Name,
        [string[]] $Spns,
        [AllowNull()] $EncryptionTypes,
        [string]   $Description
    )

    if (Get-ADUser -Filter "SamAccountName -eq '$Name'" -ErrorAction SilentlyContinue) {
        Write-Verbose "$Name already exists"
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Create service account with a service principal name')) {
        return
    }

    $arguments = @{
        Name                  = $Name
        SamAccountName        = $Name
        UserPrincipalName     = "$Name@$($domain.DNSRoot)"
        Path                  = $serviceOu
        AccountPassword       = (Get-SeedPassword)
        Enabled               = $true
        PasswordNeverExpires  = $true
        ServicePrincipalNames = $Spns
        Description           = $Description
    }
    # Left unset on purpose for the RC4 case. An absent attribute is not the
    # same as a zero, and the check has to treat both as RC4 permitted, so
    # the lab seeds the absent case rather than writing a zero.
    if ($null -ne $EncryptionTypes) {
        $arguments['OtherAttributes'] = @{ 'msDS-SupportedEncryptionTypes' = $EncryptionTypes }
    }

    New-ADUser @arguments
    Write-Verbose "Created service account $Name"
}

New-LabServiceAccount -Name 'lab_svc_sql' `
    -Spns @("MSSQLSvc/db01.$($domain.DNSRoot):1433") `
    -EncryptionTypes $null `
    -Description 'Lab: kerberoastable, encryption types unset so RC4 is offered'

# 24 is AES128 plus AES256 with no RC4 bit, which is what hardening this
# attribute actually looks like.
New-LabServiceAccount -Name 'lab_svc_web' `
    -Spns @("HTTP/web01.$($domain.DNSRoot)", "HTTP/intranet.$($domain.DNSRoot)") `
    -EncryptionTypes 24 `
    -Description 'Lab: kerberoastable but AES only, the lower-severity case'

New-LabServiceAccount -Name 'lab_svc_backup' `
    -Spns @("BackupSvc/backup01.$($domain.DNSRoot)") `
    -EncryptionTypes $null `
    -Description 'Lab: kerberoastable and privileged, the worst case'

if ($PSCmdlet.ShouldProcess('lab_svc_backup', "Add to $($domainAdmins.Name)")) {
    Add-ADGroupMember -Identity $domainAdmins -Members 'lab_svc_backup' -ErrorAction SilentlyContinue

    # adminCount is normally set by the SDProp task on the domain controller,
    # which runs every 60 minutes by default. A scan run straight after
    # seeding would therefore see the account as unprivileged and grade the
    # finding High instead of Critical, through no fault of the check. Setting
    # it here does by hand what the directory would do within the hour, so the
    # lab is consistent the moment the script finishes.
    Set-ADUser -Identity 'lab_svc_backup' -Replace @{ adminCount = 1 } -ErrorAction SilentlyContinue
}

# Seeded after section 3, so the privileged membership expectation has to be
# extended rather than replaced. This account is genuinely expected by both
# checks, and ground truth that mentioned only one of them would score the
# other as a false positive.
$groundTruth.expected['AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP'].objects =
    @($groundTruth.expected['AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP'].objects) + 'lab_svc_backup'
$groundTruth.expected['AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP'].note +=
    ' lab_svc_backup is also a direct member, seeded in section 4.'

$groundTruth.expected['AD.PRIVILEGE.KERBEROASTING'] = [ordered]@{
    shouldDetect     = $true
    objects          = @('lab_svc_sql', 'lab_svc_web', 'lab_svc_backup')
    expectedSeverity = 'Critical'
    note             = 'Three user accounts with service principal names. lab_svc_sql and lab_svc_backup leave msDS-SupportedEncryptionTypes unset so RC4 is permitted; lab_svc_web is AES only. lab_svc_backup is privileged, which is what raises the finding to Critical. krbtgt also holds an SPN and must not be reported.'
    mustNotDetect    = @('krbtgt')
    notSeeded        = 'An old password, because PasswordLastSet is maintained by the directory and cannot be written.'
}

# ---------------------------------------------------------------------------

if ($PSCmdlet.ShouldProcess($GroundTruthPath, 'Write ground truth')) {
    $groundTruth | ConvertTo-Json -Depth 10 | Set-Content -Path $GroundTruthPath -Encoding UTF8
    Write-Host "Ground truth written to $GroundTruthPath"
}

Write-Host ''
Write-Host 'Lab seeded. Verify before relying on it:'
Write-Host '  Get-ADDefaultDomainPasswordPolicy'
Write-Host '  Get-ADGroupMember -Identity ''Domain Admins'' -Recursive | Select-Object name'
Write-Host '  Get-ADUser -Filter "Enabled -eq $true" -Properties LastLogonDate | Where-Object { -not $_.LastLogonDate }'