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
    [securestring] $AccountPassword,

    # Off by default. A group managed service account needs a KDS root key,
    # which is forest-wide configuration, and this script will not create
    # that on your behalf. See section 5 for what to run first.
    [switch]       $IncludeManagedServiceAccount
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
# 5. Unconstrained delegation
#
# Three shapes, for the same reason as section 4: a lab that only seeds the
# obvious case never proves the check tells the cases apart.
#
#   LAB-APP01       a computer account trusted for unconstrained delegation,
#                   which is where this is normally found
#   lab_svc_portal  a user account with the same flag, which is rarer, less
#                   expected, and just as dangerous
#   lab_gmsa_app    a group managed service account with the same flag, which
#                   the check used to miss entirely. Opt-in: creating one
#                   needs a KDS root key, which is forest-wide configuration
#                   this script will not create for you. Pass
#                   -IncludeManagedServiceAccount once that key exists.
#
# DC01 already carries this flag, because every writable domain controller
# does. It is not seeded here and it must not be reported: that exclusion is
# the main thing this section exists to test against a real directory.
# ---------------------------------------------------------------------------

# Recorded as each account is actually flagged, so ground truth describes
# what happened rather than what the script intended. A run where an account
# could not be created, or where -Confirm was declined, must not leave a
# ground truth file claiming otherwise.
$delegationSeeded = [System.Collections.Generic.List[string]]::new()

function Enable-LabUnconstrainedDelegation {
    param(
        [Parameter(Mandatory)] [string] $SamAccountName,
        [Parameter(Mandatory)] [string] $Name
    )

    # Called unconditionally, so that -WhatIf prints this step too. An
    # earlier version only reached it when the account had just been created,
    # which meant a preview run showed the account being made and never
    # showed it being given the flag.
    if (-not $PSCmdlet.ShouldProcess($Name, 'Trust for unconstrained delegation')) { return }

    # Re-read rather than trusting an object captured earlier. Nothing exists
    # after a declined creation, and Set-ADAccountControl with -ErrorAction
    # Stop would then end the whole script here, after sections 1 to 4 have
    # already changed the domain.
    $account = Get-ADObject -LDAPFilter "(sAMAccountName=$SamAccountName)" -ErrorAction SilentlyContinue
    if (-not $account) {
        Write-Warning "$Name does not exist, so unconstrained delegation was not set on it."
        return
    }

    Set-ADAccountControl -Identity $account.DistinguishedName -TrustedForDelegation $true -ErrorAction Stop
    $delegationSeeded.Add($SamAccountName)
    Write-Verbose "Enabled unconstrained delegation on $Name"
}

$delegationComputer    = 'LAB-APP01'
$delegationComputerSam = "$delegationComputer`$"

if (-not (Get-ADComputer -Filter "Name -eq '$delegationComputer'" -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($delegationComputer, 'Create computer account')) {
        # A computer account created this way has no machine behind it, which
        # is all this check needs: it reads the flag in the directory, not
        # anything on the host.
        New-ADComputer -Name $delegationComputer `
            -SamAccountName $delegationComputerSam `
            -Path $serviceOu `
            -Enabled $true `
            -OperatingSystem 'Windows Server 2022 Standard' `
            -Description 'Lab: trusted for unconstrained delegation'
    }
}
else {
    Write-Verbose "$delegationComputer already exists"
}
Enable-LabUnconstrainedDelegation -SamAccountName $delegationComputerSam -Name $delegationComputer

$delegationUser = 'lab_svc_portal'
if (-not (Get-ADUser -Filter "SamAccountName -eq '$delegationUser'" -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($delegationUser, 'Create user account for unconstrained delegation')) {
        New-ADUser -Name $delegationUser `
            -SamAccountName $delegationUser `
            -UserPrincipalName "$delegationUser@$($domain.DNSRoot)" `
            -Path $serviceOu `
            -AccountPassword (Get-SeedPassword) `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -ServicePrincipalNames @("HTTP/portal.$($domain.DNSRoot)") `
            -Description 'Lab: user account trusted for unconstrained delegation'
    }
}
Enable-LabUnconstrainedDelegation -SamAccountName $delegationUser -Name $delegationUser

# The managed service account, which is the shape the check used to miss
# entirely. Opt-in, because creating one needs a KDS root key and that is
# forest-wide configuration this script will not create for you.
$delegationGmsa    = 'lab_gmsa_app'
$delegationGmsaSam = "$delegationGmsa`$"
$gmsaAttempted     = $false

if ($IncludeManagedServiceAccount) {
    $kdsKey = $null
    try { $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { $kdsKey = $null }

    if (-not $kdsKey) {
        Write-Warning @'
-IncludeManagedServiceAccount was requested, but this forest has no KDS root
key, so a group managed service account cannot be created.

Creating one is forest-wide configuration and this script will not do it for
you. Run this once on the domain controller as an enterprise administrator:

    Add-KdsRootKey -EffectiveImmediately

The key is only usable ten hours later, which is how long domain controllers
are given to replicate it. In an isolated single-controller lab you may
backdate it instead, which is safe there and nowhere else:

    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

Then run this script again with -IncludeManagedServiceAccount.
'@
    }
    else {
        $gmsaAttempted = $true
        if (-not (Get-ADServiceAccount -Filter "Name -eq '$delegationGmsa'" -ErrorAction SilentlyContinue)) {
            if ($PSCmdlet.ShouldProcess($delegationGmsa, 'Create group managed service account')) {
                New-ADServiceAccount -Name $delegationGmsa `
                    -DNSHostName "$delegationGmsa.$($domain.DNSRoot)" `
                    -Path $serviceOu `
                    -Enabled $true `
                    -Description 'Lab: managed service account trusted for unconstrained delegation'
            }
        }
        else {
            Write-Verbose "$delegationGmsa already exists"
        }
        Enable-LabUnconstrainedDelegation -SamAccountName $delegationGmsaSam -Name $delegationGmsa
    }
}
else {
    Write-Verbose 'Skipping the managed service account fixture. Pass -IncludeManagedServiceAccount to seed it.'
}

# lab_svc_portal holds a service principal name as well, so the Kerberoasting
# check expects it too. Ground truth that named only one of the two would
# score the other as a false positive.
if ($delegationSeeded -contains $delegationUser) {
    $groundTruth.expected['AD.PRIVILEGE.KERBEROASTING'].objects =
        @($groundTruth.expected['AD.PRIVILEGE.KERBEROASTING'].objects) + $delegationUser
    $groundTruth.expected['AD.PRIVILEGE.KERBEROASTING'].note +=
        ' lab_svc_portal, seeded in section 5, also holds an SPN and is expected here.'
}

$groundTruth.expected['AD.PRIVILEGE.UNCONSTRAINED_DELEGATION'] = [ordered]@{
    # Only the accounts the script actually flagged. Listing what it meant to
    # create would turn a half-finished run into measured false negatives.
    shouldDetect     = ($delegationSeeded.Count -gt 0)
    objects          = $delegationSeeded.ToArray()
    expectedSeverity = 'Critical'
    note             = 'Accounts carrying TRUSTED_FOR_DELEGATION, recorded as each one was flagged. All are enabled, which is what makes the finding Critical rather than High.'
    mustNotDetect    = @('DC01$')
    mustNotDetectNote = 'Every writable domain controller holds this flag by design and is excluded by the SERVER_TRUST_ACCOUNT bit. A scan that reports DC01 here has regressed.'
    managedServiceAccountSeeded = $gmsaAttempted
    notSeeded        = if ($gmsaAttempted) { $null } else { 'A managed service account. Pass -IncludeManagedServiceAccount, which needs a KDS root key in the forest, to cover that path against a live directory.' }
}

# ---------------------------------------------------------------------------
# 6. Risky group policy
#
# Two policies, neither of them linked to anything. Linking them would push
# these settings onto the lab's own machines, and the check reads what a
# policy says rather than where it applies, so leaving them unlinked seeds
# the finding without changing how the lab behaves.
#
#   Lab Legacy Preferences   a Group Policy Preferences file with a
#                            cpassword attribute, the MS14-025 problem
#   Lab Workstation Rights   SeDebugPrivilege granted to Authenticated Users,
#                            and the guest account switched on
#
# This section needs the GroupPolicy module, which a domain controller has by
# default. The auditing module deliberately does not: it reads the same files
# straight from SYSVOL, with nothing but the read access every domain member
# already has.
# ---------------------------------------------------------------------------

$gpoSeeded = [System.Collections.Generic.List[string]]::new()

if (-not (Get-Command -Name New-GPO -ErrorAction SilentlyContinue)) {
    Write-Warning @'
The GroupPolicy module is not available, so the risky group policy fixtures
were not seeded. Run this section on a domain controller, or install the
Group Policy Management feature:

    Install-WindowsFeature -Name GPMC

The ADSecurityAudit module itself does not need this. Only the seeding does.
'@
}
else {
    function New-LabGpo {
        param([Parameter(Mandatory)] [string] $Name, [Parameter(Mandatory)] [string] $Comment)

        $existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Verbose "$Name already exists"
            return $existing
        }
        if (-not $PSCmdlet.ShouldProcess($Name, 'Create group policy object')) { return $null }
        return (New-GPO -Name $Name -Comment $Comment)
    }

    function Write-LabPolicyFile {
        param(
            [Parameter(Mandatory)] $Gpo,
            [Parameter(Mandatory)] [string] $RelativePath,
            [Parameter(Mandatory)] [string] $Content
        )

        # The GPO's own folder under SYSVOL, read from the object rather than
        # assembled by hand, so a renamed domain or a non-default SYSVOL path
        # does not silently put these files somewhere nothing reads them.
        $root = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($Gpo.Id)}"

        # Joined as strings rather than with Join-Path and Split-Path. Both
        # resolve a UNC path through the provider, which needs a drive and
        # therefore only works on Windows, and that would make this section
        # untestable anywhere else. The separator is a backslash either way,
        # because the destination is always a Windows share.
        $full   = "$root\$RelativePath"
        $parent = $full.Substring(0, $full.LastIndexOf('\'))

        if (-not $PSCmdlet.ShouldProcess($full, 'Write policy file')) { return }
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }
        Set-Content -LiteralPath $full -Value $Content -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Wrote $full"
    }

    $prefsGpo = New-LabGpo -Name 'Lab Legacy Preferences' -Comment 'Lab: stores a password in SYSVOL'
    if ($prefsGpo) {
        # The cpassword below is a placeholder, not real ciphertext. The
        # check looks for the attribute being present and non-empty and
        # never decrypts it, so seeding a decryptable password would add a
        # real recoverable secret to the repository and prove nothing extra.
        Write-LabPolicyFile -Gpo $prefsGpo -RelativePath 'Machine\Preferences\Groups\Groups.xml' -Content @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="lab_local_admin"
        image="2" changed="2026-01-01 00:00:00" uid="{A1B2C3D4-0000-0000-0000-000000000001}">
    <Properties action="U" newName="" fullName="Lab local administrator" description=""
                cpassword="LAB-PLACEHOLDER-NOT-REAL-CIPHERTEXT" changeLogon="0"
                noChange="1" neverExpires="1" acctDisabled="0" userName="lab_local_admin"/>
  </User>
</Groups>
'@
        $gpoSeeded.Add('Lab Legacy Preferences')
    }

    $rightsGpo = New-LabGpo -Name 'Lab Workstation Rights' -Comment 'Lab: dangerous privilege granted broadly'
    if ($rightsGpo) {
        Write-LabPolicyFile -Gpo $rightsGpo -RelativePath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf' -Content @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
EnableGuestAccount = 1
[Privilege Rights]
SeDebugPrivilege = *S-1-5-11
SeImpersonatePrivilege = *S-1-5-11,*S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544
'@
        $gpoSeeded.Add('Lab Workstation Rights')
    }
}

$groundTruth.expected['AD.POLICY.RISKY_GPO'] = [ordered]@{
    shouldDetect     = ($gpoSeeded.Count -gt 0)
    objects          = $gpoSeeded.ToArray()
    expectedSeverity = 'Critical'
    note             = 'Lab Legacy Preferences stores a cpassword, which is Critical on its own. Lab Workstation Rights grants SeDebugPrivilege and SeImpersonatePrivilege to Authenticated Users and switches on the guest account, which is 3 further issues. SeBackupPrivilege is granted only to Administrators and must not be reported.'
    expectedIssues   = 4
    mustNotDetect    = @('SeBackupPrivilege')
    notSeeded        = 'Neither policy is linked to an organizational unit, so nothing in the lab applies these settings. The check reads policy contents rather than scope, which is recorded as a limitation on the finding.'
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