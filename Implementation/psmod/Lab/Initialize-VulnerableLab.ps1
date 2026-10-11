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
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]    $StaleAccountCount = 3,
    [string] $GroundTruthPath   = './ground-truth.json'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

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

$stalePassword = ConvertTo-SecureString 'REDACTED-LAB-PASSWORD' -AsPlainText -Force
$staleCreated  = @()

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
            -AccountPassword $stalePassword `
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
            -AccountPassword $stalePassword `
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
                -AccountPassword $stalePassword `
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

if ($PSCmdlet.ShouldProcess($GroundTruthPath, 'Write ground truth')) {
    $groundTruth | ConvertTo-Json -Depth 10 | Set-Content -Path $GroundTruthPath -Encoding UTF8
    Write-Host "Ground truth written to $GroundTruthPath"
}

Write-Host ''
Write-Host 'Lab seeded. Verify before relying on it:'
Write-Host '  Get-ADDefaultDomainPasswordPolicy'
Write-Host '  Get-ADGroupMember -Identity ''Domain Admins'' -Recursive | Select-Object name'
Write-Host '  Get-ADUser -Filter "Enabled -eq $true" -Properties LastLogonDate | Where-Object { -not $_.LastLogonDate }'
