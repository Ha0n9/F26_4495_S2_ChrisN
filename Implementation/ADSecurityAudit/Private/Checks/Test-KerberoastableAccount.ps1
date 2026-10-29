function Test-KerberoastableAccount {
    <#
    .SYNOPSIS
        Finds user accounts carrying a service principal name, which any
        domain user can request an offline-crackable ticket for.

    .DESCRIPTION
        Kerberoasting works because the directory is doing what it was
        designed to do. Any authenticated user may request a service ticket
        for any account that has a service principal name, and that ticket is
        encrypted with the service account's password hash. The attacker needs
        no privilege to ask, the request looks like ordinary Kerberos traffic,
        and once the ticket is in hand the cracking happens offline where no
        lockout policy and no alert can reach it.

        The technique is named in the joint advisory on detecting and
        mitigating Active Directory compromises, published by ASD's ACSC with
        CISA, the NSA, the Canadian Centre for Cyber Security and the UK and
        New Zealand national cyber security centres.

        Four details decide whether this check is useful or merely noisy.

        Only user accounts are reported. Computer accounts also hold service
        principal names, and far more of them, but their passwords are 120
        characters of machine-generated randomness rotated every thirty days
        by default. Reporting them would bury the handful of accounts that
        matter under every workstation in the domain. Group managed service
        accounts are excluded for the same reason: their passwords are managed
        by the directory and are not guessable. The LDAP filter pins
        objectCategory to person, which excludes both.

        krbtgt is excluded. It holds a service principal name on every domain
        that has ever existed, and reporting it means every scan opens with a
        finding nobody can act on. The reasoning is the same as excluding the
        built-in Administrator from the privileged membership check, and so is
        the mechanism: relative identifier 502, which is invariant across
        domains and across languages.

        An absent encryption type attribute is not safety. When
        msDS-SupportedEncryptionTypes is unset, the key distribution centre
        falls back to its default, and on most domains that default still
        permits RC4. RC4 tickets crack orders of magnitude faster than AES.
        Treating a null as "configured securely" would be exactly backwards,
        so a null is reported as RC4 permitted.

        Severity is derived from what was found rather than fixed. A service
        account that is also privileged turns one cracked password into
        control of the domain, so that is Critical. RC4 or a long-unchanged
        password is High. Service accounts that are all AES and all recently
        rotated are still an exposure worth knowing about, but they are
        Medium, because reporting them at High teaches an administrator that
        this check cries wolf.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER IncludeDisabledAccounts
        Whether disabled accounts are reported. Off by default: the key
        distribution centre will not issue a service ticket for a disabled
        account, so it is not roastable while it stays disabled.

    .PARAMETER StalePasswordDays
        A password older than this is reported as stale. The default of 365
        is deliberately generous, because service account passwords are
        rotated rarely and a lower threshold would flag almost every one.

    .PARAMETER ExcludedRids
        Relative identifiers never reported. Defaults to krbtgt.

    .PARAMETER ExcludedAccountNames
        SAM account names never reported. The escape hatch for an account an
        organisation has assessed and accepted.

    .OUTPUTS
        One finding covering every exposed account, or nothing when the
        domain has none.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [bool]     $IncludeDisabledAccounts = $false,
        [int]      $StalePasswordDays       = 365,
        [int[]]    $ExcludedRids            = @(502),
        [string[]] $ExcludedAccountNames    = @()
    )

    # Bit values from the msDS-SupportedEncryptionTypes attribute.
    $ETYPE_DES_CRC = 0x01
    $ETYPE_DES_MD5 = 0x02
    $ETYPE_RC4     = 0x04
    $ETYPE_AES128  = 0x08
    $ETYPE_AES256  = 0x10

    function Resolve-EncryptionTypeName {
        param([AllowNull()] $Value)

        if ($null -eq $Value) { return @('not set') }

        $value = [int] $Value
        if ($value -eq 0) { return @('not set') }

        $names = [System.Collections.Generic.List[string]]::new()
        if ($value -band $ETYPE_DES_CRC) { $names.Add('DES-CBC-CRC') }
        if ($value -band $ETYPE_DES_MD5) { $names.Add('DES-CBC-MD5') }
        if ($value -band $ETYPE_RC4)     { $names.Add('RC4-HMAC') }
        if ($value -band $ETYPE_AES128)  { $names.Add('AES128') }
        if ($value -band $ETYPE_AES256)  { $names.Add('AES256') }
        if ($names.Count -eq 0) { $names.Add("unrecognised value $value") }
        return $names.ToArray()
    }

    function Test-Rc4Permitted {
        param([AllowNull()] $Value)

        # Unset means the KDC uses its own default, which on most domains
        # still includes RC4. Absence is not a hardening signal.
        if ($null -eq $Value) { return $true }

        $value = [int] $Value
        if ($value -eq 0) { return $true }
        if ($value -band $ETYPE_RC4) { return $true }

        # Only AES bits set. RC4 is not offered for this account.
        return $false
    }

    # objectCategory=person excludes computer accounts and group managed
    # service accounts, both of which hold service principal names but have
    # directory-managed passwords that are not worth cracking.
    $filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'

    $properties = @(
        'ServicePrincipalName'
        'msDS-SupportedEncryptionTypes'
        'PasswordLastSet'
        'PasswordNeverExpires'
        'Enabled'
        'adminCount'
    )

    $candidates = @(Get-ADUser -LDAPFilter $filter -Properties $properties -Server $DomainName -ErrorAction Stop)

    $now      = (Get-Date).ToUniversalTime()
    $exposed  = [System.Collections.Generic.List[object]]::new()

    foreach ($account in $candidates) {
        if (-not $IncludeDisabledAccounts -and $account.Enabled -eq $false) { continue }

        if ($account.SamAccountName -and ($ExcludedAccountNames -contains $account.SamAccountName)) { continue }

        $sidValue = if ($account.SID) { [string] $account.SID.Value } else { $null }
        if ($sidValue) {
            $rid = ($sidValue -split '-')[-1]
            if ($ExcludedRids -contains [int] $rid) { continue }
        }

        # Wrapped twice on purpose. The inner array handles a single-valued
        # attribute arriving as a bare string, and the outer one stops
        # Where-Object unwrapping a one-element result back into a scalar.
        $spns = @(@($account.ServicePrincipalName) | Where-Object { $_ })
        if ($spns.Count -eq 0) { continue }

        $encRaw      = $account.'msDS-SupportedEncryptionTypes'
        $rc4         = Test-Rc4Permitted -Value $encRaw
        $encNames    = Resolve-EncryptionTypeName -Value $encRaw

        $passwordSet = $account.PasswordLastSet
        $ageDays     = if ($passwordSet) {
            [int] [math]::Floor(($now - $passwordSet.ToUniversalTime()).TotalDays)
        } else {
            $null
        }
        # A password that was never set cannot be judged stale, but it is not
        # reassuring either, so it is carried through as null rather than 0.
        $stale = ($null -ne $ageDays -and $ageDays -ge $StalePasswordDays)

        $privileged = ($account.adminCount -eq 1)

        $exposed.Add([pscustomobject]@{
            Account     = $account
            Spns        = $spns
            Rc4         = $rc4
            EncNames    = $encNames
            AgeDays     = $ageDays
            PasswordSet = $passwordSet
            Stale       = $stale
            Privileged  = $privileged
        })
    }

    if ($exposed.Count -eq 0) { return }

    $affected = foreach ($entry in $exposed) {
        New-AffectedObject -Name $entry.Account.SamAccountName `
            -ObjectClass 'user' `
            -DistinguishedName $entry.Account.DistinguishedName `
            -Attributes @{
                servicePrincipalNames = ($entry.Spns -join '; ')
                spnCount              = $entry.Spns.Count
                rc4Permitted          = [bool] $entry.Rc4
                encryptionTypes       = ($entry.EncNames -join ', ')
                passwordLastSet       = (ConvertTo-AuditTimestamp -Value $entry.PasswordSet)
                passwordAgeDays       = $entry.AgeDays
                passwordNeverExpires  = [bool] $entry.Account.PasswordNeverExpires
                isPrivileged          = [bool] $entry.Privileged
                enabled               = [bool] $entry.Account.Enabled
            }
    }

    $rc4Count        = @($exposed | Where-Object { $_.Rc4 }).Count
    $privilegedCount = @($exposed | Where-Object { $_.Privileged }).Count
    $staleCount      = @($exposed | Where-Object { $_.Stale }).Count

    $severity =
        if     ($privilegedCount -gt 0)              { 'Critical' }
        elseif ($rc4Count -gt 0 -or $staleCount -gt 0) { 'High' }
        else                                          { 'Medium' }

    $summary = '{0} user account(s) carry a service principal name and can therefore be asked for an offline-crackable ticket by any domain user.' -f $exposed.Count
    if ($privilegedCount -gt 0) {
        $summary += ' {0} of them also hold privileged group membership.' -f $privilegedCount
    }
    if ($rc4Count -gt 0) {
        $summary += ' {0} permit RC4, which cracks far faster than AES.' -f $rc4Count
    }
    if ($staleCount -gt 0) {
        $summary += ' {0} have a password older than {1} days.' -f $staleCount, $StalePasswordDays
    }

    return New-AuditFinding -CheckId 'AD.PRIVILEGE.KERBEROASTING' `
        -Severity $severity `
        -DomainName $DomainName `
        -AffectedObjects @($affected) `
        -Evidence @{
            summary               = $summary
            exposedAccountCount   = $exposed.Count
            rc4PermittedCount     = $rc4Count
            privilegedCount       = $privilegedCount
            stalePasswordCount    = $staleCount
            parametersUsed        = @{
                includeDisabledAccounts = $IncludeDisabledAccounts
                stalePasswordDays       = $StalePasswordDays
                excludedRids            = $ExcludedRids
                excludedAccountNames    = $ExcludedAccountNames
            }
            query                 = "Get-ADUser -LDAPFilter '$filter'"
            note                  = 'Computer accounts and group managed service accounts are excluded by objectCategory=person, because their passwords are directory-managed and not realistically crackable. krbtgt is excluded by RID 502.'
            limitation            = 'Privilege is read from adminCount, which the directory sets when an account joins a protected group but does not always clear when it leaves. An account reported as privileged may have held that privilege in the past rather than today.'
        }
}
