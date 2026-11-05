function Test-UnconstrainedDelegation {
    <#
    .SYNOPSIS
        Finds accounts trusted for unconstrained delegation, which keep a
        usable copy of the Kerberos ticket of everyone who connects to them.

    .DESCRIPTION
        When a user authenticates to a host trusted for unconstrained
        delegation, the domain controller sends that host a forwardable
        ticket-granting ticket for the user, and the host caches it in memory
        so it can act as that user against any service. Anyone who controls
        the host can take those tickets and become any account that has
        connected to it. If a domain administrator has ever logged on there,
        the host is equivalent to the domain.

        Nothing has to be exploited for this to be true. It is what the
        feature does, which is why it is named in the joint advisory on
        detecting and mitigating Active Directory compromises published by
        ASD's ACSC with CISA, the NSA, the Canadian Centre for Cyber Security
        and the UK and New Zealand national cyber security centres.

        Five things decide whether this check is worth reading.

        Three kinds of account are queried, not two. The flag lives in
        userAccountControl, which computers, ordinary accounts and managed
        service accounts all have. An earlier version of this check asked
        Get-ADComputer and Get-ADUser only, and a managed service account
        carrying the flag was invisible to it: not reported as a risk, and
        not reported as unexamined either, which is the worst shape a gap in
        a security tool can take. Get-ADServiceAccount covers both standalone
        managed service accounts and group managed service accounts.

        Domain controllers are excluded. Every writable domain controller is
        trusted for unconstrained delegation, because that is how Kerberos
        works, and reporting them means every scan of every domain opens with
        findings nobody can act on. They are identified by the
        SERVER_TRUST_ACCOUNT bit in userAccountControl rather than by
        organizational unit or group name, for the same reason the privileged
        membership check resolves groups by SID: a container called Domain
        Controllers is a convention and a localised name, while the bit is
        part of the account.

        Each account is classified by the object class the directory gives
        it, not by which query returned it. A group managed service account
        is not a user and not a computer, and calling it either in the report
        sends the reader to a remediation procedure that does not exist for
        it. Where the directory does not say, the query it came from is used
        as a fallback rather than guessing.

        Constrained delegation is not reported here. An account with
        msDS-AllowedToDelegateTo can impersonate users only to the specific
        services named in that attribute, which is a different and much
        smaller exposure. Folding the two together would bury the findings
        that matter under ones that mostly do not. Where an account has both,
        that is recorded on the object, because it usually means a migration
        to constrained delegation was started and never finished.

        Whether the exposure is real depends on who has logged on to the
        host, and this check cannot see that. It reports the condition, not
        the consequence, and says so in its evidence.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER IncludeDisabledAccounts
        Whether disabled accounts are reported. Off by default: a disabled
        account receives no tickets. Kept as an option because a disabled
        account that is re-enabled brings the exposure back with it.

    .PARAMETER ExcludedAccountNames
        SAM account names never reported, for any kind of account. The escape
        hatch for a host an organisation has assessed and accepted. Managed
        service account names end in a dollar sign, as computer names do.

    .OUTPUTS
        One finding covering every exposed account, or nothing when the
        domain has none beyond its domain controllers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [bool]     $IncludeDisabledAccounts = $false,
        [string[]] $ExcludedAccountNames    = @()
    )

    # userAccountControl bits. Named rather than inlined, because 8192 in a
    # condition tells a later reader nothing.
    $UAC_SERVER_TRUST_ACCOUNT   = 0x2000      # a writable domain controller
    $UAC_TRUSTED_FOR_DELEGATION = 0x80000

    # The LDAP bitwise AND matching rule. Asking the directory for accounts
    # that carry the flag is both faster than reading every account and
    # exact: no inference from other attributes, no guessing from names.
    $delegationFilter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

    # Property lists are per cmdlet rather than one shared list. operatingSystem
    # and dNSHostName belong to the computer class, and asking Get-ADUser for
    # them risks an invalid-property error that would fail the whole check on
    # every domain, including ones with nothing to report.
    $sharedProperties   = @('userAccountControl', 'lastLogonDate', 'servicePrincipalName', 'msDS-AllowedToDelegateTo')
    $machineProperties  = $sharedProperties + @('operatingSystem', 'dNSHostName')

    # All three run before anything is inspected, so a failure in any one of
    # them reaches the aggregator and is recorded under checksFailed. Carrying
    # on with two out of three would report part of a domain as all of it.
    $sources = @(
        [pscustomobject]@{
            Kind     = 'computer'
            Accounts = @(Get-ADComputer -LDAPFilter $delegationFilter -Properties $machineProperties -Server $DomainName -ErrorAction Stop)
        }
        [pscustomobject]@{
            Kind     = 'user'
            Accounts = @(Get-ADUser -LDAPFilter $delegationFilter -Properties $sharedProperties -Server $DomainName -ErrorAction Stop)
        }
        [pscustomobject]@{
            Kind     = 'msDS-ManagedServiceAccount'
            Accounts = @(Get-ADServiceAccount -LDAPFilter $delegationFilter -Properties $machineProperties -Server $DomainName -ErrorAction Stop)
        }
    )

    $exposed           = [System.Collections.Generic.List[object]]::new()
    $domainControllers = 0
    $duplicates        = 0

    # Managed service account classes descend from computer in the schema, so
    # an overlap between two of these queries is plausible even though the
    # object categories differ today. One account reported twice would
    # overstate the exposure, so distinguished names are tracked.
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($source in $sources) {
        foreach ($account in $source.Accounts) {
            $uac = [int] $account.userAccountControl

            # Belt and braces. The filter already asked for the flag, but a
            # check that trusts a filter it did not evaluate itself has no
            # way to notice when the filter is wrong, and this one guards
            # three different cmdlets.
            if (($uac -band $UAC_TRUSTED_FOR_DELEGATION) -eq 0) { continue }

            if (($uac -band $UAC_SERVER_TRUST_ACCOUNT) -ne 0) {
                $domainControllers++
                Write-Verbose "Skipping domain controller $($account.SamAccountName)."
                continue
            }

            $distinguishedName = [string] $account.DistinguishedName
            if ($distinguishedName -and -not $seen.Add($distinguishedName)) {
                $duplicates++
                Write-Verbose "Already reported $distinguishedName, skipping the duplicate."
                continue
            }

            if ($account.SamAccountName -and ($ExcludedAccountNames -contains $account.SamAccountName)) { continue }

            $enabled = [bool] $account.Enabled
            if (-not $IncludeDisabledAccounts -and -not $enabled) { continue }

            # The directory's own class, falling back to the query that
            # returned it. ObjectClass arrives as a single value from these
            # cmdlets, but an array is handled so a changed cmdlet cannot
            # quietly produce "System.Object[]" as a class name.
            $objectClass = @($account.ObjectClass) | Where-Object { $_ } | Select-Object -Last 1
            if (-not $objectClass) { $objectClass = $source.Kind }
            $objectClass = [string] $objectClass

            $category =
                if     ($objectClass -eq 'computer')                        { 'computer' }
                elseif ($objectClass -eq 'user')                            { 'user' }
                elseif ($objectClass -like 'msDS-*ManagedServiceAccount')   { 'managedServiceAccount' }
                else                                                        { 'other' }

            $spns        = @(@($account.ServicePrincipalName) | Where-Object { $_ })
            $constrained = @(@($account.'msDS-AllowedToDelegateTo') | Where-Object { $_ })

            $exposed.Add([pscustomobject]@{
                Account     = $account
                ObjectClass = $objectClass
                Category    = $category
                Enabled     = $enabled
                Spns        = $spns
                Constrained = $constrained
            })
        }
    }

    if ($exposed.Count -eq 0) { return }

    $affected = foreach ($item in $exposed) {
        # Values are built before the hashtable rather than with inline
        # conditionals, so the literal stays readable and nothing depends on
        # how a given PowerShell version parses an if expression in a
        # hashtable value.
        $operatingSystem = if ($item.Account.OperatingSystem) { [string] $item.Account.OperatingSystem } else { $null }
        $dnsHostName     = if ($item.Account.DNSHostName)     { [string] $item.Account.DNSHostName }     else { $null }
        $spnText         = if ($item.Spns.Count)              { ($item.Spns -join '; ') }                else { $null }

        New-AffectedObject -Name $item.Account.SamAccountName `
            -ObjectClass $item.ObjectClass `
            -DistinguishedName $item.Account.DistinguishedName `
            -Attributes @{
                # The first two names match the dictionary entry's
                # keyAttributes, so they become the table's columns.
                operatingSystem              = $operatingSystem
                lastLogonDate                = (ConvertTo-AuditTimestamp -Value $item.Account.LastLogonDate)
                enabled                      = $item.Enabled
                accountCategory              = $item.Category
                dnsHostName                  = $dnsHostName
                servicePrincipalNames        = $spnText
                alsoHasConstrainedDelegation = [bool] $item.Constrained.Count
            }
    }

    $enabledCount   = @($exposed | Where-Object { $_.Enabled }).Count
    $computerCount  = @($exposed | Where-Object { $_.Category -eq 'computer' }).Count
    $userCount      = @($exposed | Where-Object { $_.Category -eq 'user' }).Count
    $msaCount       = @($exposed | Where-Object { $_.Category -eq 'managedServiceAccount' }).Count
    $gmsaCount      = @($exposed | Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' }).Count
    $bothCount      = @($exposed | Where-Object { $_.Constrained.Count -gt 0 }).Count

    # A disabled account issues no tickets today, so the exposure is latent
    # rather than live. Saying Critical either way would make the severity
    # mean nothing.
    $severity = if ($enabledCount -gt 0) { 'Critical' } else { 'High' }

    $summary = '{0} account(s) besides the domain controllers are trusted for unconstrained delegation, so each keeps a reusable copy of the Kerberos ticket of everyone who connects to it.' -f $exposed.Count
    if ($enabledCount -lt $exposed.Count) {
        $summary += ' {0} of them are enabled.' -f $enabledCount
    }
    if ($userCount -gt 0) {
        $summary += ' {0} are user accounts rather than computers, which is unusual and worth confirming.' -f $userCount
    }
    if ($msaCount -gt 0) {
        $summary += ' {0} are managed service accounts, which are changed through PowerShell rather than through the Delegation tab.' -f $msaCount
    }
    if ($bothCount -gt 0) {
        $summary += ' {0} also have constrained delegation configured, which often means a migration was started and not finished.' -f $bothCount
    }

    return New-AuditFinding -CheckId 'AD.PRIVILEGE.UNCONSTRAINED_DELEGATION' `
        -Severity $severity `
        -DomainName $DomainName `
        -AffectedObjects @($affected) `
        -Evidence @{
            summary                         = $summary
            exposedAccountCount             = $exposed.Count
            enabledCount                    = $enabledCount
            computerAccountCount            = $computerCount
            userAccountCount                = $userCount
            managedServiceAccountCount      = $msaCount
            groupManagedServiceAccountCount = $gmsaCount
            alsoConstrainedCount            = $bothCount
            domainControllersSkipped        = $domainControllers
            duplicatesSkipped               = $duplicates
            parametersUsed                  = @{
                includeDisabledAccounts = $IncludeDisabledAccounts
                excludedAccountNames    = $ExcludedAccountNames
            }
            query                           = "Get-ADComputer, Get-ADUser and Get-ADServiceAccount with -LDAPFilter '$delegationFilter'"
            note                            = 'Domain controllers are excluded by the SERVER_TRUST_ACCOUNT bit in userAccountControl, because every writable domain controller holds this flag by design. Managed service accounts are queried as well as computers and users, because the flag lives in userAccountControl and all three have it. Constrained delegation is a separate and much smaller exposure and is not reported here.'
            limitation                      = 'Whether the exposure has been realised depends on which accounts have authenticated to these hosts, which this scan cannot see. The finding reports the condition, not evidence that a ticket was captured.'
        }
}
