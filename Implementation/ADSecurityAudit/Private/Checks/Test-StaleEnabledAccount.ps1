function Test-StaleEnabledAccount {
    <#
    .SYNOPSIS
        Finds enabled user accounts that have never signed in or have been
        inactive beyond a threshold.

    .DESCRIPTION
        NOT IMPLEMENTED YET. The signature, the contract and the research
        notes are settled; the body is the work.

        Research notes gathered so far, worth reading before writing it:

        - LastLogonDate is a calculated property. It comes from
          lastLogonTimestamp, which AD only replicates every 9 to 14 days by
          default (the msDS-LogonTimeSyncInterval attribute). So an account
          that signed in yesterday can still show a date up to two weeks old.
          That is acceptable for a 90 day threshold but would make a 7 day
          threshold meaningless. Say so in the report rather than pretending
          the number is exact.

        - lastLogon (no "timestamp") is accurate but is NOT replicated, so
          it only holds what one domain controller saw. Reading it properly
          means querying every DC and taking the maximum. Out of scope for
          now, but it is the honest answer to "why is this approximate" if
          the instructor asks.

        - An account that has never signed in has no LastLogonDate at all.
          Pipe it through ConvertTo-AuditTimestamp so it lands in the JSON as
          null, which the dashboard renders as "Never". Treating it as a very
          old date would be wrong: never used and unused since 2023 are
          different situations.

        - Filter on Enabled in the LDAP filter, not with Where-Object after
          the fact. On a real domain the difference is thousands of objects
          crossing the wire.

        Implementation sketch:
          1. Get-ADUser -Filter 'Enabled -eq $true' with LastLogonDate,
             whenCreated and PasswordLastSet in -Properties.
          2. Skip accounts created inside the threshold window. A user hired
             last week has not had time to sign in and is not stale.
          3. Partition into never-signed-in and inactive-beyond-threshold.
          4. One finding holding every stale account, not one finding each.
             An administrator reviews these as a batch.
          5. Severity: High normally. Consider Critical if any stale account
             sits in a privileged group, since that combines two problems.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER InactiveDays
        Days of inactivity after which an account counts as stale.

    .PARAMETER IncludeNeverLoggedOn
        Whether accounts that have never signed in are reported.

    .PARAMETER ExcludedOrganizationalUnits
        DNs of OUs to skip, for example a deliberate archive OU.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [int]      $InactiveDays                = 90,
        [bool]     $IncludeNeverLoggedOn        = $true,
        [string[]] $ExcludedOrganizationalUnits = @()
    )

    throw [System.NotImplementedException]::new(
        'Test-StaleEnabledAccount is not implemented yet. See the research notes in this file.')
}
