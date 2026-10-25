function Test-StaleEnabledAccount {
    <#
    .SYNOPSIS
        Finds enabled user accounts that have never signed in or have been
        inactive beyond a threshold.

    .DESCRIPTION
        Every enabled account is a way into the domain. Accounts belonging to
        people who have left, and service accounts nobody maintains, are
        rarely monitored and their passwords are rarely rotated, so an
        attacker who obtains one is unlikely to be noticed.

        Two situations are reported, and they are kept distinct because they
        call for different conversations with the account owner:

          never signed in   LastLogonDate is null. The account was created
                            and never used at all.
          inactive          LastLogonDate exists but is older than the
                            threshold.

        Accuracy caveat, which belongs in the report rather than hidden here:
        LastLogonDate is derived from lastLogonTimestamp, which Active
        Directory replicates only every 9 to 14 days by default. An account
        that signed in yesterday can therefore still show a date up to two
        weeks old. That is acceptable at a 90 day threshold and meaningless
        at a 7 day one. The precise attribute, lastLogon, is not replicated
        between domain controllers, so reading it correctly would mean
        querying every controller and taking the maximum. That is out of
        scope here and is recorded as a known limitation.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER InactiveDays
        Days of inactivity after which an account counts as stale.

    .PARAMETER NewAccountGraceDays
        How recently an account can have been created and still be excused
        for never having signed in. A person hired last week has not had time
        to use their account, and flagging them teaches an administrator to
        ignore the tool.

        Kept separate from InactiveDays because the two measure different
        things: one is how long an account has been unused, the other is how
        long somebody gets to start using a new one. Set it to 0 to report
        every never-signed-in account regardless of age, which is what a
        freshly seeded test lab needs.

    .PARAMETER IncludeNeverLoggedOn
        Whether accounts that have never signed in are reported.

    .PARAMETER ExcludedOrganizationalUnits
        Distinguished names of OUs to skip, for an organization that parks
        retained accounts somewhere on purpose.

    .OUTPUTS
        One finding covering every stale account, or nothing when none were
        found. An administrator reviews these as a batch, so one finding per
        account would be the same piece of advice repeated.

    .EXAMPLE
        Test-StaleEnabledAccount -DomainName lab.local -InactiveDays 90
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [int]      $InactiveDays                = 90,
        [int]      $NewAccountGraceDays         = 30,
        [bool]     $IncludeNeverLoggedOn        = $true,
        [string[]] $ExcludedOrganizationalUnits = @()
    )

    $now         = Get-Date
    $cutoff      = $now.AddDays(-$InactiveDays)
    $graceCutoff = $now.AddDays(-$NewAccountGraceDays)

    # Filter on Enabled in the directory query rather than with Where-Object
    # afterwards. On a real domain that is the difference between asking for
    # the accounts that matter and pulling every user object across the wire.
    #
    # LastLogonDate and whenCreated are not returned by default. Forgetting
    # -Properties yields nulls for every account, which this check would read
    # as "nobody has ever signed in anywhere".
    $users = Get-ADUser -Filter 'Enabled -eq $true' `
        -Properties LastLogonDate, whenCreated, PasswordLastSet `
        -Server $DomainName `
        -ErrorAction Stop

    $stale = [System.Collections.Generic.List[object]]::new()
    $neverCount    = 0
    $inactiveCount = 0

    foreach ($user in $users) {
        # Skip anything sitting in an OU the caller asked to leave alone.
        $excluded = $false
        foreach ($ou in $ExcludedOrganizationalUnits) {
            if ($user.DistinguishedName -like "*,$ou") { $excluded = $true; break }
        }
        if ($excluded) { continue }

        $lastLogon = $user.LastLogonDate
        $created   = $user.whenCreated

        if ($null -eq $lastLogon) {
            # Never signed in.
            if (-not $IncludeNeverLoggedOn) { continue }

            # An account created inside the grace window has not had time to
            # be used, so it is not stale yet.
            if ($created -and $created -gt $graceCutoff) { continue }

            $neverCount++
            $daysInactive = $null
        }
        else {
            if ($lastLogon -gt $cutoff) { continue }

            $inactiveCount++
            $daysInactive = [int] ($now - $lastLogon).TotalDays
        }

        $stale.Add((New-AffectedObject -Name $user.SamAccountName `
            -ObjectClass 'user' `
            -DistinguishedName $user.DistinguishedName `
            -Attributes @{
                enabled         = [bool] $user.Enabled
                # Null, not an old date. Never used and unused since 2023 are
                # different situations, and the dashboard renders null as
                # "Never".
                lastLogonDate   = ConvertTo-AuditTimestamp -Value $lastLogon
                whenCreated     = ConvertTo-AuditTimestamp -Value $created
                passwordLastSet = ConvertTo-AuditTimestamp -Value $user.PasswordLastSet
                daysInactive    = $daysInactive
            }))
    }

    # Nothing stale, so nothing to report. Returning an empty finding would
    # be counted by the aggregator as a problem that does not exist.
    if ($stale.Count -eq 0) { return }

    $summary = if ($neverCount -and $inactiveCount) {
        '{0} enabled accounts are stale: {1} have never signed in and {2} have been inactive for more than {3} days.' -f
            $stale.Count, $neverCount, $inactiveCount, $InactiveDays
    }
    elseif ($neverCount) {
        '{0} enabled accounts have never been signed into.' -f $neverCount
    }
    else {
        '{0} enabled accounts have been inactive for more than {1} days.' -f $inactiveCount, $InactiveDays
    }

    New-AuditFinding -CheckId 'AD.ACCOUNT.STALE_ENABLED' `
        -Severity 'High' `
        -DomainName $DomainName `
        -AffectedObjects $stale.ToArray() `
        -Evidence @{
            summary            = $summary
            neverSignedInCount = $neverCount
            inactiveCount      = $inactiveCount
            parametersUsed     = @{
                inactiveDays                = $InactiveDays
                newAccountGraceDays         = $NewAccountGraceDays
                includeNeverLoggedOn        = $IncludeNeverLoggedOn
                excludedOrganizationalUnits = $ExcludedOrganizationalUnits
            }
            query              = "Get-ADUser -Filter 'Enabled -eq `$true' -Properties LastLogonDate,whenCreated,PasswordLastSet"
            limitation         = 'LastLogonDate derives from lastLogonTimestamp, which replicates every 9 to 14 days by default, so inactivity figures are approximate to within that window.'
        }
}
