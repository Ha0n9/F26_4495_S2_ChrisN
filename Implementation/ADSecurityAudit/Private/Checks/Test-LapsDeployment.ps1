function ConvertFrom-LapsFileTime {
    <#
    .SYNOPSIS
        Turns a LAPS expiration attribute into a UTC DateTime, or $null when
        the value is absent or cannot be read as a time.

    .DESCRIPTION
        Both generations of LAPS store the expiration time as a Windows
        FILETIME: the number of 100-nanosecond intervals since 1601. The value
        arrives from the directory as a string of digits in some module
        versions and as an Int64 in others, so both are handled.

        Three values are not times and are reported as such rather than
        guessed at: absent, zero, and anything outside the range FILETIME can
        express. The last one matters because [datetime]::FromFileTimeUtc
        throws on an out-of-range value, and a throw here would fail the whole
        check over one malformed attribute on one computer. The caller counts
        what could not be parsed and says so in the evidence, which is the
        difference between a known gap and a silent one.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return $null }

    # An attribute can come back as a single-element collection.
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $Value = @($Value) | Where-Object { $null -ne $_ } | Select-Object -First 1
        if ($null -eq $Value) { return $null }
    }

    $text = ([string] $Value).Trim()
    if (-not $text) { return $null }

    $ticks = [int64] 0
    if (-not [int64]::TryParse($text, [ref] $ticks)) { return $null }

    # Zero is what LAPS writes when there is no password yet. It is not a
    # date in 1601.
    if ($ticks -le 0) { return $null }

    # The documented upper bound of FILETIME, which is 31 December 9999.
    if ($ticks -gt 2650467743999999999) { return $null }

    try   { return [datetime]::FromFileTimeUtc($ticks) }
    catch { return $null }
}


function Test-LapsExpiryValuePresent {
    <#
    .SYNOPSIS
        Says whether a LAPS expiration attribute holds a value at all, as
        distinct from holding one that cannot be read as a time.

    .DESCRIPTION
        The caller needs three outcomes, not two: no value, a value that is a
        time, and a value that is not. Only the third is a sign that something
        is wrong, and it is counted and reported separately, so the line
        between absent and malformed has to be drawn in one place.

        Zero sits on that line. LAPS writes zero when the attribute exists but
        no password has been set yet, so zero means absent, not malformed.
        Counting it as malformed would put a number in the report claiming
        the directory holds corrupt data when it holds a perfectly ordinary
        initial state.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return $false }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $Value = @($Value) | Where-Object { $null -ne $_ } | Select-Object -First 1
        if ($null -eq $Value) { return $false }
    }

    $text = ([string] $Value).Trim()
    if (-not $text) { return $false }

    $ticks = [int64] 0
    if ([int64]::TryParse($text, [ref] $ticks) -and $ticks -le 0) { return $false }

    return $true
}


function Test-LapsDeployment {
    <#
    .SYNOPSIS
        Reports whether the local administrator password of each domain-joined
        computer is being managed and rotated by LAPS.

    .DESCRIPTION
        Every Windows computer has a local administrator account that is not a
        domain account and is not governed by the domain password policy. When
        those passwords are set from an image, a build script or a technician's
        habit, they end up identical across the estate. One of them read from
        one machine is then a working local administrator credential on every
        machine, which is the ordinary way an intruder turns a single
        workstation into the whole network. LAPS exists to make each of those
        passwords different, random, and rotated on a schedule.

        This check reports the absence of that control. It is the only check in
        the module that reports something missing rather than something
        present, and three consequences of that shape are worth stating.

        It cannot confirm the harm. Whether those local passwords are actually
        shared is not in the directory, and a domain with no LAPS might have
        another password manager, or disabled local administrator accounts
        everywhere. The finding says the control is absent, not that the
        estate is compromised, and the evidence says so plainly.

        The password itself is never requested. Not read, not decrypted, not
        counted, not named in a query. The property list passed to the
        directory is built from named constants that hold only the expiration
        attributes, the evidence records exactly which properties were asked
        for, and a test asserts that no password attribute appears among them.
        The reason is not only that an ordinary account cannot read them. It is
        that a tool which asks for every local administrator password in the
        domain is a tool that must be trusted with them, and this one is
        designed to need no such trust.

        It distinguishes three states, not two, because the difference decides
        what an administrator should do next:

          The schema is not extended at all. LAPS has never been installed in
          this domain, so there is nothing to configure and nothing to repair.
          One finding describes the domain and the computers are not
          enumerated, because listing every computer in the domain as
          unmanaged would be true and useless.

          The schema is extended but a computer has no expiration time. The
          infrastructure exists and this machine is outside it, usually
          because the policy does not reach its organizational unit or the
          agent was never installed. This is the actionable case.

          The expiration time is in the past. LAPS was managing this machine
          and has stopped, which means the agent is not running or the policy
          was removed. The password still in place is now as old as the
          timestamp says.

        Both generations are recognised. Legacy Microsoft LAPS writes
        ms-Mcs-AdmPwdExpirationTime; Windows LAPS, built into current Windows,
        writes msLAPS-PasswordExpirationTime. A domain part way through a
        migration has both in the schema and computers on either one, so each
        computer records which generation manages it, and a computer managed by
        either is not reported. Asking the directory for an attribute that is
        not in the schema is an error, so the property list is assembled from
        what the schema probe actually found rather than from both names
        hopefully.

        Domain controllers are excluded. They are identified by the
        SERVER_TRUST_ACCOUNT bit in userAccountControl, the same way the
        delegation check identifies them, rather than by container name.
        A domain controller has no local administrator account of this kind:
        its local account database holds the directory services restore mode
        password, which is a separate thing with a separate rotation story and
        its own attribute in Windows LAPS. Reporting domain controllers here
        would send the reader to a remediation that does not apply.

        One case is reported as partial rather than clean. If the schema is
        extended and yet not one computer in the domain has a readable
        expiration time, there are two explanations and this check cannot
        separate them: nothing is managed, or the audit account has lost read
        access to the expiration attribute, which happens when the default
        permission on it is tightened. Both produce the same silence. The
        finding is still reported, because an estate with nothing managed is
        the more dangerous reading and should not be withheld, and a partial
        result is returned alongside it naming the ambiguity and how to settle
        it. Presenting that silence as a confident answer in either direction
        would be the dishonest option.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER ExpiredGraceDays
        How far past its expiration time a password may be before the computer
        is reported. The agent rotates on a schedule rather than at the exact
        moment of expiry, so a timestamp a little in the past is normal
        operation. Default 7.

    .PARAMETER IncludeDisabledComputers
        Whether disabled computer accounts are reported. Off by default: a
        disabled account cannot be used to join the domain and the machine is
        usually gone. Kept as an option because a machine that still exists
        and still has that local password is still a machine on the network.

    .PARAMETER ExcludedComputerNames
        SAM account names never reported. The escape hatch for machines an
        organisation has assessed, such as appliances that are domain-joined
        but cannot run the agent. Computer account names end in a dollar sign.

    .OUTPUTS
        One finding, or nothing when every eligible computer is managed and
        current. A partial result may accompany the finding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [ValidateRange(0, 3650)]
        [int] $ExpiredGraceDays = 7,

        [bool]     $IncludeDisabledComputers = $false,
        [string[]] $ExcludedComputerNames    = @()
    )

    $UAC_SERVER_TRUST_ACCOUNT = 0x2000      # a writable domain controller

    # The attributes this check reads. Expiration times only. The password
    # attributes of both generations are deliberately absent and must stay
    # absent: ms-Mcs-AdmPwd, msLAPS-Password, msLAPS-EncryptedPassword,
    # msLAPS-EncryptedPasswordHistory, msLAPS-EncryptedDSRMPassword and
    # msLAPS-EncryptedDSRMPasswordHistory. See the description, and
    # Tests/verify-laps-check.ps1, which fails if any of them appears in a
    # query this check makes.
    #
    # The two attributes below are the readable ones by design, which is why
    # this check works from an ordinary account. Microsoft's schema reference
    # gives msLAPS-PasswordExpirationTime searchFlags of 0, while every
    # password attribute carries 904, and the fCONFIDENTIAL bit in that value
    # is what keeps the passwords out of reach.
    $LEGACY_EXPIRY  = 'ms-Mcs-AdmPwdExpirationTime'
    $WINDOWS_EXPIRY = 'msLAPS-PasswordExpirationTime'

    # Whether each generation is in the schema. Read from the schema naming
    # context, which an ordinary domain user can read, rather than inferred
    # from whether any computer happens to have a value.
    $rootDse  = Get-ADRootDSE -Server $DomainName -ErrorAction Stop
    $schemaNC = [string] $rootDse.schemaNamingContext
    if (-not $schemaNC) {
        throw "The directory did not return a schema naming context for $DomainName, so whether LAPS is installed cannot be established."
    }

    $legacyInSchema = @(Get-ADObject -SearchBase $schemaNC `
        -LDAPFilter "(lDAPDisplayName=$LEGACY_EXPIRY)" `
        -Server $DomainName -ErrorAction Stop).Count -gt 0

    $windowsInSchema = @(Get-ADObject -SearchBase $schemaNC `
        -LDAPFilter "(lDAPDisplayName=$WINDOWS_EXPIRY)" `
        -Server $DomainName -ErrorAction Stop).Count -gt 0

    $generationsInSchema = @(
        if ($windowsInSchema) { 'Windows LAPS' }
        if ($legacyInSchema)  { 'legacy Microsoft LAPS' }
    )

    # -----------------------------------------------------------------------
    # Neither generation is installed. One finding about the domain, and the
    # computers are not enumerated.
    # -----------------------------------------------------------------------
    if (-not $legacyInSchema -and -not $windowsInSchema) {
        $affected = New-AffectedObject -Name $DomainName `
            -ObjectClass 'domainDNS' `
            -DistinguishedName ([string] $rootDse.defaultNamingContext) `
            -Attributes @{
                issue                  = 'LAPS is not installed in this domain'
                detail                 = 'Neither generation of LAPS has extended the schema, so no computer in the domain can be having its local administrator password managed and rotated by LAPS. Each of those passwords is whatever it was last set to, by whatever means.'
                windowsLapsInSchema    = $false
                legacyLapsInSchema     = $false
                computersExamined      = 0
            }

        return New-AuditFinding -CheckId 'AD.ACCOUNT.LAPS_MISSING' `
            -Severity 'High' `
            -DomainName $DomainName `
            -AffectedObjects @($affected) `
            -Evidence @{
                summary                 = 'LAPS is not installed in this domain. Neither the Windows LAPS nor the legacy Microsoft LAPS schema attributes are present, so no local administrator password here is being rotated by LAPS.'
                schemaExtended          = $false
                issueCount              = 1
                computersTotal          = 0
                computersExamined       = 0
                computersUnmanaged      = 0
                computersExpired        = 0
                computersManaged        = 0
                domainControllersSkipped = 0
                unreadableExpiryValues  = 0
                generationsInSchema     = @()
                parametersUsed          = @{
                    expiredGraceDays         = $ExpiredGraceDays
                    includeDisabledComputers = $IncludeDisabledComputers
                    excludedComputerNames    = $ExcludedComputerNames
                }
                propertiesRequested     = @('schema: lDAPDisplayName only')
                query                   = "Get-ADRootDSE, then Get-ADObject against the schema naming context for lDAPDisplayName '$WINDOWS_EXPIRY' and '$LEGACY_EXPIRY'"
                note                    = 'The computers were not enumerated. With the schema unextended, every computer in the domain is unmanaged by definition, and listing them would add length without adding information.'
                limitation              = 'This check reports that the control is absent. It cannot see whether those local administrator passwords are in fact identical across the estate, nor whether another password manager is in use, nor whether the local administrator account has been disabled on these machines. Confirming that is a manual step.'
            }
    }

    # -----------------------------------------------------------------------
    # The schema is extended. Examine the computers.
    #
    # Every computer object is read, rather than filtering server-side for the
    # ones missing the attribute, because the counts that make the finding
    # meaningful (how many are managed, how many are not) need both halves.
    # This is the one check in the module that reads every computer in the
    # domain, and on a large estate it is the slowest.
    # -----------------------------------------------------------------------
    $expiryProperties = @(
        if ($windowsInSchema) { $WINDOWS_EXPIRY }
        if ($legacyInSchema)  { $LEGACY_EXPIRY }
    )
    $properties = @('userAccountControl', 'operatingSystem', 'lastLogonDate') + $expiryProperties

    $computers = @(Get-ADComputer -Filter * -Properties $properties -Server $DomainName -ErrorAction Stop)

    $unmanaged         = [System.Collections.Generic.List[object]]::new()
    $expired           = [System.Collections.Generic.List[object]]::new()
    $managedCount      = 0
    $domainControllers = 0
    $disabledSkipped   = 0
    $excludedSkipped   = 0
    $unreadableExpiry  = 0
    $readableExpiry    = 0

    $now      = (Get-Date).ToUniversalTime()
    $cutoff   = $now.AddDays(-$ExpiredGraceDays)
    $examined = 0

    foreach ($computer in $computers) {
        $uac = [int] $computer.userAccountControl

        if (($uac -band $UAC_SERVER_TRUST_ACCOUNT) -ne 0) {
            $domainControllers++
            Write-Verbose "Skipping domain controller $($computer.SamAccountName)."
            continue
        }

        if ($computer.SamAccountName -and ($ExcludedComputerNames -contains $computer.SamAccountName)) {
            $excludedSkipped++
            continue
        }

        $enabled = [bool] $computer.Enabled
        if (-not $IncludeDisabledComputers -and -not $enabled) {
            $disabledSkipped++
            continue
        }

        $examined++

        # Raw values are distinguished from unparsable ones. A value that is
        # present but cannot be read as a time is not the same as no value,
        # and treating it as absent would report a managed machine as
        # unmanaged.
        $windowsRaw = if ($windowsInSchema) { $computer.$WINDOWS_EXPIRY } else { $null }
        $legacyRaw  = if ($legacyInSchema)  { $computer.$LEGACY_EXPIRY }  else { $null }

        $windowsExpiry = ConvertFrom-LapsFileTime -Value $windowsRaw
        $legacyExpiry  = ConvertFrom-LapsFileTime -Value $legacyRaw

        $hadRawValue    = (Test-LapsExpiryValuePresent -Value $windowsRaw) -or (Test-LapsExpiryValuePresent -Value $legacyRaw)
        $hasParsedValue = $null -ne $windowsExpiry -or $null -ne $legacyExpiry

        if ($hadRawValue -and -not $hasParsedValue) { $unreadableExpiry++ }
        if ($hasParsedValue) { $readableExpiry++ }

        # Windows LAPS wins where both are set. A migrated machine keeps the
        # legacy attribute behind it, and the newer agent is the one rotating.
        $generation =
            if     ($null -ne $windowsExpiry -and $null -ne $legacyExpiry) { 'both' }
            elseif ($null -ne $windowsExpiry)                              { 'windows' }
            elseif ($null -ne $legacyExpiry)                               { 'legacy' }
            else                                                           { $null }

        $expiry =
            if     ($null -ne $windowsExpiry) { $windowsExpiry }
            elseif ($null -ne $legacyExpiry)  { $legacyExpiry }
            else                              { $null }

        $record = [pscustomobject]@{
            Computer   = $computer
            Enabled    = $enabled
            Generation = $generation
            Expiry     = $expiry
            Unreadable = ($hadRawValue -and -not $hasParsedValue)
        }

        if ($null -eq $expiry) {
            $unmanaged.Add($record)
        }
        elseif ($expiry -lt $cutoff) {
            $expired.Add($record)
        }
        else {
            $managedCount++
        }
    }

    if ($unmanaged.Count -eq 0 -and $expired.Count -eq 0) { return }

    $affectedObjects = [System.Collections.Generic.List[object]]::new()

    foreach ($record in $unmanaged) {
        $detail =
            if ($record.Unreadable) {
                'This computer has an expiration value that could not be read as a time, so whether LAPS is managing it cannot be established from the directory. Treated as unmanaged, which is the cautious reading.'
            } else {
                'The LAPS schema exists in this domain and this computer has no expiration time, so its local administrator password is not being rotated by LAPS. The usual causes are a policy that does not reach this computer''s organizational unit and an agent that was never installed.'
            }

        $affectedObjects.Add((New-AffectedObject -Name $record.Computer.SamAccountName `
            -ObjectClass 'computer' `
            -DistinguishedName $record.Computer.DistinguishedName `
            -Attributes @{
                issue           = 'Not managed by LAPS'
                operatingSystem = if ($record.Computer.OperatingSystem) { [string] $record.Computer.OperatingSystem } else { $null }
                lastLogonDate   = (ConvertTo-AuditTimestamp -Value $record.Computer.LastLogonDate)
                enabled         = $record.Enabled
                lapsGeneration  = $null
                passwordExpires = $null
                detail          = $detail
            }))
    }

    foreach ($record in $expired) {
        $daysPast = [int] ($now - $record.Expiry).TotalDays

        $affectedObjects.Add((New-AffectedObject -Name $record.Computer.SamAccountName `
            -ObjectClass 'computer' `
            -DistinguishedName $record.Computer.DistinguishedName `
            -Attributes @{
                issue           = 'LAPS password overdue for rotation'
                operatingSystem = if ($record.Computer.OperatingSystem) { [string] $record.Computer.OperatingSystem } else { $null }
                lastLogonDate   = (ConvertTo-AuditTimestamp -Value $record.Computer.LastLogonDate)
                enabled         = $record.Enabled
                lapsGeneration  = $record.Generation
                passwordExpires = (ConvertTo-AuditTimestamp -Value $record.Expiry)
                detail          = ('LAPS has managed this computer but its password expired {0} day(s) ago, past the {1} day grace allowed here. The agent is not running, or the policy that was managing it has been removed. The password currently set is at least that old.' -f $daysPast, $ExpiredGraceDays)
            }))
    }

    # Severity by the worst thing found, as the other multi-issue checks do.
    #
    # Nothing here is Critical. A missing control is not an active exposure,
    # and this check cannot see whether the local passwords are actually
    # shared, which is the thing that would make it one. An estate where the
    # schema is extended and not one machine is managed is in practice an
    # estate without LAPS, so it is graded as such.
    $severity =
        if     ($examined -gt 0 -and $unmanaged.Count -eq $examined) { 'High' }
        elseif ($unmanaged.Count -gt 0)                             { 'Medium' }
        else                                                        { 'Low' }

    $summary = '{0} of {1} eligible computer(s) are not having their local administrator password rotated by LAPS.' -f ($unmanaged.Count + $expired.Count), $examined
    if ($unmanaged.Count -gt 0) {
        $summary += ' {0} have no LAPS expiration time at all.' -f $unmanaged.Count
    }
    if ($expired.Count -gt 0) {
        $summary += ' {0} were managed and have fallen out of rotation.' -f $expired.Count
    }
    if ($generationsInSchema.Count -gt 1) {
        $summary += ' Both generations of LAPS are present in the schema, which usually means a migration in progress.'
    }
    if ($unreadableExpiry -gt 0) {
        $summary += ' {0} had an expiration value that could not be read as a time and are counted as unmanaged.' -f $unreadableExpiry
    }

    $finding = New-AuditFinding -CheckId 'AD.ACCOUNT.LAPS_MISSING' `
        -Severity $severity `
        -DomainName $DomainName `
        -AffectedObjects @($affectedObjects) `
        -Evidence @{
            summary                  = $summary
            schemaExtended           = $true
            issueCount               = $unmanaged.Count + $expired.Count
            computersTotal           = $computers.Count
            computersExamined        = $examined
            computersUnmanaged       = $unmanaged.Count
            computersExpired         = $expired.Count
            computersManaged         = $managedCount
            domainControllersSkipped = $domainControllers
            disabledComputersSkipped = $disabledSkipped
            excludedComputersSkipped = $excludedSkipped
            unreadableExpiryValues   = $unreadableExpiry
            generationsInSchema      = $generationsInSchema
            parametersUsed           = @{
                expiredGraceDays         = $ExpiredGraceDays
                includeDisabledComputers = $IncludeDisabledComputers
                excludedComputerNames    = $ExcludedComputerNames
            }
            propertiesRequested      = $properties
            query                    = "Get-ADComputer -Filter * -Properties $($properties -join ',')"
            note                     = 'No password attribute is requested by this check. Only the expiration attributes are read, which is why propertiesRequested is recorded here and can be audited. Domain controllers are excluded by the SERVER_TRUST_ACCOUNT bit, because the local account they hold is the directory services restore mode account, which is a separate matter.'
            limitation               = 'This check reports that the control is absent or has lapsed. It cannot see whether the local administrator passwords on these machines are in fact identical, whether another password manager covers them, or whether the local administrator account has been disabled. Those are manual confirmations.'
        }

    # The ambiguity described at the top: the schema says LAPS exists and not
    # one computer gives a readable expiration time. Report the finding and
    # say what cannot be told apart from it.
    if ($readableExpiry -eq 0 -and $examined -gt 0) {
        return @(
            $finding
            New-AuditPartialResult -CheckId 'AD.ACCOUNT.LAPS_MISSING' `
                -Reason ("The LAPS schema is present and not one of the $examined computer(s) examined returned a readable expiration time. Two things look identical from here: no computer is managed, or this audit account has lost read access to $($expiryProperties -join ' and '). The finding above assumes the first, which is the more dangerous reading. To settle it, read the expiration attribute on one computer known to be managed, as an account that is allowed to.")
        )
    }

    return $finding
}
