function Test-RiskyTrust {
    <#
    .SYNOPSIS
        Reports trust relationships with another domain or forest that are
        configured in a way that lets the other side reach further into this
        domain than it should.

    .DESCRIPTION
        A trust is a decision to accept authentication from somewhere you do
        not administer. That is sometimes necessary and is not a finding on
        its own. What matters is how far the other side can reach once it is
        trusted, and that is decided by a handful of attributes which are
        easy to get wrong and invisible unless somebody looks.

        Four things are reported.

        SID filtering turned off. This is the one that matters most. With
        filtering in place, the domain controller discards any authorisation
        data arriving across the trust that claims membership of a group in
        this domain. Without it, whoever controls the trusted domain can add
        the SID of this domain's Domain Admins to a ticket and be a domain
        administrator here. They do not have to compromise anything on this
        side; they simply assert it and are believed.

        A forest trust marked to be treated as external. That attribute
        lowers a forest trust's filtering to what an external trust gets,
        across the whole boundary. It is occasionally set deliberately
        during a migration and almost never removed afterwards.

        Ticket-granting-ticket delegation allowed across a forest trust.
        This is what lets unconstrained delegation on one side reach
        accounts from the other, which is the step that turns a delegation
        problem into a cross-forest one. Modern forest trusts block it by
        default; an older trust usually does not.

        Weak Kerberos encryption on the trust, and selective authentication
        left off. Both are smaller, and both are reported at a lower
        severity so they do not drown out the first three.

        Three decisions are worth recording.

        Trusts inside this forest are not reported. A parent-child or
        tree-root trust has SID filtering off by design, because a forest is
        a single security boundary and filtering inside it would break
        ordinary operation. Reporting them would mean every scan of every
        multi-domain forest opens with findings nobody should act on. This
        is the same judgement that excludes domain controllers from the
        delegation check and Administrators from the group policy check.

        Everything is read from the TrustAttributes bitmask first, falling
        back to the named properties. The bits are defined by the protocol
        and are the same on every domain and in every language, while the
        convenience properties vary with the version of the ActiveDirectory
        module. The same reasoning resolves groups by SID elsewhere in this
        module.

        Direction is recorded but is not used to decide anything. Which
        direction exposes this domain depends on how the trust was created
        and on what the administrators of the other side can do, and this
        scan can see neither. Reporting a direction as safe would be a guess
        dressed as a finding, so the direction is put on the object and the
        reader is asked to confirm it.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER ExcludedTrustTargets
        Trust targets never reported. The escape hatch for a trust an
        organisation has assessed and accepted.

    .OUTPUTS
        One finding covering every risky trust setting found, or nothing
        when the domain has no trusts outside its own forest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [string[]] $ExcludedTrustTargets = @()
    )

    # TrustAttributes bits, from the directory protocol specification. Named
    # rather than inlined, because 0x40 in a condition tells a later reader
    # nothing at all.
    $TRUST_NON_TRANSITIVE   = 0x1
    $TRUST_QUARANTINED      = 0x4        # SID filtering is on
    $TRUST_FOREST_TRANSITIVE = 0x8       # this is a forest trust
    $TRUST_CROSS_ORG        = 0x10       # selective authentication
    $TRUST_WITHIN_FOREST    = 0x20
    $TRUST_TREAT_AS_EXTERNAL = 0x40
    $TRUST_USES_RC4         = 0x80
    $TRUST_NO_TGT_DELEGATION = 0x200

    $trusts = @(Get-ADTrust -Filter * -Server $DomainName -ErrorAction Stop)

    $issues       = [System.Collections.Generic.List[object]]::new()
    $intraForest  = 0
    $examined     = 0

    foreach ($trust in $trusts) {
        $attributes = 0
        if ($null -ne $trust.TrustAttributes) { $attributes = [int] $trust.TrustAttributes }

        $target = if ($trust.Target) { [string] $trust.Target } else { [string] $trust.Name }

        # A forest is one security boundary. Filtering inside it is off on
        # purpose and reporting it would be noise on every multi-domain
        # forest that exists.
        $isIntraForest = (($attributes -band $TRUST_WITHIN_FOREST) -ne 0) -or ($trust.IntraForest -eq $true)
        if ($isIntraForest) {
            $intraForest++
            Write-Verbose "Skipping the intra-forest trust with $target."
            continue
        }

        if ($target -and ($ExcludedTrustTargets -contains $target)) { continue }

        $examined++

        $isForestTrust = ($attributes -band $TRUST_FOREST_TRANSITIVE) -ne 0
        $kind          = if ($isForestTrust) { 'forest trust' } else { 'external trust' }
        $direction     = if ($trust.Direction) { [string] $trust.Direction } else { 'unknown' }
        $transitive    = ($attributes -band $TRUST_NON_TRANSITIVE) -eq 0

        <#
            SID filtering, read from the bit first.

            The QUARANTINED bit is the authoritative statement that filtering
            is on. SIDFilteringQuarantined and SIDFilteringForestAware are
            convenience properties over the same state and are not present
            on every version of the module, so they are only consulted when
            the bitmask is unavailable.
        #>
        $filtered =
            if ($null -ne $trust.TrustAttributes) {
                ($attributes -band $TRUST_QUARANTINED) -ne 0
            }
            elseif ($isForestTrust) {
                [bool] $trust.SIDFilteringForestAware
            }
            else {
                [bool] $trust.SIDFilteringQuarantined
            }

        $treatAsExternal = ($attributes -band $TRUST_TREAT_AS_EXTERNAL) -ne 0
        $selectiveAuth   = (($attributes -band $TRUST_CROSS_ORG) -ne 0) -or ($trust.SelectiveAuthentication -eq $true)
        $usesRc4         = (($attributes -band $TRUST_USES_RC4) -ne 0) -or ($trust.UsesRC4Encryption -eq $true)
        $tgtDelegation   = ($attributes -band $TRUST_NO_TGT_DELEGATION) -eq 0

        $common = @{
            Target          = $target
            Kind            = $kind
            Direction       = $direction
            Transitive      = $transitive
            Filtered        = $filtered
            SelectiveAuth   = $selectiveAuth
            TreatAsExternal = $treatAsExternal
            UsesRc4         = $usesRc4
            TgtDelegation   = $tgtDelegation
        }

        if (-not $filtered) {
            $issues.Add([pscustomobject]($common + @{
                Issue    = 'SID filtering disabled'
                Severity = 'Critical'
                Setting  = 'TrustAttributes: QUARANTINED_DOMAIN not set'
                Detail   = "This $kind with $target does not filter the authorisation data arriving across it. Whoever controls $target can claim membership of a privileged group in this domain and be believed, without compromising anything on this side."
            }))
        }

        if ($isForestTrust -and $treatAsExternal) {
            $issues.Add([pscustomobject]($common + @{
                Issue    = 'Forest trust treated as external'
                Severity = 'High'
                Setting  = 'TrustAttributes: TREAT_AS_EXTERNAL'
                Detail   = "The forest trust with $target carries the treat-as-external attribute, which lowers its filtering to what an external trust receives across the whole forest boundary. This is usually left over from a migration."
            }))
        }

        if ($isForestTrust -and $tgtDelegation) {
            $issues.Add([pscustomobject]($common + @{
                Issue    = 'Ticket delegation allowed across the trust'
                Severity = 'High'
                Setting  = 'TrustAttributes: CROSS_ORGANIZATION_NO_TGT_DELEGATION not set'
                Detail   = "The forest trust with $target allows ticket-granting tickets to be forwarded across it, so a host trusted for unconstrained delegation on either side can collect tickets belonging to the other. This is what turns a delegation problem into a cross-forest one."
            }))
        }

        if ($usesRc4) {
            $issues.Add([pscustomobject]($common + @{
                Issue    = 'Weak encryption on the trust'
                Severity = 'Medium'
                Setting  = 'TrustAttributes: USES_RC4_ENCRYPTION'
                Detail   = "The $kind with $target is configured to use RC4, which is far weaker than AES and far quicker to attack offline."
            }))
        }

        if (-not $selectiveAuth) {
            $issues.Add([pscustomobject]($common + @{
                Issue    = 'Selective authentication not enabled'
                Severity = 'Medium'
                Setting  = 'TrustAttributes: CROSS_ORGANIZATION not set'
                Detail   = "The $kind with $target does not use selective authentication, so accounts from $target are treated as authenticated users here rather than being allowed only on the servers you nominate."
            }))
        }
    }

    if ($issues.Count -eq 0) { return }

    $affected = foreach ($issue in $issues) {
        New-AffectedObject -Name $issue.Target `
            -ObjectClass 'trustedDomain' `
            -DistinguishedName "CN=$($issue.Target),CN=System" `
            -Attributes @{
                issue                   = $issue.Issue
                setting                 = $issue.Setting
                detail                  = $issue.Detail
                trustKind               = $issue.Kind
                # Recorded, not judged. Which direction exposes this domain
                # depends on how the trust was made and on what the other
                # side's administrators can do, neither of which this scan
                # can see.
                direction               = $issue.Direction
                transitive              = [bool] $issue.Transitive
                sidFilteringEnabled     = [bool] $issue.Filtered
                selectiveAuthentication = [bool] $issue.SelectiveAuth
            }
    }

    $unfiltered  = @($issues | Where-Object { $_.Issue -eq 'SID filtering disabled' }).Count
    $external    = @($issues | Where-Object { $_.Issue -eq 'Forest trust treated as external' }).Count
    $delegation  = @($issues | Where-Object { $_.Issue -eq 'Ticket delegation allowed across the trust' }).Count
    $rc4         = @($issues | Where-Object { $_.Issue -eq 'Weak encryption on the trust' }).Count
    $noSelective = @($issues | Where-Object { $_.Issue -eq 'Selective authentication not enabled' }).Count
    $trustCount  = @($issues.Target | Sort-Object -Unique).Count

    # Graded by the worst thing found, so a domain whose only finding is a
    # missing selective authentication setting is not told it has a Critical
    # problem.
    $severity =
        if     ($unfiltered -gt 0)                      { 'Critical' }
        elseif ($external -gt 0 -or $delegation -gt 0)  { 'High' }
        else                                            { 'Medium' }

    $summary = '{0} risky setting(s) across {1} trust(s) with domains outside this forest.' -f $issues.Count, $trustCount
    if ($unfiltered -gt 0) {
        $summary += ' {0} do not filter the authorisation data arriving across them, so the other side can claim privilege here and be believed.' -f $unfiltered
    }
    if ($external -gt 0) {
        $summary += ' {0} are forest trusts marked to be treated as external.' -f $external
    }
    if ($delegation -gt 0) {
        $summary += ' {0} allow ticket delegation across the trust.' -f $delegation
    }
    if ($rc4 -gt 0) {
        $summary += ' {0} use RC4 encryption.' -f $rc4
    }
    if ($noSelective -gt 0) {
        $summary += ' {0} do not use selective authentication.' -f $noSelective
    }

    return New-AuditFinding -CheckId 'AD.TRUST.RISKY_TRUST' `
        -Severity $severity `
        -DomainName $DomainName `
        -AffectedObjects @($affected) `
        -Evidence @{
            summary                        = $summary
            issueCount                     = $issues.Count
            trustsWithIssues               = $trustCount
            trustsExamined                 = $examined
            trustsTotal                    = $trusts.Count
            intraForestTrustsSkipped       = $intraForest
            sidFilteringDisabledCount      = $unfiltered
            treatAsExternalCount           = $external
            tgtDelegationCount             = $delegation
            rc4Count                       = $rc4
            selectiveAuthenticationOffCount = $noSelective
            parametersUsed                 = @{
                excludedTrustTargets = $ExcludedTrustTargets
            }
            query                          = 'Get-ADTrust -Filter *'
            note                           = 'Trusts inside this forest are excluded, because a forest is a single security boundary and SID filtering is off within it by design. Settings are read from the TrustAttributes bitmask, which is defined by the protocol and is the same on every domain and in every language, rather than from the convenience properties, which vary by module version.'
            limitation                     = 'The direction of each trust is recorded but is not used to decide anything, because which direction exposes this domain depends on how the trust was created and on what the administrators of the other side can do, and this scan can see neither. A trust is also not a fault in itself: the question this check answers is how far the other side can reach, not whether the relationship should exist.'
        }
}
