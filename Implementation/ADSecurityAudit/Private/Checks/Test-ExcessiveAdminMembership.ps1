function Test-ExcessiveAdminMembership {
    <#
    .SYNOPSIS
        Finds accounts holding domain-wide privilege, including membership
        inherited through nested groups.

    .DESCRIPTION
        Members of Domain Admins can do anything in the domain, including
        reading every password hash. Each additional member is another account
        an attacker can target in order to take over the whole environment.

        Nested groups make this worse in a way that is easy to miss. A
        privileged group may appear to hold three members while actually
        expanding to thirty, because one of those three is itself a group.
        An administrator reading the membership list in the GUI sees the
        small number.

        Four details here are worth understanding, because a check written
        against a single English-language lab domain appears to get all four
        right while being wrong:

        Groups are resolved by SID, never by name. "Domain Admins" is
        localised: a German domain calls it Domaenen-Admins. A name-based
        lookup finds nothing there and then reports a clean result, which is
        the worst possible failure for a security tool. The relative
        identifier is the same on every domain: 512 Domain Admins, 519
        Enterprise Admins, 518 Schema Admins.

        The built-in Administrator account, relative identifier 500, is
        excluded. It is a member of Domain Admins on every domain that has
        ever existed, so reporting it means every scan of every domain opens
        with a finding nobody can act on.

        Membership is walked manually rather than with -Recursive. The
        recursive switch flattens nesting and returns only leaf objects, so
        the chain the privilege arrived through is lost. Without that chain
        an administrator learns that a user is a domain admin but not which
        group to edit in order to change it.

        A visited set guards against cycles. Active Directory permits group A
        to contain group B while B contains A, and a naive recursion over
        that never returns.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER PrivilegedGroupRids
        Relative identifiers of the groups to inspect.

    .PARAMETER ResolveNestedGroups
        Whether nested group membership is expanded.

    .PARAMETER MaxNestingDepth
        Depth limit, and the second line of defence against a cycle.

    .PARAMETER ExcludedRids
        Relative identifiers never reported. Defaults to the built-in
        Administrator.

    .OUTPUTS
        One finding per privileged group that holds something worth
        reporting, or nothing at all when none do.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [int[]] $PrivilegedGroupRids = @(512, 519, 518),
        [bool]  $ResolveNestedGroups = $true,
        [int]   $MaxNestingDepth     = 5,
        [int[]] $ExcludedRids        = @(500)
    )

    $domain    = Get-ADDomain -Identity $DomainName -ErrorAction Stop
    $domainSid = $domain.DomainSID.Value

    $findings = [System.Collections.Generic.List[object]]::new()
    $index    = 0

    foreach ($rid in $PrivilegedGroupRids) {
        $groupSid = '{0}-{1}' -f $domainSid, $rid

        # A domain that does not hold this group is not an error. Enterprise
        # Admins and Schema Admins live in the forest root, so a child domain
        # legitimately has neither.
        $group = Get-ADGroup -Identity $groupSid -Server $DomainName -ErrorAction SilentlyContinue
        if (-not $group) {
            Write-Verbose "Group with RID $rid not present in $DomainName, skipping."
            continue
        }

        $members = [System.Collections.Generic.List[object]]::new()
        $visited = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        [void] $visited.Add($group.DistinguishedName)

        # Walk breadth first, carrying the path each member arrived through.
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue([pscustomobject]@{
            Identity = $group.DistinguishedName
            Path     = @($group.Name)
            Depth    = 0
        })

        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue()

            $children = @(Get-ADGroupMember -Identity $current.Identity -Server $DomainName -ErrorAction Stop)

            foreach ($child in $children) {
                $childSid = $child.SID.Value

                # The built-in Administrator and anything else deliberately
                # excused.
                $childRid = ($childSid -split '-')[-1]
                if ($ExcludedRids -contains [int] $childRid) { continue }

                $path = $current.Path + $child.name

                if ($child.objectClass -eq 'group') {
                    if (-not $ResolveNestedGroups) {
                        # Not expanding, but the group itself is still worth
                        # reporting: a group inside a privileged group is how
                        # membership hides.
                        $members.Add([pscustomobject]@{
                            Member        = $child
                            Path          = $path
                            IsDirect      = ($current.Depth -eq 0)
                            IsGroup       = $true
                        })
                        continue
                    }

                    if ($current.Depth + 1 -ge $MaxNestingDepth) {
                        Write-Verbose "Depth limit reached at $($child.name), not expanding further."
                        continue
                    }

                    # The cycle guard. A distinguished name already seen in
                    # this group's walk is not queued again.
                    if (-not $visited.Add($child.distinguishedName)) {
                        Write-Verbose "Already visited $($child.distinguishedName), skipping to avoid a cycle."
                        continue
                    }

                    $queue.Enqueue([pscustomobject]@{
                        Identity = $child.distinguishedName
                        Path     = $path
                        Depth    = $current.Depth + 1
                    })
                    continue
                }

                if ($child.objectClass -ne 'user') { continue }

                $members.Add([pscustomobject]@{
                    Member   = $child
                    Path     = $path
                    IsDirect = ($current.Depth -eq 0)
                    IsGroup  = $false
                })
            }
        }

        if ($members.Count -eq 0) { continue }

        $affected = foreach ($entry in $members) {
            New-AffectedObject -Name $entry.Member.name `
                -ObjectClass $entry.Member.objectClass `
                -DistinguishedName $entry.Member.distinguishedName `
                -Attributes @{
                    privilegedGroup = $group.Name
                    # Read left to right: the privileged group, then each
                    # group the privilege passed through, then the member.
                    membershipPath  = ($entry.Path -join ' -> ')
                    isDirectMember  = [bool] $entry.IsDirect
                    nestingDepth    = $entry.Path.Count - 2
                }
        }

        $directCount   = @($members | Where-Object { $_.IsDirect }).Count
        $inheritedCount = $members.Count - $directCount

        $summary = if ($inheritedCount -gt 0) {
            '{0} holds {1} account(s) with domain-wide privilege: {2} directly and {3} through nested groups.' -f
                $group.Name, $members.Count, $directCount, $inheritedCount
        }
        else {
            '{0} holds {1} account(s) with domain-wide privilege.' -f $group.Name, $members.Count
        }

        $index++
        $findings.Add((New-AuditFinding -CheckId 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP' `
            -Severity 'Critical' `
            -DomainName $DomainName `
            -AffectedObjects @($affected) `
            -Index $index `
            -Evidence @{
                summary             = $summary
                privilegedGroup     = $group.Name
                privilegedGroupSid  = $groupSid
                directMemberCount   = $directCount
                inheritedMemberCount = $inheritedCount
                parametersUsed      = @{
                    privilegedGroupRids = $PrivilegedGroupRids
                    resolveNestedGroups = $ResolveNestedGroups
                    maxNestingDepth     = $MaxNestingDepth
                    excludedRids        = $ExcludedRids
                }
                query               = 'Get-ADGroup -Identity <domain SID>-<RID>; Get-ADGroupMember walked one level at a time'
                note                = 'Membership is walked manually rather than with -Recursive, because -Recursive discards the chain the privilege arrived through.'
            }))
    }

    if ($findings.Count -eq 0) { return }
    return $findings.ToArray()
}
