function Test-ExcessiveAdminMembership {
    <#
    .SYNOPSIS
        Finds accounts holding domain-wide privilege, including membership
        inherited through nested groups.

    .DESCRIPTION
        NOT IMPLEMENTED YET. Signature and contract settled, body is the work.

        Research notes gathered so far:

        - Get-ADGroupMember -Recursive flattens nesting, which is what makes
          the count honest: Domain Admins may show three members but expand
          to thirty. The catch is that -Recursive returns only leaf objects,
          so the nested group itself disappears from the output and the
          membership path is lost. The dashboard wants that path (the
          membershipPath attribute), so recursing manually with
          Get-ADGroupMember and tracking the chain is probably necessary.
          Worth testing both and writing down which one was chosen and why.

        - Guard against cycles. AD permits group A to contain group B while
          B contains A. A naive recursion hangs. Keep a set of visited DNs
          and cap the depth with MaxNestingDepth.

        - The Domain Admins group has a well-known RID of 512, but the group
          NAME is localized: a German domain calls it Domänen-Admins.
          Resolving by SID is the portable way, and portability is one of
          the evaluation criteria in the proposal. Build the domain SID with
          (Get-ADDomain).DomainSID and append the RID.
          512 Domain Admins, 519 Enterprise Admins, 518 Schema Admins.

        - The built-in Administrator account is expected to be a member. It
          is not a finding on its own, so exclude RID 500 or the output is
          noise on every domain.

        - A privileged account that is also stale is worse than either alone.
          Once Test-StaleEnabledAccount works, consider cross referencing.

        Implementation sketch:
          1. Resolve each privileged group by SID.
          2. Walk membership, tracking the path from group to member.
          3. Flag direct user members, and nested groups that expand to
             ordinary users.
          4. One finding per privileged group inspected, using the Index
             parameter of New-AuditFinding to keep the finding ids distinct.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER PrivilegedGroupRids
        RIDs of the groups to inspect. Defaults to Domain Admins,
        Enterprise Admins and Schema Admins.

    .PARAMETER ResolveNestedGroups
        Whether nested group membership is expanded.

    .PARAMETER MaxNestingDepth
        Depth limit, also the cycle guard.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [int[]] $PrivilegedGroupRids = @(512, 519, 518),
        [bool]  $ResolveNestedGroups = $true,
        [int]   $MaxNestingDepth     = 5
    )

    throw [System.NotImplementedException]::new(
        'Test-ExcessiveAdminMembership is not implemented yet. See the research notes in this file.')
}
