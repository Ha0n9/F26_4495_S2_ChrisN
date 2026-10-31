function New-AuditFinding {
    <#
    .SYNOPSIS
        Builds one finding object in the shape defined by CONTRACT.md.

    .DESCRIPTION
        Every check returns its results through this function, so the JSON
        shape is defined in exactly one place. If the contract changes, this
        file changes and the checks do not.

        Note what is deliberately absent: there is no parameter for an
        explanation or a remediation step. Those live in
        finding-dictionary.json and are joined to the finding by CheckId in
        the dashboard. A check that wants to tell the user what to do is a
        check that is doing the dictionary's job.

    .PARAMETER CheckId
        Permanent identifier, for example AD.POLICY.WEAK_PASSWORD. This is the
        join key. Once it ships it is never renamed.

    .PARAMETER Severity
        One of Critical, High, Medium, Low, Info.

    .PARAMETER DomainName
        DNS name of the scanned domain. Used to build the finding id.

    .PARAMETER AffectedObjects
        Array of hashtables, each with Name, ObjectClass, DistinguishedName
        and Attributes.

    .PARAMETER Evidence
        Hashtable holding at least a Summary, plus whatever raw detail the
        check gathered (the parameters it ran with, the query it used).

    .PARAMETER Index
        Distinguishes multiple findings from the same check in one domain.
        Defaults to 1 because most checks emit a single finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $CheckId,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string] $Severity,

        [Parameter(Mandatory)]
        [string] $DomainName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $AffectedObjects,

        [Parameter(Mandatory)]
        [hashtable] $Evidence,

        [int] $Index = 1
    )

    [pscustomobject]@{
        findingId           = '{0}:{1}:{2}' -f $CheckId, $DomainName, $Index
        checkId             = $CheckId
        severity            = $Severity
        detectedAt          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        affectedObjectCount = $AffectedObjects.Count
        affectedObjects     = $AffectedObjects
        evidence            = $Evidence
    }
}


function New-AuditPartialResult {
    <#
    .SYNOPSIS
        Marks a check as having run successfully over only part of its ground.

    .DESCRIPTION
        There are three things a check can do, not two.

        It can complete, which the aggregator records in checksCompleted. It
        can throw, which the aggregator records in checksFailed, and the
        dashboard then refuses to call the domain clean. Between them sits a
        check that ran without error, returned real findings, and knows it did
        not see everything: a group hierarchy deeper than the traversal limit
        is the case this was written for.

        Neither existing state tells the truth about that. Recording it as
        completed presents an unexamined branch as a clean one, which is the
        failure this project argues against everywhere. Throwing it into
        checksFailed would discard the findings the check did produce, so a
        tool that found four real domain administrators would report none.

        A check therefore returns this object alongside its findings. The
        aggregator separates the two by type name and records them in
        checksPartial, and the dashboard treats a partial check as evidence
        that the scan is incomplete, exactly as it treats a failed one.

    .PARAMETER CheckId
        The check that was truncated. Same join key as a finding.

    .PARAMETER Reason
        What was not examined and why, in terms an administrator can act on.
        "Nesting deeper than 5 levels" tells somebody which parameter to
        raise; "truncated" does not.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [string] $Reason
    )

    [pscustomobject]@{
        PSTypeName = 'ADSecurityAudit.PartialResult'
        checkId    = $CheckId
        reason     = $Reason
    }
}


function New-AffectedObject {
    <#
    .SYNOPSIS
        Builds one entry for a finding's affectedObjects array.

    .DESCRIPTION
        Attributes is an open bag: which keys it holds depends on the check.
        The dictionary entry's keyAttributes decides which of them the
        dashboard promotes into table columns, so a check is free to include
        more detail than the table shows. Anything not promoted is still
        reachable in the expanded view.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]    $Name,
        [Parameter(Mandatory)] [string]    $ObjectClass,
        [Parameter(Mandatory)] [string]    $DistinguishedName,
        [Parameter(Mandatory)] [hashtable] $Attributes
    )

    [pscustomobject]@{
        name              = $Name
        objectClass       = $ObjectClass
        distinguishedName = $DistinguishedName
        attributes        = $Attributes
    }
}


function ConvertTo-AuditTimestamp {
    <#
    .SYNOPSIS
        Formats a nullable DateTime as the UTC string the contract expects,
        or $null when there is no value.

    .DESCRIPTION
        Needed because an account that has never signed in has no
        LastLogonDate at all, and the contract distinguishes "never" (null)
        from "a long time ago" (a real timestamp). Letting PowerShell
        stringify a $null DateTime would produce an empty string instead,
        which the dashboard would render as a blank cell rather than "Never".
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [Nullable[datetime]] $Value
    )

    # PowerShell unwraps a [Nullable[datetime]] parameter when it binds, so
    # $Value is a plain DateTime here, not a Nullable<DateTime>. Reaching for
    # $Value.Value therefore throws "You cannot call a method on a
    # null-valued expression" for every non-null timestamp.
    if ($null -eq $Value) { return $null }
    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
