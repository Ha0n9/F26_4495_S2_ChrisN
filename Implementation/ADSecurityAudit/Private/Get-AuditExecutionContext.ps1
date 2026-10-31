function Get-AuditExecutionContext {
    <#
    .SYNOPSIS
        Reports which account the scan is running as, and whether that account
        holds domain-wide privilege.

    .DESCRIPTION
        Pulled out of the aggregator for two reasons.

        It is the only part of the aggregator that cannot run anywhere but
        Windows: WindowsIdentity.GetCurrent throws on any other platform. With
        it inline, nothing about the aggregator could be tested without a
        Windows host and a domain, which meant the code that decides whether a
        check is recorded as completed, failed or partial had no test at all.
        Behind a function, a test can supply a known context and exercise that
        decision anywhere.

        It is also the honest place for this question. The scan records the
        account it ran as so that a reader knows what the tool could and could
        not see, which matters precisely because the tool is designed to run
        without administrative rights.

    .PARAMETER Domain
        The domain object from Get-ADDomain. Its DomainSID is needed to ask
        the question about this domain rather than about any domain.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Domain
    )

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isDomainAdmin = ([Security.Principal.WindowsPrincipal] $currentUser).IsInRole(
        [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $Domain.DomainSID))

    [pscustomobject]@{
        account              = $currentUser.Name
        hadDomainAdminRights = [bool] $isDomainAdmin
    }
}
