function Test-WeakPasswordPolicy {
    <#
    .SYNOPSIS
        Checks the default domain password policy against a baseline.

    .DESCRIPTION
        This is the reference implementation. The other checks follow the
        same shape, so read this one first.

        The pattern every check follows:
          1. Accept the baseline values as parameters, never hard code them.
          2. Query AD.
          3. Decide pass or fail.
          4. Return nothing at all when the check passes.
          5. On failure, return exactly one finding built by New-AuditFinding.

        Step 4 matters. A check that returns an empty finding and a check
        that returns nothing are different things downstream, and the
        aggregator counts findings, not calls.

        This check emits one finding covering the whole policy rather than
        one per failed setting, because an administrator fixes the password
        policy as a single piece of work. failedControls inside the evidence
        records which individual settings failed.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER MinimumPasswordLength
        Shortest password length considered acceptable.

    .PARAMETER RequireComplexity
        Whether complexity must be enabled to pass.

    .PARAMETER MinimumLockoutThreshold
        Smallest acceptable lockout threshold. A threshold of 0 in AD means
        lockout is disabled entirely, which always fails.

    .OUTPUTS
        A finding object, or nothing when the policy meets the baseline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [int]  $MinimumPasswordLength   = 14,
        [bool] $RequireComplexity       = $true,
        [int]  $MinimumLockoutThreshold = 5
    )

    # Let the caller handle a failure. The aggregator records it under
    # checksFailed so the dashboard can say this check did not run, rather
    # than silently implying the policy is fine.
    $policy = Get-ADDefaultDomainPasswordPolicy -Server $DomainName -ErrorAction Stop

    $failedControls = [System.Collections.Generic.List[string]]::new()

    if ($policy.MinPasswordLength -lt $MinimumPasswordLength) {
        $failedControls.Add('minPasswordLength')
    }
    if ($RequireComplexity -and -not $policy.ComplexityEnabled) {
        $failedControls.Add('complexityEnabled')
    }
    if ($policy.LockoutThreshold -eq 0 -or $policy.LockoutThreshold -gt $MinimumLockoutThreshold) {
        $failedControls.Add('lockoutThreshold')
    }
    if ($policy.ReversibleEncryptionEnabled) {
        $failedControls.Add('reversibleEncryptionEnabled')
    }

    # Nothing wrong, so nothing to report.
    if ($failedControls.Count -eq 0) { return }

    # Reversible encryption stores passwords in a recoverable form, which is
    # worse than any length or complexity setting, so it raises the severity
    # on its own.
    $severity = if ($failedControls -contains 'reversibleEncryptionEnabled') { 'Critical' }
                elseif ($failedControls.Count -ge 2)                         { 'Critical' }
                else                                                         { 'High' }

    $affected = New-AffectedObject -Name 'Default Domain Policy' `
        -ObjectClass 'domainDNS' `
        -DistinguishedName $policy.DistinguishedName `
        -Attributes @{
            minPasswordLength           = $policy.MinPasswordLength
            complexityEnabled           = [bool] $policy.ComplexityEnabled
            lockoutThreshold            = $policy.LockoutThreshold
            maxPasswordAgeDays          = [int] $policy.MaxPasswordAge.TotalDays
            passwordHistoryCount        = $policy.PasswordHistoryCount
            reversibleEncryptionEnabled = [bool] $policy.ReversibleEncryptionEnabled
        }

    New-AuditFinding -CheckId 'AD.POLICY.WEAK_PASSWORD' `
        -Severity $severity `
        -DomainName $DomainName `
        -AffectedObjects @($affected) `
        -Evidence @{
            summary        = 'The domain password policy failed {0} of the baseline controls.' -f $failedControls.Count
            failedControls = $failedControls.ToArray()
            parametersUsed = @{
                minPasswordLengthBaseline = $MinimumPasswordLength
                requireComplexity         = $RequireComplexity
                lockoutThresholdBaseline  = $MinimumLockoutThreshold
            }
            query          = 'Get-ADDefaultDomainPasswordPolicy'
        }
}
