function Invoke-ADSecurityAudit {
    <#
    .SYNOPSIS
        Runs the security checks against a domain and writes the results as
        JSON.

    .DESCRIPTION
        The aggregator. It owns three responsibilities and no detection logic
        of its own:

          1. Decide which checks to run.
          2. Run each one in isolation, so a check that throws cannot take
             the scan down with it.
          3. Assemble the scan envelope described in CONTRACT.md.

        Point 2 is the one worth defending. A check that fails is recorded
        under checksFailed with its error message, and it is kept out of
        checksCompleted. The dashboard reads that difference and tells the
        user part of the domain was not examined. Swallowing the error and
        reporting a clean scan would be the worst possible outcome for a
        security tool: it would say "nothing wrong here" about ground it
        never looked at.

        No security score is computed here. Scoring is presentation, it lives
        in the dashboard, and keeping it there means the weighting can change
        without re-running a scan against a production domain.

    .PARAMETER DomainName
        Domain to scan. Defaults to the current computer's domain.

    .PARAMETER OutputPath
        Where to write the JSON. Defaults to scan-result.json in the current
        directory.

    .PARAMETER CheckId
        Run only these checks. Defaults to all registered checks.

    .PARAMETER PassThru
        Also return the result object, for piping or inspection.

    .EXAMPLE
        Invoke-ADSecurityAudit -Verbose

    .EXAMPLE
        Invoke-ADSecurityAudit -DomainName lab.local `
            -OutputPath ..\ad-audit-dashboard\public\data\scan-result.json

        Writes straight into the folder the dashboard serves, so the result
        appears after pressing Reload from disk.
    #>
    [CmdletBinding()]
    param(
        [string]   $DomainName,
        [string]   $OutputPath = './scan-result.json',
        [string[]] $CheckId,
        [switch]   $PassThru
    )

    # The registry of checks. Adding a check means adding a file under
    # Private\Checks and one line here. Nothing else in the module changes.
    $registry = [ordered]@{
        'AD.ACCOUNT.STALE_ENABLED'                = 'Test-StaleEnabledAccount'
        'AD.POLICY.WEAK_PASSWORD'                 = 'Test-WeakPasswordPolicy'
        'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP' = 'Test-ExcessiveAdminMembership'
    }

    $requested = if ($CheckId) {
        $unknown = $CheckId | Where-Object { -not $registry.Contains($_) }
        if ($unknown) { throw "Unknown check id: $($unknown -join ', ')" }
        $CheckId
    }
    else {
        @($registry.Keys)
    }

    $startedAt = (Get-Date).ToUniversalTime()

    $domain = if ($DomainName) {
        Get-ADDomain -Identity $DomainName -ErrorAction Stop
    }
    else {
        Get-ADDomain -Current LocalComputer -ErrorAction Stop
    }

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isDomainAdmin = ([Security.Principal.WindowsPrincipal]$currentUser).IsInRole(
        [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $domain.DomainSID))

    $findings  = [System.Collections.Generic.List[object]]::new()
    $completed = [System.Collections.Generic.List[string]]::new()
    $failed    = [System.Collections.Generic.List[object]]::new()

    foreach ($id in $requested) {
        $function = $registry[$id]
        Write-Verbose "Running $id ($function)"

        try {
            $result = & $function -DomainName $domain.DNSRoot -ErrorAction Stop
            if ($result) { $findings.AddRange(@($result)) }
            $completed.Add($id)
        }
        catch {
            # Recorded, not rethrown. One broken check must not end the scan.
            Write-Warning "$id failed: $($_.Exception.Message)"
            $failed.Add([pscustomobject]@{
                checkId      = $id
                errorMessage = $_.Exception.Message
            })
        }
    }

    $result = [pscustomobject]@{
        schemaVersion = '1.0'
        scan          = [pscustomobject]@{
            scanId        = [guid]::NewGuid().ToString()
            startedAt     = $startedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
            completedAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            moduleName    = 'ADSecurityAudit'
            moduleVersion = (Get-Module ADSecurityAudit).Version.ToString()
            domain        = [pscustomobject]@{
                dnsName                = $domain.DNSRoot
                netbiosName            = $domain.NetBIOSName
                domainFunctionalLevel  = $domain.DomainMode.ToString()
                domainControllerQueried = $domain.PDCEmulator
            }
            executedBy = [pscustomobject]@{
                account              = $currentUser.Name
                hadDomainAdminRights = $isDomainAdmin
            }
            checksRequested = @($requested)
            checksCompleted = $completed.ToArray()
            checksFailed    = $failed.ToArray()
        }
        findings = $findings.ToArray()
    }

    # Depth 10 because findings nest four or five levels deep. The default of
    # 2 silently truncates the attribute bags into type names, which looks
    # like working output until you open the file.
    $json = $result | ConvertTo-Json -Depth 10
    Set-Content -Path $OutputPath -Value $json -Encoding UTF8

    Write-Verbose "Wrote $($findings.Count) finding(s) to $OutputPath"
    if ($failed.Count) {
        Write-Warning "$($failed.Count) check(s) did not run. The results are incomplete."
    }

    if ($PassThru) { $result }
}
