function Test-RiskyGroupPolicy {
    <#
    .SYNOPSIS
        Reads the policy files in SYSVOL and reports Group Policy settings
        that hand privilege to people who should not have it.

    .DESCRIPTION
        Group Policy is stored as files in SYSVOL, and SYSVOL is readable by
        every authenticated user, because every machine in the domain has to
        read it to apply policy. That is the premise of this check and also
        the reason two of the three problems it looks for are dangerous: an
        ordinary user can read them without touching a domain controller's
        administrative interfaces.

        Three things are reported.

        A password stored in Group Policy Preferences. Preferences that set
        a local account password, map a drive or create a scheduled task
        write that password into an XML file in SYSVOL as a cpassword
        attribute. It is encrypted with AES, and Microsoft published the key
        in the MSDN documentation, so it is decryptable by anyone who can
        read the file, which is everyone. Microsoft removed the ability to
        create these in MS14-025, but removing the feature did not remove
        the files already written, and they are still found in domains today.
        This is Critical whenever it appears.

        A dangerous privilege granted to a broad group. SeDebugPrivilege,
        SeImpersonatePrivilege and the rest of the set below are each a
        route from ordinary access to full control of the machine the policy
        applies to. Granted to Authenticated Users or Domain Users, that is
        every account in the domain on every machine the policy reaches.

        The guest account switched on by policy. A small thing beside the
        other two, so it is reported at a lower severity, but an enabled
        guest account is an unauthenticated foothold and it is switched on
        here rather than on each machine.

        Two decisions are worth recording.

        It reads SYSVOL rather than using the GroupPolicy module. Get-GPO
        and Get-GPOReport would be the obvious route, but they require a
        second RSAT feature installed on the auditing workstation, and the
        project's installation story is already two runtimes long. Reading
        the files directly needs nothing beyond the share every domain
        member already reads, which also keeps the check honest about the
        privilege it runs with: anything this check can see, any domain user
        can see.

        Principals are matched by security identifier, never by name. A
        GptTmpl.inf records them as SIDs already, and the well-known ones
        are invariant across domains and languages, so there is nothing to
        translate and nothing to get wrong on a domain that is not in
        English. This is the same reasoning the privileged membership check
        uses for group resolution.

        A policy folder that cannot be read is reported as a partial result
        rather than passed over. A low-privilege account will meet folders
        it cannot open, and a check that skipped them silently would present
        unexamined policy as clean policy.

    .PARAMETER DomainName
        DNS name of the domain being scanned.

    .PARAMETER SysvolPath
        Where the policy folders live. Defaults to the domain's own SYSVOL
        share. Exposed as a parameter so the parsing can be tested against a
        directory of real files rather than against a mocked filesystem.

    .PARAMETER DomainSid
        The domain's SID, used to recognise Domain Users and Domain Guests.
        Looked up when it is not supplied.

    .PARAMETER RiskyPrivileges
        Which privileges count as dangerous. Overridable because an
        organisation may have a considered reason to treat the list
        differently, and hardcoding it would make that an argument with the
        tool rather than a setting.

    .OUTPUTS
        One finding covering every risky setting found, plus a partial
        result marker for any policy folder that could not be read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DomainName,

        [string]   $SysvolPath,
        [string]   $DomainSid,
        [string[]] $RiskyPrivileges = @(
            'SeDebugPrivilege'          # read and write any process, including LSASS
            'SeImpersonatePrivilege'    # the potato family of local escalations
            'SeAssignPrimaryTokenPrivilege'
            'SeTcbPrivilege'            # act as part of the operating system
            'SeCreateTokenPrivilege'
            'SeLoadDriverPrivilege'     # load code into the kernel
            'SeBackupPrivilege'         # read any file, ignoring its permissions
            'SeRestorePrivilege'        # write any file, ignoring its permissions
            'SeTakeOwnershipPrivilege'
        )
    )

    if (-not $SysvolPath) {
        $SysvolPath = "\\$DomainName\SYSVOL\$DomainName\Policies"
    }

    if (-not $DomainSid) {
        $domain = Get-ADDomain -Identity $DomainName -Server $DomainName -ErrorAction Stop
        $DomainSid = [string] $domain.DomainSID
    }

    # Well-known SIDs for principals that effectively mean "everybody".
    # Written out rather than resolved by name: a GptTmpl.inf stores SIDs,
    # and the well-known ones do not change between domains or languages.
    $broadPrincipals = @{
        'S-1-1-0'      = 'Everyone'
        'S-1-5-7'      = 'Anonymous Logon'
        'S-1-5-11'     = 'Authenticated Users'
        'S-1-5-32-545' = 'Users (built-in)'
        'S-1-5-32-546' = 'Guests (built-in)'
    }
    if ($DomainSid) {
        $broadPrincipals["$DomainSid-513"] = 'Domain Users'
        $broadPrincipals["$DomainSid-514"] = 'Domain Guests'
    }

    $issues      = [System.Collections.Generic.List[object]]::new()
    $unreadable  = [System.Collections.Generic.List[string]]::new()
    $policyCount = 0

    if (-not (Test-Path -LiteralPath $SysvolPath)) {
        throw "Cannot reach the policy store at $SysvolPath. The account running the scan must be able to read SYSVOL."
    }

    $policyFolders = @(Get-ChildItem -LiteralPath $SysvolPath -Directory -ErrorAction Stop)

    foreach ($folder in $policyFolders) {
        $policyCount++

        # The folder name is the GPO's GUID. Its display name lives in the
        # directory, not in SYSVOL, so it is looked up separately and the
        # GUID is used when the lookup finds nothing.
        $displayName = $folder.Name
        $gpoObject = Get-ADObject -LDAPFilter "(cn=$($folder.Name))" -Properties displayName -Server $DomainName -ErrorAction SilentlyContinue
        if ($gpoObject -and $gpoObject.displayName) {
            $displayName = [string] $gpoObject.displayName
        }

        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $folder.FullName -Recurse -File -ErrorAction Stop)
        }
        catch {
            # Expected on a low-privilege scan. Recorded so the result can
            # say which policy was not examined, rather than implying it was.
            $unreadable.Add($displayName)
            Write-Verbose "Cannot read $($folder.FullName): $($_.Exception.Message)"
            continue
        }

        foreach ($file in $files) {
            $content = $null
            try {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            }
            catch {
                $unreadable.Add("$displayName ($($file.Name))")
                continue
            }
            if (-not $content) { continue }

            # --- A password written into Group Policy Preferences ---------
            if ($file.Extension -eq '.xml' -and $content -match 'cpassword') {
                foreach ($match in [regex]::Matches($content, 'cpassword\s*=\s*"([^"]*)"')) {
                    $value = $match.Groups[1].Value
                    # An empty cpassword means the preference sets no
                    # password. Reporting it would be a false positive on a
                    # perfectly ordinary policy.
                    if (-not $value) { continue }

                    $issues.Add([pscustomobject]@{
                        Gpo      = $displayName
                        Guid     = $folder.Name
                        Kind     = 'Stored password'
                        Severity = 'Critical'
                        Detail   = "The file $($file.Name) stores a password as a cpassword attribute. The key that decrypts it is public, and SYSVOL is readable by every account in the domain."
                        Setting  = $file.Name
                        File     = $file.FullName
                    })
                }
            }

            # --- Security settings ----------------------------------------
            if ($file.Name -ne 'GptTmpl.inf') { continue }

            $section = ''
            foreach ($line in ($content -split "`r?`n")) {
                $line = $line.Trim()
                if (-not $line -or $line.StartsWith(';')) { continue }
                if ($line -match '^\[(.+)\]$') { $section = $Matches[1].Trim(); continue }
                if ($line -notmatch '^([^=]+)=(.*)$') { continue }

                $name  = $Matches[1].Trim()
                $value = $Matches[2].Trim()

                if ($section -eq 'Privilege Rights' -and ($RiskyPrivileges -contains $name)) {
                    foreach ($entry in ($value -split ',')) {
                        # Entries are written as *S-1-5-11. A name instead of
                        # a SID is possible in a hand-edited file, and is
                        # left alone rather than guessed at.
                        $sid = $entry.Trim().TrimStart('*')
                        if (-not $broadPrincipals.ContainsKey($sid)) { continue }

                        $issues.Add([pscustomobject]@{
                            Gpo      = $displayName
                            Guid     = $folder.Name
                            Kind     = 'Dangerous privilege'
                            Severity = 'High'
                            Detail   = "$name is granted to $($broadPrincipals[$sid]), which is every account this policy reaches. That privilege is a route from ordinary access to full control of the machine."
                            Setting  = $name
                            File     = $file.FullName
                        })
                    }
                }

                if ($section -eq 'System Access' -and $name -eq 'EnableGuestAccount' -and $value -eq '1') {
                    $issues.Add([pscustomobject]@{
                        Gpo      = $displayName
                        Guid     = $folder.Name
                        Kind     = 'Guest account enabled'
                        Severity = 'Medium'
                        Detail   = 'This policy switches the local guest account on, which gives unauthenticated access to every machine it reaches.'
                        Setting  = 'EnableGuestAccount'
                        File     = $file.FullName
                    })
                }
            }
        }
    }

    $results = [System.Collections.Generic.List[object]]::new()

    if ($issues.Count -gt 0) {
        $affected = foreach ($issue in $issues) {
            New-AffectedObject -Name $issue.Gpo `
                -ObjectClass 'groupPolicyContainer' `
                -DistinguishedName "CN=$($issue.Guid),CN=Policies,CN=System" `
                -Attributes @{
                    issue       = $issue.Kind
                    setting     = $issue.Setting
                    detail      = $issue.Detail
                    policyGuid  = $issue.Guid
                }
        }

        $passwordCount  = @($issues | Where-Object { $_.Kind -eq 'Stored password' }).Count
        $privilegeCount = @($issues | Where-Object { $_.Kind -eq 'Dangerous privilege' }).Count
        $guestCount     = @($issues | Where-Object { $_.Kind -eq 'Guest account enabled' }).Count

        # Graded by the worst thing found rather than fixed, so that a domain
        # whose only finding is an enabled guest account is not told it has a
        # Critical problem.
        $severity =
            if     ($passwordCount -gt 0)  { 'Critical' }
            elseif ($privilegeCount -gt 0) { 'High' }
            else                           { 'Medium' }

        $summary = '{0} risky setting(s) across {1} group policy object(s).' -f $issues.Count, @($issues.Gpo | Sort-Object -Unique).Count
        if ($passwordCount -gt 0) {
            $summary += ' {0} store a password in SYSVOL that any domain user can decrypt.' -f $passwordCount
        }
        if ($privilegeCount -gt 0) {
            $summary += ' {0} grant a dangerous privilege to a group that means everybody.' -f $privilegeCount
        }
        if ($guestCount -gt 0) {
            $summary += ' {0} switch on the local guest account.' -f $guestCount
        }

        $results.Add((New-AuditFinding -CheckId 'AD.POLICY.RISKY_GPO' `
            -Severity $severity `
            -DomainName $DomainName `
            -AffectedObjects @($affected) `
            -Evidence @{
                summary              = $summary
                issueCount           = $issues.Count
                storedPasswordCount  = $passwordCount
                dangerousRightCount  = $privilegeCount
                guestAccountCount    = $guestCount
                policiesExamined     = $policyCount - $unreadable.Count
                policiesTotal        = $policyCount
                sysvolPath           = $SysvolPath
                riskyPrivileges      = $RiskyPrivileges
                broadPrincipals      = @($broadPrincipals.Values | Sort-Object)
                note                 = 'Policy is read from the SYSVOL share rather than through the GroupPolicy module, so this check needs no tooling beyond the share every domain member already reads. Principals are matched by security identifier, which is invariant across domains and languages.'
                limitation           = 'This reads what the policy says, not what it currently applies to. A policy that is unlinked, disabled or filtered out by security groups is reported the same as one in force, because its scope is held in the directory rather than in these files.'
            }))
    }

    if ($unreadable.Count -gt 0) {
        $results.Add((New-AuditPartialResult `
            -CheckId 'AD.POLICY.RISKY_GPO' `
            -Reason ('{0} of {1} policy folder(s) could not be read, so their settings were not examined: {2}. Grant the audit account read access to those folders in SYSVOL to include them.' -f
                $unreadable.Count, $policyCount, (($unreadable | Select-Object -First 10) -join '; '))))
    }

    if ($results.Count -eq 0) { return }
    return $results.ToArray()
}
