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
        the files already written, and they are still found in domains
        today.

        A dangerous privilege granted to a broad group. SeDebugPrivilege,
        SeImpersonatePrivilege and the rest of the set below are each a
        route from ordinary access to full control of the machine the policy
        applies to.

        The guest account switched on by policy. A small thing beside the
        other two, so it is reported at a lower severity, but an enabled
        guest account is an unauthenticated foothold and it is switched on
        here rather than on each machine.

        Several decisions are worth recording.

        It reads SYSVOL rather than using the GroupPolicy module. Get-GPO
        and Get-GPOReport would be the obvious route, but they require a
        second RSAT feature installed on the auditing workstation, and the
        project's installation story is already two runtimes long. Reading
        the files directly needs nothing beyond the share every domain
        member already reads, which also keeps the check honest about the
        privilege it runs with: anything this check can see, any domain user
        can see.

        Only folders named like a GPO are treated as one. The Policies
        directory also holds PolicyDefinitions, the ADMX Central Store,
        which is not a policy object and whose several thousand ADMX and
        ADML files are neither worth reading nor meaningful to report. A
        GPO folder is named for its GUID in registry format, braces
        included, and nothing else in that directory is.

        A cpassword value is checked for the shape of real ciphertext before
        the finding claims it can be decrypted. See Test-GppCipherText.

        XML is parsed as XML. An attribute may be quoted with single or
        double quotes, both are valid, and a regular expression that knows
        only one of them silently misses the other. A file that will not
        parse is reported as unexamined rather than as clean.

        Unreadable folders and unreadable files are counted separately.
        They are different units: a folder that cannot be opened is a policy
        nobody looked at, while a file that cannot be read inside a readable
        folder leaves the rest of that policy examined. Subtracting one from
        the other, as an earlier version did, produced a count of examined
        policies that could go negative.

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
        One finding covering every risky setting found, plus partial result
        markers for anything that could not be examined.
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

    # A GPO folder is named for its GUID in registry format, braces and all.
    # PolicyDefinitions, the ADMX Central Store, lives in the same directory
    # and is not a policy object.
    $gpoFolderPattern = '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$'

    function Test-GppCipherText {
        <#
            Does this cpassword value have the shape of a real Group Policy
            Preferences password?

            A real one is Base64 of AES-256-CBC ciphertext, which means it
            must decode as Base64 and the result must be a whole number of
            16 byte blocks. GPP writes the Base64 without its trailing
            padding, so the padding is restored before decoding.

            This is a format test, not a decryption. It cannot tell a real
            encrypted password from 64 random bytes that happen to be the
            right length, and it is not meant to: the point is to stop the
            finding claiming a value is decryptable when it plainly is not,
            such as a placeholder somebody typed into a lab fixture. The
            tool never decrypts, so it never holds a plaintext password it
            would then have to be careful with.
        #>
        param([string] $Value)

        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        if ($Value -notmatch '^[A-Za-z0-9+/]+={0,2}$') { return $false }

        $padded = $Value
        $remainder = $padded.Length % 4
        if ($remainder -eq 1) { return $false }
        if ($remainder -gt 0) { $padded = $padded + ('=' * (4 - $remainder)) }

        try { $bytes = [Convert]::FromBase64String($padded) }
        catch { return $false }

        return ($bytes.Length -gt 0 -and ($bytes.Length % 16) -eq 0)
    }

    if (-not $SysvolPath) {
        $SysvolPath = "\\$DomainName\SYSVOL\$DomainName\Policies"
    }

    if (-not $DomainSid) {
        $domain = Get-ADDomain -Identity $DomainName -Server $DomainName -ErrorAction Stop
        $DomainSid = [string] $domain.DomainSID
    }

    <#
        Principals that are broader than they should be, in two kinds.

        'everyone' really does mean every account in the domain. 'guest'
        means unauthenticated or guest access, which is a smaller set of
        accounts but not a safer one, and describing it as everybody would
        be wrong. The two are reported the same way and worded differently,
        because the remediation is the same and the sentence is not.

        Matched by security identifier rather than by name, because a
        GptTmpl.inf stores SIDs and the well-known ones are invariant across
        domains and languages.
    #>
    $broadPrincipals = @{}
    $addPrincipal = {
        param([string] $Sid, [string] $Name, [string] $Scope, [string] $Describes)
        $broadPrincipals[$Sid] = [pscustomobject]@{ Name = $Name; Scope = $Scope; Describes = $Describes }
    }

    & $addPrincipal 'S-1-1-0'      'Everyone'              'everyone' 'every account in the domain, and unauthenticated access on older configurations'
    & $addPrincipal 'S-1-5-11'     'Authenticated Users'   'everyone' 'every account in the domain'
    & $addPrincipal 'S-1-5-32-545' 'Users (built-in)'      'everyone' 'every account in the domain, because Domain Users is a member of it'
    & $addPrincipal 'S-1-5-7'      'Anonymous Logon'       'guest'    'unauthenticated access, with no account at all'
    & $addPrincipal 'S-1-5-32-546' 'Guests (built-in)'     'guest'    'guest access, including the built-in Guest account when it is enabled'
    if ($DomainSid) {
        & $addPrincipal "$DomainSid-513" 'Domain Users'  'everyone' 'every account in the domain'
        & $addPrincipal "$DomainSid-514" 'Domain Guests' 'guest'    'guest access, which is a small group but not a trusted one'
    }

    $issues              = [System.Collections.Generic.List[object]]::new()
    $unreadablePolicies  = [System.Collections.Generic.List[string]]::new()
    $unreadableFiles     = [System.Collections.Generic.List[object]]::new()
    $unparsableFiles     = [System.Collections.Generic.List[object]]::new()
    $skippedDirectories  = [System.Collections.Generic.List[string]]::new()
    $policyCount         = 0

    if (-not (Test-Path -LiteralPath $SysvolPath)) {
        throw "Cannot reach the policy store at $SysvolPath. The account running the scan must be able to read SYSVOL."
    }

    $allDirectories = @(Get-ChildItem -LiteralPath $SysvolPath -Directory -ErrorAction Stop)

    foreach ($folder in $allDirectories) {
        if ($folder.Name -notmatch $gpoFolderPattern) {
            # PolicyDefinitions and anything else somebody has put here.
            # Recorded rather than passed over silently, so that a folder
            # wrongly excluded by the pattern is visible in the evidence.
            $skippedDirectories.Add($folder.Name)
            continue
        }

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
            # The whole policy is unexamined. Expected on a low-privilege
            # scan, and recorded so the result can say so rather than imply
            # the policy was clean.
            $unreadablePolicies.Add($displayName)
            Write-Verbose "Cannot read $($folder.FullName): $($_.Exception.Message)"
            continue
        }

        foreach ($file in $files) {
            $content = $null
            try {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            }
            catch {
                # One file, not one policy. The rest of this policy was
                # still examined, and conflating the two is how an earlier
                # version reported a negative number of examined policies.
                $unreadableFiles.Add([pscustomobject]@{ Policy = $displayName; File = $file.Name })
                continue
            }
            if (-not $content) { continue }

            # --- A password written into Group Policy Preferences ---------
            if ($file.Extension -eq '.xml') {
                $document = $null
                try {
                    $document = New-Object System.Xml.XmlDocument
                    # Null resolver, so a policy file from a share cannot
                    # pull in an external entity while being inspected. This
                    # is already the default on modern runtimes; it is set
                    # anyway because the file is untrusted input.
                    $document.XmlResolver = $null
                    $document.LoadXml($content)
                }
                catch {
                    # Cannot be inspected, so nothing can be said about it.
                    # Reported rather than treated as a file with no
                    # password in it.
                    $unparsableFiles.Add([pscustomobject]@{ Policy = $displayName; File = $file.Name })
                    Write-Verbose "Cannot parse $($file.FullName): $($_.Exception.Message)"
                    $document = $null
                }

                if ($document) {
                    # Every attribute in the document, whatever quoted it and
                    # whatever element carries it. A preferences file holds
                    # one per user, service or task it configures.
                    foreach ($attribute in @($document.SelectNodes('//@*'))) {
                        if ($attribute.Name -ne 'cpassword') { continue }

                        $value = [string] $attribute.Value
                        # An empty cpassword means the preference sets no
                        # password. Reporting it would be a false positive on
                        # a perfectly ordinary policy.
                        if ([string]::IsNullOrEmpty($value)) { continue }

                        $looksEncrypted = Test-GppCipherText -Value $value

                        $issues.Add([pscustomobject]@{
                            Gpo      = $displayName
                            Guid     = $folder.Name
                            Kind     = if ($looksEncrypted) { 'Stored password' } else { 'Stored password (format not recognised)' }
                            Severity = if ($looksEncrypted) { 'Critical' } else { 'High' }
                            Detail   = if ($looksEncrypted) {
                                "The file $($file.Name) stores a password in a cpassword attribute, and the value has the form of Group Policy Preferences ciphertext. The key that decrypts it was published by Microsoft, and SYSVOL is readable by every account in the domain, so treat this password as already known."
                            } else {
                                "The file $($file.Name) has a cpassword attribute whose value is not well-formed Group Policy Preferences ciphertext, so this tool cannot say it is a recoverable password. It may be a placeholder or a truncated value. The attribute should not be present at all, so confirm what wrote it and remove it."
                            }
                            Setting  = $file.Name
                            File     = $file.FullName
                            # The value itself is never recorded. A report
                            # that quoted it would become the thing it is
                            # reporting. Its length is enough to recognise
                            # the entry in the file.
                            Length   = $value.Length
                        })
                    }
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

                        $principal = $broadPrincipals[$sid]
                        $issues.Add([pscustomobject]@{
                            Gpo      = $displayName
                            Guid     = $folder.Name
                            Kind     = 'Dangerous privilege'
                            Severity = 'High'
                            Detail   = "$name is granted to $($principal.Name), which is $($principal.Describes). That privilege is a route from ordinary access to full control of the machine."
                            Setting  = $name
                            File     = $file.FullName
                            Scope    = $principal.Scope
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

    # A policy whose folder opened is examined, whether or not one of its
    # files could be read. These are policies, not files, and the two are
    # never added together.
    $policiesExamined  = $policyCount - $unreadablePolicies.Count
    $impairedPolicies  = @(@($unreadableFiles) + @($unparsableFiles) | ForEach-Object { $_.Policy } | Sort-Object -Unique)
    $policiesPartial   = @($impairedPolicies).Count
    $policiesComplete  = $policiesExamined - $policiesPartial

    $results = [System.Collections.Generic.List[object]]::new()

    if ($issues.Count -gt 0) {
        $affected = foreach ($issue in $issues) {
            $attributes = @{
                issue       = $issue.Kind
                setting     = $issue.Setting
                detail      = $issue.Detail
                policyGuid  = $issue.Guid
            }
            if ($null -ne $issue.Scope)  { $attributes['principalScope'] = $issue.Scope }
            if ($null -ne $issue.Length) { $attributes['valueLength']    = $issue.Length }

            New-AffectedObject -Name $issue.Gpo `
                -ObjectClass 'groupPolicyContainer' `
                -DistinguishedName "CN=$($issue.Guid),CN=Policies,CN=System" `
                -Attributes $attributes
        }

        $passwordCount   = @($issues | Where-Object { $_.Kind -eq 'Stored password' }).Count
        $unverifiedCount = @($issues | Where-Object { $_.Kind -eq 'Stored password (format not recognised)' }).Count
        $privilegeCount  = @($issues | Where-Object { $_.Kind -eq 'Dangerous privilege' }).Count
        $guestCount      = @($issues | Where-Object { $_.Kind -eq 'Guest account enabled' }).Count

        # Graded by the worst thing actually established. A cpassword whose
        # format was not recognised is not a confirmed recoverable password,
        # so on its own it does not reach Critical.
        $severity =
            if     ($passwordCount -gt 0)                               { 'Critical' }
            elseif ($unverifiedCount -gt 0 -or $privilegeCount -gt 0)   { 'High' }
            else                                                        { 'Medium' }

        $summary = '{0} risky setting(s) across {1} group policy object(s).' -f $issues.Count, @($issues.Gpo | Sort-Object -Unique).Count
        if ($passwordCount -gt 0) {
            $summary += ' {0} store a password in SYSVOL that any domain user can decrypt.' -f $passwordCount
        }
        if ($unverifiedCount -gt 0) {
            $summary += ' {0} carry a cpassword attribute whose value was not recognised as ciphertext, so it is reported without that claim.' -f $unverifiedCount
        }
        if ($privilegeCount -gt 0) {
            $summary += ' {0} grant a dangerous privilege to a group far broader than it should be.' -f $privilegeCount
        }
        if ($guestCount -gt 0) {
            $summary += ' {0} switch on the local guest account.' -f $guestCount
        }

        $results.Add((New-AuditFinding -CheckId 'AD.POLICY.RISKY_GPO' `
            -Severity $severity `
            -DomainName $DomainName `
            -AffectedObjects @($affected) `
            -Evidence @{
                summary                    = $summary
                issueCount                 = $issues.Count
                storedPasswordCount        = $passwordCount
                unverifiedCpasswordCount   = $unverifiedCount
                dangerousRightCount        = $privilegeCount
                guestAccountCount          = $guestCount
                policiesTotal              = $policyCount
                policiesExamined           = $policiesExamined
                policiesFullyExamined      = $policiesComplete
                policiesPartiallyExamined  = $policiesPartial
                policiesNotExamined        = $unreadablePolicies.Count
                unreadableFileCount        = $unreadableFiles.Count
                unparsableFileCount        = $unparsableFiles.Count
                nonPolicyDirectoriesSkipped = @($skippedDirectories)
                sysvolPath                 = $SysvolPath
                riskyPrivileges            = $RiskyPrivileges
                broadPrincipals            = @($broadPrincipals.Values | ForEach-Object { $_.Name } | Sort-Object)
                note                       = 'Policy is read from the SYSVOL share rather than through the GroupPolicy module, so this check needs no tooling beyond the share every domain member already reads. Only folders named for a GPO GUID are examined, which excludes the ADMX Central Store. Principals are matched by security identifier, which is invariant across domains and languages.'
                limitation                 = 'This reads what the policy says, not what it currently applies to. A policy that is unlinked, disabled or filtered out by security groups is reported the same as one in force, because its scope is held in the directory rather than in these files. A cpassword value is checked for the shape of Group Policy Preferences ciphertext and is never decrypted, so the tool confirms the format and not the plaintext.'
            }))
    }

    if ($unreadablePolicies.Count -gt 0) {
        $results.Add((New-AuditPartialResult `
            -CheckId 'AD.POLICY.RISKY_GPO' `
            -Reason ('{0} of {1} policy folder(s) could not be opened, so none of their settings were examined: {2}. Grant the audit account read access to those folders in SYSVOL to include them.' -f
                $unreadablePolicies.Count, $policyCount, (($unreadablePolicies | Select-Object -First 10) -join '; '))))
    }

    if ($unreadableFiles.Count -gt 0) {
        $named = @($unreadableFiles | Select-Object -First 10 | ForEach-Object { "$($_.Policy)/$($_.File)" })
        $results.Add((New-AuditPartialResult `
            -CheckId 'AD.POLICY.RISKY_GPO' `
            -Reason ('{0} individual file(s) could not be read inside policies that were otherwise examined, so part of those policies was not checked: {1}. The rest of each policy was examined and anything found in it is reported.' -f
                $unreadableFiles.Count, ($named -join '; '))))
    }

    if ($unparsableFiles.Count -gt 0) {
        $named = @($unparsableFiles | Select-Object -First 10 | ForEach-Object { "$($_.Policy)/$($_.File)" })
        $results.Add((New-AuditPartialResult `
            -CheckId 'AD.POLICY.RISKY_GPO' `
            -Reason ('{0} XML file(s) could not be parsed, so they were not checked for stored passwords: {1}. A malformed policy file is not evidence that it holds nothing.' -f
                $unparsableFiles.Count, ($named -join '; '))))
    }

    if ($results.Count -eq 0) { return }
    return $results.ToArray()
}
