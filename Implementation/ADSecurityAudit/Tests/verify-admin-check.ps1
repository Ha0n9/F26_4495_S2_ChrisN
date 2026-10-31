$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Private\Checks\Test-ExcessiveAdminMembership.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

# A check now returns findings and, when it knows it did not see everything,
# partial-result markers alongside them. Tests have to look at the two
# separately, because asserting on the mixed stream is how truncation stayed
# invisible in the first place.
function Findings { param($r) @($r) | Where-Object { $_ -and -not ($_.PSObject.TypeNames -contains 'ADSecurityAudit.PartialResult') } }
function Partials { param($r) @($r) | Where-Object { $_ -and ($_.PSObject.TypeNames -contains 'ADSecurityAudit.PartialResult') } }

$SID = 'S-1-5-21-1111111111-2222222222-3333333333'

function Get-ADDomain {
    param($Identity, $Current, $Server, $ErrorAction)
    [pscustomobject]@{
        DNSRoot = 'auditlab.test'
        DomainSID = [pscustomobject]@{ Value = $SID }
    }
}

# Groups keyed by the identity the check will ask for.
$script:groups = @{}
$script:membership = @{}
$script:groupLookups = [System.Collections.Generic.List[string]]::new()

function Get-ADGroup {
    param($Identity, $Filter, $Properties, $Server, $ErrorAction)
    $script:groupLookups.Add([string]$Identity)
    if ($script:groups.ContainsKey([string]$Identity)) { return $script:groups[[string]$Identity] }
    return $null
}

function Get-ADGroupMember {
    param($Identity, [switch]$Recursive, $Server, $ErrorAction)
    if ($Recursive) { throw "The check must not use -Recursive; it discards the membership path." }
    $key = [string]$Identity
    if ($script:membership.ContainsKey($key)) { return $script:membership[$key] }
    return @()
}

function G { param([string]$Name, [string]$Rid)
    [pscustomobject]@{ Name=$Name; DistinguishedName="CN=$Name,DC=auditlab,DC=test"
                       SID=[pscustomobject]@{Value="$SID-$Rid"} } }
function M { param([string]$Name, [string]$Rid, [string]$Class='user')
    [pscustomobject]@{ name=$Name; objectClass=$Class
                       distinguishedName="CN=$Name,OU=Staff,DC=auditlab,DC=test"
                       SID=[pscustomobject]@{Value="$SID-$Rid"} } }

function Reset-Fixture {
    $script:groups = @{ "$SID-512" = (G 'Domain Admins' '512') }
    $script:membership = @{}
    $script:groupLookups.Clear()
}

# ---------------------------------------------------------------------------
"`nResolving the group"
Reset-Fixture
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"] = @()
Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512) | Out-Null
A ($script:groupLookups -contains "$SID-512")        'looks the group up by SID'
A (-not ($script:groupLookups -contains 'Domain Admins')) 'never looks it up by name'

"`nOnly the built-in Administrator"
Reset-Fixture
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"] = @( (M 'Administrator' '500') )
A ($null -eq (Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512))) 'returns nothing'

"`nA direct ordinary member"
Reset-Fixture
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"] = @( (M 'Administrator' '500'), (M 'mtran' '1105') )
$r = Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512)
A (@($r).Count -eq 1)                                   'one finding'
A ($r.affectedObjects.name -contains 'mtran')           'reports the ordinary user'
A (-not ($r.affectedObjects.name -contains 'Administrator')) 'still excludes RID 500'
A ($r.affectedObjects[0].attributes.isDirectMember -eq $true) 'marked as direct'
A ($r.affectedObjects[0].attributes.privilegedGroup -eq 'Domain Admins') 'records the group'
A ($r.severity -eq 'Critical')                          'severity Critical'
A ($r.checkId -ceq 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP') 'check id exact'

"`nNested membership"
Reset-Fixture
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"] = @(
    (M 'Administrator' '500'), (M 'LabITSupport' '1201' 'group') )
$script:membership["CN=LabITSupport,OU=Staff,DC=auditlab,DC=test"] = @( (M 'LabHelpdeskL1' '1202' 'group') )
$script:membership["CN=LabHelpdeskL1,OU=Staff,DC=auditlab,DC=test"] = @( (M 'tech_a' '1301'), (M 'tech_b' '1302') )
$r = Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512)
A ($r.affectedObjects.name -contains 'tech_a')          'finds a user two levels down'
A ($r.affectedObjects.name -contains 'tech_b')          'finds the second one'
$techA = $r.affectedObjects | Where-Object name -eq 'tech_a'
A ($techA.attributes.isDirectMember -eq $false)         'marked as inherited'
A ($techA.attributes.membershipPath -match 'LabITSupport')  'path records the first group'
A ($techA.attributes.membershipPath -match 'LabHelpdeskL1') 'path records the second group'
A ($techA.attributes.nestingDepth -eq 2)                'records the nesting depth'
A ($r.evidence.inheritedMemberCount -eq 2)              'counts inherited members'
A ($r.evidence.directMemberCount -eq 0)                 'counts direct members'

"`nNesting disabled"
$r2 = Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512) -ResolveNestedGroups $false
$f2 = Findings $r2
$p2 = Partials $r2
A (-not ($f2.affectedObjects.name -contains 'tech_a'))  'does not expand'
A ($f2.affectedObjects.name -contains 'LabITSupport')   'still reports the nested group itself'
A (@($p2).Count -eq 1)                                  'reports the unexamined branch as a partial result'
A ($p2[0].checkId -ceq 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP') 'the marker carries the check id'
A ($p2[0].reason -match 'ResolveNestedGroups')          'the reason names the parameter to change'
$group2 = $f2.affectedObjects | Where-Object name -eq 'LabITSupport'
A ($group2.attributes.membersNotExpanded -eq $true)     'the group is flagged as not expanded'

"`nDepth limit"
$r3 = Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512) -MaxNestingDepth 1
$f3 = Findings $r3
$p3 = Partials $r3
A (-not ($f3.affectedObjects.name -contains 'tech_a'))  'stops at the limit'
# This is the defect these assertions exist for. Before, the branch was
# abandoned with nothing but a verbose message, the aggregator recorded the
# check as completed, and a hierarchy the tool never walked was presented
# exactly like one it had walked to the end.
A (@($p3).Count -eq 1)                                  'truncation is reported rather than silent'
A ($p3[0].reason -match 'MaxNestingDepth')              'the reason names the parameter to raise'
A ($p3[0].reason -match 'LabITSupport')                 'the reason names the branch that was abandoned'
A ($f3.affectedObjects.name -contains 'LabITSupport')   'the group at the limit is still reported'
$group3 = $f3.affectedObjects | Where-Object name -eq 'LabITSupport'
A ($group3.attributes.membersNotExpanded -eq $true)     'and is flagged as not expanded'
$deeper = $f3.affectedObjects | Where-Object { $_.attributes.membersNotExpanded -ne $true }
A (@($deeper).Count -eq 0)                              'nothing beyond the limit is claimed as examined'

"`nMembership cycle"
Reset-Fixture
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"] = @( (M 'group_a' '1401' 'group') )
$script:membership["CN=group_a,OU=Staff,DC=auditlab,DC=test"] = @( (M 'group_b' '1402' 'group') )
$script:membership["CN=group_b,OU=Staff,DC=auditlab,DC=test"] = @( (M 'group_a' '1401' 'group'), (M 'victim' '1501') )
$threw = $false
try { $r4 = Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512) } catch { $threw = $true }
A (-not $threw)                                          'terminates instead of recursing forever'
A ((Findings $r4).affectedObjects.name -contains 'victim') 'still finds the user beyond the cycle'
# A cycle guard is not truncation. Everything reachable was reached, so
# claiming the result is partial would cry wolf on a correct walk.
A (@(Partials $r4).Count -eq 0)                          'a guarded cycle is not reported as partial'

"`nSeveral privileged groups"
Reset-Fixture
$script:groups["$SID-519"] = (G 'Enterprise Admins' '519')
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"]     = @( (M 'mtran' '1105') )
$script:membership["CN=Enterprise Admins,DC=auditlab,DC=test"] = @( (M 'ehoang' '1106') )
$rs = @(Findings (Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512, 519)))
A ($rs.Count -eq 2)                                      'one finding per group'
A (@(Partials (Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512, 519))).Count -eq 0) 'a fully walked hierarchy is not partial'
A ((($rs.findingId | Select-Object -Unique).Count) -eq 2) 'distinct finding ids'

"`nGroup absent from this domain"
Reset-Fixture
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"] = @( (M 'mtran' '1105') )
$rs2 = @(Findings (Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512, 518)))
A ($rs2.Count -eq 1)                                     'a missing group is skipped, not an error'

"`nJSON round trip"
Reset-Fixture
$script:membership["CN=Domain Admins,DC=auditlab,DC=test"] = @( (M 'mtran' '1105') )
$r5 = Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512)
$back = $r5 | ConvertTo-Json -Depth 10 | ConvertFrom-Json
A ($back.affectedObjects[0].attributes.privilegedGroup -eq 'Domain Admins') 'survives ConvertTo-Json'

"`nError propagation"
function Get-ADGroup { param($Identity, $Filter, $Properties, $Server, $ErrorAction) throw 'Access is denied' }
$threw2 = $false
try { Test-ExcessiveAdminMembership -DomainName 'auditlab.test' -PrivilegedGroupRids @(512) } catch { $threw2 = $true }
A $threw2 'a hard failure reaches the caller'

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
