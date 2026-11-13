<#
    Verification for Test-RiskyTrust.

    Runs against a stubbed Get-ADTrust, so it works on any machine and never
    touches a domain. The stub is defined whether or not RSAT is present,
    which serves two purposes: without it the script could not run at all,
    and with it a unit test able to reach a live domain is a unit test that
    might accidentally query one.

    This matters more for this check than for the others. The project's lab
    is a single domain with no trusts, so the live run will correctly report
    nothing, and these assertions are the only evidence that the check does
    anything at all until a second forest exists.

        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        .\Tests\verify-trust-check.ps1
#>

$ErrorActionPreference = 'Stop'

$moduleRoot =
    if     (Test-Path "$PSScriptRoot\Private\New-AuditFinding.ps1")    { $PSScriptRoot }
    elseif (Test-Path "$PSScriptRoot\..\Private\New-AuditFinding.ps1") { (Resolve-Path "$PSScriptRoot\..").Path }
    else { throw "Cannot find the ADSecurityAudit module." }

. (Join-Path $moduleRoot 'Private\New-AuditFinding.ps1')
. (Join-Path $moduleRoot 'Private\Checks\Test-RiskyTrust.ps1')

$script:p = 0; $script:f = 0
function A($c, $l) { if ($c) { $script:p++; "  pass  $l" } else { $script:f++; "  FAIL  $l" } }

# TrustAttributes bits, from the directory protocol specification. The
# fixtures are built from these rather than from raw numbers, so a reader can
# see what each trust actually is.
$NON_TRANSITIVE    = 0x1
$QUARANTINED       = 0x4      # SID filtering on
$FOREST_TRANSITIVE = 0x8      # a forest trust
$CROSS_ORG         = 0x10     # selective authentication
$WITHIN_FOREST     = 0x20
$TREAT_AS_EXTERNAL = 0x40
$USES_RC4          = 0x80
$NO_TGT_DELEGATION = 0x200

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

$script:trusts      = @()
$script:lastFilter  = $null
$script:lastServer  = $null

function Get-ADTrust {
    param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $ErrorAction)
    $script:lastFilter = [string] $Filter
    $script:lastServer = [string] $Server
    return $script:trusts
}

<#
    One trust. Attributes is the bitmask the directory holds; the named
    properties beside it are the convenience view the module provides, and
    they are set consistently unless a case is deliberately testing what
    happens when the bitmask is absent.
#>
function T {
    param(
        [string] $Target,
        [int]    $Attributes,
        [string] $Direction = 'BiDirectional',
        $IntraForest = $false,
        $SelectiveAuthentication,
        $SIDFilteringQuarantined,
        $SIDFilteringForestAware,
        $UsesRC4Encryption,
        [switch] $NoAttributes
    )
    [pscustomobject]@{
        Name                    = $Target
        Target                  = $Target
        TrustAttributes         = if ($NoAttributes) { $null } else { $Attributes }
        Direction               = $Direction
        IntraForest             = $IntraForest
        SelectiveAuthentication = $SelectiveAuthentication
        SIDFilteringQuarantined = $SIDFilteringQuarantined
        SIDFilteringForestAware = $SIDFilteringForestAware
        UsesRC4Encryption       = $UsesRC4Encryption
    }
}

function Reset-Fixture {
    $script:trusts     = @()
    $script:lastFilter = $null
    $script:lastServer = $null
}

function Run {
    param([hashtable] $Extra = @{})
    Test-RiskyTrust -DomainName 'auditlab.test' @Extra
}

# A healthy external trust: filtered, selective auth on, no RC4.
$HEALTHY_EXTERNAL = $QUARANTINED -bor $CROSS_ORG
# A healthy forest trust: filtered, selective auth on, delegation blocked.
$HEALTHY_FOREST   = $FOREST_TRANSITIVE -bor $QUARANTINED -bor $CROSS_ORG -bor $NO_TGT_DELEGATION

# ---------------------------------------------------------------------------
"`nThe query itself"
Reset-Fixture
$script:trusts = @( (T 'partner.test' $HEALTHY_EXTERNAL) )
Run | Out-Null
A ($script:lastFilter -eq '*')                        'asks the directory for every trust'
A ($script:lastServer -eq 'auditlab.test')            'against the domain being scanned'

# ---------------------------------------------------------------------------
"`nNothing to report"
Reset-Fixture
A ($null -eq (Run))                                   'a domain with no trusts produces no finding'

Reset-Fixture
$script:trusts = @( (T 'partner.test' $HEALTHY_EXTERNAL) )
A ($null -eq (Run))                                   'a healthy external trust produces no finding'

Reset-Fixture
$script:trusts = @( (T 'other.forest.test' $HEALTHY_FOREST) )
A ($null -eq (Run))                                   'a healthy forest trust produces no finding'

Reset-Fixture
# A forest is one security boundary. Filtering inside it is off by design,
# and reporting it would mean every multi-domain forest opens with findings
# nobody should act on.
$script:trusts = @( (T 'child.auditlab.test' ($WITHIN_FOREST) -IntraForest $true) )
$r = Run
A ($null -eq $r)                                      'an intra-forest trust is not reported'

Reset-Fixture
$script:trusts = @( (T 'partner.test' $CROSS_ORG) )
A ($null -eq (Run @{ ExcludedTrustTargets = @('partner.test') })) 'an explicitly excused trust is dropped'

# ---------------------------------------------------------------------------
"`nSID filtering turned off"
Reset-Fixture
# No QUARANTINED bit. This is the one that matters: the other side can claim
# membership of a privileged group here and be believed.
$script:trusts = @( (T 'partner.test' $CROSS_ORG) )
$r = Run
A (@($r).Count -eq 1)                                 'one finding'
A ($r.checkId -ceq 'AD.TRUST.RISKY_TRUST')            'check id exact'
A ($r.severity -eq 'Critical')                        'unfiltered is Critical'
A ($r.affectedObjectCount -eq 1)                      'one affected object'
A ($r.affectedObjects[0].name -eq 'partner.test')     'named by the trust target'
A ($r.affectedObjects[0].objectClass -eq 'trustedDomain') 'object class recorded'
A ($r.affectedObjects[0].attributes.issue -eq 'SID filtering disabled') 'the issue is named'
A ($r.affectedObjects[0].attributes.sidFilteringEnabled -eq $false) 'and recorded as an attribute'
A ($r.affectedObjects[0].attributes.trustKind -eq 'external trust') 'the kind of trust is recorded'
A ($r.affectedObjects[0].attributes.detail -match 'claim membership of a privileged group') 'the detail says what the other side can do'
A ($r.evidence.sidFilteringDisabledCount -eq 1)       'counted in the evidence'

Reset-Fixture
$script:trusts = @( (T 'other.forest.test' ($FOREST_TRANSITIVE -bor $CROSS_ORG -bor $NO_TGT_DELEGATION)) )
$r = Run
A ($r.severity -eq 'Critical')                        'an unfiltered forest trust is Critical too'
A ($r.affectedObjects[0].attributes.trustKind -eq 'forest trust') 'recognised as a forest trust'

# ---------------------------------------------------------------------------
"`nThe bitmask is read before the convenience properties"
Reset-Fixture
# The named properties say filtering is on; the bitmask says it is off. The
# bitmask is what the directory actually holds, so it wins.
$script:trusts = @( (T 'partner.test' $CROSS_ORG -SIDFilteringQuarantined $true -SIDFilteringForestAware $true) )
A ((Run).evidence.sidFilteringDisabledCount -eq 1)    'a property that disagrees with the bitmask does not win'

Reset-Fixture
# No bitmask at all, which older modules can produce. The properties are the
# only thing left, so they are used.
$script:trusts = @( (T 'partner.test' 0 -NoAttributes -SIDFilteringQuarantined $true -SelectiveAuthentication $true) )
A ($null -eq (Run))                                   'without a bitmask the properties are trusted'

Reset-Fixture
$script:trusts = @( (T 'partner.test' 0 -NoAttributes -SIDFilteringQuarantined $false -SelectiveAuthentication $true) )
A ((Run).evidence.sidFilteringDisabledCount -eq 1)    'and an unfiltered trust is still caught that way'

Reset-Fixture
# Known limit of the fallback, recorded rather than hidden. Without the
# bitmask there is nothing left that says whether this is a forest trust, so
# the external property is the one consulted, and a forest trust that only
# sets the forest-aware property reads as unfiltered. That is the safe way
# round: it over-reports on a module too old to return TrustAttributes
# rather than calling an unknown trust clean.
$script:trusts = @( (T 'other.forest.test' 0 -NoAttributes -SIDFilteringForestAware $true -SelectiveAuthentication $true) )
$r = Run
A ($r.evidence.sidFilteringDisabledCount -eq 1) 'without a bitmask a forest trust is reported rather than assumed clean'
A ($r.affectedObjects[0].attributes.trustKind -eq 'external trust') 'and it cannot be identified as a forest trust'

# ---------------------------------------------------------------------------
"`nA forest trust marked to be treated as external"
Reset-Fixture
$script:trusts = @( (T 'other.forest.test' ($HEALTHY_FOREST -bor $TREAT_AS_EXTERNAL)) )
$r = Run
A (@($r).Count -eq 1)                                 'reported'
A ($r.severity -eq 'High')                            'High, with filtering still on'
A ($r.affectedObjects[0].attributes.issue -eq 'Forest trust treated as external') 'the issue is named'
A ($r.affectedObjects[0].attributes.detail -match 'migration') 'and the usual cause is suggested'
A ($r.evidence.treatAsExternalCount -eq 1)            'counted in the evidence'

Reset-Fixture
# The attribute only means something on a forest trust. An external trust is
# already external, and reporting it would be a finding with no remedy.
$script:trusts = @( (T 'partner.test' ($HEALTHY_EXTERNAL -bor $TREAT_AS_EXTERNAL)) )
A ($null -eq (Run))                                   'the same attribute on an external trust is not reported'

# ---------------------------------------------------------------------------
"`nTicket delegation across a forest trust"
Reset-Fixture
$script:trusts = @( (T 'other.forest.test' ($FOREST_TRANSITIVE -bor $QUARANTINED -bor $CROSS_ORG)) )
$r = Run
A (@($r).Count -eq 1)                                 'reported when the blocking bit is absent'
A ($r.severity -eq 'High')                            'High'
A ($r.affectedObjects[0].attributes.issue -eq 'Ticket delegation allowed across the trust') 'the issue is named'
A ($r.affectedObjects[0].attributes.detail -match 'unconstrained delegation') 'and it is tied to the delegation check'
A ($r.evidence.tgtDelegationCount -eq 1)              'counted in the evidence'

Reset-Fixture
$script:trusts = @( (T 'other.forest.test' $HEALTHY_FOREST) )
A ($null -eq (Run))                                   'not reported when the blocking bit is set'

Reset-Fixture
# The bit is defined for forest trusts. An external trust does not forward
# tickets this way, so reporting it would be a false positive.
$script:trusts = @( (T 'partner.test' $HEALTHY_EXTERNAL) )
A ($null -eq (Run))                                   'an external trust is not reported for this'

# ---------------------------------------------------------------------------
"`nWeak encryption and selective authentication"
Reset-Fixture
$script:trusts = @( (T 'partner.test' ($HEALTHY_EXTERNAL -bor $USES_RC4)) )
$r = Run
A (@($r).Count -eq 1)                                 'RC4 is reported'
A ($r.severity -eq 'Medium')                          'at Medium, so it does not drown out the serious findings'
A ($r.evidence.rc4Count -eq 1)                        'counted in the evidence'

Reset-Fixture
$script:trusts = @( (T 'partner.test' $QUARANTINED) )
$r = Run
A (@($r).Count -eq 1)                                 'selective authentication left off is reported'
A ($r.severity -eq 'Medium')                          'at Medium'
A ($r.affectedObjects[0].attributes.selectiveAuthentication -eq $false) 'and recorded as an attribute'
A ($r.evidence.selectiveAuthenticationOffCount -eq 1) 'counted in the evidence'

Reset-Fixture
$script:trusts = @( (T 'partner.test' $QUARANTINED -SelectiveAuthentication $true) )
A ($null -eq (Run))                                   'the property alone is enough to clear it'

# ---------------------------------------------------------------------------
"`nSeverity is graded by the worst thing found"
Reset-Fixture
$script:trusts = @( (T 'partner.test' $USES_RC4) )    # unfiltered, no selective auth, RC4
$r = Run
A ($r.evidence.issueCount -eq 3)                      'one trust can raise several issues'
A ($r.affectedObjectCount -eq 3)                      'one affected object per issue'
A ($r.evidence.trustsWithIssues -eq 1)                'but they are counted as one trust'
A ($r.severity -eq 'Critical')                        'and the worst of them sets the severity'

Reset-Fixture
$script:trusts = @( (T 'other.forest.test' ($FOREST_TRANSITIVE -bor $QUARANTINED -bor $CROSS_ORG -bor $USES_RC4)) )
A ((Run).severity -eq 'High')                         'delegation outranks RC4'

Reset-Fixture
$script:trusts = @( (T 'partner.test' ($QUARANTINED -bor $USES_RC4 -bor $CROSS_ORG)) )
A ((Run).severity -eq 'Medium')                       'RC4 alone stays Medium'

# ---------------------------------------------------------------------------
"`nSeveral trusts at once"
Reset-Fixture
$script:trusts = @(
    (T 'child.auditlab.test' $WITHIN_FOREST -IntraForest $true)
    (T 'partner.test'        $CROSS_ORG)
    (T 'other.forest.test'   $HEALTHY_FOREST)
    (T 'legacy.test'         ($QUARANTINED -bor $CROSS_ORG -bor $USES_RC4))
)
$r = Run
A (@($r).Count -eq 1)                                 'still one finding, not one per trust'
A ($r.evidence.trustsTotal -eq 4)                     'every trust is counted'
A ($r.evidence.intraForestTrustsSkipped -eq 1)        'the intra-forest one is counted as skipped'
A ($r.evidence.trustsExamined -eq 3)                  'three were examined'
A ($r.evidence.trustsWithIssues -eq 2)                'two of them had something wrong'
A (-not ($r.affectedObjects.name -contains 'child.auditlab.test')) 'the intra-forest trust is not an affected object'
A (-not ($r.affectedObjects.name -contains 'other.forest.test'))   'nor is the healthy forest trust'
A ($r.evidence.summary -match 'outside this forest')  'the summary says what was in scope'

# ---------------------------------------------------------------------------
"`nDirection is recorded but never judged"
Reset-Fixture
foreach ($direction in 'Inbound', 'Outbound', 'BiDirectional') {
    $script:trusts = @( (T 'partner.test' $CROSS_ORG -Direction $direction) )
    $r = Run
    A ($r.affectedObjects[0].attributes.direction -eq $direction) "$direction is recorded on the object"
    A ($r.severity -eq 'Critical')                    "$direction does not change the severity"
}
Reset-Fixture
$script:trusts = @( (T 'partner.test' $CROSS_ORG) )
A ((Run).evidence.limitation -match 'direction of each trust is recorded but is not used') 'and the limitation says so plainly'

# ---------------------------------------------------------------------------
"`nEvidence records how the check ran"
Reset-Fixture
$script:trusts = @( (T 'partner.test' $CROSS_ORG) )
$r = Run @{ ExcludedTrustTargets = @('other.test') }
A ($r.evidence.parametersUsed.excludedTrustTargets -contains 'other.test') 'records the exclusions it ran with'
A ($r.evidence.query -match 'Get-ADTrust')            'records the query'
A ($r.evidence.note -match 'single security boundary') 'explains why intra-forest trusts are excluded'
A ($r.evidence.note -match 'TrustAttributes')         'and why the bitmask is preferred'

# ---------------------------------------------------------------------------
"`nJSON round trip"
Reset-Fixture
$script:trusts = @( (T 'partner.test' $CROSS_ORG -Direction 'Outbound') )
$back = (Run) | ConvertTo-Json -Depth 10 | ConvertFrom-Json
A ($back.affectedObjects[0].attributes.issue -eq 'SID filtering disabled') 'survives ConvertTo-Json'
A ($back.affectedObjects[0].attributes.direction -eq 'Outbound') 'with the direction intact'

# ---------------------------------------------------------------------------
"`nError propagation"
function Get-ADTrust { param($Identity, $Filter, $LDAPFilter, $Properties, $Server, $ErrorAction) throw 'Access is denied' }
$threw = $false
try { Run | Out-Null } catch { $threw = $true }
A $threw                                              'a hard failure reaches the caller rather than reading as no trusts'

"`n$script:p passed, $script:f failed"
if ($script:f) { exit 1 }
