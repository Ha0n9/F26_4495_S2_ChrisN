# ADSecurityAudit

PowerShell module that scans an Active Directory domain for common security
misconfigurations and writes the results as structured JSON for the dashboard
to render.

## Status

Seven checks are implemented. The first three have been run against a live
domain (`auditlab.test`) from an ordinary domain user account. The two
delegation-related checks, the group policy check and the trust check have
been verified against stubs and fixtures, and are waiting on a lab run.

| Check | Id | Severity | Status |
|---|---|---|---|
| Weak domain password policy | `AD.POLICY.WEAK_PASSWORD` | Critical or High | Implemented |
| Stale enabled accounts | `AD.ACCOUNT.STALE_ENABLED` | High | Implemented |
| Excessive privileged group membership | `AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP` | Critical | Implemented |
| Kerberoastable service accounts | `AD.PRIVILEGE.KERBEROASTING` | Critical, High or Medium | Implemented |
| Unconstrained delegation | `AD.PRIVILEGE.UNCONSTRAINED_DELEGATION` | Critical or High | Implemented |
| Risky group policy settings | `AD.POLICY.RISKY_GPO` | Critical, High or Medium | Implemented |
| Risky domain or forest trusts | `AD.TRUST.RISKY_TRUST` | Critical, High or Medium | Implemented |
| Local administrator passwords not managed by LAPS | `AD.ACCOUNT.LAPS_MISSING` | High, Medium or Low | Implemented |

Every check in the proposal is now implemented. What remains is evaluation,
not detection.

The LAPS check is the only one that reports something missing rather than
something present, and that shape has consequences worth reading before the
output is trusted.

It never asks for a password. Only the expiration attributes are read, the
property list it sends to the directory is recorded in the evidence as
`propertiesRequested` so a reader can audit it, and
`Tests/verify-laps-check.ps1` fails if any password attribute of either
generation appears in any query the check makes. The point is not only that
an ordinary account cannot read those attributes. It is that a tool which
asks for every local administrator password in the domain would have to be
trusted with them, and this one is built to need no such trust.

It also reports one case as partial rather than clean. If the schema says
LAPS exists and not one computer returns a readable expiration time, two
explanations look identical from an ordinary account: nothing is managed, or
the audit account has lost read access to the attribute. The finding is still
reported, at High, because an unmanaged estate is the more dangerous reading
and should not be withheld. A partial result goes out beside it naming the
other explanation and how to settle it.

The trust check carries a gap worth stating plainly. The current lab is a
single domain with no trusts, so a lab run exercises only the path where the
check reads the directory and correctly reports nothing. Every judgement it
makes is covered by `Tests/verify-trust-check.ps1` against a stubbed
`Get-ADTrust`, and nothing more than that has been demonstrated. Closing the
gap needs the second lab domain planned for the portability test, and until
then the check should not be described as lab-verified.

Kerberoasting and unconstrained delegation were taken first because both are
named in the CISA, NSA and ASD joint advisory on Active Directory
compromise.

The Kerberoasting check derives its severity from what it finds rather than
declaring one. A service account that is also privileged is Critical, RC4 or
a long-unchanged password is High, and service accounts that are all AES and
all recently rotated are Medium. The last tier exists because reporting a
well-configured service account at High teaches an administrator that the
check cries wolf.

## Requirements

- PowerShell 5.1 or 7
- RSAT ActiveDirectory module
- A domain-joined machine
- An ordinary domain account that can read the directory. Domain Admin is
  **not** required, and the scan records which rights it ran with so partial
  results are visible rather than silently incomplete.

Run in a normal, non-elevated session signed in as the audit account. An
elevated session can place the process in a local machine context rather than
the domain account context, and the Active Directory cmdlets then fail to
reach Active Directory Web Services with a misleading error.

## Running it

```powershell
Import-Module .\ADSecurityAudit.psd1 -Force

# Scan the current domain
Invoke-ADSecurityAudit -Verbose

# Write straight into the folder the dashboard serves
Invoke-ADSecurityAudit -OutputPath ..\ad-audit-dashboard\public\data\scan-result.json

# Run one check while developing it
Invoke-ADSecurityAudit -CheckId AD.ACCOUNT.STALE_ENABLED -PassThru
```

### Per-check parameters

`-CheckParameter` passes arguments to an individual check without affecting
the others or editing the check itself:

```powershell
Invoke-ADSecurityAudit -CheckParameter @{
    'AD.ACCOUNT.STALE_ENABLED' = @{ NewAccountGraceDays = 0 }
}
```

That example is what a freshly seeded test lab needs. By default an account
created in the last 30 days is excused for never having signed in, because
somebody hired last week has not had time to use their account. A lab seeded
an hour ago would otherwise report nothing.

The dashboard exposes the same setting beside its Run scan button.

### What normal output looks like

A warning that one or more checks did not run is expected behaviour, not a
crash. Checks that fail are recorded rather than allowed to end the scan.

## Layout

```
ADSecurityAudit/
  ADSecurityAudit.psd1          Manifest
  ADSecurityAudit.psm1          Loader: dot sources everything, exports Public
  Public/
    Invoke-ADSecurityAudit.ps1  Aggregator, JSON envelope, per-check parameters
  Private/
    New-AuditFinding.ps1        Builds finding objects, and partial-result
                                markers, to the contract
    Get-AuditExecutionContext.ps1  Which account the scan runs as. Separate
                                because it is the only Windows-only part of
                                the aggregator, so tests can replace it
    Checks/
      Test-WeakPasswordPolicy.ps1
      Test-StaleEnabledAccount.ps1
      Test-ExcessiveAdminMembership.ps1
      Test-KerberoastableAccount.ps1
      Test-UnconstrainedDelegation.ps1
      Test-RiskyGroupPolicy.ps1
      Test-RiskyTrust.ps1
      Test-LapsDeployment.ps1
  Tests/
    verify-stale-check.ps1      32 assertions
    verify-admin-check.ps1      40 assertions
    verify-kerberoast-check.ps1 50 assertions
    verify-delegation-check.ps1 96 assertions
    verify-gpo-check.ps1       185 assertions
    verify-trust-check.ps1      74 assertions
    verify-laps-check.ps1      134 assertions
    verify-aggregator.ps1       32 assertions
    verify-lab-seeding.ps1      72 assertions, over ..\..\Lab
```

## Testing

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Tests\verify-stale-check.ps1
.\Tests\verify-admin-check.ps1
.\Tests\verify-kerberoast-check.ps1
.\Tests\verify-delegation-check.ps1
.\Tests\verify-gpo-check.ps1
.\Tests\verify-trust-check.ps1
.\Tests\verify-laps-check.ps1
.\Tests\verify-aggregator.ps1
.\Tests\verify-lab-seeding.ps1
```

The tests stub the ActiveDirectory cmdlets, so they run on any machine and
never touch a domain. They encode the behaviour that is easy to get wrong and
that a check written against one English-language lab appears to get right:

- Never signed in is reported as null, not as a very old date.
- An account created inside the grace window is not stale.
- Privileged groups are resolved by SID, with an assertion that the check
  never looks one up by name.
- The built-in Administrator (RID 500) is excluded.
- Membership is walked one level at a time; the test fails the check if it
  calls `Get-ADGroupMember -Recursive`, which discards the membership path.
- A membership cycle terminates, and a user beyond the cycle is still found.
- Computer accounts and group managed service accounts are never queried for
  Kerberoasting, asserted against the LDAP filter the check actually sends.
- An absent `msDS-SupportedEncryptionTypes` is reported as RC4 permitted, and
  so is a zero. Absence is not a hardening signal, and treating it as one
  would be the quiet kind of wrong.
- `krbtgt` holds a service principal name on every domain and is excluded by
  RID 502, the same way RID 500 is excluded from the membership check.
- A password that was never set reports a null age rather than zero, so the
  check never calls it stale on the strength of a missing value.
- Domain controllers are excluded from the unconstrained delegation check by
  the SERVER_TRUST_ACCOUNT bit, not by an organizational unit or a group
  name. Every writable controller holds the delegation flag by design.
- That check re-reads `userAccountControl` itself rather than trusting the
  LDAP filter that selected the account, because a check that trusts a filter
  it never evaluated cannot notice when the filter is wrong.
- It asks `Get-ADServiceAccount` as well as `Get-ADComputer` and
  `Get-ADUser`, because the delegation flag lives in `userAccountControl` and
  managed service accounts have one. An account returned by two of those
  queries is reported once.
- Each account is classified by the object class the directory reports, not
  by the query that returned it, so a group managed service account is not
  described as a user or a computer.
- Property lists are per cmdlet. `operatingSystem` and `dNSHostName` belong
  to the computer class, and asking `Get-ADUser` for them risks an
  invalid-property error that would fail the whole check on every domain.
- Trusts are judged from the `TrustAttributes` bitmask, and a convenience
  property that disagrees with it does not win. A test sets the two against
  each other to prove which one is read.
- A trust inside this forest is skipped, recognised either by the
  `WITHIN_FOREST` bit or by the `IntraForest` property. Without that, every
  multi-domain forest would open with a Critical finding that is correct by
  design and cannot be fixed.
- The direction of a trust is written onto the affected object and never used
  to grade it. A test runs the same trust inbound, outbound and both ways and
  asserts the severity does not move.
- The LAPS check asks the schema whether each generation is installed before
  it reads a single computer, and builds its property list from the answer.
  Asking the directory for an attribute that is not in the schema is an
  error, so the alternative would be a check that fails on exactly the
  domains it most needs to report on.
- Where the schema is not extended at all, the computers are not enumerated
  and the finding describes the domain. Listing every computer in the domain
  as unmanaged would be true and useless.
- A LAPS expiration value is read as a FILETIME, and three outcomes are kept
  apart: no value, a value that is a time, and a value that is not. Only the
  last is counted as unreadable. Zero is what LAPS writes before a password
  exists, so it counts as absent, and treating it as malformed would put a
  number in the report claiming corrupt data where there is an ordinary
  initial state.
- Windows LAPS wins over legacy where a computer has both, because a migrated
  machine keeps the old attribute behind it and the newer agent is the one
  rotating.

`verify-gpo-check.ps1` is the one test that does not stub a filesystem. The
group policy check takes its policy store as a parameter, so each case
builds a real directory of real policy files in a temporary folder and lets
the check read them. Parsing is the part most likely to be wrong, and a
mocked filesystem would not exercise it.

`verify-lab-seeding.ps1` covers the seeding script rather than the module. It
runs the real script against a directory held in memory and checks that
`-WhatIf` writes nothing, that a second run creates nothing twice, that a
failed creation does not end the run after earlier sections have already
changed the directory, and that `ground-truth.json` lists what was actually
created. That last one matters most: ground truth is what detection accuracy
is measured against, so a file that overstates what was seeded turns a
correct scan into measured false negatives.

Writing these found a latent bug in `ConvertTo-AuditTimestamp`, which had been
unreachable for two weeks because no implemented check passed a non-null
timestamp through it.

## Adding a check

1. Write `Private/Checks/Test-YourCheck.ps1`. Take baseline values as
   parameters, return nothing when the check passes, return a finding from
   `New-AuditFinding` when it does not.
2. Add one line to the `$registry` hashtable in `Invoke-ADSecurityAudit`.
3. Add the matching entry to `finding-dictionary.json` in the dashboard
   project, keyed by the same check id.
4. Add a verification script under `Tests/`.

Nothing else changes. `Test-WeakPasswordPolicy.ps1` is the simplest reference;
`Test-ExcessiveAdminMembership.ps1` is the one to read for a check that has to
traverse the directory.

## Design rules

**Detection only.** The module never writes explanation or remediation text.
If a string would read like advice to an administrator, it belongs in the
finding dictionary, joined on `checkId` by the dashboard.

**A failed check is not a clean result.** Each check runs inside its own
try/catch in the aggregator. A check that throws is recorded under
`checksFailed` with its message and kept out of `checksCompleted`, so the
dashboard can say part of the domain was not examined.

**Nor is a truncated one.** A check that runs to the end but stops short of
part of its ground, such as a group hierarchy deeper than `MaxNestingDepth`,
returns a `New-AuditPartialResult` marker alongside its findings. The
aggregator separates markers from findings by type name and records them in
`checksPartial`. The check stays in `checksCompleted`, because it ran without
error, and the dashboard still treats the scan as incomplete. Putting it in
`checksFailed` instead would throw away the real privileged accounts it did
find; leaving it only in `checksCompleted` was the defect: a hierarchy the
tool never finished walking read exactly like one it had.

**No scoring here.** The security score is computed in the dashboard, so the
weighting can change without re-running a scan.

**Resolve privileged groups by SID, not name.** Group names are localised;
RIDs are not. Portability across domains is an evaluation criterion in the
proposal.

**Walk membership manually.** `Get-ADGroupMember -Recursive` flattens nesting
and discards the chain the privilege arrived through, and without that chain
an administrator cannot tell which group to edit.

**Only folders named for a GPO GUID are policies.** The Policies directory
also holds `PolicyDefinitions`, the ADMX Central Store, which is not a
policy object and whose thousands of files are neither worth reading nor
meaningful to report. Anything else found there is named in the evidence
rather than passed over silently, so a folder the pattern wrongly rejects
is visible.

**A cpassword is checked for the shape of ciphertext before the finding
claims it can be decrypted.** Real Group Policy Preferences values are
Base64 of whole 16 byte AES blocks. A value that does not decode that way is
still reported, because nothing should be writing a cpassword at all, but at
High rather than Critical and without the claim that a password can be
recovered from it. The tool never decrypts, so it never holds a plaintext
password it would then have to protect, and neither the encrypted value nor
any plaintext appears in the finding.

**Unreadable folders and unreadable files are different units.** A folder
that cannot be opened is a policy nobody examined; a file that cannot be
read inside a readable folder leaves the rest of that policy examined. An
earlier version added them together and could report a negative number of
examined policies. They now have separate counters and separate partial
result messages.

**XML is parsed as XML.** An attribute may be single or double quoted and
both are valid, so a regular expression that knows only one silently misses
the other. A file that will not parse is reported as unexamined rather than
as clean.

**Read group policy from SYSVOL, not through the GroupPolicy module.**
`Get-GPO` and `Get-GPOReport` would need a second RSAT feature on the
auditing workstation, and the installation story is already two runtimes
long. The policy files are on a share every domain member reads anyway,
which also keeps the check honest about the privilege it runs with: anything
it can see, any domain user can see. The seeding script does use
`New-GPO`, because it runs on a domain controller where that module is
present, and it skips the section with an explanation when it is not.

**Write JSON without a byte order mark.** PowerShell 5.1's
`Set-Content -Encoding UTF8` writes one, and Node's `JSON.parse` rejects it,
which broke the local API until the server learned to strip it.

## Lab seeding

`..\Lab\Initialize-VulnerableLab.ps1` creates the misconfigurations this
module detects and writes `ground-truth.json` recording exactly what it
seeded. That file is what detection accuracy is measured against.

The script deliberately weakens a domain. Take a VM checkpoint first, run it
once with `-WhatIf`, and never point it at anything but an isolated lab.
