# ADSecurityAudit

PowerShell module that scans an Active Directory domain for common security
misconfigurations and writes the results as structured JSON for the dashboard
to render.

## Status

Four checks are implemented. The first three have been run against a live
domain (`auditlab.test`) from an ordinary domain user account.

| Check | Id | Severity | Status |
|---|---|---|---|
| Weak domain password policy | `AD.POLICY.WEAK_PASSWORD` | Critical or High | Implemented |
| Stale enabled accounts | `AD.ACCOUNT.STALE_ENABLED` | High | Implemented |
| Excessive privileged group membership | `AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP` | Critical | Implemented |
| Kerberoastable service accounts | `AD.PRIVILEGE.KERBEROASTING` | Critical, High or Medium | Implemented |

Remaining checks from the proposal, in the order they will be attempted:
unconstrained delegation, risky GPO settings, domain trust relationships,
LAPS deployment. Unconstrained delegation is next because it, like
Kerberoasting, is named in the CISA, NSA and ASD joint advisory on Active
Directory compromise.

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
    New-AuditFinding.ps1        Builds finding objects to the contract
    Checks/
      Test-WeakPasswordPolicy.ps1
      Test-StaleEnabledAccount.ps1
      Test-ExcessiveAdminMembership.ps1
      Test-KerberoastableAccount.ps1
  Tests/
    verify-stale-check.ps1      32 assertions
    verify-admin-check.ps1      28 assertions
    verify-kerberoast-check.ps1 50 assertions
```

## Testing

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Tests\verify-stale-check.ps1
.\Tests\verify-admin-check.ps1
.\Tests\verify-kerberoast-check.ps1
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

**No scoring here.** The security score is computed in the dashboard, so the
weighting can change without re-running a scan.

**Resolve privileged groups by SID, not name.** Group names are localised;
RIDs are not. Portability across domains is an evaluation criterion in the
proposal.

**Walk membership manually.** `Get-ADGroupMember -Recursive` flattens nesting
and discards the chain the privilege arrived through, and without that chain
an administrator cannot tell which group to edit.

**Write JSON without a byte order mark.** PowerShell 5.1's
`Set-Content -Encoding UTF8` writes one, and Node's `JSON.parse` rejects it,
which broke the local API until the server learned to strip it.

## Lab seeding

`..\Lab\Initialize-VulnerableLab.ps1` creates the misconfigurations this
module detects and writes `ground-truth.json` recording exactly what it
seeded. That file is what detection accuracy is measured against.

The script deliberately weakens a domain. Take a VM checkpoint first, run it
once with `-WhatIf`, and never point it at anything but an isolated lab.
