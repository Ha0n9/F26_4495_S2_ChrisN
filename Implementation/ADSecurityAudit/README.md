# ADSecurityAudit

PowerShell module that scans an Active Directory domain for common security
misconfigurations and writes the results as structured JSON for the
dashboard to render.

## Status

Early. The module structure, the JSON envelope and one check work end to
end. Two checks are stubs that throw `NotImplementedException`, which the
aggregator records under `checksFailed` rather than treating as a clean
result.

| Check | Id | Status |
|---|---|---|
| Weak domain password policy | `AD.POLICY.WEAK_PASSWORD` | Implemented |
| Stale enabled accounts | `AD.ACCOUNT.STALE_ENABLED` | Stub, research notes in file |
| Excessive admin membership | `AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP` | Stub, research notes in file |

Later checks per the proposal: Kerberoasting exposure, unconstrained
delegation, risky GPO settings, domain trusts, LAPS status.

## Requirements

- PowerShell 5.1 or 7
- RSAT ActiveDirectory module
- An account that can read the domain. Domain Admin is not required, and
  the scan records which rights it ran with so partial results are visible
  rather than silently incomplete.

## Running it

```powershell
Import-Module .\ADSecurityAudit\ADSecurityAudit.psd1 -Force

# Scan the current domain, write scan-result.json here
Invoke-ADSecurityAudit -Verbose

# Write straight into the folder the dashboard serves
Invoke-ADSecurityAudit -DomainName lab.local `
    -OutputPath ..\ad-audit-dashboard\public\data\scan-result.json

# Run a single check while developing it
Invoke-ADSecurityAudit -CheckId AD.POLICY.WEAK_PASSWORD -PassThru
```

## Layout

```
ADSecurityAudit/
  ADSecurityAudit.psd1        Manifest
  ADSecurityAudit.psm1        Loader: dot sources everything, exports Public
  Public/
    Invoke-ADSecurityAudit.ps1   Aggregator and JSON envelope
  Private/
    New-AuditFinding.ps1         Builds finding objects to the contract
    Checks/
      Test-*.ps1                 One check per file
Lab/
  Initialize-VulnerableLab.ps1   Seeds the lab, writes ground-truth.json
```

## Adding a check

1. Write `Private/Checks/Test-YourCheck.ps1`. Take the baseline values as
   parameters, return nothing when the check passes, return a finding from
   `New-AuditFinding` when it does not.
2. Add one line to the `$registry` hashtable in `Invoke-ADSecurityAudit`.
3. Add the matching entry to `finding-dictionary.json` in the dashboard
   project, keyed by the same check id.

Nothing else changes. `Test-WeakPasswordPolicy.ps1` is the reference
implementation; read it before writing a new one.

## Design rules

**Detection only.** The module never writes explanation or remediation text.
If a string would read like advice to an administrator, it belongs in the
finding dictionary, joined on `checkId` by the dashboard.

**A failed check is not a clean result.** Each check runs inside its own
try/catch in the aggregator. A check that throws is recorded under
`checksFailed` with its message and kept out of `checksCompleted`, so the
dashboard can say part of the domain was not examined. Reporting "no issues
found" about ground the tool never looked at would be the worst failure
mode for a security tool.

**No scoring here.** The security score is computed in the dashboard, so the
weighting can change without re-running a scan.

**Resolve privileged groups by SID, not name.** Group names are localized;
RIDs are not. Portability across domains is an evaluation criterion in the
proposal.

## Lab seeding

`Lab/Initialize-VulnerableLab.ps1` creates the misconfigurations this module
detects and writes `ground-truth.json` recording exactly what it seeded.
That file is what detection accuracy is measured against.

The script deliberately weakens a domain. Take a VM checkpoint first, run it
once with `-WhatIf`, and never point it at anything but the lab.
