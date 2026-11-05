# Baseline outputs

Evidence captured from the isolated test lab, committed so that a reader can
see real output without a domain of their own.

| File | What it is |
|---|---|
| `scan-baseline.json` | A scan of `auditlab.test`, run from AUDIT01 as an ordinary domain user |
| `ground-truth.json` | What the seeding script recorded that it had planted, written by the same run that planted it |

Committing scan output is safe only because every account in that domain was
created by `Implementation/Lab/Initialize-VulnerableLab.ps1`. Output from a
real domain must never be committed; `.gitignore` excludes the dashboard's
working copy for that reason.

## These files are out of date, on purpose

Both were captured on 25 October 2026 and describe **three** checks:

```
AD.ACCOUNT.STALE_ENABLED
AD.POLICY.WEAK_PASSWORD
AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP
```

Two checks have been added since, and neither appears here:

```
AD.PRIVILEGE.KERBEROASTING
AD.PRIVILEGE.UNCONSTRAINED_DELEGATION
```

`scan-baseline.json` also predates `checksPartial`, which is why the field is
absent from it rather than empty. Readers must treat a missing `checksPartial`
as an empty list, and the dashboard's validator does.

They have not been regenerated, because a scan result is a record of
something that happened. Writing one by hand, or editing one to look like a
newer run, would make the project's own accuracy measurements meaningless:
ground truth is what detection accuracy is measured against, so an invented
baseline measures nothing. These stay as they are until a real scan replaces
them.

## Refreshing them

Both commands run on the lab, not on a development machine. Take a VM
checkpoint first.

**On DC01**, as a domain administrator, to re-seed and rewrite the ground
truth:

```powershell
cd <repo>\Implementation\Lab
.\Initialize-VulnerableLab.ps1 -WhatIf          # read the plan first
.\Initialize-VulnerableLab.ps1 -Verbose
```

Add `-IncludeManagedServiceAccount` to seed the managed service account that
exercises the unconstrained delegation check's third account type. It needs a
KDS root key in the forest, which the script will not create for you; it
prints the command and the reason if the key is missing.

**On AUDIT01**, signed in as `audit_user` in a session that is not elevated:

```powershell
cd <repo>\Implementation\ADSecurityAudit
Import-Module .\ADSecurityAudit.psd1 -Force
Invoke-ADSecurityAudit -OutputPath <repo>\BaselineOutputs\scan-baseline.json -CheckParameter @{
    'AD.ACCOUNT.STALE_ENABLED' = @{ NewAccountGraceDays = 0 }
}
```

Then copy `ground-truth.json` from DC01 into this folder, and commit both
together with the date of the run. Committing one without the other leaves a
scan with nothing to measure it against.
