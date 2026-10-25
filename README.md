# F26 CSIS 4495 S2: AD Security Auditing Tool

Applied research project, Douglas College, Fall 2026.
Student: Chris (Hoang Nghiem), individual project.

A PowerShell module that scans an Active Directory domain for common security
misconfigurations, paired with a local dashboard that presents each finding in
plain language with a severity rating and a specific remediation step. The
target user is a small IT team without a dedicated security specialist.

The tool runs as an ordinary domain user. It does not require, and is not
designed to be given, Domain Administrator rights.

## Getting started

See **[INSTALL.md](INSTALL.md)** for requirements, setup, running a scan and
viewing the results.

## Current state

Three detection checks are implemented and run end to end against a live
domain, with the scan started from the dashboard itself.

| Check | Id | State |
|---|---|---|
| Weak domain password policy | `AD.POLICY.WEAK_PASSWORD` | Implemented |
| Stale enabled accounts | `AD.ACCOUNT.STALE_ENABLED` | Implemented |
| Excessive privileged group membership | `AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP` | Implemented |
| Kerberoasting exposure | `AD.PRIVILEGE.KERBEROASTING` | Planned |
| Unconstrained delegation | `AD.PRIVILEGE.UNCONSTRAINED_DELEGATION` | Planned |
| Risky group policy settings | `AD.POLICY.RISKY_GPO` | Planned |
| Domain trust relationships | `AD.TRUST.RISKY_TRUST` | Planned |
| LAPS deployment | `AD.ACCOUNT.LAPS_MISSING` | Planned |

## Repository layout

```
DocumentsAndReports/      Proposal, progress reports, mid-course report
BaselineOutputs/          Scan results captured from the test lab, as evidence
Implementation/
  ADSecurityAudit/        PowerShell module: the detection engine
    Public/               Invoke-ADSecurityAudit, the aggregator
    Private/Checks/       One file per detection check
    Tests/                Assertions against stubbed AD cmdlets, no domain needed
  Lab/                    Script that seeds a lab domain with known-bad settings
  ad-audit-dashboard/     React and TypeScript dashboard
    server/               Local API that starts a scan on request
    public/data/          Finding dictionary, and the scan result being viewed
INSTALL.md                Requirements, setup and demo instructions
```

## How the pieces fit together

```
         AUDIT01 (ordinary domain user, RSAT only)
                        |
   +--------------------+--------------------+
   |                                         |
   v                                         v
PowerShell module  --writes-->  scan-result.json
   ^                                         |
   |                                         v
   |                               finding-dictionary.json
local API <--Run scan--  Dashboard  <--joins on checkId--+
                                         |
                                         v
                              plain language + remediation
```

Three layers, deliberately separate:

**The module detects.** It queries the domain and writes structured JSON. It
contains no explanation or remediation text at all.

**The finding dictionary explains.** Hand written content, one entry per check
id, holding the plain-language title, why the issue matters, and the steps to
fix it.

**The dashboard joins the two** on `checkId` and renders the result. It holds
no detection logic.

The JSON contract between them is documented in
[`Implementation/ad-audit-dashboard/CONTRACT.md`](Implementation/ad-audit-dashboard/CONTRACT.md),
and the TypeScript definitions in that project's `src/types/` are its typed
half.

## Design decisions worth knowing

**Low privilege by default.** An auditing tool that needs full control of a
domain in order to report on that domain's security is itself a risk, because
the account it needs is the account an attacker most wants. An administrator
grants the audit account read access to whatever they are willing to have
audited, and the tool reports honestly about anything it could not reach.

**A failed check is not a clean result.** A check that cannot run is recorded
separately from a check that ran and found nothing, and the dashboard shows
the difference. Reporting "no issues found" about ground the tool never looked
at would be the worst possible failure for a security tool.

**Scoring lives in the dashboard**, not the module, so the weighting can change
without re-running a scan against a production domain. The score states how
many checks it is based on, and gives no score at all when nothing was
examined.

**Groups are resolved by SID, never by name.** `Domain Admins` is localised, so
a name-based lookup finds nothing on a non-English domain and then reports a
clean result.

## Security note

Scan output contains live infrastructure detail: account names, group
structure, delegation paths. The dashboard and its API bind to the loopback
interface only and have no cloud dependency, and the API requires a token
generated when it starts.

Scan results from the isolated test lab are committed under `BaselineOutputs/`
as evidence, which is safe only because every account in that domain was
created by the seeding script. Output from a real domain must never be
committed; `.gitignore` excludes the dashboard's working copy for that reason.
