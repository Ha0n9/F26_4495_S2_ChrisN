# Installation and Demo Guide

This guide takes a reader from a clean machine to a working scan of an
Active Directory domain, with the results rendered in the dashboard.

Everything runs locally. Audit output contains live infrastructure detail
(account names, group membership, delegation paths), so nothing is deployed
to a server and nothing leaves the machine it runs on.

---

## 1. What this product is

An Active Directory security auditing tool in two halves.

**The PowerShell module (`ADSecurityAudit`)** queries a domain for common
security misconfigurations and writes the results as structured JSON. It only
detects. It never contains advice or explanation text.

**The web dashboard (`ad-audit-dashboard`)** reads that JSON, joins it to a
hand written finding dictionary, and presents each finding in plain language
with a severity rating and a concrete remediation step, for an administrator
who does not have a security background.

**A local API (`ad-audit-dashboard/server`)** lets the dashboard start a scan
itself, so the normal path is clicking a button rather than running a command
and reloading a file. It is optional: without it the dashboard still reads a
scan result from disk.

The two halves communicate only through JSON. The contract is documented in
`Implementation/ad-audit-dashboard/CONTRACT.md`.

```
AD domain  ->  PowerShell module  ->  scan-result.json
                                           |
                            finding-dictionary.json
                                           |
                                      Dashboard
```

---

## 2. Requirements

### For running a scan

| Requirement | Detail |
|---|---|
| Operating system | Windows 10, Windows 11, or Windows Server 2016 or later |
| PowerShell | 5.1 (shipped with Windows) or PowerShell 7 |
| RSAT | Active Directory Domain Services and Lightweight Directory Services Tools |
| Domain membership | The machine must be joined to the domain being audited |
| Account | Any ordinary domain user. Domain Administrator is **not** required |
| Node.js | Version 18 or later, to run scans from the dashboard |

### For viewing results only

| Requirement | Detail |
|---|---|
| Node.js | Version 18 or later |
| Browser | Any current browser |

Viewing can happen on a different machine from the scan: the scan produces a
file and the dashboard reads it. Starting a scan from the dashboard cannot,
because the API runs PowerShell against the domain, so for that everything
runs on the domain-joined audit workstation.

### Installing RSAT

On Windows 10 or 11:

```powershell
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
```

On Windows Server:

```powershell
Install-WindowsFeature RSAT-AD-PowerShell
```

Verify:

```powershell
Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory*"
Import-Module ActiveDirectory
```

---

## 3. A note on privileges

The tool is designed to run as an **ordinary domain user**, not as a Domain
Administrator. This is deliberate.

An auditing tool that requires full domain control in order to report on
domain security is itself a risk: the account it needs is the account an
attacker most wants. Instead, a domain administrator grants the auditing
account read access to whatever they are willing to have audited, and the
tool reports honestly on what it could not reach.

A check that cannot read what it needs is recorded under `checksFailed` in
the output and shown separately in the dashboard's Coverage tab. It is never
counted as a check that passed. The practical consequence is that running
with fewer rights produces a smaller, honest result rather than a clean
looking but meaningless one.

Run the scan in a **normal, non elevated** PowerShell session, signed in as
the auditing domain account. Running "as Administrator" can place the session
in a local machine context rather than the domain account context, and the
Active Directory cmdlets will then fail to reach Active Directory Web
Services.

---

## 4. Getting the code

```powershell
git clone https://github.com/Ha0n9/F26_4495_S2_ChrisN.git
cd F26_4495_S2_ChrisN
```

---

## 5. Running a scan from the dashboard

The normal path. Two terminals, both on the audit workstation, both signed in
as the audit account, both **non elevated**.

**Terminal 1, the API:**

```powershell
cd Implementation\ad-audit-dashboard\server
npm install
npm start
```

It prints a link carrying an access token:

```
http://127.0.0.1:5173/?token=<48 hex characters>
```

**Terminal 2, the dashboard:**

```powershell
cd Implementation\ad-audit-dashboard
npm install
npm run dev
```

Open the link from terminal 1, not the plain localhost address. The token is
removed from the address bar once the page reads it.

A **Run scan** button appears, with a new-account grace period beside it. Set
that to **0** on a freshly seeded lab, where every account was created minutes
ago and the default 30 days would excuse all of them.

The token changes every time the API restarts.

### If `npm` will not run

Windows blocks the `npm.ps1` shim by default. Either allow scripts for this
window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

or call the batch file instead, which is not affected:

```powershell
npm.cmd start
```

---

## 6. Running a scan from the command line

Useful while developing a check, and the only option on a machine without
Node.

From the repository root, in a normal PowerShell session signed in as the
auditing account:

```powershell
cd Implementation\ADSecurityAudit
Import-Module .\ADSecurityAudit.psd1 -Force
```

Confirm the module loaded and the account is what you expect:

```powershell
whoami
Get-Command -Module ADSecurityAudit
```

Run the audit against the current domain:

```powershell
Invoke-ADSecurityAudit -Verbose
```

This writes `scan-result.json` to the current directory.

### Useful parameters

```powershell
# Audit a specific domain
Invoke-ADSecurityAudit -DomainName lab.local

# Write straight into the folder the dashboard serves
Invoke-ADSecurityAudit -OutputPath ..\ad-audit-dashboard\public\data\scan-result.json

# Run a single check
Invoke-ADSecurityAudit -CheckId AD.POLICY.WEAK_PASSWORD

# Return the result object as well as writing the file
Invoke-ADSecurityAudit -PassThru

# Pass parameters to one check without affecting the others.
# Grace 0 reports accounts created in the last 30 days, which a freshly
# seeded lab needs and a production domain does not.
Invoke-ADSecurityAudit -CheckParameter @{
    'AD.ACCOUNT.STALE_ENABLED' = @{ NewAccountGraceDays = 0 }
}
```

### Reading the console output

`-Verbose` prints each check as it runs. A warning at the end stating that
one or more checks did not run is expected behaviour, not a crash: checks
that fail are recorded rather than allowed to end the scan.

---

## 7. Viewing a result without the API

```powershell
cd Implementation\ad-audit-dashboard
npm install
npm run dev
```

Open `http://127.0.0.1:5173` with no token. The dashboard says it is reading
files directly, and the Run scan button is absent rather than present and
broken.

A fresh clone has no `scan-result.json`, so the page opens with an error
saying there is nothing to read. That is expected. Use **Open a scan file**
to load one of the results under `BaselineOutputs/`, and it renders.

The finding dictionary is loaded independently of the scan result, so a
missing scan does not also cost you the explanations. If the dictionary
itself cannot be read, findings are still shown, listed by check id without
their plain-language titles, and a warning says so. Findings are never
hidden because the content layer is missing.

The dashboard reads two files from `public/data/`:

| File | Source |
|---|---|
| `scan-result.json` | Produced by a scan. Not committed, because it contains live domain data |
| `finding-dictionary.json` | Hand written content, committed with the project |

A fresh clone has no `scan-result.json`. Either run a scan, or open one of
the results committed under `BaselineOutputs/` with the **Open a scan file**
button.

Buttons in the dashboard:

- **Open a scan file** loads a scan from anywhere on the machine without
  replacing the file on disk. Use this to review an older scan, or when the
  dashboard and the domain are on different machines.
- **Reload from disk** re-reads the served files after a new scan has run.

---

## 8. Building the test lab

The repository includes a script that creates a deliberately insecure domain
for testing detection accuracy.

> **Warning:** this script weakens the security of the domain it runs
> against. Run it only on an isolated lab domain, never on anything else.
> Take a virtual machine checkpoint first.

On the lab domain controller, as a domain administrator:

```powershell
cd Implementation\Lab
.\Initialize-VulnerableLab.ps1 -WhatIf     # review what it will do
.\Initialize-VulnerableLab.ps1 -Verbose    # run it
```

It creates stale accounts, weakens the default domain password policy, and
builds both direct and nested privileged group membership. It also writes
`ground-truth.json`, a record of exactly what it seeded.

That file is how detection accuracy is measured: the tool's findings are
compared against the known seeded misconfigurations to count false positives
and false negatives.

A copy from this project's own lab is committed under `BaselineOutputs/`,
alongside the scan results it is compared against, as evidence that the tool
was run against a live domain rather than sample data. That is safe only
because `auditlab.test` is isolated and every account in it was created by
this script. Ground truth from any other domain names real accounts and must
not be committed.

---

## 9. Reference lab topology

The environment this project was developed against, for anyone reproducing
it:

| | Domain controller | Audit workstation |
|---|---|---|
| Operating system | Windows Server 2022 | Windows 11 |
| Hostname | DC01 | AUDIT01 |
| Domain | auditlab.test | auditlab.test |
| IPv4 | 192.168.100.10 | 192.168.100.20 |
| DNS | Self | 192.168.100.10 |
| Roles | AD DS, DNS | RSAT only |

Both machines sit on an isolated VirtualBox Internal Network. The audit
workstation is deliberately separate from the domain controller so that the
auditing account is never used on the controller itself.

The audit account is an ordinary domain user in a dedicated organizational
unit:

```
OU=AuditAccounts,DC=auditlab,DC=test
sAMAccountName: audit_user
```

---

## 10. Troubleshooting

**"Unable to find a default server with Active Directory Web Services
running"**

Almost always an execution context problem rather than a server problem.
Check `whoami` returns the domain account, not a local one, and that the
session is not elevated. Confirm the domain controller is reachable on TCP
9389:

```powershell
Test-NetConnection DC01.auditlab.test -Port 9389
```

**"The specified domain either does not exist or could not be contacted"**

Check DNS resolution points at the domain controller, and check clock skew.
Kerberos fails when the clocks differ by more than five minutes.

```powershell
Resolve-DnsName auditlab.test -Server 192.168.100.10
w32tm /query /status
```

**The ActiveDirectory module will not import**

Confirm RSAT is installed and that the session is 64 bit:

```powershell
Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory*"
[Environment]::Is64BitProcess
```

**The dashboard says there is no scan file yet**

A fresh clone has no `public/data/scan-result.json`, because real scan output
must never be committed. Run a scan as in section 5 or 6, or use **Open a scan
file** to load one of the results under `BaselineOutputs/`.

**The dashboard shows "That file could not be read"**

The file exists but is not valid JSON. This is a different problem from the one
above and the dashboard words them differently on purpose. Check that the file
was written by the module and not truncated part way through a scan.

**A check is marked "Partial"**

It ran to the end without error but stopped short of part of the ground it
covers. The usual cause is a group hierarchy nested deeper than the
traversal limit. What it reported is real; what lies beyond the limit was
never looked at. The Coverage tab names the branch and the setting that
would include it, for example:

```powershell
Invoke-ADSecurityAudit -CheckParameter @{
    'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP' = @{ MaxNestingDepth = 10 }
}
```

The security score stays marked as a partial view while any check is in this
state, even when every requested check completed.

**The Run scan button disappeared after a refresh**

If the server is still running, open the link it printed again. The token is
regenerated on every restart, and the dashboard discards one the server has
stopped accepting rather than offering an action that cannot succeed.

**Checks appear under "could not run"**

Expected when the auditing account lacks read access to what a check needs.
The Coverage tab names each one and gives the reason. This is the tool
working as designed, not a failure.
