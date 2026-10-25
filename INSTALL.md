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

### For running the dashboard

| Requirement | Detail |
|---|---|
| Node.js | Version 18 or later |
| Browser | Any current browser |

The dashboard can run on a different machine from the scan. The scan produces
a file; the dashboard reads it.

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

## 5. Running a scan

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
```

### Reading the console output

`-Verbose` prints each check as it runs. A warning at the end stating that
one or more checks did not run is expected behaviour, not a crash: checks
that fail are recorded rather than allowed to end the scan.

---

## 6. Viewing the results

```powershell
cd Implementation\ad-audit-dashboard
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

The dashboard reads two files from `public/data/`:

| File | Source |
|---|---|
| `scan-result.json` | Produced by a scan. Not committed, because it contains live domain data |
| `finding-dictionary.json` | Hand written content, committed with the project |

A fresh clone has no `scan-result.json`. Either write one there with the
`-OutputPath` parameter above, or copy the bundled sample to see the
interface with illustrative data:

```powershell
copy public\data\scan-result.sample.json public\data\scan-result.json
```

The sample is for exploring the interface. It contains findings from checks
that are not yet implemented, so it is not representative of what a real scan
currently returns.

Buttons in the dashboard:

- **Open a scan file** loads a scan from anywhere on the machine without
  replacing the file on disk. Use this to review an older scan, or when the
  dashboard and the domain are on different machines.
- **Reload from disk** re-reads the served files after a new scan has run.

---

## 7. Building the test lab

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
and false negatives. It is not committed, because it lists the lab's account
names.

---

## 8. Reference lab topology

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

## 9. Troubleshooting

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

**The dashboard shows "That file could not be read"**

`public/data/scan-result.json` is missing or is not valid JSON. A fresh
clone has no scan result; see section 6.

**Checks appear under "could not run"**

Expected when the auditing account lacks read access to what a check needs.
The Coverage tab names each one and gives the reason. This is the tool
working as designed, not a failure.
