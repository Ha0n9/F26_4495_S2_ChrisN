# Local API setup

## Where the files go

```
Implementation/ad-audit-dashboard/
  server/
    index.js          <- new
    run-scan.ps1      <- new
    package.json      <- new, merge if you already have one here
  src/lib/api.ts              <- new
  src/lib/dataSource.ts       <- replaces
  src/components/DataSourceBar.tsx  <- replaces
  src/App.tsx                 <- replaces
  vite.config.ts              <- replaces
```

The server's `package.json` goes in `server/`, not over the dashboard's own.

## Install

```powershell
cd Implementation\ad-audit-dashboard\server
npm install
```

## Run, two terminals

**Terminal 1, the API:**

```powershell
cd Implementation\ad-audit-dashboard\server
npm start
```

It prints a link carrying an access token. Copy it.

**Terminal 2, the dashboard:**

```powershell
cd Implementation\ad-audit-dashboard
npm run dev
```

Open the link from terminal 1, not the plain localhost address. It looks like:

```
http://127.0.0.1:5173/?token=<48 hex characters>
```

The token is removed from the address bar once the page reads it, so it is
not left in browser history.

## Using it

A **Run scan** button appears when the page has a token. Beside it is the
new account grace period: set it to **0** on the seeded lab, because the
accounts were created minutes ago and the default 30 days would excuse them.

Without a token the page falls back to reading the static files, and says so.
That fallback is deliberate: somebody reviewing a scan result has no reason
to need PowerShell or a domain.

## Where it runs

The API must run on a machine that can reach the domain, so for this lab that
is AUDIT01, signed in as `AUDITLAB\audit_user`. Node must be installed there.

If you would rather not install Node in the VM, run the scan on AUDIT01 by
hand as before and use **Open a scan file** on the host. The Run scan button
is then unavailable, which is honest rather than broken.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AUDIT_API_PORT` | 5174 | API port |
| `AUDIT_MODULE_PATH` | `../ADSecurityAudit/ADSecurityAudit.psd1` | Module manifest |
| `AUDIT_PWSH` | `powershell.exe` on Windows | Full path if PowerShell is not on PATH |
| `AUDIT_SCAN_TIMEOUT_MS` | 180000 | Kill a scan that hangs |

## Security

This process runs PowerShell on request, so three things protect it, and all
three must hold:

1. It binds `127.0.0.1` only. Nothing off the machine can reach it.
2. Every request must carry the token printed at startup. A new token is
   generated each time the server starts.
3. The `Origin` header, when present, must be one of the dashboard's own,
   which blocks a cross-site request that somehow learned the token.

Scan arguments are passed to `run-scan.ps1` as discrete arguments rather than
interpolated into a command string, so an awkward or hostile value cannot
change what runs.

## Verified

Two separate rounds of testing, which cover different things.

**Development, on Linux with Node 22 and PowerShell 7.4.6, against a stand-in
module.** Token and origin rejection (401 and 403), health, dictionary,
latest scan, a scan through the Vite dev proxy with the per-check grace
parameter reaching the module, a second concurrent scan correctly rejected
with 409, and a missing scan result returning 404 while the dictionary still
loads.

**On the lab, on Windows 11 with Windows PowerShell 5.1, against the live
`auditlab.test` domain.** The dashboard started a scan from the Run scan
button, signed in as the ordinary domain account `audit_user`, and rendered
three findings across fourteen affected objects in under seven seconds.

The first round proves the API's behaviour, including the failure paths that
are awkward to reproduce on a real domain. The second proves the whole chain
works where it has to. Neither replaces the other.

### Known environment issues

`npm.ps1` is blocked by the default Windows execution policy. Either run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` in that
window, or call `npm.cmd` instead.

Run the server in a **non elevated** session signed in as the audit account.
A child process inherits its parent's security context, so a server started
from an elevated prompt spawns PowerShell in a local machine context, and the
Active Directory cmdlets then fail to reach Active Directory Web Services
with an error that points at the wrong thing.

Set `AUDIT_PWSH` to a full path if `powershell.exe` is not on PATH.
