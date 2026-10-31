# AD Audit Dashboard

Local dashboard for the `ADSecurityAudit` PowerShell module (CSIS 4495).

It reads the raw JSON a scan produces, joins it to a hand written finding
dictionary, and presents each issue in plain language with a severity and a
remediation step. With the local API running it also starts the scan itself,
so an administrator never has to leave the interface.

## Local only

Audit output contains live infrastructure detail: account names, group
structure, delegation paths. Nothing here is deployed publicly and nothing is
sent anywhere. The dev server, the preview server and the API all bind to
`127.0.0.1`, and `public/data/scan-result.json` is gitignored so real scan
output cannot be committed by accident.

## Requirements

Node.js 18 or newer. To run scans from the interface, the machine must also be
domain joined with RSAT installed, because the API runs the PowerShell module
locally.

## Running it

Two terminals, both on the audit workstation, signed in as the audit account.

**The API:**

```bash
cd server
npm install
npm start
```

It prints a link carrying an access token. Copy it.

**The dashboard:**

```bash
npm install
npm run dev
```

Open the link the API printed, not the plain localhost address:

```
http://127.0.0.1:5173/?token=<48 hex characters>
```

The token is removed from the address bar once the page reads it, so it is not
left in browser history.

Other scripts:

```bash
npm test           # vitest run, over src/lib
npm run typecheck  # the app, then the tests
npm run build      # type check, then production build into dist/
npm run preview    # serve the production build on 127.0.0.1:4173
```

## Two ways to get data in

**With the API.** A **Run scan** button appears, with an adjustable new-account
grace period beside it. Clicking it runs the module against the domain and
renders the result. Set the grace to 0 on a freshly seeded lab, where every
account was created minutes ago.

**Without it.** The page falls back to reading the static files and says so.
**Open a scan file** loads a result from anywhere on the machine. That fallback
is deliberate rather than leftover: somebody reviewing an audit has no reason
to need PowerShell, a domain, or the machine the scan ran on.

| File | Written by | Committed |
|---|---|---|
| `public/data/scan-result.json` | A scan, via the API or the module directly | No |
| `public/data/finding-dictionary.json` | Hand written content | Yes |
| `public/data/scan-baseline.json` | A scan of the lab, kept as evidence | Yes |

A fresh clone has no `scan-result.json`, because real scan output must never be
committed. Either run a scan, or open `scan-baseline.json` with **Open a scan
file**. That baseline is a deliberately incomplete scan, with one check that
ran and two that did not, so it is also the quickest way to see how the tool
reports ground it was unable to examine.

## The JSON contract

`scan-result.json` and `finding-dictionary.json` join on `checkId`. The rules
are in `CONTRACT.md` beside this file. The two that matter most here:

1. The module never writes explanation or remediation text. If a string would
   read like advice, it belongs in the dictionary.
2. A finding whose `checkId` is missing from the dictionary is still rendered,
   using the `checkId` as its title. Findings are never hidden because the
   content layer is incomplete.

The TypeScript definitions in `src/types/` are the typed half of that contract.
Change them and the JSON together, never one alone.

## Project layout

```
server/
  index.js        Local API: health, dictionary, latest scan, run scan
  run-scan.ps1    Wrapper the API invokes, so arguments are never interpolated
src/
  types/          Contract types: scan.ts, dictionary.ts, and view models
  lib/            Pure functions: join, scoring, formatting, API client
  components/     One component per region of the page
  theme/          Colour scheme hook
  App.tsx         Composition, data state, scan state, error handling
```

`lib/` holds no React and no Ant Design imports, so the join and scoring logic
can be unit tested on its own.

## API security

The API runs PowerShell on request, so three measures protect it and all three
must hold:

1. It binds `127.0.0.1` only, so nothing off the machine can reach it.
2. Every request must carry the token generated at startup. A new one is issued
   each time the server starts.
3. The `Origin` header, when present, must be one of the dashboard's own, which
   blocks a cross-site request that somehow learned the token.

Scan arguments are passed to `run-scan.ps1` as discrete arguments rather than
interpolated into a command string, so an awkward or hostile value cannot
change what runs.

`SERVER-SETUP.md` has the environment variables and troubleshooting.

## Design constraints

The UI is built from Ant Design components as shipped. No component is hand
designed and no design token is overridden. Specifically ruled out: gradients,
translucent panels, cards nested inside cards, and hand written shadows.
Expanded table rows contain tables and description lists directly, with no
wrapper card.

The security score is computed in `lib/score.ts` rather than in the PowerShell
module, so the module stays free of presentation logic and the weighting can
change without re-running a scan. It takes the whole scan rather than just the
findings, because a score computed from findings alone reports 100 for a scan
where every check failed.

**The dictionary never gates the scan.** `App.tsx` renders as soon as a scan is
present, falling back to an empty dictionary when the content layer is missing.
An earlier version required both halves, so a null dictionary produced a page
that drew its own title and then nothing at all, with no error and no warning
to explain the emptiness. That is the same principle as `checksFailed` being
separate from `checksCompleted`: showing what is known, and saying what is not,
beats showing nothing.

**A missing file is not a corrupt file.** The dev server answers a request for
a file that is not there with `index.html` and a 200, rather than a 404, so the
HTML reached `JSON.parse` and the reader was told their scan file was invalid
when in fact no scan file existed. `lib/dataSource.ts` checks the content type
before parsing and raises `MissingFileError`, which carries the wording that
sends the reader to run a scan rather than to investigate a damaged file.

**Everything is validated at one boundary.** `lib/validate.ts` checks every
field the interface reaches for, and `lib/dataSource.ts` routes the static
file, the local API and a hand-opened file through it. The API is not trusted
for being local: it answers with a file it read from disk, and local is not
the same as known good. A result that fails validation is rejected naming the
field that is wrong, and whatever was already on screen stays there, because
replacing a good result with a blank page helps nobody.

**The token survives a refresh.** It is kept in `sessionStorage`, scoped to
the tab, rather than only in memory, so reloading does not silently take the
Run scan controls away. A token in the URL always replaces a stored one,
because a freshly printed link is the user saying the server restarted. When
the server rejects a token the dashboard discards it, stops offering a scan,
and says that a restart issues a new one.

**A truncated check is shown as Partial.** `checksPartial` carries checks that
ran without error but did not see everything, and the coverage table, the
banner and the score caption all say so. The security score is marked partial
even when every requested check completed, because completing a check is not
the same as having examined the domain. `CONTRACT.md` has the reasoning.

## Tests

```bash
npm test                 # the dashboard: validation, scoring, coverage, token
cd server && npm test    # the local API: one request, one response
```

Neither suite needs PowerShell, a domain or Windows. The server suite starts
the real server as a child process and points `AUDIT_PWSH` at something that
cannot be launched, or at a generated stub that hangs, so the failure paths
through the scan endpoint are reachable anywhere Node runs.

## Not done yet

- Comparing two scans of the same domain over time.
- Interpolating figures from the scan into the dictionary's wording, so a
  finding reads "3 service accounts in OU=ServiceAccounts" rather than a
  sentence that is the same whatever was found.
- Packaging the API as part of the module itself, using
  `System.Net.HttpListener`, so the tool does not require Node at all. Planned
  for the packaging phase in weeks 9 to 10.
