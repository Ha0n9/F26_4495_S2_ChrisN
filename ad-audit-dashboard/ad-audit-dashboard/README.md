# AD Audit Dashboard

Local web dashboard for the `ADSecurityAudit` PowerShell module (CSIS 4495).

It reads the raw JSON a scan produces, joins it to a hand written finding
dictionary, and presents each issue as plain language with a severity and a
remediation step.

## Local only

Audit output contains live infrastructure detail: account names, group
structure, delegation paths. This dashboard is never deployed publicly and
never sends data anywhere. The dev and preview servers bind to `127.0.0.1`,
and `public/data/scan-result.json` is in `.gitignore` so real scan output
cannot be committed by accident.

## Requirements

Node.js 18 or newer.

## Getting started

```bash
npm install
npm run dev        # http://127.0.0.1:5173
```

Other scripts:

```bash
npm run typecheck  # tsc --noEmit
npm run build      # type check, then production build into dist/
npm run preview    # serve the production build on 127.0.0.1:4173
```

## Where the data comes from

| File | Written by | Committed |
|---|---|---|
| `public/data/scan-result.json` | The PowerShell module, one file per scan | No |
| `public/data/scan-result.sample.json` | Hand written sample for development | Yes |
| `public/data/finding-dictionary.json` | Hand written content | Yes |

On load the dashboard fetches both files from the `data/` folder. The
"Open a scan file" button loads a scan from anywhere on the machine without
replacing the file on disk, which is useful for reviewing an older scan.
"Reload from disk" re-reads the served files after a new scan has run.

A fresh clone has no `scan-result.json`. Copy the sample to get started:

```bash
cp public/data/scan-result.sample.json public/data/scan-result.json
```

## The JSON contract

`scan-result.json` and `finding-dictionary.json` join on `checkId`. The rules
are in `CONTRACT.md` at the repository root. The two that matter most here:

1. The module never writes explanation or remediation text. If a string would
   read like advice, it belongs in the dictionary.
2. A finding whose `checkId` is missing from the dictionary is still rendered,
   using the `checkId` as its title. Findings are never hidden because the
   content layer is incomplete.

The TypeScript definitions in `src/types/` are the typed half of that
contract. Change them and the JSON together, never one alone.

## Project layout

```
src/
  types/        Contract types: scan.ts, dictionary.ts, and view models
  lib/          Pure functions: join, scoring, formatting, data loading
  components/   One component per region of the page
  theme/        Colour scheme hook
  App.tsx       Composition, data state, error handling
```

`lib/` holds no React and no Ant Design imports, so the join and scoring logic
can be unit tested on its own.

## Design constraints

The UI is built from Ant Design components as shipped. No component is hand
designed and no design token is overridden. Specifically ruled out:
gradients, translucent panels, cards nested inside cards, and hand written
shadows. Expanded table rows contain tables and description lists directly,
with no wrapper card.

The security score is computed in `lib/score.ts` rather than in the PowerShell
module, so the module stays free of presentation logic and the weighting can
change without re-running a scan.

## Not done yet

- Launcher script that runs a scan, starts the local server and opens the
  browser (planned for weeks 9 to 10).
- Unit tests for `lib/join.ts` and `lib/score.ts`.
- Comparing two scans of the same domain over time.
