# F26 CSIS 4495 S2: AD Security Auditing Tool

Applied research project, Douglas College, Fall 2026.
Student: Chris (Hoang Nghiem), individual project.

A PowerShell module that scans an Active Directory environment for common
security misconfigurations, paired with a local web dashboard that presents
each finding in plain language with a severity rating and a remediation step.
The target user is a small IT team without a dedicated security specialist.

## Repository layout

```
DocumentsAndReports/    Proposal, progress reports, final report
Implementation/         All project code
  ad-audit-dashboard/   React and TypeScript dashboard (local only)
```

## Components

**`Implementation/ad-audit-dashboard`**
Local web dashboard. Reads the JSON a scan produces, joins it to a hand
written finding dictionary, and renders the results. Built with Vite, React
and Ant Design. See its own README for how to run it.

**PowerShell module** (in progress)
Detection engine. Scans the domain and writes structured JSON. Kept free of
presentation logic so it stays usable on its own from the command line.

## How the two halves fit together

The module and the dashboard communicate through JSON only. The contract is
documented in `Implementation/ad-audit-dashboard/CONTRACT.md`, and the
TypeScript definitions in that project's `src/types/` are its typed half.

```
AD domain -> PowerShell module -> scan-result.json ->
  finding dictionary -> local dashboard
```

## Security note

Scan output contains live infrastructure detail: account names, group
structure, delegation paths. Real scan results are never committed, and the
dashboard runs on localhost only with no cloud dependency.


## Installation and demo

See [INSTALL.md](INSTALL.md) for requirements, setup, how to run a scan, and
how to view the results.