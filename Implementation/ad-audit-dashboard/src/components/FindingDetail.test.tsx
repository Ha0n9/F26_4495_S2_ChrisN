// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FindingDetail } from './FindingDetail';
import { buildFindingRows } from '@/lib/join';
import { validateDictionary, validateScanResult } from '@/lib/validate';
import type { FindingDictionary } from '@/types/dictionary';

/**
 * Rendering tests for the expanded finding row.
 *
 * These exist because validator tests alone were not enough. A dictionary
 * holding `"whatToDo": [{"bad": true}]` satisfied every assertion about
 * shapes and then threw the moment React tried to put that object in the
 * tree. The only way to be sure validated content is renderable is to
 * render it, so the cases below take data all the way through validation,
 * the join, and into the component.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(here, '..', '..');

afterEach(cleanup);

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''));
}

function scanWith(overrides: Record<string, unknown> = {}, checkId = 'AD.TEST.CHECK') {
  return {
    schemaVersion: '1.0',
    scan: {
      scanId: 'scan-1',
      startedAt: '2026-10-31T10:00:00Z',
      completedAt: '2026-10-31T10:00:08Z',
      moduleName: 'ADSecurityAudit',
      moduleVersion: '0.1.0',
      domain: { dnsName: 'auditlab.test' },
      checksRequested: [checkId],
      checksCompleted: [checkId],
      checksFailed: [],
    },
    findings: [
      {
        findingId: `${checkId}:auditlab.test:1`,
        checkId,
        severity: 'High',
        detectedAt: '2026-10-31T10:00:08Z',
        affectedObjects: [
          {
            name: 'svc_sql',
            objectClass: 'user',
            distinguishedName: 'CN=svc_sql,OU=Services,DC=auditlab,DC=test',
            attributes: { rc4Permitted: true },
          },
        ],
        evidence: { summary: 'One account is exposed.' },
        ...overrides,
      },
    ],
  };
}

function dictionaryWith(entry: Record<string, unknown>, checkId = 'AD.TEST.CHECK') {
  return { schemaVersion: '1.0', language: 'en', entries: { [checkId]: entry } };
}

function rowFor(scanRaw: unknown, dictionaryRaw: unknown, index = 0) {
  const scan = validateScanResult(scanRaw, 'scan.json');
  const dictionary = validateDictionary(dictionaryRaw, 'dictionary.json');
  return buildFindingRows(scan, dictionary)[index];
}

const FULL_ENTRY = {
  technicalName: 'Kerberoastable service accounts',
  title: 'Service accounts whose passwords can be cracked offline',
  category: 'Privilege management',
  defaultSeverity: 'High',
  whyItMatters: 'Any signed-in user can request a ticket for these accounts.',
  whatToDo: ['Give each account a long random password.', 'Remove them from administrative groups.'],
  objectColumnLabel: 'Service account',
  keyAttributes: ['rc4Permitted'],
  references: [{ label: 'Joint advisory', url: 'https://example.invalid/advisory' }],
};

describe('a fully populated entry renders', () => {
  it('shows the explanation, every step, the summary and the reference', () => {
    render(<FindingDetail row={rowFor(scanWith(), dictionaryWith(FULL_ENTRY))} />);

    expect(screen.getByText(/Any signed-in user can request a ticket/)).toBeTruthy();
    expect(screen.getByText('Give each account a long random password.')).toBeTruthy();
    expect(screen.getByText('Remove them from administrative groups.')).toBeTruthy();
    expect(screen.getByText('One account is exposed.')).toBeTruthy();

    const link = screen.getByText('Joint advisory') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('https://example.invalid/advisory');
  });
});

describe('an entry with nothing optional still renders', () => {
  // The contract rule: findings are never hidden because the content layer
  // is thin. Validation must not have turned those fallbacks into errors.
  it('falls back for a missing explanation and missing guidance', () => {
    render(<FindingDetail row={rowFor(scanWith(), dictionaryWith({}))} />);

    expect(screen.getByText('This check is not described in the finding dictionary yet.')).toBeTruthy();
    expect(screen.getByText('No remediation guidance is recorded for this check.')).toBeTruthy();
  });

  it('renders a finding whose checkId is absent from the dictionary altogether', () => {
    const dictionary = { schemaVersion: '1.0', entries: {} };
    render(<FindingDetail row={rowFor(scanWith(), dictionary)} />);

    expect(screen.getByText('This check is not described in the finding dictionary yet.')).toBeTruthy();
  });

  it('falls back when a finding carries no evidence at all', () => {
    render(<FindingDetail row={rowFor(scanWith({ evidence: undefined }), dictionaryWith(FULL_ENTRY))} />);

    expect(screen.getByText('No summary was recorded for this finding.')).toBeTruthy();
  });
});

describe('content that used to crash the row is now refused before it gets here', () => {
  // Each of these rendered a thrown exception before the fix. The assertion
  // is that validation stops them, with a path the reader can act on.
  it('refuses an object in whatToDo', () => {
    expect(() => rowFor(scanWith(), dictionaryWith({ ...FULL_ENTRY, whatToDo: [{ bad: true }] }))).toThrow(
      /entries\.AD\.TEST\.CHECK\.whatToDo\[0\] is an object/,
    );
  });

  it('refuses a reference whose label is an object', () => {
    expect(() =>
      rowFor(scanWith(), dictionaryWith({ ...FULL_ENTRY, references: [{ label: { bad: true }, url: 'u' }] })),
    ).toThrow(/references\[0\]\.label is an object/);
  });

  it('refuses an object evidence summary', () => {
    expect(() => rowFor(scanWith({ evidence: { summary: { bad: true } } }), dictionaryWith(FULL_ENTRY))).toThrow(
      /findings\[0\]\.evidence\.summary is an object/,
    );
  });
});

describe('the affected object count the row shows', () => {
  it('comes from the objects, not from a declared number that disagrees', () => {
    render(<FindingDetail row={rowFor(scanWith({ affectedObjectCount: 9999 }), dictionaryWith(FULL_ENTRY))} />);

    expect(screen.getByText('Affected objects (1)')).toBeTruthy();
    expect(screen.queryByText('Affected objects (9999)')).toBeNull();
  });

  it('corrects a declared count that is too low as well', () => {
    render(<FindingDetail row={rowFor(scanWith({ affectedObjectCount: 0 }), dictionaryWith(FULL_ENTRY))} />);

    expect(screen.getByText('Affected objects (1)')).toBeTruthy();
  });
});

describe('the committed dictionary', () => {
  const file = path.join(projectRoot, 'public', 'data', 'finding-dictionary.json');
  const dictionaryRaw = readJson(file) as { entries: Record<string, unknown> };
  const dictionary = validateDictionary(dictionaryRaw, 'finding-dictionary.json') as FindingDictionary;
  const checkIds = Object.keys(dictionary.entries);

  it('has entries to check', () => {
    expect(checkIds.length).toBeGreaterThan(0);
  });

  // Every shipped entry has to survive the component, not just the
  // validator. This is the test that would have caught the original defect
  // if the dictionary had ever held a malformed step.
  it.each(checkIds)('renders the entry for %s', (checkId) => {
    const row = rowFor(scanWith({}, checkId), dictionaryRaw);
    expect(() => render(<FindingDetail row={row} />)).not.toThrow();
  });
});

describe('the committed baseline scan', () => {
  it('renders every finding it contains', () => {
    const scanFile = path.join(projectRoot, 'public', 'data', 'scan-baseline.json');
    const dictionaryFile = path.join(projectRoot, 'public', 'data', 'finding-dictionary.json');

    const scan = validateScanResult(readJson(scanFile), 'scan-baseline.json');
    const dictionary = validateDictionary(readJson(dictionaryFile), 'finding-dictionary.json');
    const rows = buildFindingRows(scan, dictionary);

    expect(rows.length).toBeGreaterThan(0);
    rows.forEach((row) => {
      expect(() => render(<FindingDetail row={row} />)).not.toThrow();
    });
  });
});
