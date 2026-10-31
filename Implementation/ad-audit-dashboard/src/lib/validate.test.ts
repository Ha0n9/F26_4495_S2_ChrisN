import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateDictionary, validateScanResult } from './validate';
import { DataError } from './errors';
import { buildCoverageRows } from './join';
import { securityScore } from './score';
import type { FindingDictionary } from '@/types/dictionary';

const here = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(here, '..', '..');
const repoRoot = path.resolve(projectRoot, '..', '..');

function readJson(file: string): unknown {
  // The module writes UTF-8 with a byte order mark on Windows PowerShell 5.1,
  // and the committed baselines still carry one.
  return JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''));
}

/** A result with everything the interface reaches for, and nothing more. */
function validScan(): Record<string, unknown> {
  return {
    schemaVersion: '1.0',
    scan: {
      scanId: 'abc',
      startedAt: '2026-10-30T10:00:00Z',
      completedAt: '2026-10-30T10:00:08Z',
      moduleName: 'ADSecurityAudit',
      moduleVersion: '0.1.0',
      domain: { dnsName: 'auditlab.test' },
      executedBy: { account: 'AUDITLAB\\audit_user', hadDomainAdminRights: false },
      checksRequested: ['AD.POLICY.WEAK_PASSWORD'],
      checksCompleted: ['AD.POLICY.WEAK_PASSWORD'],
      checksFailed: [],
    },
    findings: [
      {
        findingId: 'AD.POLICY.WEAK_PASSWORD:auditlab.test:1',
        checkId: 'AD.POLICY.WEAK_PASSWORD',
        severity: 'Critical',
        detectedAt: '2026-10-30T10:00:08Z',
        affectedObjectCount: 1,
        affectedObjects: [
          {
            name: 'auditlab.test',
            objectClass: 'domain',
            distinguishedName: 'DC=auditlab,DC=test',
            attributes: { minPasswordLength: 4 },
          },
        ],
        evidence: { summary: 'stub' },
      },
    ],
  };
}

describe('validateScanResult', () => {
  it('rejects the shape that used to pass and then crash the renderer', () => {
    // Exactly the file from the defect report. It satisfied the old check,
    // which only asked for a `scan` property and a `findings` array, and then
    // threw on the first render at scan.checksFailed.length.
    const malformed = { schemaVersion: '1.0', scan: {}, findings: [] };

    expect(() => validateScanResult(malformed, 'broken.json')).toThrow(DataError);
    expect(() => validateScanResult(malformed, 'broken.json')).toThrow(/scan\.scanId/);
  });

  it('names the field that is wrong rather than calling the file invalid', () => {
    const scan = validScan();
    delete (scan.scan as Record<string, unknown>).checksFailed;

    expect(() => validateScanResult(scan, 'broken.json')).toThrow(
      /broken\.json is not a usable scan result: scan\.checksFailed is missing/,
    );
  });

  it.each([
    ['scan.checksRequested', (s: any) => { s.scan.checksRequested = 'all'; }, /checksRequested is a string/],
    ['scan.checksCompleted', (s: any) => { s.scan.checksCompleted = null; }, /checksCompleted is null/],
    ['scan.domain', (s: any) => { s.scan.domain = 'auditlab.test'; }, /scan\.domain is a string/],
    ['scan.domain.dnsName', (s: any) => { s.scan.domain = {}; }, /dnsName is missing/],
    ['scan.checksFailed entries', (s: any) => { s.scan.checksFailed = ['nope']; }, /checksFailed\[0\] is a string/],
    ['findings', (s: any) => { s.findings = {}; }, /findings is an object/],
    ['a finding', (s: any) => { s.findings[0] = 'nope'; }, /findings\[0\] is a string/],
    ['severity', (s: any) => { s.findings[0].severity = 'Catastrophic'; }, /not one of Critical, High/],
    ['affectedObjects', (s: any) => { s.findings[0].affectedObjects = null; }, /affectedObjects is null/],
    ['an affected object', (s: any) => { s.findings[0].affectedObjects[0] = 5; }, /affectedObjects\[0\] is a number/],
    ['attributes', (s: any) => { s.findings[0].affectedObjects[0].attributes = 'x'; }, /attributes is a string/],
    ['evidence', (s: any) => { s.findings[0].evidence = 'x'; }, /evidence is a string/],
    ['checksPartial entries', (s: any) => { s.scan.checksPartial = [{ reason: 'x' }]; }, /checksPartial\[0\]\.checkId is missing/],
  ])('rejects a malformed %s', (_label, mutate, expected) => {
    const scan = validScan();
    mutate(scan);
    expect(() => validateScanResult(scan, 'broken.json')).toThrow(expected);
  });

  it('rejects a schema version from the future rather than guessing', () => {
    const scan = validScan();
    scan.schemaVersion = '2.0';
    expect(() => validateScanResult(scan, 'future.json')).toThrow(/does not understand/);
  });

  it('accepts a valid result and fills in the optional parts', () => {
    const result = validateScanResult(validScan(), 'good.json');
    expect(result.scan.checksPartial).toEqual([]);
    expect(result.findings[0].affectedObjectCount).toBe(1);
  });

  it('derives affectedObjectCount when it is absent', () => {
    const scan = validScan();
    delete (scan.findings as any[])[0].affectedObjectCount;
    const result = validateScanResult(scan, 'good.json');
    expect(result.findings[0].affectedObjectCount).toBe(1);
  });

  it('keeps checksPartial when the module reports truncation', () => {
    const scan = validScan();
    (scan.scan as any).checksPartial = [
      { checkId: 'AD.PRIVILEGE.EXCESSIVE_ADMIN_MEMBERSHIP', reason: 'Nested membership was not followed beyond 2 levels.' },
    ];
    const result = validateScanResult(scan, 'good.json');
    expect(result.scan.checksPartial).toHaveLength(1);
    expect(result.scan.checksPartial[0].reason).toMatch(/beyond 2 levels/);
  });

  // The committed evidence has to keep loading. A validator that rejected the
  // project's own baselines would be a regression, not a fix.
  it.each([
    ['BaselineOutputs/scan-baseline.json', path.join(repoRoot, 'BaselineOutputs', 'scan-baseline.json')],
    ['public/data/scan-baseline.json', path.join(projectRoot, 'public', 'data', 'scan-baseline.json')],
  ])('still accepts %s, which predates checksPartial', (label, file) => {
    const result = validateScanResult(readJson(file), label);
    expect(result.scan.domain.dnsName).toBe('auditlab.test');
    expect(result.scan.checksPartial).toEqual([]);
    expect(result.scan.checksFailed.length).toBeGreaterThan(0);
  });
});

describe('validateDictionary', () => {
  it('accepts the committed dictionary', () => {
    const file = path.join(projectRoot, 'public', 'data', 'finding-dictionary.json');
    const dictionary = validateDictionary(readJson(file), 'finding-dictionary.json');
    expect(Object.keys(dictionary.entries).length).toBeGreaterThan(0);
  });

  it('rejects an entry whose list fields are not lists', () => {
    const broken = {
      schemaVersion: '1.0',
      entries: { 'AD.POLICY.WEAK_PASSWORD': { title: 'x', whatToDo: 'do something' } },
    };
    expect(() => validateDictionary(broken, 'broken.json')).toThrow(/whatToDo is a string/);
  });
});

describe('the interface over a validated result', () => {
  const dictionary = { schemaVersion: '1.0', entries: {} } as unknown as FindingDictionary;

  it('scores a truncated scan as partial even when every check completed', () => {
    const scan = validScan();
    (scan.scan as any).checksPartial = [{ checkId: 'AD.POLICY.WEAK_PASSWORD', reason: 'stopped short' }];
    const result = securityScore(validateScanResult(scan, 'good.json'));

    expect(result.checksCompleted).toBe(result.checksRequested);
    // The point of the fix: completing every check is not the same as having
    // examined the whole domain.
    expect(result.partial).toBe(true);
    expect(result.checksTruncated).toBe(1);
  });

  it('scores an untruncated scan as complete', () => {
    const result = securityScore(validateScanResult(validScan(), 'good.json'));
    expect(result.partial).toBe(false);
    expect(result.checksTruncated).toBe(0);
  });

  it('marks a truncated check Partial in the coverage table, not Completed', () => {
    const scan = validScan();
    (scan.scan as any).checksPartial = [
      { checkId: 'AD.POLICY.WEAK_PASSWORD', reason: 'Nesting beyond 2 levels was not followed.' },
    ];
    const rows = buildCoverageRows(validateScanResult(scan, 'good.json'), dictionary);

    expect(rows[0].status).toBe('Partial');
    expect(rows[0].partialReason).toMatch(/beyond 2 levels/);
    // Its findings are still real and still counted. Hiding them would be the
    // other way of lying about this scan.
    expect(rows[0].findingCount).toBe(1);
  });

  it('leaves an untruncated check Completed', () => {
    const rows = buildCoverageRows(validateScanResult(validScan(), 'good.json'), dictionary);
    expect(rows[0].status).toBe('Completed');
    expect(rows[0].partialReason).toBeUndefined();
  });
});
