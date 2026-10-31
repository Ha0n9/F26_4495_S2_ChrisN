/**
 * Structural validation for scan results and finding dictionaries.
 *
 * The dashboard used to accept anything with a `scan` property and a
 * `findings` array. A file as empty as
 *
 *     { "schemaVersion": "1.0", "scan": {}, "findings": [] }
 *
 * passed that check and then threw on the first render, because the summary
 * reads `scan.checksFailed.length` and the scoring reads
 * `scan.checksRequested.length`. The reader was shown a blank screen or a
 * stack trace for what is, in truth, a file the tool simply cannot use.
 *
 * So validation happens once, at the boundary, and is deep enough to cover
 * every field the interface actually reaches for. What it reports is the
 * exact path that is wrong, because "this file is invalid" tells somebody
 * holding a 2,000 line scan result nothing they can act on.
 *
 * It is deliberately a shape check, not a semantic one. It does not care
 * whether the timestamps are plausible or whether checksCompleted is a subset
 * of checksRequested. Those are questions about a scan's meaning, and a tool
 * that refused to display a scan because its internal bookkeeping looked odd
 * would be hiding exactly the evidence somebody needs.
 */

import { DataError } from './errors';
import { SEVERITIES } from '@/types/scan';
import type { FindingDictionary } from '@/types/dictionary';
import type { AffectedObject, Finding, PartialCheck, ScanResult } from '@/types/scan';

/** Major version this build understands. */
const SUPPORTED_MAJOR = 1;

function fail(origin: string, detail: string): never {
  throw new DataError(`${origin} is not a usable scan result: ${detail}`);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function describe(value: unknown): string {
  if (value === undefined) return 'is missing';
  if (value === null) return 'is null';
  if (Array.isArray(value)) return 'is an array';
  const kind = typeof value;
  return `is ${'aeiou'.includes(kind[0]) ? 'an' : 'a'} ${kind}`;
}

function requireObject(value: unknown, path: string, origin: string): Record<string, unknown> {
  if (!isPlainObject(value)) fail(origin, `${path} ${describe(value)}, and must be an object`);
  return value;
}

function requireString(value: unknown, path: string, origin: string): string {
  if (typeof value !== 'string') fail(origin, `${path} ${describe(value)}, and must be a string`);
  return value;
}

function requireNonEmptyString(value: unknown, path: string, origin: string): string {
  const text = requireString(value, path, origin);
  if (text.trim() === '') fail(origin, `${path} is empty, and must name something`);
  return text;
}

function requireArray(value: unknown, path: string, origin: string): unknown[] {
  if (!Array.isArray(value)) fail(origin, `${path} ${describe(value)}, and must be an array`);
  return value;
}

function requireStringArray(value: unknown, path: string, origin: string): string[] {
  const items = requireArray(value, path, origin);
  items.forEach((item, index) => requireString(item, `${path}[${index}]`, origin));
  return items as string[];
}

function majorOf(schemaVersion: string): number {
  const major = Number.parseInt(schemaVersion.split('.')[0] ?? '', 10);
  return Number.isNaN(major) ? -1 : major;
}

// ---------------------------------------------------------------------------

function validateAffectedObject(raw: unknown, path: string, origin: string): AffectedObject {
  const object = requireObject(raw, path, origin);
  return {
    name: requireString(object.name, `${path}.name`, origin),
    objectClass: requireString(object.objectClass, `${path}.objectClass`, origin),
    distinguishedName: requireString(object.distinguishedName, `${path}.distinguishedName`, origin),
    // An open bag by design. Which keys appear depends on the check, so the
    // only requirement is that it is a bag at all and not, say, a string the
    // table would then try to enumerate.
    attributes: requireObject(object.attributes, `${path}.attributes`, origin) as AffectedObject['attributes'],
  };
}

function validateFinding(raw: unknown, index: number, origin: string): Finding {
  const path = `findings[${index}]`;
  const finding = requireObject(raw, path, origin);

  const severity = requireString(finding.severity, `${path}.severity`, origin);
  if (!(SEVERITIES as readonly string[]).includes(severity)) {
    fail(
      origin,
      `${path}.severity is "${severity}", which is not one of ${SEVERITIES.join(', ')}`,
    );
  }

  const affectedObjects = requireArray(finding.affectedObjects, `${path}.affectedObjects`, origin)
    .map((item, i) => validateAffectedObject(item, `${path}.affectedObjects[${i}]`, origin));

  // The count is what the summary adds up, so a count that disagrees with the
  // array would make the totals lie. Trust the array and say so, rather than
  // rejecting a file over a field the interface can derive.
  const declared = finding.affectedObjectCount;
  if (declared !== undefined && typeof declared !== 'number') {
    fail(origin, `${path}.affectedObjectCount ${describe(declared)}, and must be a number`);
  }

  if (finding.evidence !== undefined && !isPlainObject(finding.evidence)) {
    fail(origin, `${path}.evidence ${describe(finding.evidence)}, and must be an object when present`);
  }

  return {
    findingId: requireString(finding.findingId, `${path}.findingId`, origin),
    checkId: requireNonEmptyString(finding.checkId, `${path}.checkId`, origin),
    severity: severity as Finding['severity'],
    detectedAt: requireString(finding.detectedAt, `${path}.detectedAt`, origin),
    affectedObjectCount: typeof declared === 'number' ? declared : affectedObjects.length,
    affectedObjects,
    evidence: finding.evidence as Finding['evidence'],
  };
}

function validatePartialChecks(raw: unknown, origin: string): PartialCheck[] {
  // Absent on every scan written before truncation was reported, including
  // the committed baselines, so absence has to mean "none" rather than
  // "invalid". A present value still has to be the right shape.
  if (raw === undefined || raw === null) return [];

  const items = requireArray(raw, 'scan.checksPartial', origin);
  return items.map((item, index) => {
    const path = `scan.checksPartial[${index}]`;
    const entry = requireObject(item, path, origin);
    return {
      checkId: requireNonEmptyString(entry.checkId, `${path}.checkId`, origin),
      reason: requireString(entry.reason, `${path}.reason`, origin),
    };
  });
}

/**
 * Validates and normalises a parsed scan result.
 *
 * Returns a new object rather than the input, so that everything downstream
 * can rely on the optional parts having been filled in.
 */
export function validateScanResult(raw: unknown, origin: string): ScanResult {
  const root = requireObject(raw, 'the file', origin);

  const schemaVersion = requireNonEmptyString(root.schemaVersion, 'schemaVersion', origin);
  const major = majorOf(schemaVersion);
  if (major === -1) {
    fail(origin, `schemaVersion "${schemaVersion}" has no readable major version`);
  }
  if (major > SUPPORTED_MAJOR) {
    fail(
      origin,
      `it uses schema version ${schemaVersion}, which this dashboard does not understand. Update the dashboard rather than reading it with the wrong reader`,
    );
  }

  const scan = requireObject(root.scan, 'scan', origin);

  // Checked in the order the contract declares them, so the first thing a
  // reader is told about a half-written file is the first thing missing from
  // it rather than whichever field this function happened to reach first.
  const scanId = requireString(scan.scanId, 'scan.scanId', origin);
  const startedAt = requireString(scan.startedAt, 'scan.startedAt', origin);
  const completedAt = requireString(scan.completedAt, 'scan.completedAt', origin);
  const moduleName = requireString(scan.moduleName, 'scan.moduleName', origin);
  const moduleVersion = requireString(scan.moduleVersion, 'scan.moduleVersion', origin);

  const domain = requireObject(scan.domain, 'scan.domain', origin);

  const checksFailed = requireArray(scan.checksFailed, 'scan.checksFailed', origin).map((item, index) => {
    const path = `scan.checksFailed[${index}]`;
    const entry = requireObject(item, path, origin);
    return {
      checkId: requireNonEmptyString(entry.checkId, `${path}.checkId`, origin),
      errorMessage: requireString(entry.errorMessage, `${path}.errorMessage`, origin),
    };
  });

  let executedBy: ScanResult['scan']['executedBy'];
  if (scan.executedBy !== undefined && scan.executedBy !== null) {
    const who = requireObject(scan.executedBy, 'scan.executedBy', origin);
    executedBy = {
      account: who.account === undefined ? undefined : requireString(who.account, 'scan.executedBy.account', origin),
      hadDomainAdminRights:
        who.hadDomainAdminRights === undefined ? undefined : Boolean(who.hadDomainAdminRights),
    };
  }

  const findings = requireArray(root.findings, 'findings', origin)
    .map((item, index) => validateFinding(item, index, origin));

  return {
    schemaVersion,
    scan: {
      scanId,
      startedAt,
      completedAt,
      moduleName,
      moduleVersion,
      domain: {
        dnsName: requireNonEmptyString(domain.dnsName, 'scan.domain.dnsName', origin),
        netbiosName: domain.netbiosName === undefined ? undefined : requireString(domain.netbiosName, 'scan.domain.netbiosName', origin),
        domainFunctionalLevel:
          domain.domainFunctionalLevel === undefined
            ? undefined
            : requireString(domain.domainFunctionalLevel, 'scan.domain.domainFunctionalLevel', origin),
        domainControllerQueried:
          domain.domainControllerQueried === undefined
            ? undefined
            : requireString(domain.domainControllerQueried, 'scan.domain.domainControllerQueried', origin),
      },
      executedBy,
      checksRequested: requireStringArray(scan.checksRequested, 'scan.checksRequested', origin),
      checksCompleted: requireStringArray(scan.checksCompleted, 'scan.checksCompleted', origin),
      checksFailed,
      checksPartial: validatePartialChecks(scan.checksPartial, origin),
    },
    findings,
  };
}

// ---------------------------------------------------------------------------

/**
 * Validates a finding dictionary.
 *
 * Lighter than the scan validator on purpose. A dictionary that cannot be
 * read at all already degrades to findings shown by check id, so the job here
 * is only to stop a half-written entry throwing while a finding is expanded.
 */
export function validateDictionary(raw: unknown, origin: string): FindingDictionary {
  if (!isPlainObject(raw)) {
    throw new DataError(`${origin} is not a usable finding dictionary: the file ${describe(raw)}`);
  }

  const schemaVersion = raw.schemaVersion;
  if (typeof schemaVersion !== 'string' || schemaVersion.trim() === '') {
    throw new DataError(`${origin} is not a usable finding dictionary: schemaVersion ${describe(schemaVersion)}`);
  }
  if (majorOf(schemaVersion) > SUPPORTED_MAJOR) {
    throw new DataError(
      `${origin} uses dictionary schema version ${schemaVersion}, which this dashboard does not understand.`,
    );
  }

  if (!isPlainObject(raw.entries)) {
    throw new DataError(`${origin} is not a usable finding dictionary: entries ${describe(raw.entries)}`);
  }

  for (const [checkId, entry] of Object.entries(raw.entries)) {
    if (!isPlainObject(entry)) {
      throw new DataError(
        `${origin} is not a usable finding dictionary: the entry for ${checkId} ${describe(entry)}`,
      );
    }
    for (const key of ['whatToDo', 'keyAttributes', 'references'] as const) {
      if (entry[key] !== undefined && !Array.isArray(entry[key])) {
        throw new DataError(
          `${origin} is not a usable finding dictionary: ${checkId}.${key} ${describe(entry[key])}, and must be an array`,
        );
      }
    }
  }

  return raw as unknown as FindingDictionary;
}
