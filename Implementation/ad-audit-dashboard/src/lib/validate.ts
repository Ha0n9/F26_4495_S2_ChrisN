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
 * every field the interface actually reaches for. Deep is the operative
 * word: checking that `whatToDo` is an array, without checking what is in
 * it, let `[{ "bad": true }]` through to a React child and crashed the page
 * just the same. A container of the right shape full of the wrong things is
 * not validated content.
 *
 * What it reports is the exact path that is wrong, because "this file is
 * invalid" tells somebody holding a 2,000 line scan result nothing they can
 * act on.
 *
 * It is deliberately a shape check, not a semantic one. It does not care
 * whether the timestamps are plausible or whether checksCompleted is a subset
 * of checksRequested. Those are questions about a scan's meaning, and a tool
 * that refused to display a scan because its internal bookkeeping looked odd
 * would be hiding exactly the evidence somebody needs.
 */

import { DataError } from './errors';
import { SEVERITIES } from '@/types/scan';
import type { DictionaryEntry, FindingDictionary } from '@/types/dictionary';
import type { AffectedObject, Finding, PartialCheck, ScanResult } from '@/types/scan';

/** Major version this build understands. */
const SUPPORTED_MAJOR = 1;

/**
 * What is being validated, so one set of helpers can serve both files and
 * still name the right thing in the error.
 */
interface Ctx {
  origin: string;
  noun: 'scan result' | 'finding dictionary';
}

function fail(ctx: Ctx, detail: string): never {
  throw new DataError(`${ctx.origin} is not a usable ${ctx.noun}: ${detail}`);
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

function requireObject(value: unknown, path: string, ctx: Ctx): Record<string, unknown> {
  if (!isPlainObject(value)) fail(ctx, `${path} ${describe(value)}, and must be an object`);
  return value;
}

function requireString(value: unknown, path: string, ctx: Ctx): string {
  if (typeof value !== 'string') fail(ctx, `${path} ${describe(value)}, and must be a string`);
  return value;
}

function requireNonEmptyString(value: unknown, path: string, ctx: Ctx): string {
  const text = requireString(value, path, ctx);
  if (text.trim() === '') fail(ctx, `${path} is empty, and must name something`);
  return text;
}

function requireArray(value: unknown, path: string, ctx: Ctx): unknown[] {
  if (!Array.isArray(value)) fail(ctx, `${path} ${describe(value)}, and must be an array`);
  return value;
}

function requireStringArray(value: unknown, path: string, ctx: Ctx): string[] {
  const items = requireArray(value, path, ctx);
  items.forEach((item, index) => requireString(item, `${path}[${index}]`, ctx));
  return items as string[];
}

/** Checks the type only when the field is there at all. */
function optionalString(value: unknown, path: string, ctx: Ctx): void {
  if (value !== undefined) requireString(value, path, ctx);
}

function optionalStringArray(value: unknown, path: string, ctx: Ctx): void {
  if (value !== undefined) requireStringArray(value, path, ctx);
}

function requireSeverity(value: unknown, path: string, ctx: Ctx): string {
  const severity = requireString(value, path, ctx);
  if (!(SEVERITIES as readonly string[]).includes(severity)) {
    fail(ctx, `${path} is "${severity}", which is not one of ${SEVERITIES.join(', ')}`);
  }
  return severity;
}

function majorOf(schemaVersion: string): number {
  const major = Number.parseInt(schemaVersion.split('.')[0] ?? '', 10);
  return Number.isNaN(major) ? -1 : major;
}

// ---------------------------------------------------------------------------
// Scan results
// ---------------------------------------------------------------------------

function validateAffectedObject(raw: unknown, path: string, ctx: Ctx): AffectedObject {
  const object = requireObject(raw, path, ctx);
  return {
    name: requireString(object.name, `${path}.name`, ctx),
    objectClass: requireString(object.objectClass, `${path}.objectClass`, ctx),
    distinguishedName: requireString(object.distinguishedName, `${path}.distinguishedName`, ctx),
    // An open bag by design. Which keys appear depends on the check, so the
    // only requirement is that it is a bag at all and not, say, a string the
    // table would then try to enumerate. The values inside are safe whatever
    // their type, because AttributeValue renders an object as JSON and
    // anything else through String.
    attributes: requireObject(object.attributes, `${path}.attributes`, ctx) as AffectedObject['attributes'],
  };
}

function validateEvidence(raw: unknown, path: string, ctx: Ctx): Finding['evidence'] {
  if (raw === undefined) return undefined;

  const evidence = requireObject(raw, path, ctx);

  // summary is the one evidence field rendered as a bare React child, so it
  // is the one that has to be a string. Every other value goes through
  // AttributeValue, which copes with an object by stringifying it, and is
  // left alone because the bag is open by design.
  if (evidence.summary !== undefined && evidence.summary !== null) {
    requireString(evidence.summary, `${path}.summary`, ctx);
  }

  return evidence as Finding['evidence'];
}

function validateFinding(raw: unknown, index: number, ctx: Ctx): Finding {
  const path = `findings[${index}]`;
  const finding = requireObject(raw, path, ctx);

  const severity = requireSeverity(finding.severity, `${path}.severity`, ctx);

  const affectedObjects = requireArray(finding.affectedObjects, `${path}.affectedObjects`, ctx)
    .map((item, i) => validateAffectedObject(item, `${path}.affectedObjects[${i}]`, ctx));

  // The count is what the summary and the expanded row both add up, so a
  // count that disagrees with the array makes the interface state a number
  // nothing in the file supports. The array is the evidence; the count is a
  // convenience field restating it. So the array wins, always, and a
  // declared 9999 beside a single object is reported as 1.
  //
  // A declared count of the wrong type is still an error rather than being
  // quietly dropped, because it says something is wrong with how the file
  // was produced.
  const declared = finding.affectedObjectCount;
  if (declared !== undefined && typeof declared !== 'number') {
    fail(ctx, `${path}.affectedObjectCount ${describe(declared)}, and must be a number`);
  }

  return {
    findingId: requireString(finding.findingId, `${path}.findingId`, ctx),
    checkId: requireNonEmptyString(finding.checkId, `${path}.checkId`, ctx),
    severity: severity as Finding['severity'],
    detectedAt: requireString(finding.detectedAt, `${path}.detectedAt`, ctx),
    affectedObjectCount: affectedObjects.length,
    affectedObjects,
    evidence: validateEvidence(finding.evidence, `${path}.evidence`, ctx),
  };
}

function validatePartialChecks(raw: unknown, ctx: Ctx): PartialCheck[] {
  // Absent on every scan written before truncation was reported, including
  // the committed baselines, so absence has to mean "none" rather than
  // "invalid". A present value still has to be the right shape.
  if (raw === undefined || raw === null) return [];

  const items = requireArray(raw, 'scan.checksPartial', ctx);
  return items.map((item, index) => {
    const path = `scan.checksPartial[${index}]`;
    const entry = requireObject(item, path, ctx);
    return {
      checkId: requireNonEmptyString(entry.checkId, `${path}.checkId`, ctx),
      reason: requireString(entry.reason, `${path}.reason`, ctx),
    };
  });
}

/**
 * Validates and normalises a parsed scan result.
 *
 * Returns a new object rather than the input, so that everything downstream
 * can rely on the optional parts having been filled in. Nothing is written
 * back: the file on disk is left exactly as the module produced it.
 */
export function validateScanResult(raw: unknown, origin: string): ScanResult {
  const ctx: Ctx = { origin, noun: 'scan result' };
  const root = requireObject(raw, 'the file', ctx);

  const schemaVersion = requireNonEmptyString(root.schemaVersion, 'schemaVersion', ctx);
  const major = majorOf(schemaVersion);
  if (major === -1) {
    fail(ctx, `schemaVersion "${schemaVersion}" has no readable major version`);
  }
  if (major > SUPPORTED_MAJOR) {
    fail(
      ctx,
      `it uses schema version ${schemaVersion}, which this dashboard does not understand. Update the dashboard rather than reading it with the wrong reader`,
    );
  }

  const scan = requireObject(root.scan, 'scan', ctx);

  // Checked in the order the contract declares them, so the first thing a
  // reader is told about a half-written file is the first thing missing from
  // it rather than whichever field this function happened to reach first.
  const scanId = requireString(scan.scanId, 'scan.scanId', ctx);
  const startedAt = requireString(scan.startedAt, 'scan.startedAt', ctx);
  const completedAt = requireString(scan.completedAt, 'scan.completedAt', ctx);
  const moduleName = requireString(scan.moduleName, 'scan.moduleName', ctx);
  const moduleVersion = requireString(scan.moduleVersion, 'scan.moduleVersion', ctx);

  const domain = requireObject(scan.domain, 'scan.domain', ctx);

  const checksFailed = requireArray(scan.checksFailed, 'scan.checksFailed', ctx).map((item, index) => {
    const path = `scan.checksFailed[${index}]`;
    const entry = requireObject(item, path, ctx);
    return {
      checkId: requireNonEmptyString(entry.checkId, `${path}.checkId`, ctx),
      errorMessage: requireString(entry.errorMessage, `${path}.errorMessage`, ctx),
    };
  });

  let executedBy: ScanResult['scan']['executedBy'];
  if (scan.executedBy !== undefined && scan.executedBy !== null) {
    const who = requireObject(scan.executedBy, 'scan.executedBy', ctx);
    executedBy = {
      account: who.account === undefined ? undefined : requireString(who.account, 'scan.executedBy.account', ctx),
      hadDomainAdminRights:
        who.hadDomainAdminRights === undefined ? undefined : Boolean(who.hadDomainAdminRights),
    };
  }

  const findings = requireArray(root.findings, 'findings', ctx)
    .map((item, index) => validateFinding(item, index, ctx));

  return {
    schemaVersion,
    scan: {
      scanId,
      startedAt,
      completedAt,
      moduleName,
      moduleVersion,
      domain: {
        dnsName: requireNonEmptyString(domain.dnsName, 'scan.domain.dnsName', ctx),
        netbiosName: domain.netbiosName === undefined ? undefined : requireString(domain.netbiosName, 'scan.domain.netbiosName', ctx),
        domainFunctionalLevel:
          domain.domainFunctionalLevel === undefined
            ? undefined
            : requireString(domain.domainFunctionalLevel, 'scan.domain.domainFunctionalLevel', ctx),
        domainControllerQueried:
          domain.domainControllerQueried === undefined
            ? undefined
            : requireString(domain.domainControllerQueried, 'scan.domain.domainControllerQueried', ctx),
      },
      executedBy,
      checksRequested: requireStringArray(scan.checksRequested, 'scan.checksRequested', ctx),
      checksCompleted: requireStringArray(scan.checksCompleted, 'scan.checksCompleted', ctx),
      checksFailed,
      checksPartial: validatePartialChecks(scan.checksPartial, ctx),
    },
    findings,
  };
}

// ---------------------------------------------------------------------------
// Finding dictionaries
// ---------------------------------------------------------------------------

/**
 * Validates one dictionary entry.
 *
 * Every field is checked only when it is present. That is deliberate and it
 * matches what the interface already does: an entry with no `whyItMatters`
 * renders "This check is not described in the finding dictionary yet", one
 * with no `whatToDo` renders "No remediation guidance is recorded", and one
 * with no `references` renders no reference section. Those fallbacks are the
 * contract rule that findings are never hidden for a thin content layer, so
 * requiring the fields here would reject content the dashboard handles
 * perfectly well.
 *
 * What the dashboard cannot survive is a field that is present and the wrong
 * type, because several of them are rendered straight into the tree as React
 * children. That is what is checked, element by element.
 */
function validateEntry(raw: unknown, checkId: string, ctx: Ctx): DictionaryEntry {
  const path = `entries.${checkId}`;
  const entry = requireObject(raw, path, ctx);

  // Rendered as text by the findings table and the expanded row.
  optionalString(entry.technicalName, `${path}.technicalName`, ctx);
  optionalString(entry.title, `${path}.title`, ctx);
  optionalString(entry.category, `${path}.category`, ctx);
  optionalString(entry.whyItMatters, `${path}.whyItMatters`, ctx);
  optionalString(entry.objectColumnLabel, `${path}.objectColumnLabel`, ctx);

  // Used as a fallback severity when a finding does not carry one, so it has
  // to be a value the severity ordering knows about.
  if (entry.defaultSeverity !== undefined) {
    requireSeverity(entry.defaultSeverity, `${path}.defaultSeverity`, ctx);
  }

  // Each step becomes a React child of its own. An object here is exactly
  // the input that crashed the expanded row while passing an array check.
  optionalStringArray(entry.whatToDo, `${path}.whatToDo`, ctx);

  // Matched against attribute names to pick table columns.
  optionalStringArray(entry.keyAttributes, `${path}.keyAttributes`, ctx);

  if (entry.references !== undefined) {
    const references = requireArray(entry.references, `${path}.references`, ctx);
    references.forEach((reference, index) => {
      const referencePath = `${path}.references[${index}]`;
      const item = requireObject(reference, referencePath, ctx);
      // The label is rendered as a child and the url becomes an href and the
      // React key, so both have to be strings for the link to work at all.
      requireString(item.label, `${referencePath}.label`, ctx);
      requireString(item.url, `${referencePath}.url`, ctx);
    });
  }

  return entry as unknown as DictionaryEntry;
}

export function validateDictionary(raw: unknown, origin: string): FindingDictionary {
  const ctx: Ctx = { origin, noun: 'finding dictionary' };
  const root = requireObject(raw, 'the file', ctx);

  const schemaVersion = requireNonEmptyString(root.schemaVersion, 'schemaVersion', ctx);
  if (majorOf(schemaVersion) > SUPPORTED_MAJOR) {
    fail(
      ctx,
      `it uses schema version ${schemaVersion}, which this dashboard does not understand. Update the dashboard rather than reading it with the wrong reader`,
    );
  }

  optionalString(root.language, 'language', ctx);
  if (root.severityScale !== undefined) {
    requireArray(root.severityScale, 'severityScale', ctx).forEach((value, index) =>
      requireSeverity(value, `severityScale[${index}]`, ctx),
    );
  }

  const entries = requireObject(root.entries, 'entries', ctx);
  for (const [checkId, entry] of Object.entries(entries)) {
    validateEntry(entry, checkId, ctx);
  }

  return root as unknown as FindingDictionary;
}
