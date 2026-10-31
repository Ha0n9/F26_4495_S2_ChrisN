/**
 * Shape of scan-result.json, produced by the ADSecurityAudit PowerShell module.
 *
 * This file is the TypeScript half of the contract described in CONTRACT.md.
 * It describes what was found, as raw technical data. It never carries
 * explanation or remediation text: that lives in finding-dictionary.json.
 */

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Any value the module may place in an object's attribute bag. */
export type AttributeValue = string | number | boolean | null | string[] | Record<string, unknown>;

export interface AffectedObject {
  name: string;
  objectClass: string;
  distinguishedName: string;
  /** Open bag. Which keys appear depends on the check. */
  attributes: Record<string, AttributeValue>;
}

export interface Evidence {
  summary?: string;
  parametersUsed?: Record<string, AttributeValue>;
  query?: string;
  /** Present on policy style checks. */
  failedControls?: string[];
  [key: string]: AttributeValue | undefined;
}

export interface Finding {
  findingId: string;
  checkId: string;
  severity: Severity;
  detectedAt: string;
  affectedObjectCount: number;
  affectedObjects: AffectedObject[];
  evidence?: Evidence;
}

export interface DomainInfo {
  dnsName: string;
  netbiosName?: string;
  domainFunctionalLevel?: string;
  domainControllerQueried?: string;
}

export interface FailedCheck {
  checkId: string;
  errorMessage: string;
}

/**
 * A check that ran to the end without error but did not see everything.
 *
 * The third state, and the reason it exists: a check that abandons a branch
 * of a group hierarchy at its depth limit has neither failed nor covered its
 * ground. Recording it as completed presented unexamined accounts as a clean
 * result; recording it as failed would have discarded the real findings it
 * did produce. Both are dishonest in different directions.
 *
 * Absent from every scan written before this existed, so readers must treat
 * a missing value as an empty list rather than as invalid.
 */
export interface PartialCheck {
  checkId: string;
  /** What was not examined, and which parameter would widen it. */
  reason: string;
}

export interface ScanMeta {
  scanId: string;
  startedAt: string;
  completedAt: string;
  moduleName: string;
  moduleVersion: string;
  domain: DomainInfo;
  executedBy?: { account?: string; hadDomainAdminRights?: boolean };
  checksRequested: string[];
  checksCompleted: string[];
  checksFailed: FailedCheck[];
  checksPartial: PartialCheck[];
}

export interface ScanResult {
  schemaVersion: string;
  scan: ScanMeta;
  findings: Finding[];
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}
