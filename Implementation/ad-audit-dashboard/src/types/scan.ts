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
}

export interface ScanResult {
  schemaVersion: string;
  scan: ScanMeta;
  findings: Finding[];
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}
