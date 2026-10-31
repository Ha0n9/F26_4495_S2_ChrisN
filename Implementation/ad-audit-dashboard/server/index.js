/**
 * Local API for the AD Security Auditing Tool.
 *
 * It exists so the dashboard can start a scan itself rather than asking the
 * user to run a command and then reload a file. It is not a web service: it
 * binds to the loopback interface only, and it is expected to be started and
 * stopped alongside the dashboard on one machine.
 *
 * Security, which matters more here than the small size suggests. This
 * process runs PowerShell on the user's machine on request. Any page open in
 * that user's browser can send requests to 127.0.0.1, so without protection
 * this would be a way for an unrelated website to trigger a domain scan, or
 * worse. Three measures, all of which must hold:
 *
 *   1. The listener binds 127.0.0.1, so nothing off the machine can reach it.
 *   2. Every request must carry a token generated at startup and printed to
 *      the console. A page that cannot read that console cannot guess it.
 *   3. The Origin header, when present, must be one of the dashboard's own.
 *      This blocks a cross-site request that somehow learned the token.
 *
 * The scan arguments are passed to a PowerShell file as discrete arguments
 * rather than interpolated into a command string, so a hostile or merely
 * awkward value cannot change what runs.
 */

import express from 'express';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile, access } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(here, '..');

const PORT = Number(process.env.AUDIT_API_PORT ?? 5174);
const HOST = '127.0.0.1';

const MODULE_PATH = process.env.AUDIT_MODULE_PATH
  ?? path.resolve(projectRoot, '..', 'ADSecurityAudit', 'ADSecurityAudit.psd1');

const DATA_DIR = path.resolve(projectRoot, 'public', 'data');
const SCAN_PATH = path.join(DATA_DIR, 'scan-result.json');
const DICTIONARY_PATH = path.join(DATA_DIR, 'finding-dictionary.json');
const RUNNER = path.join(here, 'run-scan.ps1');

/** Printed at startup. Not persisted: a restart invalidates every old token. */
const TOKEN = randomBytes(24).toString('hex');

const ALLOWED_ORIGINS = new Set([
  `http://127.0.0.1:5173`,
  `http://localhost:5173`,
  `http://127.0.0.1:${PORT}`,
  `http://localhost:${PORT}`,
]);

const app = express();
app.use(express.json({ limit: '1mb' }));

/** Which PowerShell to use. pwsh when present, otherwise Windows PowerShell. */
async function resolvePowerShell() {
  if (process.env.AUDIT_PWSH) return process.env.AUDIT_PWSH;
  return process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
}

function authorise(req, res, next) {
  const origin = req.get('origin');
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: 'Request origin is not allowed.' });
  }

  const supplied = req.get('x-audit-token') ?? req.query.token;
  if (supplied !== TOKEN) {
    return res.status(401).json({
      error: 'Missing or incorrect token. Open the dashboard using the link printed when this server started.',
    });
  }

  return next();
}

async function readJsonFile(file) {
  const text = await readFile(file, 'utf8');
  // Windows PowerShell 5.1 writes UTF-8 with a byte order mark, and
  // JSON.parse rejects a leading BOM. Browsers strip it during their own
  // UTF-8 decode, which is why the dashboard reads these files happily while
  // Node refuses them. The module now writes without a BOM, but files
  // produced before that change still have one.
  return JSON.parse(text.replace(/^\uFEFF/, ''));
}

app.get('/api/health', authorise, async (_req, res) => {
  let moduleFound = true;
  try {
    await access(MODULE_PATH, constants.R_OK);
  } catch {
    moduleFound = false;
  }
  res.json({
    ok: true,
    modulePath: MODULE_PATH,
    moduleFound,
    scanOutputPath: SCAN_PATH,
    platform: process.platform,
  });
});

app.get('/api/dictionary', authorise, async (_req, res) => {
  try {
    res.json(await readJsonFile(DICTIONARY_PATH));
  } catch (error) {
    res.status(500).json({ error: `Could not read the finding dictionary: ${error.message}` });
  }
});

app.get('/api/scan/latest', authorise, async (_req, res) => {
  try {
    res.json(await readJsonFile(SCAN_PATH));
  } catch (error) {
    if (error.code === 'ENOENT') {
      return res.status(404).json({
        error: 'No scan has been run yet. Use Run scan, or write a scan result to public/data/scan-result.json.',
      });
    }
    res.status(500).json({ error: `Could not read the scan result: ${error.message}` });
  }
});

/** Only one scan at a time. A second request while one runs is rejected. */
let scanInFlight = false;

app.post('/api/scan', authorise, async (req, res) => {
  if (scanInFlight) {
    return res.status(409).json({ error: 'A scan is already running.' });
  }

  const { domainName, newAccountGraceDays } = req.body ?? {};

  if (domainName !== undefined && typeof domainName !== 'string') {
    return res.status(400).json({ error: 'domainName must be a string.' });
  }
  if (newAccountGraceDays !== undefined && !Number.isInteger(newAccountGraceDays)) {
    return res.status(400).json({ error: 'newAccountGraceDays must be an integer.' });
  }

  const shell = await resolvePowerShell();

  // Discrete arguments, never an interpolated command string.
  const args = [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', RUNNER,
    '-ModulePath', MODULE_PATH,
    '-OutputPath', SCAN_PATH,
  ];
  if (domainName) args.push('-DomainName', domainName);
  if (Number.isInteger(newAccountGraceDays)) {
    args.push('-NewAccountGraceDays', String(newAccountGraceDays));
  }

  scanInFlight = true;
  const startedAt = Date.now();

  const child = spawn(shell, args, { windowsHide: true });

  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

  /**
   * One request, one response, one release of the lock.
   *
   * A spawn that fails emits 'error' and then also emits 'close', with a
   * negative exit code. Two handlers each calling res therefore sent two
   * responses for one request: the second threw ERR_HTTP_HEADERS_SENT inside
   * an event handler, where there is no request context to catch it, and the
   * lock was left in whatever state the last handler set. Everything that
   * ends this request goes through here instead.
   */
  const timeoutMs = Number(process.env.AUDIT_SCAN_TIMEOUT_MS ?? 180000);

  let settled = false;
  let timedOut = false;
  let timeout;

  const settle = (status, body) => {
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    scanInFlight = false;
    res.status(status).json(body);
  };

  // A scan that hangs must not hold the server open forever. The flag is set
  // before the kill, because killing the child produces an ordinary 'close'
  // that is otherwise indistinguishable from the scan failing on its own.
  timeout = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, timeoutMs);

  child.on('error', (error) => {
    settle(500, {
      error: `Could not start PowerShell (${shell}): ${error.message}`,
      hint: 'Set AUDIT_PWSH to the full path of powershell.exe or pwsh.exe if it is not on PATH.',
    });
  });

  child.on('close', async (code) => {
    // Already answered by the error handler above. Nothing useful is left to
    // say, and saying it would be the bug this guard exists for.
    if (settled) return;

    if (timedOut) {
      return settle(504, {
        error: `The scan was still running after ${timeoutMs / 1000} seconds and was stopped.`,
        detail: stderr.trim() || stdout.trim() || 'No output was captured before the scan was stopped.',
      });
    }

    if (code !== 0) {
      return settle(500, {
        error: 'The scan failed.',
        exitCode: code,
        // stderr carries the PowerShell error, which is the useful part.
        detail: stderr.trim() || stdout.trim() || 'No output was captured.',
      });
    }

    try {
      const result = await readJsonFile(SCAN_PATH);
      settle(200, {
        result,
        durationMs: Date.now() - startedAt,
        // Warnings about checks that did not run arrive here. They are not
        // failures, and the dashboard surfaces the same information from
        // checksFailed, but showing them confirms the scan really ran.
        warnings: stderr.trim() ? stderr.trim().split(/\r?\n/) : [],
      });
    } catch (error) {
      settle(500, {
        error: `The scan reported success but its output could not be read: ${error.message}`,
      });
    }
  });
});

app.use((_req, res) => res.status(404).json({ error: 'Unknown endpoint.' }));

app.listen(PORT, HOST, () => {
  const url = `http://127.0.0.1:5173/?token=${TOKEN}`;
  console.log('');
  console.log('  AD Security Audit local API');
  console.log(`  listening on   http://${HOST}:${PORT}`);
  console.log(`  module         ${MODULE_PATH}`);
  console.log(`  scan output    ${SCAN_PATH}`);
  console.log('');
  console.log('  Open the dashboard with this link. It carries the access token:');
  console.log('');
  console.log(`      ${url}`);
  console.log('');
  console.log('  The token changes every time this server starts.');
  console.log('');
});
