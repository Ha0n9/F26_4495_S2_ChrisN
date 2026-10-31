/**
 * Regression tests for the local API.
 *
 * These start the real server as a child process and talk to it over HTTP,
 * rather than importing it, because the defect being guarded against lives in
 * how one request is finalised and only shows up end to end.
 *
 * No PowerShell, no domain and no RSAT are involved. AUDIT_PWSH is pointed at
 * a path that does not exist, or at a generated stub that hangs, so every
 * path through the scan endpoint can be exercised anywhere Node runs.
 *
 *     cd Implementation/ad-audit-dashboard/server
 *     npm install
 *     npm test
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(here, 'index.js');

let nextPort = 5300 + Math.floor(Math.random() * 400);

/**
 * Starts the server and waits for the token it prints.
 *
 * The token is only ever printed, never persisted, so reading stdout is also
 * the only way a legitimate client obtains it. The test does exactly what the
 * dashboard's launcher asks a human to do.
 */
async function startServer(env = {}) {
  const port = nextPort++;
  const child = spawn(process.execPath, [SERVER], {
    env: { ...process.env, AUDIT_API_PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (c) => { stdout += c.toString(); });
  child.stderr.on('data', (c) => { stderr += c.toString(); });

  const token = await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Server did not start.\nstdout:\n${stdout}\nstderr:\n${stderr}`)),
      10000,
    );
    const check = setInterval(() => {
      const match = stdout.match(/token=([0-9a-f]{48})/);
      if (match) {
        clearInterval(check);
        clearTimeout(timer);
        resolve(match[1]);
      }
    }, 25);
    child.on('exit', () => {
      clearInterval(check);
      clearTimeout(timer);
      reject(new Error(`Server exited early.\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    });
  });

  const base = `http://127.0.0.1:${port}`;

  return {
    token,
    base,
    get stderr() { return stderr; },
    call(pathname, init = {}) {
      return fetch(base + pathname, {
        ...init,
        headers: { 'X-Audit-Token': token, 'Content-Type': 'application/json', ...init.headers },
      });
    },
    async stop() {
      child.kill();
      await new Promise((resolve) => child.on('exit', resolve));
    },
  };
}

/**
 * Writes an executable that ignores its arguments and hangs.
 *
 * The scan endpoint always passes the same PowerShell argument list, so a
 * stub cannot be `node` or `sleep` directly: both reject -NoProfile. A tiny
 * platform-appropriate script is generated instead.
 */
async function makeHangingShell() {
  const dir = await mkdtemp(path.join(tmpdir(), 'audit-stub-'));
  if (process.platform === 'win32') {
    const file = path.join(dir, 'hang.cmd');
    await writeFile(file, '@echo off\r\nping -n 10 127.0.0.1 >nul\r\n');
    return { file, cleanup: () => rm(dir, { recursive: true, force: true }) };
  }
  const file = path.join(dir, 'hang.sh');
  // exec, so the shell is replaced by sleep rather than becoming its parent.
  // Without it, killing the shell leaves sleep holding the stdio pipes open
  // and 'close' does not fire until the sleep finishes on its own.
  await writeFile(file, '#!/bin/sh\nexec sleep 10\n');
  await chmod(file, 0o755);
  return { file, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

// ---------------------------------------------------------------------------

test('a PowerShell that cannot be launched produces exactly one useful error', async (t) => {
  const server = await startServer({ AUDIT_PWSH: '/nonexistent/definitely-not-powershell' });
  t.after(() => server.stop());

  const response = await server.call('/api/scan', { method: 'POST', body: '{}' });
  assert.equal(response.status, 500);

  const body = await response.json();
  assert.match(body.error, /Could not start PowerShell/);
  assert.ok(body.hint, 'the error carries a hint about AUDIT_PWSH');

  // The spawn failure emits both 'error' and 'close'. If the second one also
  // answered, Node would log ERR_HTTP_HEADERS_SENT here.
  await new Promise((r) => setTimeout(r, 300));
  assert.doesNotMatch(server.stderr, /ERR_HTTP_HEADERS_SENT/);
  assert.doesNotMatch(server.stderr, /UnhandledPromiseRejection/);
});

test('the API stays usable after a failed launch', async (t) => {
  const server = await startServer({ AUDIT_PWSH: '/nonexistent/definitely-not-powershell' });
  t.after(() => server.stop());

  await server.call('/api/scan', { method: 'POST', body: '{}' });

  const health = await server.call('/api/health');
  assert.equal(health.status, 200, 'health still answers');

  // The scan lock has to be released on the failure path too, or every later
  // scan is refused with 409 until the server is restarted.
  const second = await server.call('/api/scan', { method: 'POST', body: '{}' });
  assert.notEqual(second.status, 409, 'the scan lock was released');
  assert.equal(second.status, 500);
});

test('a scan that overruns its timeout is reported as a timeout, not a failure', async (t) => {
  const stub = await makeHangingShell();
  t.after(() => stub.cleanup());

  const server = await startServer({ AUDIT_PWSH: stub.file, AUDIT_SCAN_TIMEOUT_MS: '600' });
  t.after(() => server.stop());

  const response = await server.call('/api/scan', { method: 'POST', body: '{}' });
  assert.equal(response.status, 504, 'a timeout is not the same as a scan that failed');

  const body = await response.json();
  assert.match(body.error, /still running after/);

  const second = await server.call('/api/scan', { method: 'POST', body: '{}' });
  assert.notEqual(second.status, 409, 'the lock is released after a timeout too');
});

test('a second scan while one is running is refused rather than queued', async (t) => {
  const stub = await makeHangingShell();
  t.after(() => stub.cleanup());

  const server = await startServer({ AUDIT_PWSH: stub.file, AUDIT_SCAN_TIMEOUT_MS: '2000' });
  t.after(() => server.stop());

  const first = server.call('/api/scan', { method: 'POST', body: '{}' });
  await new Promise((r) => setTimeout(r, 200));

  const second = await server.call('/api/scan', { method: 'POST', body: '{}' });
  assert.equal(second.status, 409);

  await first;
});

// ---------------------------------------------------------------------------
// The protections these fixes must not weaken.

test('the token is still required', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const response = await fetch(`${server.base}/api/health`);
  assert.equal(response.status, 401);

  const wrong = await fetch(`${server.base}/api/health`, {
    headers: { 'X-Audit-Token': 'f'.repeat(48) },
  });
  assert.equal(wrong.status, 401);
});

test('a foreign origin is still refused', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const response = await server.call('/api/health', { headers: { Origin: 'https://example.com' } });
  assert.equal(response.status, 403);

  const allowed = await server.call('/api/health', { headers: { Origin: 'http://127.0.0.1:5173' } });
  assert.equal(allowed.status, 200);
});

test('the listener is bound to loopback only', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());

  const health = await server.call('/api/health');
  const body = await health.json();
  assert.equal(body.ok, true);
  // Binding is asserted in the server source rather than by dialling an
  // external address, which a sandboxed test runner cannot do reliably.
  const source = await import('node:fs/promises').then((fs) => fs.readFile(SERVER, 'utf8'));
  assert.match(source, /const HOST = '127\.0\.0\.1'/);
  assert.match(source, /app\.listen\(PORT, HOST/);
});
