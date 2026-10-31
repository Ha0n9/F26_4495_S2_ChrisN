import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Tests for how the access token is obtained, kept and discarded.
 *
 * The browser globals are faked by hand rather than by pulling in a DOM
 * implementation, because only three of them are involved and a fake makes
 * the storage failure cases, which a real DOM will not reproduce on demand,
 * straightforward to write.
 *
 * Every test re-imports the module, since the token is read once at load.
 * That is the behaviour under test: a page view decides what access it has
 * when it loads.
 */

const TOKEN_A = 'a'.repeat(48);
const TOKEN_B = 'b'.repeat(48);

interface FakeStorage {
  store: Map<string, string>;
  throwOnRead?: boolean;
  throwOnWrite?: boolean;
}

function installWindow(search: string, storage: FakeStorage | null) {
  const replaceState = vi.fn();

  const sessionStorage = storage
    ? {
        getItem(key: string) {
          if (storage.throwOnRead) throw new Error('blocked');
          return storage.store.get(key) ?? null;
        },
        setItem(key: string, value: string) {
          if (storage.throwOnWrite) throw new Error('blocked');
          storage.store.set(key, value);
        },
        removeItem(key: string) {
          storage.store.delete(key);
        },
      }
    : undefined;

  const fakeWindow = {
    location: { search, href: `http://127.0.0.1:5173/${search}` },
    history: { replaceState },
    // Omitted entirely when storage is null, which is how a locked-down
    // browser presents it. Reading it then throws rather than returning null.
    get sessionStorage() {
      if (!sessionStorage) throw new Error('sessionStorage is not available');
      return sessionStorage;
    },
  };

  vi.stubGlobal('window', fakeWindow);
  return { replaceState };
}

async function loadApi() {
  vi.resetModules();
  return import('./api');
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('reading the token', () => {
  it('takes it from the URL and clears it from the address bar', async () => {
    const storage: FakeStorage = { store: new Map() };
    const { replaceState } = installWindow(`?token=${TOKEN_A}`, storage);

    const api = await loadApi();

    expect(api.apiAvailable).toBe(true);
    expect(api.tokenPresent()).toBe(true);
    expect(replaceState).toHaveBeenCalled();
    expect(String(replaceState.mock.calls[0][2])).not.toContain('token=');
  });

  it('keeps the token across a refresh in the same tab', async () => {
    const storage: FakeStorage = { store: new Map() };

    installWindow(`?token=${TOKEN_A}`, storage);
    await loadApi();

    // The refresh: same tab, same storage, but the URL no longer carries the
    // token because the first load removed it. Before this fix the page came
    // back with no access and hid the Run scan controls.
    installWindow('', storage);
    const afterRefresh = await loadApi();

    expect(afterRefresh.apiAvailable).toBe(true);
    expect(afterRefresh.tokenPresent()).toBe(true);
  });

  it('lets a token in the URL replace an older stored one', async () => {
    const storage: FakeStorage = { store: new Map([['adAudit.token', TOKEN_A]]) };

    installWindow(`?token=${TOKEN_B}`, storage);
    await loadApi();

    // The server was restarted and printed a new link. Preferring storage
    // here would keep using a token that stopped working.
    expect(storage.store.get('adAudit.token')).toBe(TOKEN_B);
  });

  it('reports no access when there is neither a URL token nor a stored one', async () => {
    installWindow('', { store: new Map() });
    const api = await loadApi();

    expect(api.apiAvailable).toBe(false);
    expect(api.tokenPresent()).toBe(false);
  });

  it('still works for this page view when storage is unavailable', async () => {
    installWindow(`?token=${TOKEN_A}`, null);
    const api = await loadApi();

    // A private window, or site data blocked. The token cannot be kept, but
    // refusing to use it at all would be worse than losing it on refresh.
    expect(api.apiAvailable).toBe(true);
  });

  it('survives storage that throws on read', async () => {
    installWindow('', { store: new Map(), throwOnRead: true });
    const api = await loadApi();
    expect(api.apiAvailable).toBe(false);
  });
});

describe('a token the server no longer accepts', () => {
  it('is discarded, with a message naming the restart', async () => {
    const storage: FakeStorage = { store: new Map() };
    installWindow(`?token=${TOKEN_A}`, storage);
    const api = await loadApi();

    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: 'Missing or incorrect token.' }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );

    await expect(api.api.health()).rejects.toMatchObject({ status: 401 });

    // Dropped from storage as well, so a refresh shows the honest "no access"
    // state rather than failing the same way again.
    expect(api.tokenPresent()).toBe(false);
    expect(storage.store.has('adAudit.token')).toBe(false);
  });

  it('explains how to recover', async () => {
    installWindow(`?token=${TOKEN_A}`, { store: new Map() });
    const api = await loadApi();

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('{}', { status: 401, headers: { 'content-type': 'application/json' } })),
    );

    await expect(api.api.health()).rejects.toMatchObject({
      detail: expect.stringMatching(/new token every time it starts/),
    });
  });

  it('leaves other failures alone', async () => {
    installWindow(`?token=${TOKEN_A}`, { store: new Map() });
    const api = await loadApi();

    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: 'A scan is already running.' }), {
          status: 409,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );

    await expect(api.api.runScan()).rejects.toMatchObject({ status: 409 });
    // A 409 says nothing about the token, so the page keeps its access.
    expect(api.tokenPresent()).toBe(true);
  });

  it('sends the token as a header, never only in the URL', async () => {
    installWindow(`?token=${TOKEN_A}`, { store: new Map() });
    const api = await loadApi();

    const fetchMock = vi.fn(async () =>
      new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.api.health();

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/health');
    expect(url).not.toContain('token=');
    expect((init.headers as Record<string, string>)['X-Audit-Token']).toBe(TOKEN_A);
  });
});
