/**
 * Browser APIs jsdom does not implement but Ant Design calls during render.
 *
 * Without these every render throws before reaching the component under
 * test, which is worse than it sounds: a test asserting that bad input
 * throws would pass for the wrong reason and report a defect as fixed when
 * nothing had been checked at all.
 *
 * This file is loaded for every test, including the pure-function ones that
 * run without a DOM, so it does nothing when there is no window.
 */

if (typeof window !== 'undefined') {
  installBrowserStubs();
}

function installBrowserStubs(): void {
  if (!window.matchMedia) {
    window.matchMedia = (query: string): MediaQueryList =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList;
  }

  if (!('ResizeObserver' in window)) {
    class ResizeObserverStub {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    (window as unknown as Record<string, unknown>).ResizeObserver = ResizeObserverStub;
  }
}
