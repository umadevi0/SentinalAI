const API_BASE = 'http://127.0.0.1:8000';
const CACHE_TTL_MS = 5 * 60 * 1000;      // domain trust survival
const CACHE_KEY = 'sentinelaiAnalyzeCache';

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ sentinelaiEnabled: true });
});

// In-flight dedupe: a single outstanding request per URL.
const inFlight = new Map();

async function getCache() {
  try {
    const stored = await chrome.storage.session.get(CACHE_KEY);
    return stored[CACHE_KEY] || {};
  } catch (e) {
    return {};
  }
}

async function setCache(store) {
  try {
    await chrome.storage.session.set({ [CACHE_KEY]: store });
  } catch (e) {
    // quota / transient errors are non-fatal
  }
}

async function analyze(payload) {
  const key = payload.url.split('#')[0];
  if (inFlight.has(key)) {
    return inFlight.get(key);
  }

  // Bounded cache lookup: re-verify credential pages more eagerly.
  const needsFresh = (payload.metadata && payload.metadata.passwordFields > 0);
  const store = await getCache();
  const hit = store[key];
  if (hit && (!needsFresh || hit.tier === 'high')) {
    const age = Date.now() - hit.ts;
    if (age < CACHE_TTL_MS) {
      return { ok: true, data: hit.data, cached: true };
    }
  }

  const t0 = Date.now();
  const promise = fetch(`${API_BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then(async (response) => {
      const data = await response.json();
      const elapsed = Date.now() - t0;
      if (data && data.timing_ms) {
        data.timing_ms.roundtrip_ms = elapsed;
      } else {
        data.timing_ms = { roundtrip_ms: elapsed };
      }
      const action = data?.decision?.action;
      const tier = action === 'block' ? 'high' : action === 'continue_monitoring' ? 'low' : 'ambiguous';
      store[key] = { ts: Date.now(), data, tier };
      setCache(store);
      return { ok: response.ok, data };
    })
    .catch((error) => ({ ok: false, error: error.message }));
  inFlight.set(key, promise);
  promise.finally(() => inFlight.delete(key));
  return promise;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'EVENT_BATCH') {
    fetch(`${API_BASE}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message.payload),
    })
      .then(async (response) => sendResponse({ ok: response.ok, data: await response.json() }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.type === 'ANALYZE') {
    analyze(message.payload)
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  return false;
});