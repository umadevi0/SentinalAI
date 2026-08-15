const API_BASE = 'http://127.0.0.1:8000';

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ sentinelaiEnabled: true });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'EVENT_BATCH') {
    fetch(`${API_BASE}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message.payload)
    }).then(async (response) => {
      const data = await response.json();
      sendResponse({ ok: response.ok, data });
    }).catch((error) => {
      sendResponse({ ok: false, error: error.message });
    });
    return true;
  }

  if (message.type === 'ANALYZE') {
    fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message.payload)
    }).then(async (response) => {
      const data = await response.json();
      sendResponse({ ok: response.ok, data });
    }).catch((error) => {
      sendResponse({ ok: false, error: error.message });
    });
    return true;
  }

  return false;
});
