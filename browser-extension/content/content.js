const sendEventBatch = (payload) => {
  chrome.runtime.sendMessage({ type: 'EVENT_BATCH', payload }, () => {
    // no-op; background handles transport
  });
};

const collectPageSnapshot = () => {
  const passwordFields = document.querySelectorAll('input[type="password"]').length;
  const forms = document.querySelectorAll('form').length;
  const hiddenElements = document.querySelectorAll('input[type="hidden"], [style*="display: none"], [aria-hidden="true"], .hidden, [hidden]').length;
  const externalScripts = Array.from(document.scripts).filter((script) => script.src).length;
  const permissionRequests = document.querySelectorAll('button, input, a').length;
  const promptSignals = document.querySelectorAll('[aria-label*="login" i], [placeholder*="password" i], [data-login], [onclick*="submit" i], [style*="opacity:0" i], [style*="font-size:0" i], [style*="color:transparent" i], .prompt-injection').length;
  const inputs = document.querySelectorAll('input, textarea, select').length;
  const links = document.querySelectorAll('a[href]').length;
  const metaTags = document.querySelectorAll('meta').length;

  return {
    url: window.location.href,
    title: document.title,
    domain: window.location.hostname,
    passwordFields,
    forms,
    hiddenElements,
    externalScripts,
    metadataTags: metaTags,
    permissionRequests,
    promptInjectionSignals: promptSignals,
    inputFields: inputs,
    linkCount: links,
    hasLoginIntent: /login|signin|account|password/i.test(document.title + ' ' + window.location.pathname)
  };
};

const emitPageEvent = () => {
  const snapshot = collectPageSnapshot();
  sendEventBatch({
    source: 'content-script',
    event_type: 'page_snapshot',
    timestamp: new Date().toISOString(),
    payload: snapshot
  });
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === 'GET_PAGE_CONTEXT') {
    sendResponse(collectPageSnapshot());
    return true;
  }

  return false;
});

window.addEventListener('load', emitPageEvent);
window.addEventListener('beforeunload', () => sendEventBatch({
  source: 'content-script',
  event_type: 'page_unload',
  timestamp: new Date().toISOString(),
  payload: collectPageSnapshot()
}));

const observer = new MutationObserver(() => {
  emitPageEvent();
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: true
});
