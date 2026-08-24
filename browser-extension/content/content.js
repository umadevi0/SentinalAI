// SentinelAI content script v2
//
// - Tier-0/1 fast screening runs locally so most pages never hit the backend.
// - The MutationObserver batches mutations and only re-derives *targeted*
//   credential-flow state (forms, password inputs, action changes) instead of
//   re-scanning the whole DOM per mutation.
// - A temporal timeline records WHEN security-relevant events happen.
// - permissionRequests counts real browser-API uses, not all DOM elements.

(() => {
  // Compact offline knowledge for the *local* fast screen only. The backend
  // owns the authoritative (and larger) knowledge bases.
  const KNOWN_DOMAINS = new Set([
    'google', 'gmail', 'youtube', 'facebook', 'instagram', 'whatsapp',
    'microsoft', 'outlook', 'live', 'apple', 'icloud', 'amazon', 'paypal',
    'netflix', 'github', 'stackoverflow', 'wikipedia', 'reddit', 'yahoo',
    'linkedin', 'spotify', 'twitch', 'ebay', 'shopify', 'wordpress',
    'example', 'test', 'asana', 'stripe', 'slack', 'zoom', 'dropbox',
    'adobe', 'cloudflare', 'medium',
  ]);
  const KNOWN_TLDS = new Set([
    'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'me', 'ai', 'app', 'dev',
    'tech', 'online', 'site', 'live', 'top', 'info', 'biz', 'us', 'uk', 'ca',
    'au', 'de', 'fr', 'jp', 'in', 'br', 'ru', 'it', 'nl', 'es', 'pl', 'xyz',
  ]);

  const HOST = window.location.hostname.toLowerCase();
  const LABELS = HOST.split('.').filter(Boolean);
  const SLD = LABELS.length >= 2 ? LABELS[LABELS.length - 2] : (LABELS[0] || '');
  const TLD = LABELS.length ? LABELS[LABELS.length - 1] : '';
  const IS_IP = /^\d{1,3}(\.\d{1,3}){3}$/.test(HOST);
  const PUNYCODE = HOST.startsWith('xn--');
  const HAS_AT = window.location.href.includes('@') && !/^mailto:/.test(window.location.href);
  const KNOWN_DOMAIN = KNOWN_DOMAINS.has(SLD);
  const TLD_KNOWN = KNOWN_TLDS.has(TLD);

  const nav = performance.getEntriesByType('navigation')[0] || {};
  const redirectCount = nav.redirectCount || 0;

  const state = {
    passwordFields: 0,
    forms: 0,
    hiddenElements: 0,
    externalScripts: 0,
    permissionRequests: 0,
    promptInjectionSignals: 0,
    iframes: 0,
    downloads: 0,
    clipboardUses: 0,
    otpRequest: false,
    hiddenLoginForm: false,
    obfuscated: false,
    formActionDomainMismatch: false,
    credentialSubmissionDestinationMismatch: false,
    redirectCount,
    loginIntent: /login|signin|account|password/i.test(document.title + ' ' + window.location.pathname),
    timeline: [],
  };

  const mark = (type) => {
    state.timeline.push({ type, t: Math.round(performance.now()) });
    if (state.timeline.length > 50) state.timeline.shift();
  };
  mark('page_load');

  // ---- targeted credential-flow analysis ---------------------------------
  const actionHostOf = (form) => {
    try {
      const a = form.getAttribute('action') || '';
      if (!a) return HOST; // '' means same page -> same host
      const url = new URL(a, window.location.href);
      return url.hostname ? url.hostname.toLowerCase() : HOST;
    } catch (e) {
      return HOST;
    }
  };

  const methodOf = (form) => (form.getAttribute('method') || 'get').toLowerCase();

  const isHidden = (el) => {
    const style = window.getComputedStyle(el);
    return style.display === 'none' || style.visibility === 'hidden' ||
      style.opacity === '0' || style.width === '0px' || style.height === '0px';
  };

  const scanCredentialFlow = (root) => {
    let passwordFields = 0;
    if (root.querySelectorAll || root.matchMedia !== undefined) {
      passwordFields += (root.querySelectorAll ? root.querySelectorAll('input[type="password"]').length : 0);
    }
    state.passwordFields = passwordFields;

    let forms = 0;
    state.formActionDomainMismatch = false;
    state.credentialSubmissionDestinationMismatch = false;
    state.hiddenLoginForm = false;
    (root.querySelectorAll ? root.querySelectorAll('form') : []).forEach((f) => {
      forms += 1;
      const destHost = actionHostOf(f);
      const mismatch = destHost !== HOST;
      if (mismatch) {
        state.formActionDomainMismatch = true;
        const hasPassword = f.querySelector('input[type="password"]') !== null;
        if (hasPassword && (methodOf(f) === 'post' || methodOf(f) === '')) {
          state.credentialSubmissionDestinationMismatch = true;
        }
      }
      const pw = f.querySelector('input[type="password"]');
      if (pw && (isHidden(pw) || isHidden(f))) {
        state.hiddenLoginForm = true;
      }
    });
    state.forms = forms;

    const passInputs = document.querySelectorAll('input[type="password"], input[autocomplete="one-time-code"], input[name$="otp" i], input[name$="token" i]');
    state.otpRequest = Array.prototype.some.call(passInputs, (el) =>
      /otp|one-time|2fa|two.factor/i.test(
        el.getAttribute('autocomplete') + ' ' + (el.getAttribute('name') || '') + ' ' + (el.getAttribute('aria-label') || '')
      ));

    // obfuscation check (script-level obfuscation, or invisible TEXT
    // hidden inside/near a credential form; carousels / sr-only labels /
    // scroll clones elsewhere are benign and must NOT fire this)
    state.obfuscated = (() => {
      const OBF_SCRIPT_RE = /\beval\s*\(|\batob\s*\(|unescape\s*\(|String\.fromCharCode|document\.write\s*\(\s*unescape|(?:\\x[0-9a-fA-F]{2}){6,}/;
      try {
        const scripts = document.querySelectorAll('script:not([src])');
        for (let i = 0; i < scripts.length && i < 200; i++) {
          const t = scripts[i].textContent || '';
          if (t.length > 60 && OBF_SCRIPT_RE.test(t)) return true;
        }
      } catch (e) { /* best-effort */ }
      const invis = (el) => {
        const s = window.getComputedStyle(el);
        if (!s || s.display === 'none' || s.visibility === 'hidden') return false;
        if ((el.textContent || '').trim().length < 8) return false;
        if (parseFloat(s.opacity) === 0) return true;
        if (parseFloat(s.fontSize) === 0) return true;
        if (parseFloat(s.textIndent) <= -999) return true;
        const c = s.color || '';
        if (c === 'transparent') return true;
        const m = c.match(/rgba?\(([^)]+)\)/);
        if (m) { const p = m[1].split(','); if (p.length === 4 && parseFloat(p[3]) === 0) return true; }
        return false;
      };
      const credForms = Array.from(document.querySelectorAll('form')).filter(
        (f) => f.querySelector('input[type="password"], input[type="email"], input[name*="mail" i], input[autocomplete*="user" i]'));
      for (const f of credForms.slice(0, 10)) {
        const els = f.querySelectorAll('*');
        for (let i = 0; i < els.length && i < 800; i++) {
          if (invis(els[i])) return true;
        }
      }
      return false;
    })();
  };

  // ---- prompt-injection signals (narrowed: hidden long text w/ prompt cues) -
  const PROMPT_RE = /ignore (all |previous )?(instructions|prompts|text|content)|system prompt|you are now |disregard (the )?(previous|above)|"role"\s*:\s*"system"/i;
  const scanPromptSignals = () => {
    let hits = 0;
    const hidden = document.querySelectorAll(
      '[style*="opacity:0" i],[style*="opacity: 0" i],[style*="font-size:0" i],[style*="font-size: 0" i],' +
      '[style*="display:none" i] textarea,[style*="display: none" i] textarea,[type="hidden" i] textarea'
    );
    for (let i = 0; i < hidden.length && i < 200; i++) {
      const text = hidden[i].textContent || '';
      if (text.length > 40 && PROMPT_RE.test(text.slice(0, 300))) hits++;
    }
    return hits;
  };

  // ---- full (initial) snapshot --------------------------------------------
  const collectPageSnapshot = () => {
    state.passwordFields = document.querySelectorAll('input[type="password"]').length;
    state.forms = document.querySelectorAll('form').length;
    state.hiddenElements = document.querySelectorAll(
      'input[type="hidden"], [style*="display: none"], [style*="display:none"],' +
      ' [aria-hidden="true"], .hidden, [hidden], [style*="visibility:hidden" i]'
    ).length;
    state.externalScripts = Array.from(document.scripts).filter((s) => s.src).length;
    state.iframes = document.querySelectorAll('iframe').length;
    state.loginIntent = /login|signin|account|password/i.test(document.title + ' ' + window.location.pathname);
    scanCredentialFlow(document);
    state.promptInjectionSignals = scanPromptSignals();
  };

  // ---- permission API instrumentation (real requests only) -----------------
  const bumpPermissions = () => {
    state.permissionRequests += 1;
    mark('permission_request');
  };
  try {
    if (navigator.geolocation) {
      ['getCurrentPosition', 'watchPosition'].forEach((m) => {
        const orig = navigator.geolocation[m];
        if (typeof orig === 'function') {
          navigator.geolocation[m] = function (...args) {
            bumpPermissions();
            return orig.apply(this, args);
          };
        }
      });
    }
    if (window.Notification && Notification.requestPermission) {
      const orig = Notification.requestPermission;
      Notification.requestPermission = function (...args) {
        bumpPermissions();
        return orig.apply(this, args);
      };
    }
    if (navigator.clipboard) {
      ['read', 'write'].forEach((m) => {
        try {
          const orig = navigator.clipboard[m];
          if (typeof orig === 'function') {
            navigator.clipboard[m] = function (...args) {
              state.clipboardUses += 1;
              return orig.apply(this, args);
            };
          }
        } catch (e) { /* ignore */ }
      });
    }
    const fs = document.documentElement && document.documentElement.requestFullscreen;
    if (typeof fs === 'function') {
      document.documentElement.requestFullscreen = function (...args) {
        bumpPermissions();
        return fs.apply(this, args);
      };
    }
  } catch (e) { /* instrumented best-effort */ }

  document.addEventListener('submit', (e) => {
    const form = e.target;
    const destHost = actionHostOf(form);
    const hasPassword = form.querySelector('input[type="password"]') !== null;
    state.credentialSubmissionDestinationMismatch =
      hasPassword && destHost !== HOST && (methodOf(form) === 'post' || methodOf(form) === '');
    mark('credential_submit_destination=' + destHost);
    analyzeIfNeeded(true);
  }, true);

  // ---- local fast screen ----------------------------------------------------
  const computeFastTier = () => {
    if (state.credentialSubmissionDestinationMismatch ||
        (state.formActionDomainMismatch && state.passwordFields > 0)) return 'high';
    if (state.hiddenLoginForm) return 'high';
    if (IS_IP || HAS_AT || PUNYCODE) return 'high';
    if (state.passwordFields > 0 && !KNOWN_DOMAIN) return 'ambiguous';
    if (state.passwordFields > 0 && !TLD_KNOWN) return 'ambiguous';
    if (state.obfuscated) return 'ambiguous';
    return 'low';
  };

  const snapshotForBackend = () => ({
    url: window.location.href,
    title: document.title,
    domain: HOST,
    passwordFields: state.passwordFields,
    forms: state.forms,
    hiddenElements: state.hiddenElements,
    externalScripts: state.externalScripts,
    permissionRequests: state.permissionRequests,
    promptInjectionSignals: state.promptInjectionSignals,
    iframes: state.iframes,
    downloads: state.downloads,
    clipboardAccess: state.clipboardUses,
    otpRequest: state.otpRequest,
    hiddenLoginForm: state.hiddenLoginForm,
    obfuscatedContent: state.obfuscated,
    redirectCount: state.redirectCount,
    hasLoginIntent: state.loginIntent,
    formActionDomainMismatch: state.formActionDomainMismatch,
    credentialSubmissionDestinationMismatch: state.credentialSubmissionDestinationMismatch,
    brandHints: document.title.replace(/[|_>-]/g, ' ').slice(0, 200),
    timeline: state.timeline,
  });

  let lastAnalyzeKey = '';
  let lastTier = 'low';
  const analyzeIfNeeded = (force) => {
    const tier = computeFastTier();
    const key = window.location.href + '|' + tier;
    if (tier === 'low' && !force) return;
    if (key === lastAnalyzeKey) return; // already analyzed this state
    lastAnalyzeKey = key;
    lastTier = tier;
    chrome.runtime.sendMessage({
      type: 'ANALYZE',
      payload: { url: window.location.href, metadata: snapshotForBackend() },
    });
  };

  // ---- mutation batching (no full-DOM rescans per mutation) ----------------
  let mutationTimer = null;
  let pendingScan = false;
  const MUTATION_DEBOUNCE = 220;
  const scheduleScan = () => {
    if (mutationTimer) clearTimeout(mutationTimer);
    mutationTimer = setTimeout(() => {
      mutationTimer = null;
      if (!pendingScan) return;
      pendingScan = false;
      scanCredentialFlow(document);
      mark('dom_mutation_batch');
      const tier = computeFastTier();
      if (state.passwordFields > 0 || tier !== lastTier) {
        analyzeIfNeeded(state.passwordFields > 0);
      }
    }, MUTATION_DEBOUNCE);
  };

  const observer = new MutationObserver((mutations) => {
    if (!pendingScan) {
      pendingScan = true;
      mark('mutation');
    }
    scheduleScan();
  });
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
  });

  // ---- initial run ----------------------------------------------------------
  collectPageSnapshot();
  state.promptInjectionSignals = scanPromptSignals();
  const tier = computeFastTier();
  lastTier = tier;
  if (tier !== 'low') {
    analyzeIfNeeded(true);
  }

  // ---- messaging ------------------------------------------------------------
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'GET_PAGE_CONTEXT') {
      sendResponse(snapshotForBackend());
      return true;
    }
    return false;
  });

  window.addEventListener('beforeunload', () => {
    chrome.runtime.sendMessage({
      type: 'EVENT_BATCH',
      payload: {
        source: 'content-script',
        event_type: 'page_unload',
        timestamp: new Date().toISOString(),
        payload: snapshotForBackend(),
      },
    });
  });
})();