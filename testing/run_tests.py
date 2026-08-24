r"""SentinelAI batch URL tester.

Pipeline per URL (no browser extension loaded - same logic replicated):
  open in headless Chromium -> classify how it opened ->
  collect the same page snapshot the extension's content script sends ->
  POST {url, metadata} to /api/analyze -> record decision + resources.

Input CSV
    Must contain a column named (or containing) 'url'.
    Optionally a second column holding the ground truth; its header may be
    label / actual / ground_truth / class / verdict / result / legit /
    is_legit / phishing / category / target. Values are normalized:
      phishing, phish, bad, malicious, scam, fraud, 0  -> phishing
      legit, legitimate, safe, benign, good, 1         -> legit
    (digit convention matches the output: 1 = legit, 0 = phishing)

Output CSV  (testing/results.csv, overwritten each run)
    Only pages that loaded cleanly (opened_ok), are English-language, and
    render actual content get a row. Everything else is skipped with a
    console note and appears nowhere in the CSV:
      - load failures: dns/connection/certificate/blocked/timeout
      - HTTP error statuses (4xx/5xx like 404 or 503)
      - browser error pages (DNS_PROBE_FINISHED_NXDOMAIN etc.)
      - non-English pages (skipped_non_english)
      - empty / parked pages with no usable content (empty_or_parked)
      - off-target redirects / cloaking (redirected_off_target)
      - Google Docs/Sheets/Slides/Sites hosts (skipped_untestable_host)
    Columns:
    url, page_status, decision, trust, confidence, ml_probability, threat,
    stage, certainty, evidence, latency_ms,
    cpu_usage, memory_usage_mb, bandwidth_kb,
    predicted, actual
    predicted: 1 = legit, 0 = phishing (block/warn count as phishing;
               blank when the page never opened).
    actual:    normalized ground-truth from the input CSV ('' if absent).

Usage:
    python testing/run_tests.py                        # root backend, 4 workers
    python testing/run_tests.py --backends nested      # test the older copy
    python testing/run_tests.py --input my_urls.csv --workers 8
    python testing/run_tests.py --max-results 100      # stop after 100 rows
                                                       # (default 50; 0 = all)
"""
import argparse
import csv
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from multiprocessing import Event as MPEvent, Process, Queue
from urllib import request as urlrequest
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PY_CANDIDATES = [
    os.path.join(ROOT, '.venv313', 'Scripts', 'python.exe'),
    os.path.join(ROOT, '.venv', 'Scripts', 'python.exe'),
]
VENV_PYTHON = next((p for p in _PY_CANDIDATES if os.path.exists(p)), sys.executable)

BACKENDS = {
    'root': {'dir': ROOT, 'module': 'backend.api.main:app', 'base_port': 8619},
    'nested': {'dir': os.path.join(ROOT, 'SentinalAI'),
               'module': 'backend.api.main:app', 'base_port': 8620},
}

RESULT_COLUMNS = [
    'url', 'page_status', 'decision', 'trust', 'confidence', 'ml_probability',
    'threat', 'stage', 'certainty', 'evidence', 'latency_ms',
    'cpu_usage', 'memory_usage_mb', 'bandwidth_kb',
    'predicted', 'actual',
]

# Page never actually loaded / not classifiable -> no result row for these.
LOAD_FAILURE_STATUSES = {
    'dns_error', 'connection_error', 'security_error_certificate',
    'security_warning_safebrowsing', 'browser_blocked', 'timeout',
    'other_error', 'skipped_non_english', 'empty_or_parked',
    'redirected_off_target', 'skipped_untestable_host',
}

SKIP_REASONS = {
    'skipped_non_english': 'page content is not English',
    'empty_or_parked': 'page rendered empty/parked (dead or parked domain)',
    'redirected_off_target': 'page redirected to an unrelated domain '
                             '(scanner-evasion / cloaking)',
    'skipped_untestable_host': 'URL hosts user content behind a legitimate '
                               'platform UI (Google Docs/Sheets/Slides/Sites)',
}

# Platforms that serve arbitrary user uploads behind their own genuine UI
# (sign-in walls, viewers). The rendered page is really Google's, so the
# classifier can never see the payload -> untestable, always discard.
UNTESTABLE_HOSTS = {
    'docs.google.com', 'sites.google.com', 'slides.google.com',
    'sheets.google.com',
}

URL_HEADER_HINTS = {'url', 'urls', 'link', 'links', 'website', 'site', 'address'}
LABEL_HEADER_HINTS = {'label', 'labels', 'actual', 'actual_answer', 'ground_truth',
                      'truth', 'class', 'target', 'verdict', 'result', 'legit',
                      'is_legit', 'phishing', 'category'}
PHISHING_VALUES = {'phishing', 'phish', 'bad', 'malicious', 'malware', 'scam',
                   'fraud', 'attack', 'unsafe', '0'}
LEGIT_VALUES = {'legit', 'legitimate', 'benign', 'safe', 'good', 'ham',
                'trusted', 'normal', 'ok', '1'}

SNAPSHOT_JS = r"""
() => {
  const HOST = window.location.hostname.toLowerCase();
  const LABELS = HOST.split('.').filter(Boolean);
  const SLD = LABELS.length >= 2 ? LABELS[LABELS.length - 2] : (LABELS[0] || '');
  const TLD = LABELS.length ? LABELS[LABELS.length - 1] : '';
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const redirectCount = nav.redirectCount || 0;
  const state = {
    passwordFields: 0, forms: 0, hiddenElements: 0, externalScripts: 0,
    permissionRequests: 0, promptInjectionSignals: 0, iframes: 0,
    otpRequest: false, hiddenLoginForm: false, obfuscated: false,
    formActionDomainMismatch: false,
    credentialSubmissionDestinationMismatch: false, redirectCount,
    loginIntent: false,
  };
  const actionHostOf = (form) => {
    try {
      const a = form.getAttribute('action') || '';
      if (!a) return HOST;
      const url = new URL(a, window.location.href);
      return url.hostname ? url.hostname.toLowerCase() : HOST;
    } catch (e) { return HOST; }
  };
  const methodOf = (form) => (form.getAttribute('method') || 'get').toLowerCase();
  const isHidden = (el) => {
    const style = window.getComputedStyle(el);
    return style.display === 'none' || style.visibility === 'hidden' ||
      style.opacity === '0' || style.width === '0px' || style.height === '0px';
  };
  state.passwordFields = document.querySelectorAll('input[type="password"]').length;
  state.forms = document.querySelectorAll('form').length;
  state.hiddenElements = document.querySelectorAll(
    'input[type="hidden"], [style*="display: none"], [style*="display:none"],' +
    ' [aria-hidden="true"], .hidden, [hidden], [style*="visibility:hidden" i]'
  ).length;
  state.externalScripts = Array.from(document.scripts).filter((s) => s.src).length;
  state.iframes = document.querySelectorAll('iframe').length;
  state.loginIntent = /login|signin|account|password/i.test(document.title + ' ' + window.location.pathname);
  document.querySelectorAll('form').forEach((f) => {
    const destHost = actionHostOf(f);
    if (destHost !== HOST) {
      state.formActionDomainMismatch = true;
      const hasPassword = f.querySelector('input[type="password"]') !== null;
      if (hasPassword && (methodOf(f) === 'post' || methodOf(f) === '')) {
        state.credentialSubmissionDestinationMismatch = true;
      }
    }
    const pw = f.querySelector('input[type="password"]');
    if (pw && (isHidden(pw) || isHidden(f))) state.hiddenLoginForm = true;
  });
  const passInputs = document.querySelectorAll('input[type="password"], input[autocomplete="one-time-code"], input[name$="otp" i], input[name$="token" i]');
  state.otpRequest = Array.prototype.some.call(passInputs, (el) =>
    /otp|one-time|2fa|two.factor/i.test(
      el.getAttribute('autocomplete') + ' ' + (el.getAttribute('name') || '') + ' ' + (el.getAttribute('aria-label') || '')
    ));
  state.obfuscated = (() => {
    // (a) script-level obfuscation: eval/atob/unescape blobs in inline JS
    const OBF_SCRIPT_RE = /\beval\s*\(|\batob\s*\(|unescape\s*\(|String\.fromCharCode|document\.write\s*\(\s*unescape|(?:\\x[0-9a-fA-F]{2}){6,}/;
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      for (let i = 0; i < scripts.length && i < 200; i++) {
        const t = scripts[i].textContent || '';
        if (t.length > 60 && OBF_SCRIPT_RE.test(t)) return true;
      }
    } catch (e) {}
    // (b) invisible TEXT hidden inside/near a credential form
    //     (carousels, sr-only labels and scroll clones elsewhere are benign)
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
  const PROMPT_RE = /ignore (all |previous )?(instructions|prompts|text|content)|system prompt|you are now |disregard (the )?(previous|above)|"role"\s*:\s*"system"/i;
  let hits = 0;
  const hidden = document.querySelectorAll(
    '[style*="opacity:0" i],[style*="opacity: 0" i],[style*="font-size:0" i],[style*="font-size: 0" i],' +
    '[style*="display:none" i] textarea,[style*="display: none" i] textarea,[type="hidden" i] textarea'
  );
  for (let i = 0; i < hidden.length && i < 200; i++) {
    const text = hidden[i].textContent || '';
    if (text.length > 40 && PROMPT_RE.test(text.slice(0, 300))) hits++;
  }
  state.promptInjectionSignals = hits;
  return {
    url: window.location.href,
    title: document.title,
    domain: HOST,
    passwordFields: state.passwordFields,
    forms: state.forms,
    hiddenElements: state.hiddenElements,
    externalScripts: state.externalScripts,
    permissionRequests: 0,
    promptInjectionSignals: state.promptInjectionSignals,
    iframes: state.iframes,
    downloads: 0,
    clipboardAccess: 0,
    otpRequest: state.otpRequest,
    hiddenLoginForm: state.hiddenLoginForm,
    obfuscatedContent: state.obfuscated,
    redirectCount: state.redirectCount,
    hasLoginIntent: state.loginIntent,
    formActionDomainMismatch: state.formActionDomainMismatch,
    credentialSubmissionDestinationMismatch: state.credentialSubmissionDestinationMismatch,
    brandHints: document.title.replace(/[|_>-]/g, ' ').slice(0, 200),
    timeline: [{ type: 'page_load', t: 0 }],
    lang: (document.documentElement && document.documentElement.lang) || '',
    textSample: document.body ? document.body.innerText.slice(0, 3000) : '',
  };
}
"""

INTERSTITIAL_MARKERS = [
    ('security_warning_safebrowsing',
     ['deceptive site ahead', 'dangerous site', 'visitors, beware',
      'the site ahead contains harmful programs']),
    ('security_error_certificate',
     ["your connection isn't private", 'your connection is not private',
      "your connection isn\u2019t private",
      'this site is not secure', 'net::err_cert']),
    ('connection_error',
     ["this site can't be reached", "this site can\u2019t be reached",
      "hmmm… can't reach this page", "hmmm\u2026 can\u2019t reach this page",
      'this webpage is not available', 'no internet',
      'dns_probe_finished_nxdomain',
      'err_name_not_resolved', 'err_address_unreachable',
      'dns address could not be found', 'server ip address could not be found',
      'check if there is a typo in',
      'is currently unable to handle this request', 'err_connection_refused',
      'err_connection_timed_out', 'this page has been removed']),
    ('browser_blocked',
     ['blocked by your network administrator', 'this site is blocked',
      'access to this site is blocked', 'site is blocked by the administrator']),
]

ERR_MAP = [
    (('ERR_NAME_NOT_RESOLVED', 'ERR_DNS'), 'dns_error'),    (('ERR_CERT_', 'ERR_SSL', 'ERR_HTTPS', 'ERR_SSL_PROTOCOL_ERROR',
      'ERR_PROXY_CERTIFICATE'), 'security_error_certificate'),
    (('ERR_BLOCKED_BY_ADMINISTRATOR', 'ERR_ACCESS_DENIED', 'ERR_BLOCKED_BY_CLIENT',
      'ERR_BLOCKED_BY_RESPONSE', 'ERR_BLOCKED_BY_ORB', 'ERR_BLOCKED_AS_INSECURE'),
     'browser_blocked'),
    (('ERR_CONNECTION_REFUSED', 'ERR_CONNECTION_RESET', 'ERR_CONNECTION_TIMED_OUT',
      'ERR_CONNECTION_CLOSED', 'ERR_TIMED_OUT', 'ERR_INTERNET_DISCONNECTED',
      'ERR_EMPTY_RESPONSE', 'ERR_ADDRESS_UNREACHABLE', 'ERR_NETWORK_CHANGED',
      'ERR_NAME_RESOLUTION_FAILED', 'ERR_UNSAFE_PORT', 'ERR_HTTP2_PROTOCOL_ERROR'),
     'connection_error'),
]


def classify_nav_error(message):
    msg = message or ''
    for needles, status in ERR_MAP:
        for n in needles:
            if n in msg:
                m = re.search(r'(net::ERR_[A-Z_]+)', msg)
                return status, (m.group(1) if m else n)
    if 'Timeout' in msg or 'TIMEOUT' in msg:
        return 'timeout', 'nav_timeout'
    return 'other_error', msg[:120]


def classify_page_content(title, body_sample):
    hay = (title + ' ' + body_sample).lower()
    for status, markers in INTERSTITIAL_MARKERS:
        for mk in markers:
            if mk in hay:
                return status
    return None


# ---- language gate -----------------------------------------------------------
# Non-Latin script runs (CJK / Cyrillic / Arabic / Hebrew / Greek / Thai /
# Devanagari / Hangul / Kana) plus an English-stopword ratio test.
_NON_LATIN_RE = re.compile(
    r'[\u0370-\u03ff\u0400-\u04ff\u0590-\u05ff\u0600-\u06ff\u0900-\u097f'
    r'\u0e00-\u0e7f\u10a0-\u10ff\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff'
    r'\uf900-\ufaff\uff00-\uffef\uac00-\ud7af]')
EN_STOPWORDS = {
    'the', 'and', 'of', 'to', 'you', 'your', 'is', 'for', 'in', 'on', 'with',
    'account', 'login', 'password', 'click', 'here', 'email', 'not', 'it',
    'this', 'that', 'be', 'are', 'as', 'we', 'our', 'will', 'or', 'if',
    'from', 'at', 'by', 'an', 'have', 'has', 'can', 'please', 'enter',
    'sign', 'up', 'new', 'free', 'all', 'more', 'get', 'how', 'what', 'us',
}


def is_english_page(snapshot):
    """True when the page looks English enough to keep for testing."""
    text = str(snapshot.get('textSample') or '')
    html_lang = str(snapshot.get('lang') or '').strip().lower()

    letters = len(re.findall(r'[^\W\d_]', text, re.UNICODE))
    if letters >= 40:
        nonlatin = len(_NON_LATIN_RE.findall(text))
        if nonlatin / max(1, letters) > 0.25:
            return False

    if html_lang and not html_lang.startswith('en'):
        # e.g. lang="pt-BR" / "de" — explicit non-English declaration wins,
        # but only trust it when there is real text backing it up (many kits
        # leave a bogus lang attribute on image-only pages).
        if len(re.findall(r'[A-Za-z]', text)) >= 120:
            return False

    words = re.findall(r"[A-Za-z']+", text)
    if len(words) >= 60:
        hits = sum(1 for w in words if w.lower().strip("'") in EN_STOPWORDS)
        if hits / len(words) < 0.08:
            return False
    return True


def looks_empty_or_parked(snapshot, body_text):
    """Dead domain that still resolves somewhere: no usable content at all."""
    txt = (body_text or '').strip()
    interactive = sum(int(snapshot.get(k) or 0)
                      for k in ('passwordFields', 'forms'))
    return len(txt) < 60 and interactive == 0


def merge_snapshots(a, b):
    """Element-wise worst-case merge of two snapshots (extension parity)."""
    out = dict(b)
    for k in ('passwordFields', 'forms', 'hiddenElements', 'externalScripts',
              'permissionRequests', 'promptInjectionSignals', 'iframes',
              'redirectCount'):
        out[k] = max(int(a.get(k) or 0), int(b.get(k) or 0))
    for k in ('otpRequest', 'hiddenLoginForm', 'obfuscatedContent',
              'formActionDomainMismatch',
              'credentialSubmissionDestinationMismatch', 'hasLoginIntent'):
        out[k] = bool(a.get(k)) or bool(b.get(k))
    if len(str(a.get('textSample') or '')) > len(str(out.get('textSample') or '')):
        out['textSample'] = a.get('textSample')
    if len(str(a.get('title') or '')) > len(str(out.get('title') or '')):
        out['title'] = a.get('title')
        out['brandHints'] = a.get('brandHints')
    return out


# Two-part suffixes so core-domain comparison works for hosts like
# promocaopontosfidelidade.k6.com.br (core must be k6.com.br, not com.br).
_MULTIPART_SUFFIXES = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.in', 'net.in', 'org.in',
    'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'com.br',
    'gov.br', 'com.mx', 'com.ar', 'co.za', 'com.tr', 'com.sg', 'co.kr',
    'com.cn', 'com.hk', 'co.id', 'com.my', 'com.ph', 'com.vn', 'com.tw',
}


def _core_domain(host):
    """Registrable-ish ('k6','com','br') tuple used for redirect comparison."""
    labels = [l for l in str(host or '').lower().split('.') if l]
    if len(labels) >= 3 and '.'.join(labels[-2:]) in _MULTIPART_SUFFIXES:
        return tuple(labels[-3:])
    if len(labels) >= 2:
        return tuple(labels[-2:])
    return tuple(labels)


def redirected_off_target(requested_url, final_host):
    try:
        req_host = urlparse(requested_url).hostname or ''
    except Exception:
        return False
    if not req_host or not final_host:
        return False
    return _core_domain(req_host) != _core_domain(final_host)


def http_json(url, payload=None, timeout=60):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers['Content-Type'] = 'application/json'
    req = urlrequest.Request(url, data=data, headers=headers)
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def wait_for_health(base, deadline_s=40):
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            if http_json(base + '/health', timeout=3).get('status') == 'ok':
                return True
        except Exception:
            time.sleep(0.5)
    return False


def start_server(name, port):
    cfg = BACKENDS[name]
    proc = subprocess.Popen(
        [VENV_PYTHON, '-m', 'uvicorn', cfg['module'], '--host', '127.0.0.1',
         '--port', str(port), '--log-level', 'warning'],
        cwd=cfg['dir'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f'http://127.0.0.1:{port}'
    if not wait_for_health(base):
        proc.terminate()
        raise RuntimeError(f'{name} backend failed to start on port {port}')
    return proc, base


def free_port(start):
    import socket
    port = start
    while port < start + 50:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
            except OSError:
                port += 1
                continue
        break
    return port


def normalize_label(value):
    v = str(value or '').strip().lower()
    if not v:
        return ''
    if v in PHISHING_VALUES:
        return 'phishing'
    if v in LEGIT_VALUES:
        return 'legit'
    if 'phishing' in v or 'phish' in v:
        return 'phishing'
    if 'legit' in v:
        return 'legit'
    return ''


def load_rows(path):
    with open(path, newline='', encoding='utf-8-sig') as f:
        rows = list(csv.reader(f))
    if not rows:
        return [], []
    header = [h.strip().lower().lstrip('\ufeff') for h in rows[0]] if rows[0] else []

    def find(hints, fallback_idx=None):
        for i, h in enumerate(header):
            if h in hints or any(hint in h for hint in hints):
                return i
        return fallback_idx

    url_col = find(URL_HEADER_HINTS, 0 if len(rows[0]) == 1 else None)
    if url_col is None and len(rows[0]) >= 1:
        url_col = 0
    label_col = find(LABEL_HEADER_HINTS) if len(header) > 1 else None
    if label_col is not None and label_col == url_col:
        label_col = None

    out = []
    start = 1 if header else 0
    for r in rows[start:]:
        u = r[url_col].strip() if url_col < len(r) else ''
        if not u or u.startswith('#'):
            continue
        if not u.lower().startswith(('http://', 'https://')):
            u = 'http://' + u
        actual = ''
        if label_col is not None and label_col < len(r):
            actual = normalize_label(r[label_col])
        out.append({'url': u, 'actual': actual})

    seen, uniq = set(), []
    for item in out:
        if item['url'] not in seen:
            seen.add(item['url'])
            uniq.append(item)
    return uniq, (label_col is not None)


def worker(base_url, task_q, result_q, nav_timeout_ms, stop_evt=None):
    from playwright.sync_api import sync_playwright
    import psutil

    me = psutil.Process()
    net0 = psutil.net_io_counters()

    def family():
        try:
            return [me] + me.children(recursive=True)
        except Exception:
            return [me]

    with sync_playwright() as p:
        # Basic stealth: many phishing kits fingerprint headless browsers and
        # redirect them to benign sites (cloaking). Look like a normal Chrome.
        browser = p.chromium.launch(
            headless=True,
            args=['--disable-blink-features=AutomationControlled'])
        real_ua = None
        try:
            probe_ctx = browser.new_context()
            pg = probe_ctx.new_page()
            real_ua = pg.evaluate('navigator.userAgent')
            probe_ctx.close()
        except Exception:
            real_ua = ''
        ua = (real_ua or '').replace('HeadlessChrome', 'Chrome')

        def new_context():
            ctx = browser.new_context(
                user_agent=ua or None,
                viewport={'width': 1366, 'height': 768},
                locale='en-US',
            )
            try:
                ctx.add_init_script(
                    "Object.defineProperty(navigator,'webdriver',"
                    "{get:()=>undefined});")
            except Exception:
                pass
            return ctx
        try:
            while True:
                try:
                    task = task_q.get(timeout=2)
                except queue.Empty:
                    if stop_evt is not None and stop_evt.is_set():
                        break
                    continue
                if task is None:
                    break
                if stop_evt is not None and stop_evt.is_set():
                    break
                url, actual = task

                # Platform-hosted user content (Google Docs/Sheets/Slides/
                # Sites): the page really is Google's UI - untestable.
                req_host = urlparse(url).hostname or ''
                if req_host in UNTESTABLE_HOSTS:
                    print(f'[worker] skip untestable host: {url}')
                    row = {c: '' for c in RESULT_COLUMNS}
                    row.update({'url': url, 'actual': actual,
                                'page_status': 'skipped_untestable_host',
                                'timestamp_sent': datetime.now().isoformat(timespec='seconds')})
                    result_q.put(row)
                    continue

                row = {c: '' for c in RESULT_COLUMNS}
                row['url'] = url
                row['actual'] = actual
                t_start = time.perf_counter()
                cpu_samples = []
                mem_samples = []
                for pr in family():
                    try:
                        pr.cpu_percent(None)
                    except Exception:
                        pass

                def sample():
                    vals = []
                    for pr in family():
                        try:
                            v = pr.cpu_percent(None)
                            if v:
                                vals.append(v)
                            mem_samples.append(pr.memory_info().rss)
                        except Exception:
                            pass
                    if vals:
                        cpu_samples.append(sum(vals) / len(vals))

                status = 'opened_ok'
                snapshot = None
                context = new_context()
                page = context.new_page()

                def safe_snapshot():
                    try:
                        return page.evaluate(SNAPSHOT_JS)
                    except Exception:
                        return None

                def body_text():
                    try:
                        return page.evaluate(
                            "document.body ? document.body.innerText"
                            ".slice(0,4000) : ''")
                    except Exception:
                        return ''

                try:
                    resp = page.goto(url, wait_until='domcontentloaded',
                                     timeout=nav_timeout_ms)
                    try:
                        page.wait_for_load_state('load', timeout=8000)
                    except Exception:
                        pass
                    try:
                        # let XHR/fetch traffic settle before first look
                        page.wait_for_load_state('networkidle', timeout=6000)
                    except Exception:
                        pass

                    if resp is not None and resp.status >= 400:
                        status = f'http_error_{resp.status}'
                    sample()
                    title = ''
                    try:
                        title = page.title()
                    except Exception:
                        pass
                    body = body_text()
                    # Chrome/edge error pages keep the original URL and can
                    # even return 200 - classify by rendered text FIRST so
                    # DNS_PROBE_FINISHED_NXDOMAIN-style pages are never
                    # mistaken for real site content.
                    content_status = classify_page_content(title, body)
                    if content_status and status == 'opened_ok':
                        status = content_status

                    if status == 'opened_ok':
                        # Two-pass settled snapshot: SPA / phishing-kit pages
                        # render their login form AFTER load (the extension
                        # sees this via its MutationObserver). Wait, then
                        # merge both passes element-wise (worst case).
                        time.sleep(1.2)
                        s1 = safe_snapshot()
                        time.sleep(2.3)
                        s2 = safe_snapshot()
                        if s1 is not None and s2 is not None:
                            snapshot = merge_snapshots(s1, s2)
                        else:
                            snapshot = s2 or s1
                        body = body_text() or body

                        if snapshot is not None and redirected_off_target(
                                url, snapshot.get('domain')):
                            print(f'[worker] skip off-target redirect: {url} '
                                  f'-> {snapshot.get("domain")}')
                            status = 'redirected_off_target'
                            snapshot = None
                        elif snapshot is not None and not is_english_page(snapshot):
                            print(f'[worker] skip non-English page: {url} '
                                  f'(lang={snapshot.get("lang")!r})')
                            status = 'skipped_non_english'
                            snapshot = None
                        elif snapshot is not None and looks_empty_or_parked(snapshot, body):
                            print(f'[worker] skip empty/parked page: {url}')
                            status = 'empty_or_parked'
                            snapshot = None
                except Exception as e:
                    status, _ = classify_nav_error(str(e))

                if snapshot is not None:
                    try:
                        api = http_json(base_url + '/api/analyze',
                                        payload={'url': url, 'metadata': snapshot},
                                        timeout=90)
                        dec = api.get('decision', {}) or {}
                        prof = api.get('trust_profile', {}) or {}
                        ev = api.get('evidence', {}) or {}
                        timing = api.get('timing_ms', {}) or {}
                        action = dec.get('action', '')
                        stage_no = dec.get('stage', '')
                        stage_txt = (f'{stage_no} + deep-analysis'
                                     if dec.get('needs_deep_analysis') else str(stage_no))
                        row.update({
                            'decision': action,
                            'trust': prof.get('overall', ''),
                            'confidence': dec.get('confidence', ''),
                            'ml_probability': (dec.get('ml_probability')
                                               if dec.get('ml_probability') is not None else ''),
                            'threat': ev.get('threat_category', ''),
                            'stage': stage_txt,
                            'certainty': dec.get('certainty', ''),
                            'evidence': ';'.join(ev.get('supporting_evidence', []) or []),
                            'latency_ms': timing.get('total_ms', ''),
                            'predicted': '0' if action in ('block', 'warn')
                                         else ('1' if action else ''),
                        })
                    except Exception as e:
                        row['evidence'] = f'analyze_failed: {e}'[:200]

                try:
                    context.close()
                except Exception:
                    pass

                sample()

                net1 = psutil.net_io_counters()
                net_bytes = (net1.bytes_sent + net1.bytes_recv) - \
                            (net0.bytes_sent + net0.bytes_recv)
                net0 = net1

                row['page_status'] = status
                row['cpu_usage'] = round(max(cpu_samples), 1) if cpu_samples else ''
                row['memory_usage_mb'] = round(
                    max(mem_samples) / (1024 * 1024), 1) if mem_samples else ''
                row['bandwidth_kb'] = round(net_bytes / 1024, 1)
                row['timestamp_sent'] = datetime.now().isoformat(timespec='seconds')
                result_q.put(row)
        finally:
            try:
                browser.close()
            except Exception:
                pass


def writer_thread(csv_path, result_q, done_evt, workers, stats,
                  max_results=0, stop_evt=None):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=RESULT_COLUMNS)
        w.writeheader()
        f.flush()
        idle = 0
        while True:
            try:
                row = result_q.get(timeout=1)
                idle = 0
            except queue.Empty:
                if all(not p.is_alive() for p in workers):
                    idle += 1
                    if idle > 5:
                        break
                continue
            if not isinstance(row, dict) or not row.get('url'):
                print(f'[writer] discarding invalid row: {row!r}', file=sys.stderr)
                continue
            if (row.get('page_status') in LOAD_FAILURE_STATUSES
                    or str(row.get('page_status', '')).startswith('http_error')):
                stats['skipped'] += 1
                st = row.get('page_status')
                reason = SKIP_REASONS.get(st, 'page did not load')
                print(f"[writer] no result kept - {reason}: "
                      f"{row['url']} ({st})", file=sys.stderr)
                continue
            w.writerow({k: row.get(k, '') for k in RESULT_COLUMNS})
            f.flush()
            stats['written'] += 1
            if max_results and stats['written'] >= int(max_results):
                print(f"[writer] results.csv has {stats['written']} rows "
                      f"(--max-results {int(max_results)}) - stopping test")
                if stop_evt is not None:
                    stop_evt.set()
                break
        done_evt.set()


def run_backend(name, items, has_labels, workers_count, nav_timeout_ms,
                csv_path, max_results=0):
    port = free_port(BACKENDS[name]['base_port'])
    print(f'[{name}] starting backend on :{port} ({BACKENDS[name]["dir"]})')
    server, base = start_server(name, port)
    task_q, result_q = Queue(), Queue()
    stop_evt = MPEvent()  # mp.Event: must survive pickling to worker procs
    procs = []
    try:
        for _ in range(workers_count):
            pr = Process(target=worker,
                         args=(base, task_q, result_q, nav_timeout_ms),
                         kwargs={'stop_evt': stop_evt},
                         daemon=True)
            pr.start()
            procs.append(pr)

        done_evt = threading.Event()
        stats = {'written': 0, 'skipped': 0}
        wr = threading.Thread(target=writer_thread,
                              args=(csv_path, result_q, done_evt, procs, stats),
                              kwargs={'max_results': max_results,
                                      'stop_evt': stop_evt},
                              daemon=True)
        wr.start()

        for item in items:
            task_q.put((item['url'], item['actual']))
        for _ in procs:
            task_q.put(None)

        done_evt.wait(timeout=max(600, len(items) * nav_timeout_ms / 1000))
        for pr in procs:
            pr.join(timeout=10)
    finally:
        for pr in procs:
            if pr.is_alive():
                pr.terminate()
        server.terminate()

    correct = summary = 0
    try:
        with open(csv_path, newline='', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                if r.get('predicted') != '':
                    summary += 1
                    if has_labels and r.get('predicted') and r.get('actual'):
                        if ((r['predicted'] == '1') == (r['actual'] == 'legit')):
                            correct += 1
    except OSError:
        pass
    line = (f'[{name}] done -> {csv_path} ({summary}/{len(items)} analyzed'
            f' | {stats["skipped"]} not loaded -> no result')
    if max_results and summary >= int(max_results):
        line += f' | stopped early: --max-results {int(max_results)} reached'
    if has_labels and summary:
        line += f' | agreement with actual: {correct}/{summary}'
    print(line + ')')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', default=os.path.join(ROOT, 'testing', 'input.csv'))
    ap.add_argument('--backends', default='root', choices=['root', 'nested'])
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--timeout-ms', type=int, default=30000)
    ap.add_argument('--max-results', type=int, default=50,
                    help='stop the test once results.csv holds this many '
                         'rows (default 50; 0 = run every URL)')
    ap.add_argument('--output', default=os.path.join(ROOT, 'testing', 'results.csv'))
    args = ap.parse_args()

    items, has_labels = load_rows(args.input)
    if not items:
        print(f'No URLs found in {args.input}')
        sys.exit(1)
    print(f'{len(items)} URLs | backend={args.backends} | workers={args.workers}'
          f' | stop after {args.max_results or "all"} result row(s)'
          f' | label column: {"detected" if has_labels else "not found (actual blank)"}')
    run_backend(args.backends, items, has_labels, args.workers,
                args.timeout_ms, args.output, max_results=args.max_results)


if __name__ == '__main__':
    main()
