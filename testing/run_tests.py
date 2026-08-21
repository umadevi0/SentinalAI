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
from multiprocessing import Process, Queue
from urllib import request as urlrequest

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
  state.obfuscated = !!document.querySelector(
    '[style*="font-size" i][style*="0" i], [style*="opacity" i][style*="0" i], [style*="color:transparent" i], [style*="text-indent" i][style*="-9999" i]'
  );
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
  };
}
"""

INTERSTITIAL_MARKERS = [
    ('security_warning_safebrowsing',
     ['deceptive site ahead', 'dangerous site', 'visitors, beware',
      'the site ahead contains harmful programs']),
    ('security_error_certificate',
     ["your connection isn't private", 'your connection is not private',
      'this site is not secure', 'net::err_cert']),
    ('connection_error',
     ["this site can't be reached", "hmmm… can't reach this page",
      'this webpage is not available', 'no internet']),
    ('browser_blocked',
     ['blocked by your network administrator', 'this site is blocked',
      'access to this site is blocked', 'site is blocked by the administrator']),
]

ERR_MAP = [
    (('ERR_NAME_NOT_RESOLVED', 'ERR_DNS'), 'dns_error'),
    (('ERR_CERT_', 'ERR_SSL', 'ERR_HTTPS', 'ERR_SSL_PROTOCOL_ERROR',
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


def worker(base_url, task_q, result_q, nav_timeout_ms):
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
        browser = p.chromium.launch(headless=True)
        try:
            while True:
                task = task_q.get()
                if task is None:
                    break
                url, actual = task
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
                context = browser.new_context()
                page = context.new_page()
                try:
                    resp = page.goto(url, wait_until='domcontentloaded',
                                     timeout=nav_timeout_ms)
                    try:
                        page.wait_for_load_state('load', timeout=8000)
                    except Exception:
                        pass
                    if resp is not None and resp.status >= 400:
                        status = f'http_error_{resp.status}'
                    sample()
                    body = ''
                    try:
                        body = page.evaluate(
                            "document.body ? document.body.innerText.slice(0,4000) : ''")
                    except Exception:
                        pass
                    content_status = classify_page_content(page.title(), body)
                    if content_status and status == 'opened_ok':
                        status = content_status
                    if status == 'opened_ok' or status.startswith('http_error'):
                        snapshot = page.evaluate(SNAPSHOT_JS)
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


def writer_thread(csv_path, result_q, done_evt, total, workers):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=RESULT_COLUMNS)
        w.writeheader()
        f.flush()
        written = 0
        idle = 0
        while written < total:
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
            w.writerow({k: row.get(k, '') for k in RESULT_COLUMNS})
            f.flush()
            written += 1
        done_evt.set()


def run_backend(name, items, has_labels, workers_count, nav_timeout_ms, csv_path):
    port = free_port(BACKENDS[name]['base_port'])
    print(f'[{name}] starting backend on :{port} ({BACKENDS[name]["dir"]})')
    server, base = start_server(name, port)
    task_q, result_q = Queue(), Queue()
    procs = []
    try:
        for _ in range(workers_count):
            pr = Process(target=worker,
                         args=(base, task_q, result_q, nav_timeout_ms),
                         daemon=True)
            pr.start()
            procs.append(pr)

        done_evt = threading.Event()
        wr = threading.Thread(target=writer_thread,
                              args=(csv_path, result_q, done_evt, len(items), procs),
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
    line = f'[{name}] done -> {csv_path} ({summary}/{len(items)} analyzed'
    if has_labels and summary:
        line += f' | agreement with actual: {correct}/{summary}'
    print(line + ')')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', default=os.path.join(ROOT, 'testing', 'input.csv'))
    ap.add_argument('--backends', default='root', choices=['root', 'nested'])
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--timeout-ms', type=int, default=30000)
    ap.add_argument('--output', default=os.path.join(ROOT, 'testing', 'results.csv'))
    args = ap.parse_args()

    items, has_labels = load_rows(args.input)
    if not items:
        print(f'No URLs found in {args.input}')
        sys.exit(1)
    print(f'{len(items)} URLs | backend={args.backends} | workers={args.workers}'
          f' | label column: {"detected" if has_labels else "not found (actual blank)"}')
    run_backend(args.backends, items, has_labels, args.workers,
                args.timeout_ms, args.output)


if __name__ == '__main__':
    main()
