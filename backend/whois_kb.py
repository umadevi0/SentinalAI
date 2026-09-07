"""SentinelAI offline-first + async WHOIS/RDAP registration lookup.

Two-tier reputation design:

1. OFFLINE SAFE-LIST (instant, sub-millisecond, no network).
   The evidence engine's own curated list of real brands + real services
   (REAL_DOMAINS / BRAND_DOMAINS / KNOWN_DOMAINS) decides known/owned domains
   immediately. This never needs a network call.

2. ASYNC RDAP FALLBACK (background, non-blocking, does NOT add latency to the
   user-facing decision).
   When a domain is NOT in the offline safe-list, we fire an RDAP (HTTPS,
   JSON) lookup in a background thread. RDAP is the modern replacement for
   classic WHOIS: it returns who registered the domain, the registrar, and the
   registration date, over plain HTTPS (no port-43 helper). The result is
   stored in a cache and used to REFINE the verdict on a later pass (and to
   enrich logs). The first response is returned immediately using only the
   offline signals, so there is no added latency.

Registration data (age + owner) helps a lot here:
  - A domain registered only a few days ago on a suspicious host is a strong
    phishing signal (phishers use fresh domains).
  - A domain registered years ago (or owned by the matching brand) is strong
    protective evidence that a curious login page is legitimate.
"""
import json
import threading
import time
import urllib.request
from typing import Any, Dict, Optional

# RFC 7480 endpoint that redirects to the correct TLD RDAP server.
_RDAP_BOOTSTRAP = 'https://rdap.org/domain/{}'
# Per-request network timeout; the whole request runs in a background thread so
# it never blocks the fast decision path.
_RDAP_TIMEOUT = 6.0
_RDAP_RETRIES = 2
_LOOKUP_TTL = 6 * 60 * 60  # seconds; re-check every 6h
# Heuristics
_RECENTLY_REGISTERED_DAYS = 60
_ESTABLISHED_DAYS = 730  # ~2 years


class RegistrationKB:
    """Offline-first registration knowledge base with a tiny thread-safe cache."""

    def __init__(self, enabled: bool = True, rdap_timeout: float = _RDAP_TIMEOUT):
        self.enabled = enabled
        self.timeout = rdap_timeout
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._inflight: Dict[str, bool] = {}

    # ---- cache ---------------------------------------------------------------
    def get(self, registrable: str) -> Optional[Dict[str, Any]]:
        """Return cached registration context for a registrable label, or None."""
        with self._lock:
            entry = self._cache.get(registrable)
        if not entry:
            return None
        # TTL
        if time.time() - entry.get('ts', 0) > _LOOKUP_TTL:
            return None
        return entry.get('data')

    def _store(self, registrable: str, data: Dict[str, Any]) -> None:
        with self._lock:
            self._cache[registrable] = {'ts': time.time(), 'data': data}
            self._inflight.pop(registrable, None)

    # ---- background async fallback ------------------------------------------
    def request_async(self, registrable: str) -> None:
        """Fire a background RDAP lookup for a registrable label (non-blocking).

        Returns immediately. The result is cached when the thread completes.
        A public suffix / registrable with no dot suffix (rare) is skipped.
        """
        if not self.enabled or not registrable:
            return
        # Fast path: already cached or already being fetched.
        with self._lock:
            if registrable in self._cache:
                return
            if self._inflight.get(registrable):
                return
            self._inflight[registrable] = True
        thread = threading.Thread(
            target=self._fetch, args=(registrable,), daemon=True)
        thread.start()

    def _fetch(self, registrable: str) -> None:
        """Background: resolve the full domain label is not required; RDAP needs
        the registrable domain (e.g. 'example.com'), not just 'example'. We
        reconstruct it from a cached full-host map maintained by the caller, or
        look up 'registrable.com' as a reasonable default. In practice the
        evidence engine passes the full registrable domain string here."""
        try:
            data = self._lookup_rdap(registrable)
        except Exception:
            data = None
        if data is not None:
            self._store(registrable, data)

    def _lookup_rdap(self, domain: str) -> Optional[Dict[str, Any]]:
        """Perform a single RDAP request and return parsed context, or None."""
        if '.' not in domain:
            return None
        url = _RDAP_BOOTSTRAP.format(domain)
        last_err: Optional[Exception] = None
        for attempt in range(_RDAP_RETRIES):
            try:
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'SentinelAI/2.0',
                             'Accept': 'application/rdap+json'})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # pyright: ignore[reportGeneralTypeIssues]
                    raw = resp.read()
                return self._parse(json.loads(raw.decode('utf-8', 'replace')))
            except Exception as exc:  # noqa: BLE001 - network best-effort
                last_err = exc
                if attempt < _RDAP_RETRIES - 1:
                    time.sleep(0.3)
        return None

    @staticmethod
    def _parse(doc: Dict[str, Any]) -> Dict[str, Any]:
        """Extract owner + registration date + age from an RDAP JSON document."""
        # Registrar name
        registrar = None
        for e in doc.get('entities', []) or []:
            for r in (e.get('roles') or []):
                if r == 'registrar':
                    vcard = e.get('vcardArray', [[], []])
                    for item in (vcard[1] if len(vcard) > 1 else []):
                        if item and len(item) >= 3 and item[0] == 'fn':
                            registrar = item[3]
        # Registered/registration event (oldest "registration" event)
        created = None
        for e in doc.get('events', []) or []:
            if e.get('eventAction') == 'registration':
                created = e.get('eventDate')
                break
        if not created:
            for e in doc.get('events', []) or []:
                if e.get('eventAction') in ('registration', 'created'):
                    created = e.get('eventDate')
                    break
        age_days = None
        if created:
            try:
                # eventDate example: "2023-01-15T00:00:00Z" (or offset)
                ds = created.strip()
                if ds.endswith('Z'):
                    ds = ds[:-1]
                ds = ds.replace('T', ' ')[:19]
                from datetime import datetime
                created_dt = datetime.strptime(ds, '%Y-%m-%d %H:%M:%S')
                now = datetime.utcnow()
                age_days = max(0, int((now - created_dt).total_seconds() / 86400))
            except Exception:
                age_days = None
        # Registrant organization (if disclosed)
        registrant_org = None
        for e in doc.get('entities', []) or []:
            for r in (e.get('roles') or []):
                if r in ('registrant', 'administrative'):
                    vcard = e.get('vcardArray', [[], []])
                    for item in (vcard[1] if len(vcard) > 1 else []):
                        if item and len(item) >= 3 and item[0] == 'fn':
                            registrant_org = item[3]
                            break
                    if registrant_org:
                        break
        return {
            'registrar': registrar,
            'registrant': registrant_org,
            'created': created,
            'age_days': age_days,
            'recently_registered': (
                age_days is not None and age_days <= _RECENTLY_REGISTERED_DAYS
            ) if age_days is not None else None,
            'established': (
                age_days is not None and age_days >= _ESTABLISHED_DAYS
            ) if age_days is not None else None,
        }


# A single shared instance used across the backend (FastAPI workers + harness).
_registration_kb = RegistrationKB()


def get_registration_kb() -> RegistrationKB:
    return _registration_kb


def registration_context(registrable: str) -> Optional[Dict[str, Any]]:
    """Return cached registration context for a registrable label (None if none)."""
    return _registration_kb.get(registrable)


def request_registration_async(registrable: str) -> None:
    """Ask the registration KB to enrich this domain in the background."""
    _registration_kb.request_async(registrable)
