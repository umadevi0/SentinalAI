"""IdentityTrustModule v2.

Deterministic brand/domain consistency + offline reputation heuristics.
Lightweight enough to run in Stage-1 screening; deep features live in the
evidence engine.
"""
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from backend.evidence_engine.evidence_engine import (
    BRAND_NAMES,
    KNOWN_DOMAINS,
    KNOWN_TLDS,
    _canonical_hosts,
    registrable_info,
)

IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


class IdentityTrustModule:
    def score(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        host = (parsed.netloc or '').split('@')[-1].lower().split(':')[0]
        labels = [l for l in host.split('.') if l]
        registrable, sub_count, public_suffix, public_sector = registrable_info(labels)
        tld = labels[-1] if labels else ''

        known_domain = registrable in KNOWN_DOMAINS or public_sector
        tld_known = tld in KNOWN_TLDS
        is_ip = bool(IPV4_RE.match(host))
        punycode = host.startswith('xn--')

        brand = None
        for name in BRAND_NAMES:
            canonical = _canonical_hosts(name)
            domain_match = any(host == d or host.endswith('.' + d) for d in canonical)
            if domain_match:
                brand = name
                break

        risk = 0.0
        signals: List[str] = []
        if is_ip:
            risk += 0.5
            signals.append('host_is_ip')
        if punycode:
            risk += 0.4
            signals.append('punycode')
        if not tld_known:
            risk += 0.35
            signals.append('unknown_tld')
        if not known_domain:
            risk += 0.25
            signals.append('domain_unfamiliar')
        if registrable.count('-') >= 2:
            risk += 0.3
            signals.append('hyphenated_domain')
        if public_sector:
            risk -= 0.25
            signals.append('public_sector')

        score = max(0.05, min(0.99, 1.0 - risk))
        return {
            'module': 'M4',
            'category': 'identity',
            'score': round(score, 3),
            'details': {
                'url': url,
                'domain': host,
                'registrable': registrable,
                'known_domain': known_domain,
                'brand': brand,
                'signals': signals,
            },
        }