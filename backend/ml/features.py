"""Feature vector builder for the lightweight ML classifier (stage 2).

Maps the same inputs as the evidence engine onto a fixed, ordered numeric
vector. Must stay in sync with tools/train_model.py and tools/cases.py.
"""
from typing import Any, Dict, List
from urllib.parse import urlparse

from backend.evidence_engine.evidence_engine import ThreatEvidenceEngine, registrable_info

FEATURE_NAMES = [
    'https',
    'known_domain',
    'unknown_tld',
    'is_ip_host',
    'has_at_sign',
    'punycode',
    'hyphen_heavy_sld',
    'excessive_subdomains',
    'brand_impersonation',
    'lookalike_brand_domain',
    'suspicious_path',
    'password_fields',
    'form_count',
    'hidden_elements',
    'external_scripts',
    'hidden_login_form',
    'otp_request',
    'permission_requests',
    'prompt_signals',
    'iframes',
    'download_triggers',
    'clipboard_access',
    'redirect_count',
    'form_action_domain_mismatch',
    'credential_submission_mismatch',
    'login_intent',
]


def build_feature_vector(url: str, metadata: Dict[str, Any] | None = None) -> List[float]:
    metadata = metadata or {}
    parsed = urlparse(url)
    host = (parsed.netloc or '').split('@')[-1].lower().split(':')[0]
    labels = [l for l in host.split('.') if l]
    registrable, sub_count, public_suffix, public_sector = registrable_info(labels)

    def mget(*keys, default=0):
        for k in keys:
            if k in metadata:
                return metadata[k]
        return default

    title = str(mget('title', default=''))
    brand_hints = str(mget('brandHints', 'brand_hints', default=''))
    form_action_mismatch = bool(mget('formActionDomainMismatch', 'form_action_domain_mismatch', default=False))
    cred_mismatch = bool(mget('credentialSubmissionDestinationMismatch',
                              'credential_submission_destination_mismatch', default=False))

    ev = ThreatEvidenceEngine().build_evidence(url, metadata)

    def has_feature(name: str) -> bool:
        for d in ev.get('detectors', []):
            if d.get('feature') == name and d.get('value'):
                return True
        return False

    return [
        float(parsed.scheme == 'https'),
        float(ev.get('known_domain', False)),
        float(has_feature('unknown_tld')),
        float(has_feature('domain_is_ip')),
        float(has_feature('url_has_at_sign')),
        float(has_feature('punycode_homoglyph')),
        float(registrable.count('-') >= 2),
        float(sub_count >= 3),
        float(has_feature('brand_impersonation')),
        float(has_feature('lookalike_brand_domain')),
        float(has_feature('suspicious_path')),
        float(int(mget('passwordFields', 'password_fields', default=0))),
        float(int(mget('forms', 'form_count', default=0))),
        float(int(mget('hiddenElements', 'hidden_elements', default=0))),
        float(int(mget('externalScripts', 'external_scripts', default=0))),
        float(bool(mget('hiddenLoginForm', 'hidden_login_form', default=False))),
        float(bool(mget('otpRequest', 'otp_request', default=False))),
        float(int(mget('permissionRequests', 'permission_requests', default=0))),
        float(int(mget('promptInjectionSignals', 'prompt_injection_signals', default=0))),
        float(int(mget('iframes', default=0))),
        float(int(mget('downloadTriggers', 'download_triggers', default=0))),
        float(int(mget('clipboardAccess', 'clipboard_access', default=0))),
        float(int(mget('redirectCount', 'redirect_count', default=0))),
        float(form_action_mismatch or bool(has_feature('form_action_domain_mismatch'))),
        float(cred_mismatch or bool(has_feature('credential_submission_mismatch'))),
        float(bool(mget('hasLoginIntent', default=False))),
    ]