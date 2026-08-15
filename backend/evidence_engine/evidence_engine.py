from typing import Any, Dict
from urllib.parse import urlparse


class ThreatEvidenceEngine:
    def build_evidence(self, url: str, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        metadata = metadata or {}
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        password_fields = int(metadata.get('passwordFields', metadata.get('password_fields', 0)) or 0)
        form_count = int(metadata.get('forms', metadata.get('form_count', 0)) or 0)
        hidden_elements = int(metadata.get('hiddenElements', metadata.get('hidden_elements', 0)) or 0)
        external_scripts = int(metadata.get('externalScripts', metadata.get('external_scripts', 0)) or 0)
        permission_requests = int(metadata.get('permissionRequests', metadata.get('permission_requests', 0)) or 0)
        prompt_signals = int(metadata.get('promptInjectionSignals', metadata.get('prompt_injection_signals', 0)) or 0)
        login_intent = bool(metadata.get('hasLoginIntent', False))

        if 'login' in path or 'signin' in path or login_intent:
            interaction_score = 0.28
        elif password_fields > 0:
            interaction_score = 0.35
        else:
            interaction_score = 0.76

        identity_score = 0.72 if 'login' in domain or 'account' in domain else 0.92
        behavior_score = 0.82 if hidden_elements > 3 or form_count > 2 else 0.91
        privacy_score = 0.74 if permission_requests > 0 else 0.9
        ai_score = 0.38 if prompt_signals > 0 else 0.82

        # Stronger phishing rule (Option B):
        # - Password fields remain a clear phishing indicator.
        # - Prompt-injection signals alone are noisy, require corroboration
        #   (hidden elements OR many external scripts) to be considered phishing.
        # - Very large counts of hidden elements alone can also indicate phishing.
        if password_fields > 0 or hidden_elements > 10 or (prompt_signals > 0 and (hidden_elements > 3 or external_scripts > 5)):
            threat_category = 'phishing'
            severity = 'high' if prompt_signals > 0 or password_fields > 0 else 'medium'
        elif permission_requests > 0:
            threat_category = 'privacy'
            severity = 'medium'
        elif external_scripts > 10:
            threat_category = 'behavior'
            severity = 'medium'
        else:
            threat_category = 'safe'
            severity = 'low'

        confidence = min(0.98, 0.45 + (password_fields * 0.12) + (hidden_elements * 0.04) + (prompt_signals * 0.2))
        supporting_evidence = []
        if password_fields > 0:
            supporting_evidence.append('password_fields_detected')
        if hidden_elements > 0:
            supporting_evidence.append('hidden_elements_detected')
        # Only mark external script evidence as "high" when count is meaningfully large
        if external_scripts > 10:
            supporting_evidence.append('external_script_count_high')
        if permission_requests > 0:
            supporting_evidence.append('permission_requests_detected')
        if prompt_signals > 0:
            supporting_evidence.append('prompt_injection_signals_detected')
        if not supporting_evidence:
            supporting_evidence = ['no_suspicious_signals_detected']

        return {
            'url': url,
            'domain': domain,
            'identity_score': round(identity_score, 2),
            'behavior_score': round(behavior_score, 2),
            'interaction_score': round(interaction_score, 2),
            'privacy_score': round(privacy_score, 2),
            'ai_score': round(ai_score, 2),
            'threat_category': threat_category,
            'severity': severity,
            'confidence': round(confidence, 2),
            'supporting_evidence': supporting_evidence
        }
