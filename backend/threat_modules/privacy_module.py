from typing import Dict, Any


class PrivacyTrustModule:
    def score(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'module': 'M6',
            'category': 'privacy',
            'score': 0.92,
            'details': {'permission_requests': payload.get('permissions_requested', 0)}
        }
