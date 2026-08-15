from typing import Dict, Any


class InteractionTrustModule:
    def score(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'module': 'M5',
            'category': 'interaction',
            'score': 0.31,
            'details': {'credential_harvesting_signals': payload.get('password_fields', 0) > 0}
        }
