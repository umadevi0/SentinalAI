from typing import Dict, Any


class IdentityTrustModule:
    def score(self, url: str) -> Dict[str, Any]:
        return {
            'module': 'M4',
            'category': 'identity',
            'score': 0.94,
            'details': {'url': url, 'brand_consistency': True}
        }
