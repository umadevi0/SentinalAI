from typing import Dict, Any


class TrustEngine:
    def compute_trust_profile(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        identity = evidence.get('identity_score', 0.9)
        behavior = evidence.get('behavior_score', 0.8)
        interaction = evidence.get('interaction_score', 0.4)
        privacy = evidence.get('privacy_score', 0.7)
        ai = evidence.get('ai_score', 0.6)

        overall = round((identity + behavior + interaction + privacy + ai) / 5, 3)
        return {
            'identity': identity,
            'behavior': behavior,
            'interaction': interaction,
            'privacy': privacy,
            'ai': ai,
            'overall': overall
        }
