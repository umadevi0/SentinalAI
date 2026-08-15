from typing import Any, Dict


class AdaptiveThreatOrchestrator:
    def decide(self, evidence: Dict[str, Any], trust_profile: Dict[str, Any]) -> Dict[str, Any]:
        overall = trust_profile.get('overall', 0.0)
        if overall < 0.4:
            action = 'block'
        elif overall < 0.65:
            action = 'warn'
        else:
            action = 'continue_monitoring'

        return {
            'action': action,
            'confidence': evidence.get('confidence', 0.0),
            'reason': 'Adaptive decision based on aggregated trust evidence.'
        }
