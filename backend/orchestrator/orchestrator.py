"""Adaptive Threat Orchestrator v2.

Maps the TrustEngine profile onto a browser action using the two-stage flow:

    Stage 1 (fast):  LOW      -> allow
                     HIGH     -> block / immediate protection
    Stage 2 (verify):AMBIGUOUS -? deep analysis -> final decision
"""
from typing import Any, Dict


class AdaptiveThreatOrchestrator:
    def decide(self, evidence: Dict[str, Any],
               trust_profile: Dict[str, Any],
               metadata: Dict[str, Any] | None = None,
               predictor=None) -> Dict[str, Any]:
        decision = trust_profile.get('decision', 'monitor')
        certainty = trust_profile.get('certainty', 'medium')
        overall = trust_profile.get('overall', 0.5)
        ph_conf = trust_profile.get('phishing_confidence', 0.0)
        matched = trust_profile.get('matched_rule')

        stage = 1
        action = 'continue_monitoring'
        needs_deep_analysis = False
        ml_prob = None

        if decision == 'block':
            action = 'block'
            stage = 1 if certainty == 'high' else 2
        elif decision == 'deep_analysis':
            stage = 2
            needs_deep_analysis = True
            if predictor is not None:
                try:
                    ml_prob, ml_model = predictor(evidence.get('url', ''),
                                                  metadata or {})
                except Exception:
                    ml_prob = None
            if ml_prob is not None:
                if ml_prob >= 0.75:
                    action = 'block'
                    ph_conf = max(ph_conf, ml_prob)
                elif ml_prob < 0.35:
                    action = 'allow'
                    ph_conf = min(ph_conf, ml_prob)
                else:
                    action = 'warn'
            else:
                action = 'warn'
        elif decision == 'monitor':
            action = 'continue_monitoring'
            stage = 2 if certainty == 'low' else 1
        else:  # allow
            action = 'continue_monitoring'
            stage = 1

        reason = matched or 'adaptive trust decision'
        return {
            'action': action,
            'stage': stage,
            'needs_deep_analysis': needs_deep_analysis,
            'confidence': round(ph_conf, 3),
            'overall': round(overall, 3),
            'certainty': certainty,
            'reason': reason,
            'ml_probability': round(ml_prob, 3) if ml_prob is not None else None,
        }