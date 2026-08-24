"""Adaptive Threat Orchestrator v2.

Maps the TrustEngine profile onto a browser action using the two-stage flow:

    Stage 1 (fast):  LOW      -> allow
                     HIGH     -> block / immediate protection
    Stage 2 (verify):AMBIGUOUS -? deep analysis -> final decision
"""
from typing import Any, Dict


class AdaptiveThreatOrchestrator:
    # Deterministic high-severity evidence that a weak/uncalibrated ML
    # score must never downgrade to 'allow'.
    CRITICAL_FEATURES = {
        'credential_submission_mismatch', 'brand_impersonation',
        'hidden_login_form', 'credentials_on_unknown_target',
        'form_action_domain_mismatch', 'lookalike_brand_domain',
        'lookalike_domain', 'punycode_homoglyph',
        'brand_in_path', 'phish_kit_url',
    }

    # Feature *combinations* that are critical even though each feature alone
    # is weak (these are exactly the combos the Trust Engine escalates to deep
    # analysis). All are gated on unprotected hosts by the evidence engine,
    # so benign big-brand sites can never match them.
    CRITICAL_COMBOS = {
        frozenset({'obfuscated_content', 'login_intent'}),
        frozenset({'hidden_elements_count', 'login_intent'}),
        frozenset({'promo_scam_keywords', 'free_hosting_subdomain'}),
    }

    @staticmethod
    def _critical_features(evidence: Dict[str, Any]) -> set:
        feats = set()
        for d in evidence.get('detectors') or []:
            if (d.get('polarity', 'positive') == 'positive'
                    and d.get('value') and d['value'] is not False
                    and d['value'] != 0):
                feats.add(d.get('feature', ''))
        crit = feats & AdaptiveThreatOrchestrator.CRITICAL_FEATURES
        for combo in AdaptiveThreatOrchestrator.CRITICAL_COMBOS:
            if combo <= feats:
                crit |= combo
        return crit

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
            critical = self._critical_features(evidence)
            if ml_prob is not None:
                if ml_prob >= 0.75:
                    action = 'block'
                    ph_conf = max(ph_conf, ml_prob)
                elif ml_prob < 0.35 and not critical:
                    action = 'allow'
                    ph_conf = min(ph_conf, ml_prob)
                else:
                    action = 'warn'
                    if critical:
                        ph_conf = max(ph_conf, 0.55)
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