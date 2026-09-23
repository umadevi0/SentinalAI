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
        'random_domain_name', 'credential_keyword_in_subdomain',
        'high_risk_tld',
    }

    # ---- credential-risk tiers -------------------------------------------
    # Direct evidence that credentials are being harvested/exfiltrated.
    # These are unconditional: protective evidence (HTTPS / known domain /
    # public-sector) must never downgrade them.
    CREDENTIAL_COMPROMISE = {
        'credential_submission_mismatch',
        'credentials_on_unknown_target',
        'phish_kit_url',
    }

    # Strong signals that a login page is impersonating a legitimate brand or
    # hiding its credential flow. On a login page these warrant deep analysis.
    SUSPICIOUS_LOGIN = {
        'brand_impersonation',
        'lookalike_brand_domain',
        'lookalike_domain',
        'form_action_domain_mismatch',
        'hidden_login_form',
        'punycode_homoglyph',
        'brand_in_path',
        'claimed_brand_in_url',
    }

    # Weak/contextual URL signals. Alone (without login context) these stay
    # under normal TrustEngine handling to avoid false positives.
    WEAK_URL_SIGNALS = {
        'random_domain_name',
        'high_risk_tld',
        'credential_keyword_in_subdomain',
        'unknown_tld',
        'suspicious_path',
        'credential_path_keywords',
    }

    # A page is "login context" when it collects credentials or signals intent.
    LOGIN_CONTEXT = {'login_intent', 'password_field_present'}

    # Feature *combinations* that are critical even though each feature alone
    # is weak (these are exactly the combos the Trust Engine escalates to deep
    # analysis). All are gated on unprotected hosts by the evidence engine,
    # so benign big-brand sites can never match them.
    CRITICAL_COMBOS = {
        frozenset({'obfuscated_content', 'login_intent'}),
        frozenset({'hidden_elements_count', 'login_intent'}),
        frozenset({'promo_scam_keywords', 'free_hosting_subdomain'}),
        frozenset({'random_domain_name', 'login_intent'}),
        frozenset({'high_risk_tld', 'login_intent'}),
        frozenset({'credential_keyword_in_subdomain', 'login_intent'}),
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

    @staticmethod
    def _triggered_features(evidence: Dict[str, Any]) -> set:
        feats = set()
        for d in evidence.get('detectors') or []:
            if (d.get('polarity', 'positive') == 'positive'
                    and d.get('value') and d['value'] is not False
                    and d['value'] != 0):
                feats.add(d.get('feature', ''))
        return {f for f in feats if f}

    def _login_risk(self, evidence: Dict[str, Any]) -> tuple:
        """Classify a page's credential risk into (tier, label).

        tier: 'compromise' | 'suspicious' | 'none'
        Returns the tier for the strongest evidence found.
        """
        feats = self._triggered_features(evidence)

        is_login = bool(feats & self.LOGIN_CONTEXT)
        if not is_login:
            return 'none', None

        compromise = feats & self.CREDENTIAL_COMPROMISE
        if compromise:
            return 'compromise', 'credential_' + sorted(compromise)[0]

        suspicious = feats & self.SUSPICIOUS_LOGIN
        if suspicious:
            return 'suspicious', 'login_' + sorted(suspicious)[0]

        weak = feats & self.WEAK_URL_SIGNALS
        if len(weak) >= 2:
            return 'suspicious', 'login_multi_' + '_'.join(sorted(weak))

        return 'none', None

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
        action = 'legit'
        needs_deep_analysis = False
        ml_prob = None

        # ---- credential-risk escalation ------------------------------------
        # Login-aware: don't rely only on the general trust score. A page that
        # collects credentials and shows harvesting evidence must not pass as
        # benign just because its generic score is moderate or protective
        # context (HTTPS / known domain) is present.
        risk_tier, risk_label = self._login_risk(evidence)
        critical = self._critical_features(evidence)

        if decision == 'block':
            action = 'block'
            stage = 1 if certainty == 'high' else 2
            if risk_tier == 'compromise':
                ph_conf = max(ph_conf, 0.9)
        elif decision == 'deep_analysis':
            stage = 2
            needs_deep_analysis = True
            if risk_tier == 'compromise':
                # Direct credential-theft evidence: never let a weak ML score
                # downgrade to 'allow' -- escalate straight to warn/block.
                ph_conf = max(ph_conf, 0.75)
                if ml_prob is None:
                    action = 'warn'
                else:
                    action = 'block' if ml_prob >= 0.6 else 'warn'
            elif predictor is not None:
                try:
                    ml_prob, ml_model = predictor(evidence.get('url', ''),
                                                  metadata or {})
                except Exception:
                    ml_prob = None
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
            else:
                action = 'warn'
        elif decision == 'monitor':
            if risk_tier in ('compromise', 'suspicious'):
                # Narrow escalation: only suspicious LOGIN pages get a second
                # look. Ordinary pages otherwise keep monitoring.
                stage = 2
                needs_deep_analysis = True
                if risk_tier == 'compromise':
                    ph_conf = max(ph_conf, 0.7)
                    action = 'warn'
                elif predictor is not None:
                    try:
                        ml_prob, ml_model = predictor(evidence.get('url', ''),
                                                      metadata or {})
                    except Exception:
                        ml_prob = None
                    if ml_prob is not None and ml_prob >= 0.6:
                        action = 'warn'
                    else:
                        action = 'legit'
                else:
                    action = 'legit'
            else:
                # NEW: Credential-aware escalation for login pages on unprotected hosts.
                # If the page collects credentials (login context) AND lacks protective
                # features (known domain, public sector, established RDAP domain),
                # escalate from legit to warn. This catches phishing
                # on unknown hosts that would otherwise fly under the radar.
                feats = self._triggered_features(evidence)
                has_login = bool(feats & self.LOGIN_CONTEXT)
                has_protection = bool(feats & {
                    'known_domain', 'public_sector_domain', 'established_registered_domain', 'safe_login_context'
                })
                if has_login and not has_protection:
                    # Check for any weak risk signal to avoid escalating clean unknowns
                    has_weak_risk = bool(feats & self.WEAK_URL_SIGNALS)
                    has_suspicious_login = bool(feats & self.SUSPICIOUS_LOGIN)
                    if has_weak_risk or has_suspicious_login:
                        stage = 2
                        needs_deep_analysis = True
                        action = 'warn'
                        ph_conf = max(ph_conf, 0.5)
                    else:
                        action = 'legit'
                        stage = 2 if certainty == 'low' else 1
                else:
                    action = 'legit'
                    stage = 2 if certainty == 'low' else 1
        else:  # allow
            if risk_tier == 'compromise':
                # Protective evidence (HTTPS/known domain) can never suppress
                # direct credential-theft evidence.
                stage = 2
                needs_deep_analysis = True
                action = 'warn'
                ph_conf = max(ph_conf, 0.7)
            else:
                action = 'legit'
                stage = 1

        reason = matched or risk_label or 'adaptive trust decision'
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