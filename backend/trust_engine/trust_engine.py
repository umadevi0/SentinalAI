"""SentinelAI TrustEngine v2.

Evidence-driven, stage-aware trust computation.

- Detectors are *triggered risk evidence* with specificity/severity/confidence.
- Per-category TRUST = 1 - risk (risk accumulated only from triggered detectors).
- Conditional override rules: specific feature combinations override the
  weighted average (avoiding a naive weighted-sum classifier).
- An explicit `uncertainty` state prevents guessing on sparse/contradictory
  evidence, which keeps the false-positive rate low on legitimate sites.
"""
from itertools import combinations
from typing import Any, Dict, List


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


class TrustEngine:
    CATEGORY_WEIGHTS = {
        'identity': 1.5,
        'behavior': 1.0,
        'interaction': 1.2,
        'privacy': 0.8,
        'ai': 1.0,
    }

    SPECIFICITY_WEIGHT = {
        'low': 0.6,
        'medium': 1.0,
        'high': 1.5,
        'very_high': 2.0,
    }

    SEVERITY_WEIGHT = {
        'low': 0.3,
        'medium': 0.6,
        'high': 1.0,
        'critical': 1.5,
    }

    # Strong, credible phish scenarios that force a block (high confidence).
    BLOCK_RULES = [
        {'all': ['credential_submission_mismatch'], 'confidence': 0.95, 'label': 'credential_submission_mismatch'},
        {'all': ['credential_submission_mismatch', 'brand_impersonation'], 'confidence': 0.97, 'label': 'branded_credential_theft'},
        {'all': ['form_action_domain_mismatch', 'password_field_present'], 'confidence': 0.92, 'label': 'login_form_exfiltrates'},
        {'all': ['brand_impersonation', 'form_action_domain_mismatch'], 'confidence': 0.9, 'label': 'brand_impersonation'},
        {'all': ['hidden_login_form', 'brand_impersonation'], 'confidence': 0.93, 'label': 'hidden_branded_login'},
        {'all': ['hidden_login_form', 'credentials_on_unknown_target'], 'confidence': 0.9, 'label': 'hidden_credential_form'},
        {'all': ['credential_submission_mismatch', 'hidden_login_form'], 'confidence': 0.96, 'label': 'hidden_credential_exfil'},
    ]

    # Scenarios that are clearly worth a deep (stage-2) look but not a block.
    DEEP_RULES = [
        {'all': ['brand_impersonation'], 'label': 'brand_impersonation'},
        {'all': ['hidden_login_form'], 'label': 'hidden_login_form'},
        {'all': ['credentials_on_unknown_target'], 'label': 'credentials_on_unknown_target'},
        {'all': ['punycode_homoglyph', 'password_field_present'], 'label': 'punycode_credentials'},
        {'all': ['lookalike_brand_domain', 'password_field_present'], 'label': 'lookalike_login'},
    ]

    # Protective features that reduce conviction even when other weak signals fire.
    PROTECTIVE_FEATURES = {'known_domain', 'has_https', 'public_sector_domain'}

    def _feature_set(self, detectors: List[Dict[str, Any]]) -> set:
        out = set()
        for d in detectors:
            if d.get('polarity', 'positive') != 'positive':
                continue
            if d.get('value') and d['value'] is not False and d['value'] != 0:
                out.add(d.get('feature', ''))
        return {f for f in out if f}

    def _protective_facts(self, detectors: List[Dict[str, Any]]) -> set:
        out = set()
        for d in detectors:
            if d.get('polarity', 'positive') == 'positive':
                continue
            if d.get('value') and d['value'] is not False and d['value'] != 0:
                out.add(d.get('feature', ''))
        return out

    def _category_risks(self, detectors: List[Dict[str, Any]]) -> Dict[str, float]:
        risks = {k: 0.0 for k in self.CATEGORY_WEIGHTS}
        weight_sum = {k: 0.0 for k in self.CATEGORY_WEIGHTS}
        for d in detectors:
            if d.get('polarity', 'positive') != 'positive':
                continue
            if not (d.get('value') and d['value'] is not False and d['value'] != 0):
                continue
            cat = d.get('category', 'behavior')
            if cat not in risks:
                cat = 'behavior'
            strength = float(d.get('evidence_strength', 0.3)) * float(d.get('confidence', 0.5))
            w = self.SPECIFICITY_WEIGHT.get(d.get('specificity', 'medium'), 1.0)
            risks[cat] += strength * w
            weight_sum[cat] += w
        # logistic-style calibration: f(s) = s / (s + k)
        return {k: _clamp01(risks[k] / (risks[k] + 0.8)) for k in self.CATEGORY_WEIGHTS}

    def _trust_vector(self, risks: Dict[str, float]) -> Dict[str, float]:
        return {k: round(_clamp01(1.0 - v), 3) for k, v in risks.items()}

    def _overall(self, trusts: Dict[str, float]) -> float:
        total = sum(self.CATEGORY_WEIGHTS.values())
        return _clamp01(sum(trusts[k] * self.CATEGORY_WEIGHTS[k] for k in trusts) / total)

    def _uncertainty(self, triggered_count: int, trusts: Dict[str, float],
                     overall: float) -> str:
        """Return 'high' | 'medium' | 'low' certainty."""
        values = list(trusts.values())
        spread = max(values) - min(values)
        low_cats = sum(1 for v in values if v < 0.4)
        if triggered_count <= 1:
            if overall >= 0.7:
                return 'high'
            return 'low'
        if spread > 0.6 and low_cats >= 2:
            return 'low'          # strongly contradictory categories -> uncertain
        if overall >= 0.85:
            return 'high'
        if overall >= 0.6:
            return 'medium'
        if triggered_count <= 2:
            return 'low'
        return 'medium'

    def compute_trust_profile(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        detectors = evidence.get('detectors') or []
        if not detectors:
            return self._legacy_profile(evidence)

        triggered = [
            d for d in detectors
            if d.get('polarity', 'positive') == 'positive'
            and d.get('value') and d['value'] is not False and d['value'] != 0
        ]
        feats = self._feature_set(detectors)
        protective = self._protective_facts(detectors)

        # ---- conditional override rules -----------------------------------
        block = None
        for rule in self.BLOCK_RULES:
            if all(f in feats for f in rule['all']):
                block = rule
                break
        deep = None
        if block is None:
            for rule in self.DEEP_RULES:
                if all(f in feats for f in rule['all']):
                    deep = rule
                    break

        risks = self._category_risks(detectors)
        trusts = self._trust_vector(risks)
        overall = self._overall(trusts)

        # ---- protective (negative evidence) handling ----------------------
        if block is None:
            protected = protective.intersection(self.PROTECTIVE_FEATURES)
            if protected:
                # Known / public-sector domain + HTTPS is strong exculpatory
                # evidence: the benign login-form case must survive weak
                # generic signals (e.g. saral.iitjammu.ac.in/login).
                anchor = ('known_domain' in protected) or ('public_sector_domain' in protected)
                exculpatory = anchor and ('has_https' in protected)
                critical = feats.intersection({
                    'hidden_login_form', 'credentials_on_unknown_target',
                    'lookalike_brand_domain', 'lookalike_domain',
                })
                if exculpatory and not critical:
                    overall = max(overall, 0.78)
                elif anchor and feats.intersection({
                    'password_field_present', 'login_intent', 'permission_requests',
                }) and not feats.intersection({
                    'brand_impersonation', 'lookalike_brand_domain',
                    'credentials_on_unknown_target',
                }):
                    overall = max(overall, 0.6)

        # ---- decision ------------------------------------------------------
        decision = 'allow'
        if block is not None:
            decision = 'block'
            overall = 0.05
        elif deep is not None:
            decision = 'deep_analysis'
            overall = min(overall, 0.45)
        elif overall >= 0.72:
            decision = 'allow'
        elif overall >= 0.5:
            decision = 'monitor'
        elif overall >= 0.3:
            decision = 'deep_analysis'
        else:
            decision = 'block'

        certainty = 'high' if block else self._uncertainty(len(triggered), trusts, overall)

        # ---- calibrated confidence ----------------------------------------
        if block:
            ph_conf = block['confidence']
        else:
            positive = sum(
                float(d.get('evidence_strength', 0.0)) * float(d.get('confidence', 0.0))
                for d in triggered
            ) / max(1, len(triggered))
            ph_conf = _clamp01((1.0 - overall) * 0.5 + positive * 0.5)
            if deep is not None:
                ph_conf = max(ph_conf, 0.55)

        reasons = [
            {'feature': d.get('feature'), 'category': d.get('category'),
             'severity': d.get('severity'), 'confidence': d.get('confidence'),
             'evidence_strength': d.get('evidence_strength')}
            for d in triggered
        ]
        if block:
            reasons.insert(0, {'note': block['label'], 'phishing_confidence': ph_conf})
        elif deep:
            reasons.insert(0, {'note': deep['label'], 'needs_deep_analysis': True})

        return {
            'identity': trusts.get('identity', 0.5),
            'behavior': trusts.get('behavior', 0.5),
            'interaction': trusts.get('interaction', 0.5),
            'privacy': trusts.get('privacy', 0.5),
            'ai': trusts.get('ai', 0.5),
            'overall': round(overall, 3),
            'decision': decision,
            'certainty': certainty,
            'phishing_confidence': round(ph_conf, 3),
            'uncertainty': (certainty == 'low'),
            'reasons': reasons,
            'triggered_count': len(triggered),
            'matched_rule': (block or deep or {}).get('label'),
        }

    def _legacy_profile(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        identity = _clamp01(float(evidence.get('identity_score', 0.9)))
        behavior = _clamp01(float(evidence.get('behavior_score', 0.85)))
        interaction = _clamp01(float(evidence.get('interaction_score', 0.5)))
        privacy = _clamp01(float(evidence.get('privacy_score', 0.8)))
        ai = _clamp01(float(evidence.get('ai_score', 0.7)))
        overall = _clamp01(
            (identity * 1.5 + behavior + interaction * 1.2 + privacy * 0.8 + ai) /
            (1.5 + 1 + 1.2 + 0.8 + 1)
        )
        decision = ('allow' if overall >= 0.72 else
                    'monitor' if overall >= 0.5 else
                    'deep_analysis' if overall >= 0.3 else 'block')
        return {
            'identity': round(identity, 3), 'behavior': round(behavior, 3),
            'interaction': round(interaction, 3), 'privacy': round(privacy, 3),
            'ai': round(ai, 3), 'overall': round(overall, 3),
            'decision': decision, 'certainty': 'medium',
            'phishing_confidence': round(1.0 - overall, 3),
            'uncertainty': False, 'reasons': [],
            'triggered_count': 0, 'matched_rule': None,
        }