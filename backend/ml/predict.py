"""Lightweight ML inference (stage 2) for SentinelAI.

Loads a trained scikit-learn model (logistic regression / random forest /
XGBoost if available) plus a calibration that mirrors the TRUST_FUSION path.

Expected file layout (written by tools/train_model.py):
    backend/ml/models/<name>/model.joblib
    backend/ml/models/<name>/names.json
"""
import json
import os
from typing import Any, Dict, List, Optional

from backend.ml.features import FEATURE_NAMES, build_feature_vector

_MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
_DEFAULT_ACCURACY = 0.55  # prior when no model is available


def _dict_from_vector(vector: List[float]) -> Dict[str, float]:
    return dict(zip(FEATURE_NAMES, vector))


def _available_models() -> List[str]:
    if not os.path.isdir(_MODEL_DIR):
        return []
    order = ['xgboost', 'random_forest', 'logistic']
    found = [n for n in order if os.path.exists(os.path.join(_MODEL_DIR, n, 'model.joblib'))]
    return found or sorted(os.listdir(_MODEL_DIR))


def load_model(name: str = 'auto', accuracy: float = _DEFAULT_ACCURACY):
    """Return a callable predict_proba(url, metadata) -> (phishing_prob, used_model)."""
    try:
        import joblib
    except ImportError:
        joblib = None

    if name == 'auto':
        available = _available_models()
        name = available[0] if available else 'rules'

    model_path = os.path.join(_MODEL_DIR, name, 'model.joblib')
    names_path = os.path.join(_MODEL_DIR, name, 'names.json')

    if joblib is not None and os.path.exists(model_path):
        model = joblib.load(model_path)
        try:
            names = json.load(open(names_path, encoding='utf-8'))['features']
        except Exception:
            names = FEATURE_NAMES
        expected = FEATURE_NAMES

        def predict(url, metadata):
            vec = build_feature_vector(url, metadata)
            ordered = [vec[expected.index(n)] for n in names] if names != expected else vec
            prob = float(model.predict_proba([ordered])[0][1])
            return prob, name

        return predict

    # Fallback: weakly calibrated rule fusion from the evidence engine.
    from backend.evidence_engine.evidence_engine import ThreatEvidenceEngine
    from backend.trust_engine.trust_engine import TrustEngine

    ee = ThreatEvidenceEngine()
    te = TrustEngine()

    def predict(url, metadata):
        evidence = ee.build_evidence(url, metadata)
        profile = te.compute_trust_profile(evidence)
        prob = profile.get('phishing_confidence', _DEFAULT_ACCURACY)
        return float(prob), 'rules'

    return predict


def score(url: str, metadata: Optional[Dict[str, Any]] = None,
          model: str = 'auto', accuracy: float = _DEFAULT_ACCURACY):
    if model == 'auto':
        predictor = load_model()
    else:
        predictor = load_model(model, accuracy)
    return predictor(url, metadata)


def load_model_as_predictor(model: str = 'auto'):
    """Compatibility alias returning a (url, metadata) -> (prob, model_name)."""
    return load_model(model) if model != 'auto' else load_model()