"""Train the lightweight stage-2 ML classifier (logistic regression +
random forest; XGBoost if available) on the labeled benchmark cases.

Produces, for each model: backend/ml/models/<name>/model.joblib + names.json.

Run:
    cd D:/SentinalAI
    ./.venv313/Scripts/python.exe -m pip install -r requirements.txt
    ./.venv313/Scripts/python.exe tools/train_model.py
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.ml.features import FEATURE_NAMES, build_feature_vector

from tools.cases import CASES, VALIDATION_CASES


def build_matrix(cases):
    X, y, names = [], [], []
    for c in cases:
        names.append(c['name'])
        X.append(build_feature_vector(c['url'], c['metadata']))
        y.append(1 if c['expected'] == 'phish' else 0)
    return X, y, names


def main():
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, precision_score, recall_score
        from sklearn.model_selection import LeaveOneOut
    except ImportError as exc:
        print('scikit-learn not installed. Run: .\\.venv313\\Scripts\\python.exe -m pip install -r requirements.txt')
        sys.exit(1)

    X, y, names = build_matrix(CASES + VALIDATION_CASES)
    Xv = build_feature_vector  # noqa: F841 (reference for future batch eval)

    print(f'Training on {len(X)} labeled cases, {len(FEATURE_NAMES)} features.')
    print('Feature names:', FEATURE_NAMES)

    models = {
        'logistic': LogisticRegression(max_iter=2000, C=1.0),
        'random_forest': RandomForestClassifier(n_estimators=120, max_depth=5,
                                                random_state=0, class_weight='balanced'),
    }
    try:
        from xgboost import XGBClassifier
        models['xgboost'] = XGBClassifier(n_estimators=60, max_depth=3, random_state=0,
                                          eval_metric='logloss')
    except ImportError:
        print('  (xgboost not installed - skipping)')

    import joblib

    out_dir = os.path.join(os.path.dirname(__file__), '..', 'backend', 'ml', 'models')
    os.makedirs(out_dir, exist_ok=True)

    print(f'\nLeave-One-Out cross-validation on {len(X)} cases:')
    for name, model in models.items():
        loo = LeaveOneOut()
        preds = []
        for train_idx, test_idx in loo.split(X):
            m = model.__class__()
            try:
                m.set_params(**model.get_params())
            except Exception:
                m = model
            m.fit([X[i] for i in train_idx], [y[i] for i in train_idx])
            prob = m.predict_proba([X[test_idx[0]]])[0][1]
            preds.append(1 if prob >= 0.5 else 0)
        acc = accuracy_score(y, preds)
        prec = precision_score(y, preds, zero_division=0)
        rec = recall_score(y, preds, zero_division=0)
        print(f'  {name:<14} accuracy={acc:.2%} precision={prec:.2%} recall={rec:.2%}')

        # fit on full data, dump
        model.fit(X, y)
        model_dir = os.path.join(out_dir, name)
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(model, os.path.join(model_dir, 'model.joblib'))
        with open(os.path.join(model_dir, 'names.json'), 'w', encoding='utf-8') as f:
            json.dump({'features': FEATURE_NAMES}, f)
        print(f'    saved -> {os.path.join(model_dir, "model.joblib")}')

    print('\nDone. Backend will use the saved model as the stage-2 scorer; the')
    print('deterministic rule-fusion pipeline remains the primary boundary.')


if __name__ == '__main__':
    main()