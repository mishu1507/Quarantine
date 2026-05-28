"""
Quarantine — ML Model Training Script
======================================
Run:
    python train.py --data PATH_TO_EMBER --output ./models

EMBER dataset download (~8 GB):
    pip install ember
    python -c "import ember; ember.download_data(2)"
    # Downloads to ~/.ember/ by default

The output model file (malware_model.pkl) is used by the Flask app.
Update MODEL_PATH in .env after training.
"""

import os
import sys
import json
import time
import argparse
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

try:
    import ember
    EMBER_AVAILABLE = True
except ImportError:
    print('ERROR: ember is not installed. Run: pip install ember')
    sys.exit(1)


def load_data(data_path: str):
    """Load and clean EMBER vectorised features."""
    print(f'[1/5] Loading EMBER data from {data_path} ...')
    try:
        X_train, y_train, X_test, y_test = ember.read_vectorized_features(data_path)
    except Exception as e:
        print(f'ERROR loading EMBER data: {e}')
        print('Make sure you downloaded the dataset first:')
        print('  python -c "import ember; ember.download_data(2)"')
        sys.exit(1)

    # Filter out unlabelled samples (label == -1)
    train_mask = y_train != -1
    test_mask = y_test != -1
    X_train = X_train[train_mask]
    y_train = y_train[train_mask]
    X_test = X_test[test_mask]
    y_test = y_test[test_mask]

    # Convert sparse matrices to dense arrays if necessary
    if hasattr(X_train, 'toarray'):
        X_train = X_train.toarray()
    if hasattr(X_test, 'toarray'):
        X_test = X_test.toarray()

    # Sanitise NaN / Inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)

    print(f'    Training samples : {X_train.shape[0]:>10,}')
    print(f'    Test samples     : {X_test.shape[0]:>10,}')
    print(f'    Features         : {X_train.shape[1]}')
    print(f'    Train — benign   : {int(np.sum(y_train == 0)):>10,}')
    print(f'    Train — malware  : {int(np.sum(y_train == 1)):>10,}')

    return X_train, y_train, X_test, y_test


def train_model(X_train, y_train) -> RandomForestClassifier:
    """Train a Random Forest classifier."""
    print('[2/5] Training Random Forest classifier ...')
    print('      (This typically takes 30–60 min on CPU with EMBER2)')

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=30,
        min_samples_split=20,
        min_samples_leaf=10,
        max_features='sqrt',
        class_weight='balanced',
        n_jobs=-1,
        random_state=42,
        verbose=1,
        oob_score=True,
    )

    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = (time.time() - t0) / 60.0

    print(f'\n    Finished in {elapsed:.1f} minutes')
    if hasattr(model, 'oob_score_'):
        print(f'    OOB score : {model.oob_score_:.4f}')

    return model


def evaluate_model(model, X_test, y_test) -> dict:
    """Compute and print evaluation metrics."""
    print('[3/5] Evaluating on held-out test set ...')

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        'accuracy':  round(float(accuracy_score(y_test, y_pred)), 4),
        'precision': round(float(precision_score(y_test, y_pred)), 4),
        'recall':    round(float(recall_score(y_test, y_pred)), 4),
        'f1':        round(float(f1_score(y_test, y_pred)), 4),
        'roc_auc':   round(float(roc_auc_score(y_test, y_proba)), 4),
    }

    print(f'    Accuracy  : {metrics["accuracy"]}')
    print(f'    Precision : {metrics["precision"]}')
    print(f'    Recall    : {metrics["recall"]}')
    print(f'    F1        : {metrics["f1"]}')
    print(f'    ROC-AUC   : {metrics["roc_auc"]}')
    print()
    print(classification_report(y_test, y_pred, target_names=['benign', 'malware']))
    print('Confusion matrix:')
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    return metrics


def save_artifacts(model, metrics: dict, output_dir: str):
    """Persist model, metrics, and feature importance to disk."""
    print(f'[4/5] Saving artifacts to {output_dir} ...')
    os.makedirs(output_dir, exist_ok=True)

    model_path = os.path.join(output_dir, 'malware_model.pkl')
    joblib.dump(model, model_path, compress=3)
    print(f'    Model saved      : {model_path}')

    metrics_path = os.path.join(output_dir, 'metrics.json')
    with open(metrics_path, 'w') as fh:
        json.dump(metrics, fh, indent=2)
    print(f'    Metrics saved    : {metrics_path}')

    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        top_idx = np.argsort(importances)[-50:][::-1]
        fi = [
            {'index': int(i), 'importance': float(importances[i])}
            for i in top_idx
        ]
        fi_path = os.path.join(output_dir, 'feature_importance.json')
        with open(fi_path, 'w') as fh:
            json.dump(fi, fh, indent=2)
        print(f'    Feature imp saved: {fi_path}')

    print('[5/5] Done!')
    print()
    print(f'  ✓  Model ready at: {model_path}')
    print(f'     Update your .env:  MODEL_PATH={model_path}')
    print('     Then restart Flask to load it.')


def main():
    parser = argparse.ArgumentParser(
        description='Train Quarantine malware detection model on EMBER dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        '--data',
        required=True,
        help='Path to directory containing EMBER vectorized features',
    )
    parser.add_argument(
        '--output',
        default='./models',
        help='Output directory for model files (default: ./models)',
    )
    args = parser.parse_args()

    X_train, y_train, X_test, y_test = load_data(args.data)
    model = train_model(X_train, y_train)
    metrics = evaluate_model(model, X_test, y_test)
    save_artifacts(model, metrics, args.output)


if __name__ == '__main__':
    main()
