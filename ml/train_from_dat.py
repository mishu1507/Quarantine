"""
Quarantine — Standalone ML Training Script (No ember package needed)
=====================================================================
Reads EMBER2 pre-vectorized feature files directly as numpy arrays.

Usage:
    python ml/train_from_dat.py --data d:/QUARANTINE/ember_data --output ml/models

Required files in --data dir:
    X_train.dat   (N_train x 2381 float32 mmap array)
    y_train.dat   (N_train float32 labels: 0=benign, 1=malware, -1=unlabelled)
    X_test.dat    (N_test x 2381 float32)
    y_test.dat    (N_test float32)
"""

import os
import sys
import json
import time
import argparse
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report, confusion_matrix,
)

FEATURE_DIM = 2381  # EMBER v2 feature vector size


def load_dat(path: str, n_features: int = FEATURE_DIM) -> np.ndarray:
    """Load an EMBER .dat file as a numpy float32 matrix."""
    data = np.fromfile(path, dtype=np.float32)
    if data.ndim == 1 and data.shape[0] % n_features == 0:
        n_samples = data.shape[0] // n_features
        data = data.reshape(n_samples, n_features)
    return data


def load_labels(path: str) -> np.ndarray:
    """Load label .dat file (float32 vector: 0, 1, or -1)."""
    return np.fromfile(path, dtype=np.float32)


def load_data(data_dir: str):
    """Load and clean all four EMBER split files."""
    print(f'\n[1/5] Loading EMBER data from: {data_dir}')

    required = ['X_train.dat', 'y_train.dat', 'X_test.dat', 'y_test.dat']
    missing = [f for f in required if not os.path.exists(os.path.join(data_dir, f))]
    if missing:
        print(f'  ERROR: Missing files: {missing}')
        print(f'  Please extract all .dat files into {data_dir}')
        sys.exit(1)

    print('  Loading X_train.dat (this is large — may take 30-60s)...')
    X_train = load_dat(os.path.join(data_dir, 'X_train.dat'))
    y_train = load_labels(os.path.join(data_dir, 'y_train.dat'))

    print('  Loading X_test.dat...')
    X_test = load_dat(os.path.join(data_dir, 'X_test.dat'))
    y_test = load_labels(os.path.join(data_dir, 'y_test.dat'))

    # Filter unlabelled (label == -1)
    train_mask = y_train != -1
    test_mask  = y_test  != -1
    X_train, y_train = X_train[train_mask], y_train[train_mask]
    X_test,  y_test  = X_test[test_mask],   y_test[test_mask]

    # Sanitise NaN / Inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    X_test  = np.nan_to_num(X_test,  nan=0.0, posinf=0.0, neginf=0.0)

    y_train = y_train.astype(np.int32)
    y_test  = y_test.astype(np.int32)

    print(f'  X_train: {X_train.shape}  y_train: {y_train.shape}')
    print(f'  X_test : {X_test.shape}   y_test : {y_test.shape}')
    print(f'  Train — benign:  {int((y_train == 0).sum()):>10,}')
    print(f'  Train — malware: {int((y_train == 1).sum()):>10,}')
    print(f'  Test  — benign:  {int((y_test  == 0).sum()):>10,}')
    print(f'  Test  — malware: {int((y_test  == 1).sum()):>10,}')

    return X_train, y_train, X_test, y_test


def train_model(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """Train Random Forest classifier on EMBER features."""
    print('\n[2/5] Training Random Forest (n_estimators=100, n_jobs=-1)...')
    print('      Estimated time: 20-45 minutes on CPU (uses all cores)')

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

    print(f'\n  [DONE] Training complete in {elapsed:.1f} minutes')
    if hasattr(model, 'oob_score_'):
        print(f'  OOB score: {model.oob_score_:.4f}')

    return model


def evaluate(model, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Evaluate model on held-out test set."""
    print('\n[3/5] Evaluating on test set...')

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        'accuracy':  round(float(accuracy_score(y_test,  y_pred)), 4),
        'precision': round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        'recall':    round(float(recall_score(y_test,    y_pred, zero_division=0)), 4),
        'f1':        round(float(f1_score(y_test,        y_pred, zero_division=0)), 4),
        'roc_auc':   round(float(roc_auc_score(y_test,   y_proba)), 4),
    }

    print(f'  Accuracy : {metrics["accuracy"]}')
    print(f'  Precision: {metrics["precision"]}')
    print(f'  Recall   : {metrics["recall"]}')
    print(f'  F1       : {metrics["f1"]}')
    print(f'  ROC-AUC  : {metrics["roc_auc"]}')
    print()
    print(classification_report(y_test, y_pred, target_names=['benign', 'malware']))
    print('Confusion matrix:')
    print(confusion_matrix(y_test, y_pred))

    return metrics


def save_artifacts(model, metrics: dict, output_dir: str):
    """Save model + metrics + feature importance to disk."""
    print(f'\n[4/5] Saving to {output_dir}...')
    os.makedirs(output_dir, exist_ok=True)

    model_path = os.path.join(output_dir, 'malware_model.pkl')
    joblib.dump(model, model_path, compress=3)
    print(f'  Model saved: {model_path}')

    metrics_path = os.path.join(output_dir, 'metrics.json')
    with open(metrics_path, 'w') as fh:
        json.dump(metrics, fh, indent=2)
    print(f'  Metrics:     {metrics_path}')

    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        top_idx = np.argsort(importances)[-50:][::-1]
        fi = [{'index': int(i), 'importance': float(importances[i])} for i in top_idx]
        fi_path = os.path.join(output_dir, 'feature_importance.json')
        with open(fi_path, 'w') as fh:
            json.dump(fi, fh, indent=2)
        print(f'  Feature imp: {fi_path}')

    print('\n[5/5] Done!')
    print(f'  Set in your .env:')
    print('     MODEL_PATH=' + os.path.abspath(model_path))
    print('     Then restart Flask -- you should see: [ml_engine] Model loaded')


def main():
    parser = argparse.ArgumentParser(
        description='Train Quarantine malware classifier on EMBER dataset (.dat files)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        '--data', required=True,
        help='Directory containing X_train.dat, y_train.dat, X_test.dat, y_test.dat',
    )
    parser.add_argument(
        '--output', default='./models',
        help='Output directory for model files (default: ./models)',
    )
    parser.add_argument(
        '--fast', action='store_true',
        help='Use smaller RF (n_estimators=50, max_depth=20) for a quicker test run',
    )
    args = parser.parse_args()

    X_train, y_train, X_test, y_test = load_data(args.data)

    if args.fast:
        print('\n  [FAST MODE] Using n_estimators=50, max_depth=20')
        model = RandomForestClassifier(
            n_estimators=50, max_depth=20, min_samples_split=20,
            min_samples_leaf=10, max_features='sqrt', class_weight='balanced',
            n_jobs=-1, random_state=42, verbose=1,
        )
        import time as _t; t0 = _t.time()
        model.fit(X_train, y_train)
        print(f'\n  Done in {(_t.time()-t0)/60:.1f} min')
    else:
        model = train_model(X_train, y_train)

    metrics = evaluate(model, X_test, y_test)
    save_artifacts(model, metrics, args.output)


if __name__ == '__main__':
    main()
