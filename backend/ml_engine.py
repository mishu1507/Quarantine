import os
import numpy as np
import joblib

# ── Apply lief compatibility shim BEFORE importing ember ─────────────────────
# Patches old lief 0.9 exception names that ember 0.1.0 expects
try:
    if __package__:
        from . import lief_compat  # noqa: F401
    else:
        from backend import lief_compat  # noqa: F401
except Exception:
    pass

# ── Try real ember extractor first (exact feature match with training data) ───
EMBER_AVAILABLE = False

try:
    import ember as _ember
    _extractor = _ember.PEFeatureExtractor(feature_version=2)
    EMBER_AVAILABLE = True

    def extract_feature_vector(bytez: bytes):
        try:
            return np.array(_extractor.feature_vector(bytez), dtype=np.float32)
        except Exception as e:
            print(f'[ml_engine] ember extraction error: {e}')
            return None

    print('[ml_engine] Feature extractor ready (ember — exact EMBER v2 features)')

except Exception:
    # Fallback: our lief-based approximation
    try:
        if __package__:
            from .ember_features import extract_feature_vector, LIEF_AVAILABLE
        else:
            from backend.ember_features import extract_feature_vector, LIEF_AVAILABLE
        EMBER_AVAILABLE = LIEF_AVAILABLE
        if EMBER_AVAILABLE:
            print('[ml_engine] Feature extractor ready (lief approximation — slight score variance)')
        else:
            print('[ml_engine] WARNING: No feature extractor available (install lief)')
    except Exception:
        EMBER_AVAILABLE = False
        def extract_feature_vector(bytez):
            return None
        print('[ml_engine] WARNING: No feature extractor available')

# ── Module-level singleton — loaded ONCE at app startup ──────────────────────
_model = None
_model_path = None


def load_model(model_path: str) -> bool:
    """
    Load the trained model into memory.
    Must be called once inside app.app_context() at startup.
    Returns True on success, False otherwise.
    """
    global _model, _model_path
    if not os.path.exists(model_path):
        print(f'[ml_engine] WARNING: No model at {model_path}. Run ml/train_from_dat.py first.')
        print('[ml_engine] Static analysis + YARA still work without a model.')
        return False
    try:
        _model = joblib.load(model_path)
        _model_path = model_path
        print(f'[ml_engine] Model loaded from {model_path}')
        return True
    except Exception as e:
        print(f'[ml_engine] Failed to load model: {e}')
        return False


def is_model_loaded() -> bool:
    return _model is not None


def predict(file_path: str) -> dict:
    """
    Run ML prediction on a file.
    Always returns a dict — never raises.
    Falls back gracefully when model or lief are unavailable.
    """
    base = {
        'ml_score': None,
        'verdict': 'unknown',
        'confidence': 0.0,
        'top_features': [],
        'error': None,
    }

    if _model is None:
        base['error'] = 'Model not loaded — run ml/train_from_dat.py first'
        return base

    if not EMBER_AVAILABLE:
        base['error'] = 'lief not installed — run: pip install lief'
        return base

    try:
        with open(file_path, 'rb') as f:
            bytez = f.read()
    except Exception as e:
        base['error'] = f'Cannot read file: {e}'
        return base

    features = extract_feature_vector(bytez)
    if features is None:
        base['error'] = 'Feature extraction failed'
        return base

    # Sanitise NaN/Inf
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

    try:
        proba = _model.predict_proba([features])[0]
        malware_score = float(proba[1])

        if malware_score < 0.30:
            verdict = 'clean'
        elif malware_score < 0.70:
            verdict = 'suspicious'
        else:
            verdict = 'malware'

        # Top-10 most important features (tree-based models)
        top_features = []
        if hasattr(_model, 'feature_importances_'):
            importances = _model.feature_importances_
            top_idx = np.argsort(importances)[-10:][::-1]
            top_features = [
                {
                    'index': int(i),
                    'importance': round(float(importances[i]), 6),
                    'value': round(float(features[i]), 4),
                }
                for i in top_idx
            ]

        return {
            'ml_score': round(malware_score, 4),
            'verdict': verdict,
            'confidence': round(malware_score, 4),
            'top_features': top_features,
            'error': None,
        }

    except Exception as e:
        base['error'] = f'Prediction failed: {type(e).__name__}: {e}'
        return base


def aggregate_verdict(ml_result: dict, static_result: dict) -> dict:
    """
    Combine the ML probability score with static analysis signals to produce
    a final verdict and confidence score.

    Design principles:
    - Static signals can only BOOST the score — never decrease it.
    - If ML is unavailable, fall back to a pure signal-count heuristic.
    - The score is clamped to [0.0, 1.0].
    """
    base_score = ml_result.get('ml_score')

    # ── Fallback: pure static scoring when ML is unavailable ─────────────
    if base_score is None:
        signal_count = (
            len(static_result.get('imports', {}).get('suspicious_apis', [])) +
            len(static_result.get('yara_matches', [])) * 2 +
            (1 if static_result.get('packing', {}).get('is_packed') else 0)
        )
        base_score = min(signal_count * 0.15, 0.90)

    score = base_score

    suspicious_apis = static_result.get('imports', {}).get('suspicious_apis', [])
    if len(suspicious_apis) >= 3:
        score = min(score + 0.10, 1.0)
    if len(suspicious_apis) >= 6:
        score = min(score + 0.10, 1.0)

    packing = static_result.get('packing', {})
    if packing.get('is_packed'):
        score = min(score + 0.08, 1.0)

    yara_matches = static_result.get('yara_matches', [])
    if yara_matches:
        score = min(score + 0.15 * len(yara_matches), 1.0)

    strings = static_result.get('strings', {})
    if strings.get('ips'):
        score = min(score + 0.05, 1.0)
    if strings.get('urls'):
        score = min(score + 0.03, 1.0)

    # ── Build human-readable indicators ──────────────────────────────────
    indicators = []

    ml_score_val = ml_result.get('ml_score')
    if ml_score_val is not None:
        indicators.append({
            'severity': 'info',
            'text': f'ML model score: {ml_score_val:.0%} malware probability',
        })
    else:
        error = ml_result.get('error')
        if error:
            indicators.append({
                'severity': 'info',
                'text': f'ML model unavailable: {error}',
            })

    for api in suspicious_apis[:8]:
        indicators.append({'severity': 'high', 'text': f'Suspicious API import: {api}'})

    if packing.get('is_packed'):
        name = packing.get('packer_name') or 'unknown packer'
        indicators.append({'severity': 'high', 'text': f'File appears packed ({name})'})
    if packing.get('max_entropy', 0) > 7.0:
        indicators.append({
            'severity': 'medium',
            'text': f'High section entropy: {packing.get("max_entropy", 0):.2f} / 8.00',
        })

    for rule in yara_matches:
        indicators.append({'severity': 'high', 'text': f'YARA rule matched: {rule}'})

    for ip in strings.get('ips', [])[:3]:
        indicators.append({'severity': 'medium', 'text': f'Hardcoded IP address found: {ip}'})

    for url in strings.get('urls', [])[:3]:
        indicators.append({'severity': 'medium', 'text': f'Hardcoded URL found: {url}'})

    for reg in strings.get('registry_keys', [])[:3]:
        indicators.append({'severity': 'low', 'text': f'Registry key reference: {reg}'})

    for susp in strings.get('suspicious', [])[:3]:
        indicators.append({'severity': 'medium', 'text': f'Suspicious string: {susp}'})

    if not indicators:
        indicators.append({'severity': 'info', 'text': 'No suspicious indicators detected'})

    # ── Final verdict ─────────────────────────────────────────────────────
    if score < 0.30:
        verdict = 'clean'
    elif score < 0.70:
        verdict = 'suspicious'
    else:
        verdict = 'malware'

    return {
        'verdict': verdict,
        'confidence': round(score, 4),
        'ml_score': ml_score_val,
        'is_packed': packing.get('is_packed', False),
        'packer_name': packing.get('packer_name'),
        'yara_matches': yara_matches,
        'indicators': indicators,
    }
