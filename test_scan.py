import sys
sys.path.insert(0, r'D:\QUARANTINE')
import backend.lief_compat  # patch lief first
import ember, numpy as np, joblib

e = ember.PEFeatureExtractor(feature_version=2)
model = joblib.load(r'D:\QUARANTINE\ml\models\malware_model.pkl')

def verdict(p):
    if p < 0.30: return 'CLEAN'
    if p < 0.70: return 'SUSPICIOUS'
    return 'MALWARE'

files = [
    r'C:\Windows\System32\notepad.exe',
    r'C:\Windows\System32\calc.exe',
    r'C:\Windows\System32\cmd.exe',
]

for path in files:
    with open(path, 'rb') as f:
        data = f.read()
    vec = np.array(e.feature_vector(data), dtype=np.float32)
    p = model.predict_proba([vec])[0][1]
    name = path.split('\\')[-1]
    print(f'{name:20s}  {p:.2%}  {verdict(p)}')
