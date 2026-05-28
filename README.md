# Quarantine 🔬

A self-hosted malware detection tool for Windows PE files. Drag and drop a `.exe`, `.dll`, `.sys`, or similar — get back a verdict: **clean**, **suspicious**, or **malware**, with a confidence score and a full breakdown of signals.

---

## Features

- **Static analysis**: PE header parsing, section entropy, import table, string extraction
- **ML-based scoring**: EMBER feature extraction + Random Forest classifier
- **YARA rules**: Packer detection, process injection, PowerShell abuse, EICAR test
- **Detect It Easy integration**: Packer/protector identification
- **Aggregated verdict**: ML score boosted by static signals
- **Full history**: SQLite-backed scan history with search
- **Docker-ready**: One command to deploy

---

## Quick Start

### Without Docker

```bash
# 1. Clone and set up
git clone <repo>
cd quarantine

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env: set SECRET_KEY to a random 32-char string

# 4. Run
python -m flask --app backend.app run --host=0.0.0.0 --port=5000
```

The app starts without a model — static analysis and YARA still work. To enable ML:

```bash
# 5. Train the model (requires EMBER dataset ~8 GB download)
pip install ember
python -c "import ember; ember.download_data(2)"
python ml/train.py --data ~/.ember --output ml/models

# 6. Update .env
MODEL_PATH=ml/models/malware_model.pkl

# 7. Restart Flask — look for: [ML] Model loaded
```

### With Docker

```bash
cp .env.example .env
# Edit .env

docker compose build
docker compose up
# App at http://localhost:5000
```

---

## Testing

### EICAR test file (safe, always triggers YARA)

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Save as `eicar.com` and upload. Expected: YARA match `EICAR_Test`, verdict `suspicious` or `malware`.

### API

```bash
# Scan a file
curl -X POST http://localhost:5000/api/scan \
  -F "file=@test.exe"

# Get a report
curl http://localhost:5000/api/report/<scan_id>

# History
curl http://localhost:5000/api/history

# Delete a scan
curl -X DELETE http://localhost:5000/api/scan/<scan_id>
```

---

## Project Structure

```
quarantine/
├── backend/          Flask app, analysis engines, DB models
├── ml/               Training script and model output
├── yara_rules/       YARA detection rules
├── static/           Frontend (vanilla HTML/CSS/JS)
└── data/uploads/     Uploaded files (UUID-named)
```

---

## Verdict Logic

| Score | Verdict |
|---|---|
| < 30% | ✅ Clean |
| 30–70% | ⚠️ Suspicious |
| > 70% | 🚨 Malware |

Static signals (suspicious APIs, YARA matches, packing) boost the base ML score upward only — never downward.

---

## License

MIT
