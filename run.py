"""
QUARANTINE - entry point
Run from D:\\QUARANTINE with:  python run.py
"""
import os
import sys

# Allow Unicode output on Windows consoles that default to CP1252
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Ensure the project root is on sys.path so 'backend' is importable as a package
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.app import app  # noqa: E402

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    print(f'\n  QUARANTINE running at http://127.0.0.1:{port}\n')
    app.run(debug=debug, host='0.0.0.0', port=port)
