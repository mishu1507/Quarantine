r"""
QUARANTINE backend - works when run directly OR imported as a package.

  python app.py          (from D:\QUARANTINE\backend\)
  python run.py          (from D:\QUARANTINE\)
  python -m flask --app backend.app run   (from D:\QUARANTINE\)
"""
import os
import sys

# ── Portable import resolution ────────────────────────────────────────────────
# When run as `python app.py` inside the backend/ dir, __package__ is None
# and relative imports crash.  Detect that case, fix sys.path, then import.
if __package__ in (None, ''):
    # Running directly: make the project root importable and use absolute refs
    _BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
    _ROOT = os.path.dirname(_BACKEND_DIR)
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    from backend.config import Config        # noqa: E402
    from backend.models import db            # noqa: E402
    from backend import ml_engine            # noqa: E402
    _routes_module = 'backend.routes'
else:
    # Imported as part of the package (normal usage)
    from .config import Config               # noqa: E402
    from .models import db                   # noqa: E402
    from . import ml_engine                  # noqa: E402
    _routes_module = None  # routes imported below inside create_app

from flask import Flask
from flask_cors import CORS

# Absolute path to static/ regardless of cwd
_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC = os.path.abspath(os.path.join(_HERE, '..', 'static'))
_ROOT_DIR = os.path.abspath(os.path.join(_HERE, '..'))


def create_app(config_class=Config):
    app = Flask(__name__, static_folder=_STATIC)
    app.config.from_object(config_class)

    # Resolve relative paths to absolute so cwd doesn't matter
    for key in ('UPLOAD_FOLDER', 'MODEL_PATH', 'YARA_RULES_PATH'):
        if not os.path.isabs(app.config[key]):
            app.config[key] = os.path.join(_ROOT_DIR, app.config[key])

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    CORS(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()
        ml_engine.load_model(app.config['MODEL_PATH'])

    # Routes import works whether we're a package or running standalone
    if _routes_module:
        import importlib
        routes = importlib.import_module(_routes_module)
    else:
        from backend import routes  # noqa: E402 (standalone mode)

    app.register_blueprint(routes.bp)

    return app


app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print(f'\n  QUARANTINE running at http://127.0.0.1:{port}\n')
    app.run(debug=True, host='0.0.0.0', port=port)
