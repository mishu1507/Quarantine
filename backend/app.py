from flask import Flask
from flask_cors import CORS
from .config import Config
from .models import db
from . import ml_engine


def create_app(config_class=Config):
    app = Flask(__name__, static_folder='../static')
    app.config.from_object(config_class)

    CORS(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()
        ml_engine.load_model(app.config['MODEL_PATH'])

    from .routes import bp
    app.register_blueprint(bp)

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
