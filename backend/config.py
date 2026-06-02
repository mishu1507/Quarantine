import os
from dotenv import load_dotenv

# Load .env from the project root (two levels up from this file: backend/ → root)
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
load_dotenv(os.path.join(_ROOT, '.env'))


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-this')

    # Check if running in Vercel serverless environment
    IS_VERCEL = os.getenv('VERCEL') == '1' or os.getenv('VERCEL') is not None

    if IS_VERCEL:
        _db_path = '/tmp/quarantine.db'
        UPLOAD_FOLDER = '/tmp/uploads'
    else:
        _db_path = os.path.join(_ROOT, 'instance', 'quarantine.db')
        UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'data/uploads')

    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL', f'sqlite:///{_db_path}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Relative paths — app.py will make them absolute at startup
    MODEL_PATH       = os.getenv('MODEL_PATH',       'ml/models/malware_model.pkl')
    YARA_RULES_PATH  = os.getenv('YARA_RULES_PATH',  'yara_rules/index.yar')
    DIE_BINARY       = os.getenv('DIE_BINARY',       'diec')

    MAX_FILE_SIZE_MB    = int(os.getenv('MAX_FILE_SIZE_MB', 50))
    MAX_CONTENT_LENGTH  = int(os.getenv('MAX_FILE_SIZE_MB', 50)) * 1024 * 1024
    ALLOWED_EXTENSIONS  = {'.exe', '.dll', '.sys', '.scr', '.com', '.bin'}
