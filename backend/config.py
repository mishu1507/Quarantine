import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-this')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///quarantine.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'data/uploads')
    MODEL_PATH = os.getenv('MODEL_PATH', 'ml/models/malware_model.pkl')
    YARA_RULES_PATH = os.getenv('YARA_RULES_PATH', 'yara_rules/index.yar')
    DIE_BINARY = os.getenv('DIE_BINARY', 'diec')
    MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', 50))
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_FILE_SIZE_MB', 50)) * 1024 * 1024
    ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.com', '.bin'}
