from datetime import datetime
import uuid
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    md5 = db.Column(db.String(32), nullable=True)
    sha256 = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, running, done, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    report = db.relationship('Report', backref='scan', uselist=False, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.original_filename,
            'file_size': self.file_size,
            'sha256': self.sha256,
            'md5': self.md5,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
        }


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False)
    verdict = db.Column(db.String(20), nullable=False)       # clean / suspicious / malware
    confidence = db.Column(db.Float, nullable=False)         # 0.0 to 1.0
    ml_score = db.Column(db.Float, nullable=True)
    is_packed = db.Column(db.Boolean, default=False)
    packer_name = db.Column(db.String(100), nullable=True)
    yara_matches = db.Column(db.JSON, default=list)
    indicators = db.Column(db.JSON, default=list)
    pe_info = db.Column(db.JSON, default=dict)
    static_features = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'verdict': self.verdict,
            'confidence': self.confidence,
            'ml_score': self.ml_score,
            'is_packed': self.is_packed,
            'packer_name': self.packer_name,
            'yara_matches': self.yara_matches,
            'indicators': self.indicators,
            'pe_info': self.pe_info,
            'static_features': self.static_features,
            'created_at': self.created_at.isoformat(),
        }
