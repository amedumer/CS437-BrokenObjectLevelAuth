import uuid
from app import db
from helpers.guid import GUID

class User(db.Model):
    id = db.Column(GUID(), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    roles = db.Column(db.String(80), nullable=False)
    messages = db.relationship('Message', backref='author', lazy=True)