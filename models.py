from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    country = db.Column(db.String(50), nullable=False)
    region = db.Column(db.String(50), nullable=False)
    id_number = db.Column(db.String(50), nullable=True)
    password = db.Column(db.String(200), nullable=False)
    invitation_code = db.Column(db.String(20), nullable=True, unique=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    balance = db.Column(db.Float, default=0)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    inviter = db.relationship("User", remote_side=[id], backref="invited_users")

    def generate_invitation_code(self):
        """Generates a unique 8-character invitation code"""
        self.invitation_code = str(uuid.uuid4())[:8]