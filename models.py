from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    balance = db.Column(db.Float, default=0)
    verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    verification_file = db.Column(db.String(200), nullable=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    task_type = db.Column(db.String(20), nullable=False)  # media, link, survey, poll
    external_link = db.Column(db.String(255), nullable=True)
    media_url = db.Column(db.String(255), nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reward = db.Column(db.Float, nullable=False)
    file_required = db.Column(db.Boolean, default=False)
    submitted_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
