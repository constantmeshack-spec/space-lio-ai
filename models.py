from datetime import datetime
from app import db

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    link = db.Column(db.String(500), nullable=True)  # link to outside
    media_filename = db.Column(db.String(500), nullable=True)  # uploaded media
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)

class Affiliate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True)
    referral_code = db.Column(db.String(20), unique=True)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    earnings = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=False)  # 🔒 IMPORTANT
@app.route("/tasks")
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    # 🔒 Check if user is an ACTIVE affiliate
    affiliate = Affiliate.query.filter_by(
        user_id=user.id,
        is_active=True
    ).first()

    # Load tasks normally (affiliate is OPTIONAL)
    tasks = Task.query.filter_by(
        assigned_to_id=user.id,
        completed=False
    ).all()

    return render_template(
        "tasks.html",
        user=user,
        tasks=tasks,
        affiliate=affiliate
    )
