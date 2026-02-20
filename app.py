from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import os, random, string

# ------------------ APP CONFIG ------------------
app = Flask(__name__)
app.secret_key = "super-secret-key-change-this"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR

db = SQLAlchemy(app)

# ------------------ MODELS ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120))
    id_number = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    verified = db.Column(db.Boolean, default=False)
    verified_at = db.Column(db.DateTime)
    id_document = db.Column(db.String(200))

    balance = db.Column(db.Float, default=0.0)
    is_admin = db.Column(db.Boolean, default=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    link = db.Column(db.String(255), nullable=True)         # optional external link
    media_file = db.Column(db.String(255), nullable=True)   # optional media
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)

class Affiliate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    referral_code = db.Column(db.String(10), unique=True)
    earnings = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=False)

# ------------------ HELPERS ------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        user = User.query.get(session["user_id"])
        if not user or not user.is_admin:
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

def generate_referral_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

# ------------------ ROUTES ------------------

@app.route("/")
def index():
    return redirect(url_for("login"))

# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = User(
            full_name=request.form["full_name"],
            phone=request.form["phone"],
            email=request.form.get("email"),
            id_number=request.form["id_number"],
            country=request.form["country"],
            password=generate_password_hash(request.form["password"])
        )
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id
        return redirect(url_for("verify"))
    return render_template("register.html")

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(phone=request.form["phone"]).first()
        if not user or not check_password_hash(user.password, request.form["password"]):
            flash("Invalid login")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        return redirect(url_for("admin_dashboard" if user.is_admin else "dashboard"))
    return render_template("login.html")

# USER DASHBOARD
@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    if user.is_admin:
        return redirect(url_for("admin_dashboard"))
    return render_template("dashboard.html", user=user)

# TASKS
@app.route("/tasks")
@login_required
def user_tasks():
    user = User.query.get(session["user_id"])
    tasks = Task.query.filter_by(assigned_to_id=user.id).all()
    return render_template("tasks.html", tasks=tasks)

# VERIFY
@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        file = request.files["id_document"]
        filename = secure_filename(file.filename)
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(path)

        user.id_document = path
        user.verified = True
        user.verified_at = datetime.utcnow()
        db.session.commit()
        return redirect(url_for("dashboard"))
    return render_template("verify_phone.html")
@app.route("/admin/verify-user/<int:user_id>")
@admin_required
def admin_verify_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found")
        return redirect(url_for("admin_dashboard"))
    
    user.verified = True
    user.verified_at = datetime.utcnow()
    db.session.commit()
    
    flash(f"{user.full_name} has been verified ✅")
    return redirect(url_for("admin_dashboard"))

# ADMIN DASHBOARD
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    users = User.query.all()
    tasks = Task.query.all()
    return render_template("admin_dashboard.html", users=users, tasks=tasks)
@app.route("/admin/tasks")
@admin_required
def admin_tasks():
    tasks = Task.query.all()  # show all tasks
    return render_template("admin_tasks.html", tasks=tasks)

# ADD TASK
@app.route("/admin/add-task", methods=["GET", "POST"])
@admin_required
def add_task():
    users = User.query.filter_by(is_admin=False).all()
    if request.method == "POST":
        task = Task(
            title=request.form["title"],
            description=request.form.get("description"),
            assigned_to_id=request.form["assigned_to_id"]
        )
        db.session.add(task)
        db.session.commit()
        return redirect(url_for("admin_dashboard"))
    return render_template("add_task.html", users=users)

# JOIN AFFILIATE (PAYMENT REQUIRED)
@app.route("/join-affiliate", methods=["GET", "POST"])
@login_required
def join_affiliate():
    user = User.query.get(session["user_id"])
    affiliate = Affiliate.query.filter_by(user_id=user.id).first()

    if request.method == "POST":
        if not affiliate:
            affiliate = Affiliate(
                user_id=user.id,
                referral_code=generate_referral_code(),
                is_active=False
            )
            db.session.add(affiliate)
            db.session.commit()
        flash("Payment required: KES 200")
        return redirect(url_for("dashboard"))

    return render_template("join_affiliate.html")

# AFFILIATE DASHBOARD
@app.route("/affiliate/dashboard")
@login_required
def affiliate_dashboard():
    affiliate = Affiliate.query.filter_by(
        user_id=session["user_id"],
        is_active=True
    ).first()

    if not affiliate:
        return redirect(url_for("join_affiliate"))

    return render_template("affiliate_dashboard.html", affiliate=affiliate)

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ------------------ RUN ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
