from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import random
import os
from datetime import datetime

# ------------------ APP CONFIG ------------------
app = Flask(__name__)
app.secret_key = "super-secret-key-change-this"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_DIR = os.path.join(INSTANCE_DIR, "uploads")

# Create directories if they don't exist
for directory in [INSTANCE_DIR, UPLOAD_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(INSTANCE_DIR, "spacelio.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # Max 5MB upload

db = SQLAlchemy(app)

# ------------------ DATABASE MODEL ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=True)
    id_number = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    referral_code = db.Column(db.String(10), nullable=True)
    balance = db.Column(db.Float, default=0.0)

    verified = db.Column(db.Boolean, default=False)
    phone_otp = db.Column(db.String(6), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    id_document = db.Column(db.String(200), nullable=True)

# ------------------ INIT DB ------------------
with app.app_context():
    db.create_all()

# ------------------ HELPERS ------------------
def generate_otp():
    return str(random.randint(100000, 999999))

def generate_referral_code():
    return ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=6))

# ------------------ ROUTES ------------------

# -------- HOME --------
@app.route("/")
def index():
    return redirect(url_for("login"))

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]
        email = request.form.get("email")
        id_number = request.form["id_number"]
        country = request.form["country"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        invitation_code = request.form.get("invitation_code")

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("register"))

        if User.query.filter_by(phone=phone).first():
            flash("Phone number already registered")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        otp = generate_otp()
        referral_code = generate_referral_code()

        user = User(
            full_name=full_name,
            phone=phone,
            email=email,
            id_number=id_number,
            country=country,
            password=hashed_password,
            phone_otp=otp,
            referral_code=referral_code
        )

        # Handle invitation code bonus
        if invitation_code:
            inviter = User.query.filter_by(referral_code=invitation_code).first()
            if inviter:
                inviter.balance += 1.0  # simple referral bonus
                db.session.commit()

        db.session.add(user)
        db.session.commit()

        # DEV: show OTP in console
        print(f"[DEV OTP] Phone OTP for {phone}: {otp}")

        session["user_id"] = user.id
        flash("Account created! Verify your phone and upload ID.")
        return redirect(url_for("verify_phone"))

    return render_template("register.html")

# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form["phone"]
        password = request.form.get("password")

        user = User.query.filter_by(phone=phone).first()

        if not user:
            flash("Phone number not registered")
            return redirect(url_for("login"))

        if password:
            if not check_password_hash(user.password, password):
                flash("Invalid password")
                return redirect(url_for("login"))
        else:
            # Generate OTP for login
            otp = generate_otp()
            user.phone_otp = otp
            db.session.commit()
            print(f"[DEV OTP] Login OTP for {phone}: {otp}")
            flash("OTP sent to your phone")
            return redirect(url_for("verify_phone"))

        session["user_id"] = user.id
        return redirect(url_for("dashboard"))

    return render_template("login.html")

# -------- DASHBOARD --------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    return render_template("dashboard.html", user=user)

# -------- VERIFY PHONE + ID --------
@app.route("/verify-phone", methods=["GET", "POST"])
def verify_phone():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if user.verified and user.id_document:
        flash("Account already verified")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        entered_otp = request.form["otp"]
        id_file = request.files.get("id_document")

        if entered_otp != user.phone_otp:
            flash("Invalid OTP")
            return redirect(url_for("verify_phone"))

        if not id_file:
            flash("Please upload your ID document")
            return redirect(url_for("verify_phone"))

        filename = secure_filename(id_file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{user.id}_{filename}")
        id_file.save(file_path)

        # Update user record
        user.phone_otp = None
        user.verified = True
        user.verified_at = datetime.utcnow()
        user.id_document = file_path
        db.session.commit()

        flash("Phone and ID verification completed")
        return redirect(url_for("dashboard"))

    return render_template("verify_phone.html", user=user)

# -------- TASKS PAGE --------
@app.route("/tasks")
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("tasks.html")

# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully")
    return redirect(url_for("login"))

# ------------------ RUN ------------------
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

