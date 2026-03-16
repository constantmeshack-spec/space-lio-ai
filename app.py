from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_from_directory
)
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
import os

from flask_sqlalchemy import SQLAlchemy
import mimetypes

from dotenv import load_dotenv
load_dotenv()

# ----------------- App Setup -----------------
app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
app.config["APP_NAME"] = "SPACE LIO AI"

# ----------------- Database -----------------
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"
# Recommended for remote Postgres (Render)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,       # Checks if connection is alive before using
    "pool_recycle": 280,         # Recycle connections older than 280s
    "pool_size": 5,              # Number of connections in the pool
    "max_overflow": 10            # Extra connections allowed
}

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ----------------- Uploads -----------------
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ----------------- Serve Files -----------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/uploads/verification/<path:filename>")
def verification_file(filename):
    verification_folder = os.path.join(app.config["UPLOAD_FOLDER"], "verification")
    return send_from_directory(verification_folder, filename)
@app.route("/uploads/tasks/<path:filename>")
def task_file(filename):
    task_folder = os.path.join(app.config["UPLOAD_FOLDER"], "tasks")
    mimetype, _ = mimetypes.guess_type(filename)
    return send_from_directory(task_folder, filename)

# ----------------- Context Processor -----------------
@app.context_processor
def inject_app_name():
    return dict(APP_NAME=app.config["APP_NAME"])

# ----------------- Models -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Float, default=0)  # User account balance
    verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    verification_file = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # ---------- Affiliate Fields ----------
    is_affiliate = db.Column(db.Boolean, default=False)  # True if joined affiliate
    referral_code = db.Column(db.String(50), unique=True, nullable=True)  # User’s unique referral code
    earnings = db.Column(db.Float, default=0)  # Affiliate earnings, separate from balance
    invited_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)  # Who invited them
    invited_members = db.relationship(
        "User",
        backref=db.backref("inviter", remote_side=[id]),
        lazy=True
    )
    pending_checkout_id = db.Column(db.String(50), nullable=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    task_type = db.Column(db.String(20), nullable=False)
    external_link = db.Column(db.String(500), nullable=True)
    admin_file = db.Column(db.String(255), nullable=True)  # <-- NEW
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reward = db.Column(db.Float, nullable=False)   
    submitted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    approved = db.Column(db.Boolean, default=False)
   

    # Relationship to submissions
    submissions = db.relationship(
        "TaskSubmission",
        backref="task",
        lazy=True,
        cascade="all, delete"
    )

class TaskSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submission_file = db.Column(db.String(255), nullable=True)
    approved = db.Column(db.Boolean, default=False)

    user = db.relationship("User", backref="task_submissions")
class AffiliateTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # "join", "referral_bonus", "withdraw"
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    status = db.Column(db.String(20), default="pending")  # pending, completed, failed

    # New fields for withdrawals
    withdraw_method = db.Column(db.String(20), nullable=True)  # "mpesa" or "bank"
    mpesa_phone = db.Column(db.String(20), nullable=True)
    bank_name = db.Column(db.String(50), nullable=True)
    paybill = db.Column(db.String(50), nullable=True)
    account_no = db.Column(db.String(50), nullable=True)

    user = db.relationship("User", backref="affiliate_transactions")

class AffiliatePayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # in kobo
    status = db.Column(db.String(20), default="pending")  # pending / completed / failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="affiliate_payments")
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    subject = db.Column(db.String(200))
    message = db.Column(db.Text, nullable=False)

    admin_reply = db.Column(db.Text)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="contact_messages")
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    title = db.Column(db.String(200))
    message = db.Column(db.Text)

    is_read = db.Column(db.Boolean, default=False)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="notifications")
    # Earn With Ads settings
class AdSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reward = db.Column(db.Float, default=0.01)
    daily_limit = db.Column(db.Integer, default=20)
    cooldown = db.Column(db.Integer, default=30)  # seconds between ads


# Track user ad views
class AdView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
# ----------------- Helpers -----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first")
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("Admin access only")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

def get_admin_user():
    return User.query.filter_by(is_admin=True).first()
import requests, base64, datetime, os


# ----------------- Routes -----------------
@app.route("/")
def index():
    user = None
    user_id = session.get("user_id")
    if user_id:
        user = User.query.get(user_id)
    return render_template("index.html", user=user)

# ----------- Register -----------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        full_name = request.form.get("full_name")
        phone = request.form.get("phone")
        password = request.form.get("password")

        if User.query.filter_by(phone=phone).first():
            flash("Phone already registered.", "error")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        user = User(full_name=full_name, phone=phone, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id
        return redirect(url_for("verify_account"))

    return render_template("register.html")

# ----------- Login -----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone")
        password = request.form.get("password")

        user = User.query.filter_by(phone=phone).first()
        if not user or not check_password_hash(user.password, password):
            flash("Invalid login details", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user.id
        session["is_admin"] = user.is_admin

        if user.is_admin:
            return redirect(url_for("admin_dashboard"))

        if not user.verified:
            return redirect(url_for("verify_account"))

        return redirect(url_for("index"))

    return render_template("login.html")

# ----------- Logout -----------
@app.route("/logout")
@login_required
def logout():
    session.pop("user_id", None)
    session.pop("is_admin", None)
    flash("Logged out successfully.")
    return redirect(url_for("login"))

# ----------- Verify Account -----------
@app.route("/verify", methods=["GET","POST"])
@login_required
def verify_account():
    user = User.query.get(session["user_id"])
    if user.verified:
        return redirect(url_for("index"))

    if request.method=="POST":
        id_file = request.files.get("id_file")
        if id_file and id_file.filename != "":
            filename = secure_filename(id_file.filename)
            upload_folder = os.path.join(app.config["UPLOAD_FOLDER"], "verification")
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            id_file.save(filepath)
            user.verification_file = filepath
            db.session.commit()
            flash("Verification uploaded. Waiting for admin approval.")
            return redirect(url_for("verify_account"))
        else:
            flash("No file selected.", "error")
            accept_terms = request.form.get("accept_terms")
      

            if not accept_terms:
                flash("You must accept the Terms and Conditions.", "error")
                return redirect(url_for("verify_account"))
    return render_template("verify_phone.html", user=user)
@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/about")
def about():
    return render_template("about.html")
@app.route("/notifications")
@login_required
def notifications():

    user = User.query.get(session["user_id"])

    notifications = Notification.query.filter_by(
        user_id=user.id
    ).order_by(Notification.timestamp.desc()).all()

    return render_template(
        "notifications.html",
        notifications=notifications
    )


@app.route("/contact", methods=["GET","POST"])
@login_required
def contact():

    user = User.query.get(session["user_id"])

    if request.method == "POST":

        subject = request.form.get("subject")
        message = request.form.get("message")

        msg = ContactMessage(
            user_id=user.id,
            subject=subject,
            message=message
        )

        db.session.add(msg)
        db.session.commit()

        flash("Message sent. Admin will reply soon.","success")

        return redirect(url_for("contact"))

    messages = ContactMessage.query.filter_by(user_id=user.id).order_by(ContactMessage.timestamp.desc()).all()

    return render_template("contact.html", user=user, messages=messages)

    from datetime import datetime, timedelta

@app.route("/earn_ads")
@login_required
def earn_ads():

    settings = AdSettings.query.first()
    from datetime import datetime
    today = datetime.utcnow().date()

    views_today = AdView.query.filter(
        AdView.user_id == session["user_id"],
        db.func.date(AdView.timestamp) == today
    ).count()

    return render_template(
        "earn_ads.html",
        settings=settings,
        views_today=views_today
    )

@app.route("/cash_dashboard")
@login_required
def cash_dashboard():
    return render_template("cash_dashboard.html")

# ----------- Dashboard & Tasks -----------
@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    return render_template("dashboard.html", user=user)

@app.route("/tasks")
@login_required
def tasks():
    user = User.query.get(session["user_id"])
    tasks = Task.query.filter((Task.assigned_to_id==None) | (Task.assigned_to_id==user.id)).all()
    return render_template("tasks.html", tasks=tasks, user=user)

@app.route("/submit_task/<int:task_id>", methods=["POST"])
@login_required
def submit_task(task_id):
    task = Task.query.get_or_404(task_id)
    user_id = session["user_id"]

    submission = TaskSubmission.query.filter_by(task_id=task.id, user_id=user_id).first()
    if submission:
        flash("You have already submitted this task.", "info")
        return redirect(url_for("tasks"))

    uploaded_file = request.files.get("file")
    filename = None
    if uploaded_file and uploaded_file.filename != "":
        filename = secure_filename(uploaded_file.filename)
        uploaded_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    submission = TaskSubmission(task_id=task.id, user_id=user_id, submission_file=filename)
    db.session.add(submission)
    db.session.commit()
    flash("Task submitted successfully!", "success")
    return redirect(url_for("tasks"))

# Withdraw Dashboard
@app.route("/withdraw_dashboard")
@login_required
def withdraw_dashboard():
    user = User.query.get(session["user_id"])
    return render_template("withdraw_dashboard.html", user=user)


# Handle Withdraw Submit
@app.route("/user_withdraw", methods=["POST"])
@login_required
def user_withdraw():
    user = User.query.get(session["user_id"])
    MIN_WITHDRAW = 500

    try:
        amount = float(request.form.get("withdraw_amount", 0))
    except:
        flash("Invalid withdrawal amount.", "error")
        return redirect(url_for("withdraw_dashboard"))

    if amount < MIN_WITHDRAW:
        flash(f"Minimum withdrawal is KES {MIN_WITHDRAW}.", "error")
        return redirect(url_for("withdraw_dashboard"))

    if amount > user.balance:
        flash("You cannot withdraw more than your current balance.", "error")
        return redirect(url_for("withdraw_dashboard"))

    method = request.form.get("method")
    if method == "mpesa":
        phone = request.form.get("mpesa_phone")
        if not phone:
            flash("Please provide MPESA phone number.", "error")
            return redirect(url_for("withdraw_dashboard"))

        transaction = AffiliateTransaction(
            user_id=user.id,
            type="balance_withdraw",
            amount=amount,
            status="pending",
            withdraw_method="mpesa",
            mpesa_phone=phone
        )

    elif method == "bank":
        bank_name = request.form.get("bank_name")
        paybill = request.form.get("bank_paybill")
        account_no = request.form.get("bank_account")
        if not bank_name or not paybill or not account_no:
            flash("Please provide all bank details.", "error")
            return redirect(url_for("withdraw_dashboard"))

        transaction = AffiliateTransaction(
            user_id=user.id,
            type="balance_withdraw",
            amount=amount,
            status="pending",
            withdraw_method="bank",
            bank_name=bank_name,
            paybill=paybill,
            account_no=account_no
        )
    else:
        flash("Invalid withdrawal method.", "error")
        return redirect(url_for("withdraw_dashboard"))

    db.session.add(transaction)
    db.session.commit()

    flash(f"Withdrawal request for KES {amount} submitted successfully!", "success")
    # ✅ redirect to status page
    return redirect(url_for("view_withdraw_status"))


# View Withdraw Status
@app.route("/view_withdraw_status")
@login_required
def view_withdraw_status():
    user = User.query.get(session["user_id"])
    withdrawals = AffiliateTransaction.query.filter_by(
        user_id=user.id, type="balance_withdraw"
    ).order_by(AffiliateTransaction.timestamp.desc()).all()
    return render_template("view_withdraw_status.html", withdrawals=withdrawals)

# ----------- Admin Dashboard -----------
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    tasks = Task.query.all()
    submitted_tasks = TaskSubmission.query.all()
    users = User.query.all()
    affiliate_transactions = AffiliateTransaction.query.order_by(
        AffiliateTransaction.timestamp.desc()
    ).all()

    return render_template(
        "admin_dashboard.html",
        tasks=tasks,
        submitted_tasks=submitted_tasks,
        users=users,
        affiliate_transactions=affiliate_transactions
    )

# ----------- Admin Verify/Reject Users -----------
@app.route("/admin/verify_user/<int:user_id>")
@admin_required
def verify_user(user_id):
    user = User.query.get_or_404(user_id)
    user.verified = True
    db.session.commit()
    flash(f"{user.full_name} verified.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/reject_user/<int:user_id>")
@admin_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.verification_file and os.path.exists(user.verification_file):
        os.remove(user.verification_file)
    user.verification_file = None
    db.session.commit()
    flash(f"{user.full_name} rejected.")
    return redirect(url_for("admin_dashboard"))

# ----------- Admin Add Task -----------
@app.route("/admin/add_task", methods=["GET","POST"])
@admin_required
def add_task():
    users = User.query.filter_by(verified=True).all()
    if request.method == "POST":
        title = request.form.get("title")
        task_type = request.form.get("task_type")
        reward = request.form.get("reward")
        description = request.form.get("description")
        external_link = request.form.get("external_link")
        assigned_to_id = request.form.get("assigned_to_id")

              # Handle admin-uploaded file (MEDIA)
              
        uploaded_file = request.files.get("task_file")
        admin_filename = None

        if uploaded_file and uploaded_file.filename:
            admin_filename = secure_filename(uploaded_file.filename)

            task_folder = os.path.join(app.config["UPLOAD_FOLDER"], "tasks")
            os.makedirs(task_folder, exist_ok=True)

            uploaded_file.save(os.path.join(task_folder, admin_filename))


        if not title or not task_type or not reward:
            flash("Missing required fields.", "error")
            return redirect(url_for("add_task"))

        task = Task(
            title=title,
            task_type=task_type,
            reward=float(reward),
            description=description,
            external_link=external_link,
            admin_file=admin_filename,   # Save admin-uploaded file here
            assigned_to_id=int(assigned_to_id) if assigned_to_id else None
        )
        db.session.add(task)
        db.session.commit()
        flash("Task added successfully.")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_task.html", users=users)

# ----------- Edit Task -----------
@app.route("/admin/edit_task/<int:task_id>", methods=["GET", "POST"])
@admin_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    users = User.query.filter_by(verified=True).all()
    if request.method == "POST":
        task.title = request.form.get("title")
        task.task_type = request.form.get("task_type")
        task.reward = float(request.form.get("reward") or task.reward)
        task.description = request.form.get("description")
        assigned_to_id = request.form.get("assigned_to_id")
        task.assigned_to_id = int(assigned_to_id) if assigned_to_id else None
        db.session.commit()
        flash("Task updated successfully.")
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_task.html", task=task, users=users)

# ----------- Delete Task -----------
@app.route("/admin/delete_task/<int:task_id>")
@admin_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash("Task deleted successfully.")
    return redirect(url_for("admin_dashboard"))

# ----------- Admin Approve Task Submission -----------
@app.route("/admin/approve_task/<int:submission_id>")
@admin_required
def approve_task(submission_id):
    submission = TaskSubmission.query.get_or_404(submission_id)
    if submission.approved:
        flash("Submission already approved.", "info")
        return redirect(url_for("admin_dashboard"))

    submission.approved = True
    user = User.query.get(submission.user_id)
    user.balance += submission.task.reward
    db.session.commit()
    flash(f"Task '{submission.task.title}' approved. Reward added to {user.full_name}'s balance.")
    return redirect(url_for("admin_dashboard"))

   # ---------ADMIN RESET AFFILIATE USERS ---------
@app.route('/admin/reset-affiliate/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_affiliate(user_id):
    user = User.query.get_or_404(user_id)

    # Reset ONLY affiliate-related fields
    user.is_affiliate = False
    user.earnings = 0.0
    user.referral_code = None
    user.invited_by_id = None

    db.session.commit()

    flash(f"Affiliate status reset for {user.full_name}", "success")
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/affiliate_withdrawals")
@admin_required
def admin_affiliate_withdrawals():
    transactions = AffiliateTransaction.query.filter_by(
        type="affiliate_withdraw"  # <- changed here
    ).order_by(AffiliateTransaction.timestamp.desc()).all()
    return render_template("admin_affiliate_withdrawals.html",
                           affiliate_transactions=transactions)

@app.route("/admin/process_withdraw/<int:transaction_id>", methods=["POST"])
@admin_required
def admin_process_withdraw(transaction_id):
    action = request.form.get("action")
    transaction = AffiliateTransaction.query.get_or_404(transaction_id)
    user = transaction.user

    if transaction.status != "pending":
        flash("This withdrawal has already been processed.", "info")
        return redirect(url_for("admin_affiliate_withdrawals"))

    if action == "paid":
        # Ensure user has enough earnings before deducting
        if user.earnings < transaction.amount:
            flash(f"Cannot approve: user has insufficient earnings. Current earnings: KES {user.earnings}", "error")
            return redirect(url_for("admin_affiliate_withdrawals"))

        # Deduct the requested amount
        user.earnings -= transaction.amount
        transaction.status = "completed"

    elif action == "rejected":
        transaction.status = "failed"
        # If you deducted on request, restore the amount:
        # user.earnings += transaction.amount
        # If you deduct only on approval, nothing to restore.

    else:
        flash("Invalid action.", "error")
        return redirect(url_for("admin_affiliate_withdrawals"))

    db.session.commit()
    flash(f"Withdrawal marked as {transaction.status} for {user.full_name}", "success")
    return redirect(url_for("admin_affiliate_withdrawals"))

@app.route("/admin/balance_withdrawals")
@admin_required
def admin_balance_withdrawals():
    withdrawals = AffiliateTransaction.query.filter_by(
        type="balance_withdraw"
    ).order_by(AffiliateTransaction.timestamp.desc()).all()
    return render_template("admin_balance_withdrawals.html", withdrawals=withdrawals)

@app.route("/reward_ad", methods=["POST"])
@login_required
def reward_ad():

    settings = AdSettings.query.first()

    today = datetime.utcnow().date()

    views_today = AdView.query.filter(
        AdView.user_id == current_user.id,
        db.func.date(AdView.timestamp) == today
    ).count()

    if views_today >= settings.daily_limit:
        return {"status": "limit"}

    view = AdView(user_id=current_user.id)
    db.session.add(view)

    current_user.balance += settings.reward

    db.session.commit()

    return {"status": "success", "reward": settings.reward}

@app.route("/admin/ads_settings", methods=["GET","POST"])
@admin_required
def ads_settings():

    settings = AdSettings.query.first()

    if not settings:
        settings = AdSettings()
        db.session.add(settings)
        db.session.commit()

    if request.method == "POST":

        settings.reward = float(request.form["reward"])
        settings.daily_limit = int(request.form["limit"])
        settings.cooldown = int(request.form["cooldown"])

        db.session.commit()

        flash("Ad settings updated")

    return render_template("admin_ads.html", settings=settings)

@app.route("/admin/process_balance_withdraw/<int:transaction_id>", methods=["POST"])
@admin_required
def admin_process_balance_withdraw(transaction_id):
    action = request.form.get("action")
    transaction = AffiliateTransaction.query.get_or_404(transaction_id)
    user = transaction.user

    if transaction.status != "pending":
        flash("This withdrawal has already been processed.", "info")
        return redirect(url_for("admin_balance_withdrawals"))

    if action == "paid":
        if user.balance < transaction.amount:
            flash(f"Cannot complete: user has insufficient balance.", "error")
            return redirect(url_for("admin_balance_withdrawals"))

        # Deduct user balance and mark completed
        user.balance -= transaction.amount
        transaction.status = "completed"

    elif action == "rejected":
        transaction.status = "failed"
        # Balance not deducted

    else:
        flash("Invalid action.", "error")
        return redirect(url_for("admin_balance_withdrawals"))

    db.session.commit()
    flash(f"Withdrawal marked as {transaction.status} for {user.full_name}.", "success")
    return redirect(url_for("admin_balance_withdrawals"))

# Display affiliate management page
@app.route("/admin/affiliate_management")
@admin_required
def admin_affiliate_management():
    affiliate_users = User.query.filter_by(is_affiliate=True).all()
    return render_template("admin_affiliate_management.html", affiliate_users=affiliate_users)

# Reward route
@app.route("/admin/reward_affiliate", methods=["POST"])
@admin_required
def admin_reward_affiliate():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")

    if not user_id or not amount:
        flash("User or amount missing.", "error")
        return redirect(url_for("admin_affiliate_management"))

    try:
        amount = float(amount)
        if amount <= 0:
            flash("Amount must be greater than 0.", "error")
            return redirect(url_for("admin_affiliate_management"))
    except:
        flash("Invalid amount.", "error")
        return redirect(url_for("admin_affiliate_management"))

    user = User.query.get(user_id)
    if not user or not user.is_affiliate:
        flash("User not found or not an affiliate.", "error")
        return redirect(url_for("admin_affiliate_management"))

    user.earnings += amount

    db.session.add(AffiliateTransaction(
        user_id=user.id,
        type="reward",
        amount=amount,
        status="completed",
        withdraw_method="admin"
    ))

    db.session.commit()
    flash(f"Rewarded KES {amount} to {user.full_name}.", "success")
    return redirect(url_for("admin_affiliate_management"))

# Ban/Deregister route
@app.route("/admin/ban_affiliate", methods=["POST"])
@admin_required
def admin_ban_affiliate():
    user_id = request.form.get("user_id")
    user = User.query.get(user_id)
    if not user or not user.is_affiliate:
        flash("User not found or not an affiliate.", "error")
        return redirect(url_for("admin_affiliate_management"))

    # Deregister user as affiliate
    user.is_affiliate = False
    user.earnings = 0
    user.referral_code = None
    user.invited_by_id = None

    db.session.commit()
    flash(f"{user.full_name} has been banned as affiliate.", "success")
    return redirect(url_for("admin_affiliate_management"))

@app.route("/admin/contact_messages")
@admin_required
def admin_contact_messages():

    messages = ContactMessage.query.order_by(ContactMessage.timestamp.desc()).all()

    return render_template(
        "admin_contact_messages.html",
        messages=messages
    )

@app.route("/admin/reply_message/<int:message_id>", methods=["POST"])
@admin_required
def admin_reply_message(message_id):

    msg = ContactMessage.query.get_or_404(message_id)

    msg.admin_reply = request.form.get("reply")

    db.session.commit()

    return redirect(url_for("admin_contact_messages"))

@app.route("/admin/send_message", methods=["GET","POST"])
@admin_required
def admin_send_message():

    users = User.query.all()

    if request.method == "POST":

        user_id = request.form.get("user_id")
        title = request.form.get("title")
        message = request.form.get("message")

        if not user_id or not message:
            flash("User and message required.", "error")
            return redirect(url_for("admin_send_message"))

        notification = Notification(
            user_id=user_id,
            title=title,
            message=message
        )

        db.session.add(notification)
        db.session.commit()

        flash("Message sent to user.", "success")
        return redirect(url_for("admin_send_message"))

    return render_template("admin_send_message.html", users=users)
# ----------------- Affiliate Route -----------------
@app.route("/affiliate")
@login_required
def affiliate():
    user = User.query.get(session["user_id"])
    
    if user.is_affiliate:
        # Already an affiliate → go to affiliate dashboard
        return redirect(url_for("affiliate_dashboard"))
    else:
        # Not an affiliate yet → go to join affiliate page
        return redirect(url_for("join_affiliate"))

@app.route("/affiliate_dashboard")
@login_required
def affiliate_dashboard():
    user = User.query.get(session["user_id"])

    # Enforce payment before access
    if not user.is_affiliate:
        flash("Affiliate access requires payment.", "error")
        return redirect(url_for("join_affiliate"))

    # Load dashboard data
    earnings = user.earnings or 0
    referral_code = user.referral_code or "Not assigned"
    invited_members = User.query.filter_by(invited_by_id=user.id).all()
    invited_count = len(invited_members)

    return render_template(
        "affiliate_dashboard.html",
        user=user,
        earnings=earnings,
        referral_code=referral_code,
        invited_members=invited_members,
        invited_count=invited_count
    )

@app.route("/join_affiliate", methods=["GET"])
@login_required
def join_affiliate():
    user = User.query.get(session["user_id"])

    if user.is_affiliate:
        return redirect(url_for("affiliate_dashboard"))

    return render_template("join_affiliate.html")
@app.route("/process_affiliate_join", methods=["POST"])
@login_required
def process_affiliate_join():
    import requests
    import os

    user = User.query.get(session["user_id"])

    if user.is_affiliate:
        flash("You are already an affiliate.", "info")
        return redirect(url_for("affiliate_dashboard"))

    phone = request.form.get("phone", "").strip()
    referral_code_input = request.form.get("referral_code", "").strip()

    inviter = None
    if referral_code_input:
        inviter = User.query.filter_by(referral_code=referral_code_input).first()
        if inviter:
            user.invited_by_id = inviter.id

    # Paystack Payment Initialization
    PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "email": f"{user.phone}@example.com",
        "amount": 10000,  # in kobo
        "currency": "KES",
        "callback_url": url_for("affiliate_complete", _external=True),
        "metadata": {
            "user_id": user.id,
            "inviter_id": inviter.id if inviter else None
        }
    }

    response = requests.post("https://api.paystack.co/transaction/initialize", json=data, headers=headers)
    resp_json = response.json()

    if not resp_json.get("status"):
        flash("Failed to initialize payment. Try again.", "error")
        return redirect(url_for("join_affiliate"))

    # Save pending transaction reference
    user.pending_checkout_id = resp_json["data"]["reference"]
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("DB commit failed:", e)
        flash("Temporary database error. Please try again.", "error")
        return redirect(url_for("join_affiliate"))

    # ✅ FIX: redirect user to Paystack payment page
    authorization_url = resp_json["data"]["authorization_url"]
    return redirect(authorization_url)

@app.route("/affiliate/complete", methods=["GET"])
@login_required
def affiliate_complete():
    reference = request.args.get("reference")

    if not reference:
        flash("Payment reference missing.", "error")
        return redirect(url_for("join_affiliate"))

    PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"
    }

    # 1️⃣ Verify payment with Paystack
    verify_url = f"https://api.paystack.co/transaction/verify/{reference}"
    response = requests.get(verify_url, headers=headers)
    result = response.json()

    if not result.get("status"):
        flash("Payment verification failed.", "error")
        return redirect(url_for("join_affiliate"))

    data = result["data"]

    if data["status"] != "success":
        flash("Payment not successful.", "error")
        return redirect(url_for("join_affiliate"))

    # 2️⃣ Activate affiliate
    user = User.query.get(session["user_id"])

    if not user.is_affiliate:
        user.is_affiliate = True

        # Assign referral code if missing
        if not user.referral_code:
            count = User.query.filter_by(is_affiliate=True).count()
        import uuid
        
        user.referral_code = f"UCSLAA-{uuid.uuid4().hex[:6]}"

        # Record join transaction
        db.session.add(AffiliateTransaction(
            user_id=user.id,
            type="join",
            amount=data["amount"] / 100,  # Convert kobo to KES
            status="completed"
        ))

        # --------- Referral bonus logic ---------
        REFERRAL_BONUS = 50  # KES
        if user.invited_by_id:
            inviter = User.query.get(user.invited_by_id)
            if inviter:
                inviter.earnings += REFERRAL_BONUS
                db.session.add(AffiliateTransaction(
                    user_id=inviter.id,
                    type="referral_bonus",
                    amount=REFERRAL_BONUS,
                    status="completed"
                ))

        db.session.commit()

    flash("Affiliate activated successfully!", "success")
    return redirect(url_for("affiliate_dashboard"))

@app.route("/affiliate_withdraw", methods=["POST"])
@login_required
def affiliate_withdraw():
    user = User.query.get(session["user_id"])
    MIN_WITHDRAW = 100  # minimum withdrawal

    try:
        amount = float(request.form.get("withdraw_amount", 0))
    except:
        flash("Invalid withdrawal amount.", "error")
        return redirect(url_for("affiliate_dashboard"))

    if amount < MIN_WITHDRAW:
        flash(f"Minimum withdrawal is KES {MIN_WITHDRAW}.", "error")
        return redirect(url_for("affiliate_dashboard"))

    if amount > user.earnings:
        flash("You cannot withdraw more than your current earnings.", "error")
        return redirect(url_for("affiliate_dashboard"))

    method = request.form.get("method")  # 'mpesa' or 'bank'

    if method == "mpesa":
        phone = request.form.get("mpesa_phone")
        if not phone:
            flash("Please provide MPESA phone number.", "error")
            return redirect(url_for("affiliate_dashboard"))

        transaction = AffiliateTransaction(
            user_id=user.id,
            type="affiliate_withdraw",
            amount=amount,
            status="pending",
            withdraw_method="mpesa",
            mpesa_phone=phone
        )

    elif method == "bank":
        bank_name = request.form.get("bank_name")
        paybill = request.form.get("bank_paybill")
        account_no = request.form.get("bank_account")
        if not bank_name or not paybill or not account_no:
            flash("Please provide all bank details.", "error")
            return redirect(url_for("affiliate_dashboard"))

        transaction = AffiliateTransaction(
            user_id=user.id,
            type="affiliate_withdraw",
            amount=amount,
            status="pending",
            withdraw_method="bank",
            bank_name=bank_name,
            paybill=paybill,
            account_no=account_no
        )

    else:
        flash("Invalid withdrawal method.", "error")
        return redirect(url_for("affiliate_dashboard"))

    # Only deduct when admin approves if you follow previous fix
    # If you want to deduct now, uncomment the next line:
    # user.earnings -= amount

    db.session.add(transaction)
    db.session.commit()

    flash(f"Withdrawal request submitted for KES {amount}. Waiting for admin approval.", "success")
    return redirect(url_for("affiliate_withdrawals"))

@app.route("/affiliate/withdrawals")
@login_required
def affiliate_withdrawals():
    user = User.query.get(session["user_id"])
    withdrawals = AffiliateTransaction.query.filter_by(
        user_id=user.id,
        type="affiliate_withdraw"
    ).order_by(AffiliateTransaction.timestamp.desc()).all()

    return render_template("affiliate_withdrawals.html", withdrawals=withdrawals)

import hmac, hashlib, json
from flask import request

import hmac
import hashlib
import json

@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    payload = request.data
    signature = request.headers.get("x-paystack-signature")

    secret = os.environ.get("PAYSTACK_SECRET_KEY").encode()
    computed = hmac.new(secret, payload, hashlib.sha512).hexdigest()

    if signature != computed:
        return "Invalid signature", 400

    event = json.loads(payload)

    if event["event"] != "charge.success":
        return "Ignored", 200

    data = event["data"]
    metadata = data.get("metadata", {})
    user_id = metadata.get("user_id")

    if not user_id:
        return "No user_id", 400

    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    # Activate affiliate
    if not user.is_affiliate:
        user.is_affiliate = True

    # Assign referral code if missing
    if not user.referral_code:
        count = User.query.filter_by(is_affiliate=True).count()
        user.referral_code = f"UCSLAA{count + 1}"

    # Record join transaction
    db.session.add(AffiliateTransaction(
        user_id=user.id,
        type="join",
        amount=data["amount"] / 100,  # KES
        status="completed"
    ))

    # --------- Referral bonus logic ---------
    REFERRAL_BONUS = 50  # KES
    if user.invited_by_id:
        inviter = User.query.get(user.invited_by_id)
        if inviter:
            inviter.earnings += REFERRAL_BONUS
            db.session.add(AffiliateTransaction(
                user_id=inviter.id,
                type="referral_bonus",
                amount=REFERRAL_BONUS,
                status="completed"
            ))

    db.session.commit()

    return "OK", 200

from flask import Response

@app.route("/sitemap.xml", methods=["GET"])
def sitemap():
    pages = []

    # List your main pages
    routes = [
        "index",
        "register",
        "login",
        "tasks",
        "affiliate",
        "dashboard"
    ]

    for route in routes:
        url = url_for(route, _external=True)
        pages.append(f"""
        <url>
            <loc>{url}</loc>
        </url>
        """)

    sitemap_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        {''.join(pages)}
    </urlset>"""

    return Response(sitemap_xml, mimetype="application/xml")

from flask import Flask, render_template, send_from_directory
import os

app = Flask(__name__)

# Serve the sw.js file
@app.route('/sw.js')
def service_worker():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'sw.js')
# ----------------- Run App -----------------
if __name__ == "__main__":
       app.run(host="0.0.0.0", port=5000, debug=False)
