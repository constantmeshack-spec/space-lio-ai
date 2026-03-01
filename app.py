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

    user = db.relationship("User", backref="affiliate_transactions")
class AffiliatePayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reference = db.Column(db.String(100), unique=True, nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # in kobo
    status = db.Column(db.String(20), default="pending")  # pending / completed / failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="affiliate_payments")

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
    return redirect(url_for("login"))

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

        return redirect(url_for("dashboard"))

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
        return redirect(url_for("dashboard"))

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
    return render_template("verify_phone.html", user=user)

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

# ----------- Withdraw placeholder -----------
@app.route("/withdraw")
@login_required
def withdraw():
    flash("Withdraw functionality will be available soon.", "info")
    return redirect(url_for("dashboard"))

# ----------- Admin Dashboard -----------
@app.route("/admin/reset-users")
def reset_users():
    User.query.delete()
    db.session.commit()
    return "All users deleted"

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

    # Validate phone
    if not phone.startswith("254") or len(phone) != 12 or not phone.isdigit():
        flash("Phone number must start with 254 and be 12 digits long.", "error")
        return redirect(url_for("join_affiliate"))

    # Prepare inviter
    inviter = None
    if referral_code_input:
        inviter = User.query.filter_by(referral_code=referral_code_input).first()
        if not inviter:
            flash("Invalid referral code. You can still join without it.", "warning")

    # Paystack Payment Initialization
    PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "email": f"{user.phone}@example.com",  # Paystack needs email, fake with phone
        "amount": 10000,  # Amount in kobo (100 KES)
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
    if inviter:
        user.invited_by_id = inviter.id
    db.session.commit()

    # Redirect to Paystack checkout
    return redirect(resp_json["data"]["authorization_url"])

import hmac
import hashlib
from flask import request

@app.route("/affiliate/complete", methods=["POST"])
def affiliate_complete():
    """
    Paystack webhook for affiliate joining.
    Verifies signature, activates affiliate, logs transaction, and gives referral bonus.
    """
    paystack_secret = os.environ.get("PAYSTACK_SECRET_KEY")
    signature = request.headers.get("X-Paystack-Signature", "")
    payload = request.get_data()

    # 1️⃣ Verify webhook signature
    computed = hmac.new(
        key=paystack_secret.encode(),
        msg=payload,
        digestmod=hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed, signature):
        print("⚠️ Invalid Paystack signature")
        return {"status": "error", "message": "Invalid signature"}, 400

    # 2️⃣ Parse webhook data
    data = request.json
    event = data.get("event")
    payment_data = data.get("data", {})

    # Only handle successful charges
    if event != "charge.success":
        return {"status": "ignored"}, 200

    # 3️⃣ Identify the user
    metadata = payment_data.get("metadata", {})
    user_id = metadata.get("user_id")  # Make sure you sent user_id in Paystack metadata
    if not user_id:
        print("⚠️ No user_id in metadata")
        return {"status": "error", "message": "Missing user_id"}, 400

    user = User.query.get(user_id)
    if not user:
        print(f"⚠️ User not found: {user_id}")
        return {"status": "error", "message": "User not found"}, 404

    # 4️⃣ Activate affiliate if not already
    if not user.is_affiliate:
        user.is_affiliate = True

        # Generate unique referral code
        count = User.query.filter_by(is_affiliate=True).count()
        user.referral_code = f"UCSLAA{count + 1}"

        # Add transaction record
        amount_paid = float(payment_data.get("amount", 0)) / 100  # Paystack sends in kobo
        transaction = AffiliateTransaction(
            user_id=user.id,
            type="join",
            amount=amount_paid,
            status="completed"
        )
        db.session.add(transaction)

        # 5️⃣ Handle referral bonus
        inviter_code = metadata.get("referral_code")
        if inviter_code:
            inviter = User.query.filter_by(referral_code=inviter_code).first()
            if inviter and inviter.id != user.id:
                bonus = amount_paid / 2  # 50% referral bonus
                inviter.earnings += bonus
                db.session.add(AffiliateTransaction(
                    user_id=inviter.id,
                    type="referral_bonus",
                    amount=bonus,
                    status="completed"
                ))
                db.session.commit()
                print(f"✅ Referral bonus added to {inviter.full_name}")

        db.session.commit()
        print(f"✅ Affiliate activated: {user.full_name}")

    else:
        print(f"ℹ️ User already affiliate: {user.full_name}")

    return {"status": "success"}, 200

@app.route("/affiliate_withdraw", methods=["POST"])
@login_required
def affiliate_withdraw():
    user = User.query.get(session["user_id"])
    MIN_WITHDRAW = 50  # Minimum in KES

    if user.earnings < MIN_WITHDRAW:
        flash(f"Minimum withdrawal is KES {MIN_WITHDRAW}. Your earnings: KES {user.earnings}", "error")
        return redirect(url_for("affiliate_dashboard"))

    amount = int(user.earnings)  # B2C needs integer KES
    phone = user.phone  # Recipient phone

    # ------------------ M-Pesa B2C ------------------
    token = get_mpesa_token()
    if not token:
        flash("Failed to authenticate M-Pesa. Try again.", "error")
        return redirect(url_for("affiliate_dashboard"))

    SHORTCODE = os.environ.get("MPESA_SHORTCODE")
    PASSKEY = os.environ.get("MPESA_PASSKEY")
    CALLBACK_URL = os.environ.get("MPESA_CALLBACK_URL")  # Can be separate for B2C

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(f"{SHORTCODE}{PASSKEY}{timestamp}".encode()).decode()

    b2c_request = {
        "InitiatorName": os.environ.get("MPESA_INITIATOR"),  # MPESA B2C Initiator username
        "SecurityCredential": os.environ.get("MPESA_SECURITY_CRED"),  # encrypted password
        "CommandID": "BusinessPayment",
        "Amount": amount,
        "PartyA": SHORTCODE,
        "PartyB": phone,
        "Remarks": f"Affiliate withdrawal for {user.full_name}",
        "QueueTimeOutURL": CALLBACK_URL,
        "ResultURL": CALLBACK_URL,
        "Occasion": "AffiliateWithdrawal"
    }

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    response = requests.post(
        "https://api.safaricom.co.ke/mpesa/b2c/v1/paymentrequest",
        json=b2c_request,
        headers=headers
    )

    resp_json = response.json()
    if resp_json.get("ResponseCode") != "0":
        flash(f"Withdrawal failed: {resp_json.get('errorMessage', 'Unknown error')}", "error")
        return redirect(url_for("affiliate_dashboard"))

    # ------------------ Update DB ------------------
    user.earnings = 0
    db.session.add(AffiliateTransaction(
        user_id=user.id,
        type="withdraw",
        amount=amount,
        status="pending"  # will update after B2C callback
    ))
    db.session.commit()

    flash(f"Withdrawal of KES {amount} initiated! Check your phone.", "success")
    return redirect(url_for("affiliate_dashboard"))

@app.route("/mpesa/b2c/callback", methods=["POST"])
def mpesa_b2c_callback():
    data = request.get_json()
    print("B2C Callback received:", data)  # For debugging

    try:
        # Extract transaction details
        result_code = data.get("Result", {}).get("ResultCode")
        amount = float(data.get("Result", {}).get("TransactionAmount", 0))
        phone = data.get("Result", {}).get("ReceiverPartyPublicName", "").split(" ")[0]  # Safaricom sends full name
        trans_id = data.get("Result", {}).get("TransactionReceipt")
        remarks = data.get("Result", {}).get("ResultDesc")

        # Find the user
        user = User.query.filter_by(phone=phone).first()
        if not user:
            print("User not found for B2C callback:", phone)
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        # Find pending transaction
        transaction = AffiliateTransaction.query.filter_by(
            user_id=user.id,
            type="withdraw",
            status="pending"
        ).order_by(AffiliateTransaction.timestamp.desc()).first()

        if not transaction:
            print("No pending withdrawal for user:", user.phone)
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        # Update status based on ResultCode
        if result_code == 0:
            transaction.status = "completed"
        else:
            transaction.status = "failed"
            # If failed, restore earnings
            user.earnings += amount

        db.session.commit()

    except Exception as e:
        print("Error processing B2C callback:", e)

    return {"ResultCode": 0, "ResultDesc": "Accepted"}

import hmac, hashlib, json
from flask import request

@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    payload = request.data
    signature = request.headers.get("x-paystack-signature")

    secret = os.environ["PAYSTACK_SECRET_KEY"].encode()
    computed = hmac.new(secret, payload, hashlib.sha512).hexdigest()
    if signature != computed:
        return "Invalid signature", 400

    event = json.loads(payload)

    if event["event"] != "charge.success":
        return "Ignored", 200

    data = event["data"]
    reference = data["reference"]

    payment = AffiliatePayment.query.filter_by(reference=reference).first()
    if not payment or payment.status == "completed":
        return "OK", 200

    if data["status"] == "success":
        payment.status = "completed"
        user = payment.user
        user.is_affiliate = True
        user.referral_code = f"AFF{user.id}"
        # Optional: handle inviter bonus
        if user.inviter:
            user.inviter.earnings += 50  # referral bonus
        db.session.commit()

    return "OK", 200
   
# ----------------- Run App -----------------
if __name__ == "__main__":
       app.run(host="0.0.0.0", port=5000, debug=False)
