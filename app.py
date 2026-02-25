from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os


# ----------------- App Setup -----------------
app = Flask(__name__)
from flask import send_from_directory
import os

# Serve general uploads (task submissions)
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Serve verification documents separately
@app.route('/uploads/verification/<path:filename>')
def verification_file(filename):
    verification_folder = os.path.join(app.config['UPLOAD_FOLDER'], "verification")
    return send_from_directory(verification_folder, filename)

app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
db = SQLAlchemy(app)

# ----------------- Models -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Float, default=0)
    verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    verification_file = db.Column(db.String(255), nullable=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    task_type = db.Column(db.String(20), nullable=False)
    external_link = db.Column(db.String(500), nullable=True)
    media_url = db.Column(db.String(500), nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reward = db.Column(db.Float, nullable=False)
    submission_file = db.Column(db.String(255), nullable=True)
    submitted_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved = db.Column(db.Boolean, default=False)

# ----------------- Helpers -----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

from functools import wraps
from flask import session, redirect, url_for, flash

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

        # Set session variables
        session["user_id"] = user.id
        session["is_admin"] = user.is_admin

        # 🔴 ADMIN FLOW
        if user.is_admin:
            return redirect(url_for("admin_dashboard"))

        # 🔒 USER FLOW
        if not user.verified:
            return redirect(url_for("verify_account"))

        # Optional: If you have a field `approved`, check it
        if hasattr(user, "approved") and not user.approved:
            return redirect(url_for("waiting_approval"))

        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/submit_task/<int:task_id>", methods=["POST"])
@login_required
def submit_task(task_id):
    task = Task.query.get_or_404(task_id)

    # 🚫 STEP 1: BLOCK DOUBLE SUBMISSION
    if task.submitted_by_id == session["user_id"]:
        flash("You have already submitted this task.", "warning")
        return redirect(url_for("tasks"))

    # 📁 STEP 2: HANDLE FILE UPLOAD
    uploaded_file = request.files.get("file")
    if uploaded_file and uploaded_file.filename != "":
        filename = secure_filename(uploaded_file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        uploaded_file.save(filepath)

        task.submission_file = filename  # store filename only
        task.submitted_by_id = session["user_id"]  # 🔒 LOCK IT

        db.session.commit()
        flash("Task submitted successfully!", "success")
    else:
        flash("Please upload a file.", "error")

    return redirect(url_for("tasks"))


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

# ----------- Dashboard -----------
# User dashboard (general info)
@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    return render_template("dashboard.html", user=user)

# User tasks page
@app.route("/tasks")
@login_required
def tasks():
    user = User.query.get(session["user_id"])
    # Tasks assigned to user or global
    tasks = Task.query.filter((Task.assigned_to_id==None) | (Task.assigned_to_id==user.id)).all()
    return render_template("tasks.html", tasks=tasks, user=user)


@app.route("/withdraw")
@login_required
def withdraw():
    # Temporary placeholder
    flash("Withdraw functionality will be available soon.", "info")
    return redirect(url_for("dashboard"))

# ----------- Admin Dashboard -----------
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    all_tasks = Task.query.all()
    submitted_tasks = Task.query.filter(Task.submitted_by_id.isnot(None)).all()
    users = User.query.all()

    return render_template(
        "admin_dashboard.html",
        tasks=all_tasks,
        submitted_tasks=submitted_tasks,
        users=users
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
        media_url = request.form.get("media_url")
        assigned_to_id = request.form.get("assigned_to_id")
        file_required = True if request.form.get("file_required") else False

        # Handle admin-uploaded file
        uploaded_file = request.files.get("task_file")
        admin_filename = None
        if uploaded_file and uploaded_file.filename != "":
            admin_filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join(app.config["UPLOAD_FOLDER"], admin_filename))

        # Validate required fields
        if not title or not task_type or not reward:
            flash("Missing required fields.", "error")
            return redirect(url_for("add_task"))

        # Create task
        task = Task(
            title=title,
            task_type=task_type,
            reward=float(reward),
            description=description if task_type in ["survey", "media", "link", "poll"] else None,
            external_link=external_link if task_type in ["link","media", "poll", "survey"] else None,
            media_url=media_url if media_url in ["link","media", "poll", "survey"] else None,  # optional external link or media URL
            assigned_to_id=int(assigned_to_id) if assigned_to_id else None,
            submission_file=admin_filename,   # admin-uploaded file
            # Note: submitted_by_id stays None for admin-uploaded files
        )

        db.session.add(task)
        db.session.commit()
        flash("Task added successfully.")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_task.html", users=users)


# Edit Task
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

# Delete Task
@app.route("/admin/delete_task/<int:task_id>")
@admin_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash("Task deleted successfully.")
    return redirect(url_for("admin_dashboard"))

# ----------- Admin Approve Task Submission -----------
@app.route("/admin/approve_task/<int:task_id>")
@admin_required
def approve_task(task_id):
    task = Task.query.get_or_404(task_id)
    task.approved = True
    if task.assigned_to_id:
        user = User.query.get(task.assigned_to_id)
        user.balance += task.reward
    db.session.commit()
    flash(f"Task '{task.title}' approved and reward added to user balance.")
    return redirect(url_for("admin_dashboard"))

# ----------------- Run App -----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
