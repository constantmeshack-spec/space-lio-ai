from app import db, app, User
from werkzeug.security import generate_password_hash
from datetime import datetime

with app.app_context():
    # Check if admin already exists
    if User.query.filter_by(phone="0799886134").first():
        print("Admin account already exists!")
    else:
        admin = User(
            full_name="Meshack Constant Simiyu",
            phone="0799886134",
            email="constantmeshack@gmail.com",
            id_number="0799886134",
            country="Kenya",
            password=generate_password_hash("123456"),  # password you chose
            referral_code="K0UGUT",
            balance=0.0,
            verified=True,  # mark as verified
            verified_at=datetime.utcnow()
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin account created successfully!")
