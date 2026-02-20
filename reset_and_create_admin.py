from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

ADMIN_PHONE = "0799886134"

with app.app_context():
    print("⚠️ DROPPING ALL TABLES...")
    db.drop_all()

    print("✅ CREATING TABLES...")
    db.create_all()

    print("👤 CREATING ADMIN USER...")
    admin = User(
        full_name="Meshack Constant Simiyu",
        phone=ADMIN_PHONE,
        email="constantmeshack@gmail.com",
        id_number="0799886134",
        country="Kenya",
        password=generate_password_hash("admin123"),
        verified=True,
        verified_at=datetime.utcnow(),
        is_admin=True
    )

    db.session.add(admin)
    db.session.commit()

    print("✅ ADMIN CREATED SUCCESSFULLY")
    print("📞 Phone:", ADMIN_PHONE)
    print("🔐 Password: admin123")
    print("🛡️ is_admin:", admin.is_admin)
