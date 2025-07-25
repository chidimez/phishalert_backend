from database.session import SessionLocal
from models.user import User
from core.security import get_password_hash

def seed():
    db = SessionLocal()
    if not db.query(User).filter(User.email == "chidi_mez@yahoo.com").first():
        admin = User(
            email="chidi_mez@yahoo.com",
            firstname="chidi",
            lastname="mez",
            hashed_password=get_password_hash("123456"),
            is_active=True
        )
        db.add(admin)
        db.commit()
        print("[✔] Admin user created.")
    else:
        print("[i] Admin user already exists.")
    db.close()

if __name__ == "__main__":
    seed()
