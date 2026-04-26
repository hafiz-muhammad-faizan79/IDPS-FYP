# idps-backend/seed_users.py
from database import SessionLocal, engine, Base
from models.user import User
from auth import hash_password

Base.metadata.create_all(bind=engine)
db = SessionLocal()

USERS = [
    {"id":"USR-001","name":"Faiz Bugti",   "email":"faiz@cyguardian.local",    "username":"admin",    "password":"admin123",    "role":"admin",    "avatar":"FB"},
    {"id":"USR-002","name":"Ahmad Raza",   "email":"ahmad@cyguardian.local",   "username":"soc_lead", "password":"socpass123",  "role":"soc_lead", "avatar":"AR"},
    {"id":"USR-003","name":"Sara Malik",   "email":"sara@cyguardian.local",    "username":"analyst1", "password":"analyst123",  "role":"analyst",  "avatar":"SM"},
    {"id":"USR-004","name":"Omar Sheikh",  "email":"omar@cyguardian.local",    "username":"analyst2", "password":"analyst123",  "role":"analyst",  "avatar":"OS"},
    {"id":"USR-005","name":"Zara Khan",    "email":"zara@cyguardian.local",    "username":"analyst3", "password":"analyst123",  "role":"analyst",  "avatar":"ZK"},
]

for u in USERS:
    if not db.query(User).filter(User.username == u["username"]).first():
        db.add(User(
            id=u["id"], name=u["name"], email=u["email"],
            username=u["username"], password=hash_password(u["password"]),
            role=u["role"], avatar=u["avatar"],
        ))

db.commit()
db.close()
print("✅ Users seed complete.")
print("\nLogin credentials:")
print("  admin    / admin123")
print("  soc_lead / socpass123")
print("  analyst1 / analyst123")