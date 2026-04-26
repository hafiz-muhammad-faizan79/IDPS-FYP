# idps-backend/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from database import get_db
from models.user import User
from auth import hash_password, verify_password, create_token, get_current_user

router = APIRouter(prefix="/api/auth", tags=["Auth"])


# ── Schemas ────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    name:     str
    email:    str
    username: str
    password: str
    role:     Optional[str] = "analyst"

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


# ── Login ──────────────────────────────────────────────────────
@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.password):
        raise HTTPException(401, "Invalid username or password")
    if not user.is_active:
        raise HTTPException(403, "Account is deactivated")

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    token = create_token({"sub": user.username, "role": user.role})
    return {
        "access_token": token,
        "token_type":   "bearer",
        "user": {
            "id":       user.id,
            "name":     user.name,
            "email":    user.email,
            "username": user.username,
            "role":     user.role,
            "avatar":   user.avatar,
        }
    }


# ── Logout ─────────────────────────────────────────────────────
@router.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    # JWT is stateless — client just deletes the token
    return {"success": True, "message": f"Goodbye {current_user.name}"}


# ── Me — get current user info ─────────────────────────────────
@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id":         current_user.id,
        "name":       current_user.name,
        "email":      current_user.email,
        "username":   current_user.username,
        "role":       current_user.role,
        "avatar":     current_user.avatar,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "created_at": current_user.created_at.isoformat(),
    }


# ── Register (admin only in production) ───────────────────────
@router.post("/register", status_code=201)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(400, f"Username '{body.username}' already taken")
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, f"Email '{body.email}' already registered")

    # Generate next ID
    count  = db.query(User).count()
    new_id = f"USR-{(count+1):03d}"
    avatar = "".join([p[0].upper() for p in body.name.split()[:2]])

    user = User(
        id       = new_id,
        name     = body.name,
        email    = body.email,
        username = body.username,
        password = hash_password(body.password),
        role     = body.role,
        avatar   = avatar,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"success": True, "user_id": user.id, "message": f"User {body.username} created"}


# ── Change password ────────────────────────────────────────────
@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.old_password, current_user.password):
        raise HTTPException(400, "Old password is incorrect")
    current_user.password = hash_password(body.new_password)
    db.commit()
    return {"success": True, "message": "Password updated successfully"}


# ── List users (admin only) ────────────────────────────────────
@router.get("/users")
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role not in ("admin", "soc_lead"):
        raise HTTPException(403, "Not permitted")
    users = db.query(User).order_by(User.created_at.desc()).all()
    return {
        "total": len(users),
        "users": [
            {
                "id":         u.id,
                "name":       u.name,
                "email":      u.email,
                "username":   u.username,
                "role":       u.role,
                "avatar":     u.avatar,
                "is_active":  u.is_active,
                "last_login": u.last_login.isoformat() if u.last_login else None,
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ]
    }


# ── Deactivate user (admin only) ───────────────────────────────
@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, f"User {user_id} not found")
    user.is_active = False
    db.commit()
    return {"success": True, "message": f"User {user_id} deactivated"}

# ── Reactivate user ────────────────────────────────────────────
@router.post("/users/{user_id}/reactivate")
def reactivate_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, f"User {user_id} not found")
    user.is_active = True
    db.commit()
    return {"success": True, "message": f"User {user_id} reactivated"}


# ── Update user role ───────────────────────────────────────────
@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    body: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, f"User {user_id} not found")
    if "role" in body:
        user.role = body["role"]
    if "name" in body:
        user.name = body["name"]
    if "email" in body:
        user.email = body["email"]
    db.commit()
    db.refresh(user)
    return {"success": True, "user": {
        "id": user.id, "name": user.name, "email": user.email,
        "username": user.username, "role": user.role,
        "avatar": user.avatar, "is_active": user.is_active,
    }}


# ── Reset password (admin only) ────────────────────────────────
@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: str,
    body: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, f"User {user_id} not found")
    from auth import hash_password
    user.password = hash_password(body.get("new_password", "changeme123"))
    db.commit()
    return {"success": True, "message": f"Password reset for {user.username}"}
