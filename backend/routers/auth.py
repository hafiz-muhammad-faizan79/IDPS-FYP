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
    if hasattr(user, "verified") and user.verified is False:
        raise HTTPException(403, "Email not verified — please check your inbox and click the verification link")
    if not user.is_active:
        raise HTTPException(403, "Account is deactivated. Please contact your administrator.")

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



# ══════════════════════════════════════════════════════════════
# PUBLIC SIGNUP — creates new user with analyst role
# ══════════════════════════════════════════════════════════════
@router.post("/signup")
def public_signup(body: dict, db: Session = Depends(get_db)):
    """Public signup — analyst role, requires email verification."""
    import secrets
    from email_service import send_verification_email

    username  = (body.get("username")  or "").strip()
    password  = body.get("password") or ""
    email     = (body.get("email")     or "").strip().lower()
    full_name = (body.get("full_name") or "").strip()
    phone     = (body.get("phone")     or "").strip()

    # ── Validation ────────────────────────────────────────────
    if not username or not password or not email or not full_name or not phone:
        raise HTTPException(400, "All fields are required")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if len(username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if "@" not in email or "." not in email:
        raise HTTPException(400, "Invalid email format")
    if len(phone) < 7:
        raise HTTPException(400, "Invalid phone number")

    # ── Duplicate check ───────────────────────────────────────
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(409, "Username already taken")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Email already registered")

    # ── Generate ID + verification token ──────────────────────
    last_user = db.query(User).order_by(User.id.desc()).first()
    if last_user and last_user.id.startswith("USR-"):
        try:
            next_num = int(last_user.id.split("-")[1]) + 1
        except Exception:
            next_num = 1
    else:
        next_num = 1
    new_id = f"USR-{next_num:03d}"

    token = secrets.token_urlsafe(48)
    initials = "".join([p[0].upper() for p in full_name.split()[:2]]) or username[:2].upper()

    new_user = User(
        id                 = new_id,
        name               = full_name,
        username           = username,
        email              = email,
        phone              = phone,
        password           = hash_password(password),
        role               = "analyst",
        avatar             = initials[:5],
        is_active          = False,    # inactive until verified
        verified           = False,
        verification_token = token,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # ── Send verification email (async) ──────────────────────
    send_verification_email(email, full_name or username, token)

    print(f"[AUTH] New signup pending verification: {username} ({email})")

    return {
        "success":  True,
        "message":  "Account created! Please check your email to verify your account.",
        "username": username,
        "email":    email,
    }


@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """Email verification endpoint — clicked from email link."""
    from fastapi.responses import HTMLResponse
    from email_service import send_welcome_email
    import os

    frontend = os.getenv("FRONTEND_URL", "http://localhost:3000")
    user = db.query(User).filter(User.verification_token == token).first()

    if not user:
        return HTMLResponse(f"""
        <html><head><title>CyGuardian-X — Verification</title></head>
        <body style="font-family:sans-serif; background:#030712; color:#fff; text-align:center; padding-top:80px;">
            <h1 style="color:#ff006e;">✗ Invalid verification link</h1>
            <p>This link is either expired or already used.</p>
            <a href="{frontend}/login" style="color:#00d4ff;">Go to Login</a>
        </body></html>
        """, status_code=400)

    if user.verified:
        return HTMLResponse(f"""
        <html><head><title>CyGuardian-X — Already Verified</title></head>
        <body style="font-family:sans-serif; background:#030712; color:#fff; text-align:center; padding-top:80px;">
            <h1 style="color:#00d4ff;">Already Verified</h1>
            <p>Your account is already active. You can log in normally.</p>
            <a href="{frontend}/login" style="color:#00d4ff;">Go to Login</a>
        </body></html>
        """)

    # ── Mark as verified ──────────────────────────────────────
    user.verified           = True
    user.is_active          = True
    user.verification_token = None
    db.commit()

    send_welcome_email(user.email, user.name or user.username)
    print(f"[AUTH] Email verified: {user.username}")

    return HTMLResponse(f"""
    <html><head><title>CyGuardian-X — Verified</title></head>
    <body style="font-family:sans-serif; background:#030712; color:#fff; text-align:center; padding-top:80px;">
        <div style="max-width:480px; margin:0 auto; padding:40px; background:rgba(10,15,30,0.95); border:1px solid #00d4ff; border-radius:8px;">
            <h1 style="color:#00d4ff;">✓ Email Verified!</h1>
            <p style="color:#94a3b8;">Welcome to CyGuardian-X, {user.name or user.username}.</p>
            <p style="color:#94a3b8;">Your account is now active.</p>
            <a href="{frontend}/login" style="display:inline-block; background:#00d4ff; color:#030712; padding:14px 32px; text-decoration:none; border-radius:6px; font-weight:bold; margin-top:24px;">GO TO LOGIN</a>
        </div>
    </body></html>
    """)


# ══════════════════════════════════════════════════════════════
# FORGOT PASSWORD FLOW
# ══════════════════════════════════════════════════════════════
@router.post("/forgot-password")
def forgot_password(body: dict, db: Session = Depends(get_db)):
    """Request password reset link via email."""
    import secrets
    from datetime import datetime, timedelta
    from email_service import send_async, BASE_STYLE, FRONTEND_URL

    email = (body.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Please provide a valid email address")

    user = db.query(User).filter(User.email == email).first()

    # Always return success (don't leak which emails exist — security best practice)
    if not user:
        print(f"[AUTH] Password reset requested for non-existent: {email}")
        return {"success": True, "message": "If an account exists with that email, a reset link has been sent."}

    # Generate token + 1 hour expiry
    token  = secrets.token_urlsafe(48)
    expiry = datetime.utcnow() + timedelta(hours=1)

    user.reset_token        = token
    user.reset_token_expiry = expiry
    db.commit()

    # Build reset URL pointing to frontend
    reset_url = f"{FRONTEND_URL}/reset-password?token={token}"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">{BASE_STYLE}</head><body>
<div class="wrap"><div class="card">
    <div class="logo">CyGuardian-X</div>
    <div class="subtitle">PASSWORD RESET REQUEST</div>
    <h2>Hi {user.name or user.username},</h2>
    <p>We received a request to reset the password for your CyGuardian-X account.</p>
    <p>Click the button below to set a new password. This link expires in <strong style="color:#00d4ff;">1 hour</strong>.</p>
    <p style="text-align:center; margin:32px 0;">
        <a href="{reset_url}" class="btn">RESET PASSWORD</a>
    </p>
    <p style="color:#94a3b8; font-size:13px;">
        Or paste this link:<br>
        <a href="{reset_url}" style="word-break:break-all;">{reset_url}</a>
    </p>
    <p style="color:#94a3b8; font-size:13px;">
        If you didn't request this, ignore this email — your password won't change.
    </p>
    <div class="footer">
        CyGuardian-X • Automated security message — do not reply
    </div>
</div></div>
</body></html>"""

    send_async(user.email, "Reset your CyGuardian-X password", html)
    print(f"[AUTH] Password reset sent: {user.username} ({email})")

    return {"success": True, "message": "If an account exists with that email, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(body: dict, db: Session = Depends(get_db)):
    """Reset password using token from email."""
    from datetime import datetime

    token        = (body.get("token") or "").strip()
    new_password = body.get("password") or ""

    if not token or not new_password:
        raise HTTPException(400, "Token and password are required")
    if len(new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if not any(c.isupper() for c in new_password):
        raise HTTPException(400, "Password must contain at least one uppercase letter")
    if not any(c.isdigit() for c in new_password):
        raise HTTPException(400, "Password must contain at least one number")

    user = db.query(User).filter(User.reset_token == token).first()
    if not user:
        raise HTTPException(400, "Invalid or expired reset link")

    # Check expiry
    if user.reset_token_expiry and user.reset_token_expiry.replace(tzinfo=None) < datetime.utcnow():
        raise HTTPException(400, "Reset link has expired. Please request a new one.")

    # Update password
    user.password           = hash_password(new_password)
    user.reset_token        = None
    user.reset_token_expiry = None
    db.commit()

    print(f"[AUTH] Password reset successful: {user.username}")
    return {"success": True, "message": "Password reset successfully. You can now log in."}
