"""
email_service.py
================
Email sender for CyGuardian-X.
Uses Gmail SMTP to send verification, alerts, password reset emails.
"""

import os
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST    = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER    = os.getenv("SMTP_USER", "")
SMTP_PASS    = os.getenv("SMTP_PASSWORD", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
BACKEND_URL  = os.getenv("BACKEND_URL",  "http://localhost:8000")


def _send_smtp(to_email: str, subject: str, html_body: str, text_body: str = ""):
    """Send email via Gmail SMTP — blocking. Use in background thread."""
    if not SMTP_USER or not SMTP_PASS:
        print(f"[EMAIL] ❌ SMTP credentials missing — email NOT sent to {to_email}")
        return False

    msg = MIMEMultipart("alternative")
    msg["From"]    = f"CyGuardian-X <{SMTP_USER}>"
    msg["To"]      = to_email
    msg["Subject"] = subject
    msg["Date"]    = formatdate(localtime=True)

    if text_body:
        msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"[EMAIL] ✅ Sent to {to_email}: {subject}")
        return True
    except Exception as e:
        print(f"[EMAIL] ❌ Failed to send to {to_email}: {e}")
        return False


def send_async(to_email: str, subject: str, html_body: str, text_body: str = ""):
    """Send email in background thread — non-blocking."""
    t = threading.Thread(
        target=_send_smtp,
        args=(to_email, subject, html_body, text_body),
        daemon=True,
    )
    t.start()


# ══════════════════════════════════════════════════════════════
# Email Templates
# ══════════════════════════════════════════════════════════════
BASE_STYLE = """
<style>
    body { background:#0a0f1e; color:#e2e8f0; font-family:'Segoe UI',Arial,sans-serif; margin:0; padding:0; }
    .wrap { max-width:600px; margin:0 auto; padding:40px 20px; }
    .card { background:rgba(10,15,30,0.95); border:1px solid rgba(0,212,255,0.2); border-radius:8px; padding:32px; }
    .logo { font-size:28px; font-weight:bold; color:#00d4ff; letter-spacing:2px; text-align:center; margin-bottom:8px; font-family:'Courier New',monospace; }
    .subtitle { color:#94a3b8; text-align:center; font-size:11px; letter-spacing:3px; margin-bottom:32px; }
    .btn { display:inline-block; background:linear-gradient(135deg,#00d4ff 0%,#0099cc 100%); color:#030712 !important; padding:14px 32px; border-radius:6px; text-decoration:none; font-weight:bold; letter-spacing:1px; }
    .footer { color:#475569; font-size:11px; text-align:center; margin-top:32px; padding-top:24px; border-top:1px solid rgba(148,163,184,0.1); }
    h2 { color:#00d4ff; font-size:20px; }
    a { color:#00d4ff; }
</style>
"""


def send_verification_email(to_email: str, username: str, token: str):
    """Send email verification link to new signup."""
    verify_url = f"{BACKEND_URL}/api/auth/verify-email?token={token}"

    html = f"""
<!DOCTYPE html>
<html><head><meta charset="UTF-8">{BASE_STYLE}</head><body>
<div class="wrap"><div class="card">
    <div class="logo">CyGuardian-X</div>
    <div class="subtitle">SECURE OPERATIONS PORTAL</div>
    <h2>Welcome, {username}!</h2>
    <p>Thanks for signing up to CyGuardian-X — your AI-powered network intrusion detection platform.</p>
    <p>Please verify your email address to activate your account:</p>
    <p style="text-align:center; margin:32px 0;">
        <a href="{verify_url}" class="btn">VERIFY EMAIL ADDRESS</a>
    </p>
    <p style="color:#94a3b8; font-size:13px;">
        Or copy this link into your browser:<br>
        <a href="{verify_url}" style="word-break:break-all;">{verify_url}</a>
    </p>
    <p style="color:#94a3b8; font-size:13px;">
        This link expires in 24 hours. If you didn't sign up for CyGuardian-X, please ignore this email.
    </p>
    <div class="footer">
        CyGuardian-X • AI-Based Intrusion Detection & Prevention System<br>
        This is an automated message. Do not reply.
    </div>
</div></div>
</body></html>
"""

    text = f"""Welcome to CyGuardian-X, {username}!

Please verify your email by clicking this link:
{verify_url}

This link expires in 24 hours.
If you didn't sign up, ignore this email.

— CyGuardian-X Security Team"""

    send_async(to_email, "Verify your CyGuardian-X account", html, text)


def send_welcome_email(to_email: str, username: str):
    """Send welcome message after successful verification."""
    login_url = f"{FRONTEND_URL}/login"

    html = f"""
<!DOCTYPE html>
<html><head><meta charset="UTF-8">{BASE_STYLE}</head><body>
<div class="wrap"><div class="card">
    <div class="logo">CyGuardian-X</div>
    <div class="subtitle">SECURE OPERATIONS PORTAL</div>
    <h2>Account Verified ✓</h2>
    <p>Hi {username},</p>
    <p>Your email has been verified successfully. You can now log in to your CyGuardian-X account.</p>
    <p style="text-align:center; margin:32px 0;">
        <a href="{login_url}" class="btn">GO TO LOGIN</a>
    </p>
    <p style="color:#94a3b8; font-size:13px;">
        You've been assigned the <strong style="color:#00d4ff;">Analyst</strong> role. You can now:
    </p>
    <ul style="color:#cbd5e1; font-size:13px;">
        <li>Monitor live network traffic</li>
        <li>View security incidents and alerts</li>
        <li>Investigate threats detected by ShieldNet + DeepDefend AI</li>
    </ul>
    <div class="footer">
        CyGuardian-X • Need help? Contact your SOC administrator
    </div>
</div></div>
</body></html>
"""

    send_async(to_email, "Welcome to CyGuardian-X", html)
