"""
notifications.py — API endpoints for in-app notifications
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from auth import get_current_user
from models.user import User
import notification_service as nsvc

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])


@router.get("")
def list_notifications(
    limit: int = 50,
    only_unread: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return notifications for the current user."""
    items = nsvc.get_notifications_for_user(db, user.username, limit, only_unread)
    return {"notifications": items, "count": len(items)}


@router.get("/unread-count")
def unread_count(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return {"count": nsvc.count_unread(db, user.username)}


@router.post("/{notif_id}/read")
def mark_one_read(
    notif_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ok = nsvc.mark_read(db, user.username, notif_id)
    if not ok:
        raise HTTPException(404, "Notification not found")
    return {"ok": True}


@router.post("/mark-all-read")
def mark_all_read(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    count = nsvc.mark_all_read(db, user.username)
    return {"ok": True, "marked": count}
