"""
Frontend Pages Router (routers/pages.py)
----------------------------------------
Renders Jinja2 HTML templates for the web interface:
- GET /: Landing redirect (to /dashboard if authenticated, else /login)
- GET /register: Account registration page
- GET /login: Account login page
- GET /dashboard: Transfer dashboard (Sent & Received files tables)
- GET /upload: Secure file upload interface
- GET /logs: Security audit trail log viewer
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, FileTransfer, TransferLog
from app.deps import get_current_user_optional

router = APIRouter(tags=["Frontend Pages"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def index(request: Request, current_user: User = Depends(get_current_user_optional)):
    """Redirects to dashboard if logged in, else to login page."""
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    """Displays login form. Redirects to dashboard if already authenticated."""
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "user": None})


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    """Displays user registration form."""
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "user": None})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Displays user dashboard with two tables:
    1. 'Files I Sent'
    2. 'Files I Received'
    Redirects to /login if unauthenticated.
    """
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)

    sent_files = (
        db.query(FileTransfer)
        .filter(FileTransfer.sender_id == current_user.id)
        .order_by(FileTransfer.created_at.desc())
        .all()
    )

    received_files = (
        db.query(FileTransfer)
        .filter(FileTransfer.receiver_id == current_user.id)
        .order_by(FileTransfer.created_at.desc())
        .all()
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": current_user,
            "sent_files": sent_files,
            "received_files": received_files
        }
    )


@router.get("/upload", response_class=HTMLResponse)
def upload_page(
    request: Request,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Displays the secure file upload interface.
    Passes a list of other registered users to assist with receiver selection.
    """
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)

    # Fetch other registered users (excluding current user) for convenient autocomplete / dropdown
    other_users = (
        db.query(User)
        .filter(User.id != current_user.id)
        .order_by(User.username.asc())
        .all()
    )

    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "user": current_user,
            "other_users": other_users
        }
    )


@router.get("/logs", response_class=HTMLResponse)
def logs_page(
    request: Request,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Displays the security audit trail of all transfer logs for transparency.
    """
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)

    logs = (
        db.query(TransferLog)
        .order_by(TransferLog.timestamp.desc())
        .limit(100)
        .all()
    )

    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "user": current_user,
            "logs": logs
        }
    )
