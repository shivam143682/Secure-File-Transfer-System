"""
Main Application Entrypoint (main.py)
--------------------------------------
Configures the FastAPI web application:
- Auto-creates PostgreSQL database tables at application startup.
- Mounts static files (CSS, JS).
- Attaches REST API routers (/auth, /files) and web UI router (pages).
- Provides a /health endpoint for monitoring database connectivity.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
import os

from app.database import engine, Base, get_db
from app.routers import auth, files, pages
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager that runs on application startup and shutdown.
    Auto-creates all database tables if they do not already exist.
    """
    print("[STARTUP] Initializing Secure File Transfer System...")
    # Create all database tables defined in models.py
    Base.metadata.create_all(bind=engine)
    print("[STARTUP] Database tables verified/created successfully.")
    yield
    print("[SHUTDOWN] Shutting down application cleanly.")


# Initialize FastAPI application
app = FastAPI(
    title="Secure File Transfer System",
    description="A cybersecurity-focused web app for end-to-end encrypted file dispatch and audit logging.",
    version="1.0.0",
    lifespan=lifespan
)

# Ensure static folder exists and mount it
os.makedirs("app/static/css", exist_ok=True)
os.makedirs("app/static/js", exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include Routers
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(pages.router)


@app.get(
    "/health",
    tags=["System"],
    summary="Health check endpoint"
)
def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint to verify that the FastAPI server is running
    and can successfully query the PostgreSQL database.
    """
    try:
        # Execute simple query to test DB liveness
        db.execute(text("SELECT 1;"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "ok",
        "database": db_status,
        "max_upload_mb": settings.MAX_UPLOAD_MB,
        "allowed_extensions": sorted(list(settings.ALLOWED_EXTENSIONS))
    }
