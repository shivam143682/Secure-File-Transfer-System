"""
Database Connection Module (database.py)
----------------------------------------
Sets up the SQLAlchemy 2.0 database engine, session factory, and base model class.
Also provides a dependency function (get_db) to yield database sessions for FastAPI requests.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

# Create the SQLAlchemy engine connecting to PostgreSQL via psycopg2
# pool_pre_ping=True helps detect and recycle dropped connections automatically
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False  # Set to True if you want to inspect generated SQL queries in the console
)

# SessionLocal is a factory that produces a new Session object for each database interaction
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for all our database models (tables)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides an isolated database session for each request.
    Automatically closes the session after the request finishes to prevent connection leaks.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
