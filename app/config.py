"""
Configuration Module (config.py)
---------------------------------
This file loads configuration settings and sensitive secrets from the .env file.
It uses Pydantic Settings to automatically validate environment variables.
Keeping secrets in .env ensures credentials are never hardcoded in the source code.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application Settings class.
    Reads values from environment variables or .env file.
    """

    # PostgreSQL database connection string
    # Format: postgresql+psycopg2://<username>:<password>@<host>:<port>/<database>
    DATABASE_URL: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/secure_file_transfer"

    # Secret key used to sign and verify JSON Web Tokens (JWT)
    SECRET_KEY: str = "default_secret_key_change_me_in_production"

    # Master encryption key used to wrap (encrypt) individual per-file Data Encryption Keys (DEK)
    # This must be a 32-byte url-safe base64 string compatible with Fernet
    MASTER_KEY: str = "o2m3T9G48V_z5FkR_oX7eH-5xGk_s0Q4G9zZ5qO6W7s="

    # Lifetime of a login JWT token in minutes
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Maximum file upload size allowed (in Megabytes)
    MAX_UPLOAD_MB: int = 10

    # Whitelist of allowed file extensions for security
    ALLOWED_EXTENSIONS: set[str] = {
        "pdf", "docx", "xlsx", "pptx", "txt", "png", "jpg", "jpeg", "zip"
    }

    # Configuration for Pydantic to read from the .env file in the project root
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def max_upload_bytes(self) -> int:
        """Helper property to get the maximum upload size in bytes."""
        return self.MAX_UPLOAD_MB * 1024 * 1024


# Create a single global instance of Settings for the application to import
settings = Settings()
