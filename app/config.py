"""Central application configuration."""

from datetime import timedelta
import os

from dotenv import load_dotenv

load_dotenv()


class BaseConfig:
    APP_ENV = "development"
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    ENFORCE_LOOPBACK = True
    LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
    LAB_ENABLE = os.getenv("LAB_ENABLE", "").strip().lower() in {"true", "1", "yes"}


class DevelopmentConfig(BaseConfig):
    APP_ENV = "development"


class TestingConfig(BaseConfig):
    APP_ENV = "testing"
    SECRET_KEY = "synthetic-test-secret-not-for-use"
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "TEST_DATABASE_URL", "sqlite+pysqlite:///:memory:"
    )
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True
    TESTING = True


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
}
