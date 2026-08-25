import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./shadowtrace.db")
SHADOWTRACE_API_KEY = os.getenv("SHADOWTRACE_API_KEY", "")
APP_ENV = os.getenv("APP_ENV", "development")
