import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # Base de données SQLite
    DB_URL = os.environ.get("DB_URL", "sqlite:///instance/app.db")

    # --- Cookies sécurisés (conditionnels HTTPS / CI) ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")

    # Secure = True en prod HTTPS, False en CI HTTP
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = os.environ.get("REMEMBER_COOKIE_SAMESITE", "Lax")
    REMEMBER_COOKIE_SECURE = os.environ.get("REMEMBER_COOKIE_SECURE", "true").lower() == "true"

    # --- CSRF ---
    WTF_CSRF_TIME_LIMIT = 3600

    # Désactiver CSRF uniquement pendant le scan ZAP (CI)
    if os.environ.get("ZAP_SCAN", "false").lower() == "true":
        WTF_CSRF_ENABLED = False
