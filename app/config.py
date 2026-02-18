# config.py
import os

def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

def env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    return int(v) if v is not None else default


class BaseConfig:
    #Config de base
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    DB_URL = os.getenv("DB_URL", "sqlite:///instance/app.db")

    #Cookie,Session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = os.getenv("REMEMBER_COOKIE_SAMESITE", "Lax")
    REMEMBER_COOKIE_SECURE = env_bool("REMEMBER_COOKIE_SECURE", False)

    #CSRF
    WTF_CSRF_ENABLED = env_bool("WTF_CSRF_ENABLED", True)
    WTF_CSRF_TIME_LIMIT = env_int("WTF_CSRF_TIME_LIMIT", 3600)
    WTF_CSRF_SSL_STRICT = env_bool("WTF_CSRF_SSL_STRICT", False)
    
    #Limitation
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_ENABLED = env_bool("RATELIMIT_ENABLED", True)
    
    #Log
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_JSON = env_bool("LOG_JSON", False)



class DevConfig(BaseConfig):
    DEBUG = True
    TESTING = False


class ProdConfig(BaseConfig):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", True)
    REMEMBER_COOKIE_SECURE = env_bool("REMEMBER_COOKIE_SECURE", True)
    WTF_CSRF_SSL_STRICT = env_bool("WTF_CSRF_SSL_STRICT", True)