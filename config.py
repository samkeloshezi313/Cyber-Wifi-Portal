"""Central configuration. Override anything with environment variables."""
import os
import secrets
import stat
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
(BASE_DIR / "models").mkdir(exist_ok=True)


def _secret_key() -> str:
    """Use SECRET_KEY if set, otherwise create one once and keep it on disk."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    key_file = INSTANCE_DIR / "secret.key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    try:
        key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)       # 0o600 — owner only
    except OSError:
        pass  # Windows may not support POSIX permissions
    return key


class Config:
    SECRET_KEY = _secret_key()
    DATABASE = str(INSTANCE_DIR / "portal.db")
    MODEL_PATH = str(BASE_DIR / "models" / "rf_risk.joblib")
    METRICS_PATH = str(BASE_DIR / "models" / "rf_metrics.json")

    INSTITUTION_NAME = os.environ.get("INSTITUTION_NAME", "PENTA-CYSECURITY")
    SLOGAN = os.environ.get("SLOGAN", "A Good Dream & Secure Future")
    WIFI_SSID = os.environ.get("WIFI_SSID", "Coulombs-WiFi")
    TIMEZONE = os.environ.get("TIMEZONE", "Africa/Johannesburg")

    # Keep operational test controls off unless explicitly enabled locally.
    SHOW_TEST_CONTROLS = os.environ.get("SHOW_TEST_CONTROLS", "0") == "1"

    # Risk policy: P(suspicious) from the Random Forest.
    RISK_STEP_UP = float(os.environ.get("RISK_STEP_UP", "0.40"))   # >= : extra OTP
    RISK_HIGH_ALERT = float(os.environ.get("RISK_HIGH_ALERT", "0.65"))  # >= : high-severity review
    RISK_BLOCK = float(os.environ.get("RISK_BLOCK", "0.85"))       # >= : deny access

    OTP_TTL_SECONDS = 300
    OTP_MAX_ATTEMPTS = 3
    OTP_RESEND_SECONDS = 60
    OTP_MAX_RESENDS = 5           # max OTP codes per login/reset session

    FAILED_WINDOW_MINUTES = 15
    LOCKOUT_FAILED = 3

    # Optional real email delivery. Without SMTP, OTPs are logged locally.
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "no-reply@example.com")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SECURE_COOKIES", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
