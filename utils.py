"""Small security helpers: OTPs, password rules, device parsing, email delivery."""
import hashlib
import hmac
import re
import secrets
import smtplib
import time
from email.message import EmailMessage

from flask import current_app, request
from werkzeug.security import generate_password_hash

# Compared against when the account doesn't exist, so timing doesn't reveal valid usernames.
DUMMY_HASH = generate_password_hash("not-a-real-password")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IDENT_RE = re.compile(r"^[A-Za-z0-9._@+-]{3,64}$")


def client_ip() -> str:
    # If you deploy behind a reverse proxy/controller, configure ProxyFix instead of
    # trusting X-Forwarded-For directly.
    return request.remote_addr or "0.0.0.0"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------- OTP ----------
def _digest(otp_id: int, code: str) -> str:
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{otp_id}:{code}".encode(), hashlib.sha256).hexdigest()


def create_otp(db, user_id: int, purpose: str) -> str:
    """Create a fresh 6-digit code (stored only as an HMAC) and invalidate older ones."""
    now = time.time()
    db.execute("UPDATE otps SET used=1 WHERE user_id=? AND used=0", (user_id,))
    code = f"{secrets.randbelow(10 ** 6):06d}"
    cur = db.execute(
        "INSERT INTO otps(user_id,purpose,code_hash,expires_at,attempts,created_at,used)"
        " VALUES (?,?,?,?,0,?,0)",
        (user_id, purpose, "", now + current_app.config["OTP_TTL_SECONDS"], now),
    )
    db.execute("UPDATE otps SET code_hash=? WHERE id=?", (_digest(cur.lastrowid, code), cur.lastrowid))
    db.commit()
    return code


def verify_otp(db, user_id: int, purpose: str, code: str):
    """Return (status, attempts_left). status: ok | bad | expired | locked | none."""
    max_attempts = current_app.config["OTP_MAX_ATTEMPTS"]
    row = db.execute(
        "SELECT * FROM otps WHERE user_id=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1",
        (user_id, purpose),
    ).fetchone()
    if not row:
        return "none", 0
    if time.time() > row["expires_at"]:
        db.execute("UPDATE otps SET used=1 WHERE id=?", (row["id"],))
        db.commit()
        return "expired", 0
    attempts = row["attempts"] + 1
    if hmac.compare_digest(row["code_hash"], _digest(row["id"], code)):
        db.execute("UPDATE otps SET used=1, attempts=? WHERE id=?", (attempts, row["id"]))
        db.commit()
        return "ok", max_attempts - attempts
    left = max_attempts - attempts
    db.execute("UPDATE otps SET attempts=?, used=? WHERE id=?", (attempts, 1 if left <= 0 else 0, row["id"]))
    db.commit()
    return ("locked" if left <= 0 else "bad"), max(left, 0)


def otp_resend_wait(db, user_id: int) -> int:
    """Seconds until another code may be requested."""
    row = db.execute(
        "SELECT created_at FROM otps WHERE user_id=? ORDER BY id DESC LIMIT 1", (user_id,)
    ).fetchone()
    if not row:
        return 0
    wait = current_app.config["OTP_RESEND_SECONDS"] - (time.time() - row["created_at"])
    return max(0, int(wait + 0.999))


def send_otp(email: str, name: str, code: str):
    """Print to the console; also send by SMTP if SMTP_HOST is configured."""
    cfg = current_app.config
    current_app.logger.warning("OTP for %s: %s  (console delivery)", email, code)
    if not cfg["SMTP_HOST"]:
        return
    msg = EmailMessage()
    msg["Subject"] = f"{cfg['INSTITUTION_NAME']} Wi-Fi verification code"
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = email
    msg.set_content(
        f"Hi {name},\n\nYour Wi-Fi verification code is {code}. It expires in "
        f"{cfg['OTP_TTL_SECONDS'] // 60} minutes.\nIf you did not try to connect, ignore this "
        f"message and change your password.\n"
    )
    try:
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as smtp:
            smtp.starttls()
            if cfg["SMTP_USER"]:
                smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            smtp.send_message(msg)
    except Exception:                                    # delivery must not crash the login flow
        current_app.logger.exception("SMTP delivery failed")


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        return local[:1] + "***@" + domain
    return f"{local[0]}{'*' * min(len(local) - 2, 6)}{local[-1]}@{domain}"


# ---------- validation ----------
COMMON_PASSWORDS = frozenset([
    "password1", "12345678", "qwerty123", "abc12345", "password123",
    "admin123", "letmein1", "welcome1", "monkey123", "1234567890",
    "changeme1", "iloveyou1", "trustno1", "sunshine1", "princess1",
])


def validate_password(pw: str):
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", pw):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", pw):
        return "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must contain at least one special character (!@#$%^&* etc.)."
    if pw.lower() in COMMON_PASSWORDS:
        return "That password is too common. Choose something stronger."
    return None


# ---------- device description ----------
def parse_user_agent(ua: str) -> dict:
    ua = ua or ""
    if "Android" in ua:
        ver = re.search(r"Android ([\d.]+)", ua)
        model = re.search(r"Android [\d.]+;\s*([^;)]+)", ua)
        model = model.group(1).strip() if model else ""
        model = "" if model in ("K", "") else model
        os_name = "Android " + ver.group(1).split(".")[0] if ver else "Android"
        name = f"{model} ({os_name})" if model else f"Android device ({os_name})"
    elif "iPhone" in ua:
        os_name, name = "iOS", "iPhone"
    elif "iPad" in ua:
        os_name, name = "iPadOS", "iPad"
    elif "Windows" in ua:
        os_name, name = "Windows", "Windows PC"
    elif "Macintosh" in ua or "Mac OS X" in ua:
        os_name, name = "macOS", "Mac"
    elif "Linux" in ua:
        os_name, name = "Linux", "Linux PC"
    else:
        os_name, name = "Unknown OS", "Unknown device"

    if "Edg/" in ua:
        browser = "Edge"
    elif "OPR/" in ua or "Opera" in ua:
        browser = "Opera"
    elif "SamsungBrowser" in ua:
        browser = "Samsung Internet"
    elif "Firefox/" in ua or "FxiOS" in ua:
        browser = "Firefox"
    elif "Chrome/" in ua or "CriOS" in ua:
        browser = "Chrome"
    elif "Safari/" in ua:
        browser = "Safari"
    else:
        browser = "Unknown browser"
    return {"name": name, "os": os_name, "browser": browser}
