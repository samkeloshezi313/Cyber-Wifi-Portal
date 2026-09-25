"""Risk-based adaptive Wi-Fi captive portal.

Flow:  login -> device registration (new devices) -> email OTP -> ML security check
       -> access granted | step-up OTP | blocked
"""
import json
import secrets
import time
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db as database
from config import Config
from features import build_features, count_failures
from ml_engine import FEATURE_LABELS, RiskModel
from utils import (DUMMY_HASH, EMAIL_RE, IDENT_RE, client_ip, create_otp,
                   mask_email, otp_resend_wait, parse_user_agent, send_otp,
                   sha256, validate_password, verify_otp)


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if config:
        app.config.update(config)

    database.init_app(app)
    model = RiskModel(app.config["MODEL_PATH"], app.config["METRICS_PATH"])
    app.extensions["risk_model"] = model
    tz = ZoneInfo(app.config["TIMEZONE"])

    with app.app_context():
        _ensure_admin(app)

    # ------------------------------------------------------------------ helpers
    def db():
        return database.get_db()

    def current_user():
        uid = session.get("uid")
        if not uid:
            return None
        return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    def active_portal_session():
        """Return the current connected session while it remains authorised."""
        sid = session.get("sid")
        uid = session.get("uid")
        if not sid or not uid:
            return None
        return db().execute(
            "SELECT id FROM sessions WHERE id=? AND user_id=? AND ended_at IS NULL",
            (sid, uid),
        ).fetchone()

    def require_stage(*stages):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if not session.get("uid") or session.get("stage") not in stages:
                    flash("Your sign-in session expired. Please log in again.", "warning")
                    return redirect(url_for("login"))
                if session.get("stage") == "connected" and "connected" in stages and not active_portal_session():
                    session.clear()
                    flash("Your Wi-Fi session was ended by an administrator.", "warning")
                    return redirect(url_for("login"))
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def recognise_device(user_id):
        token = request.cookies.get("device_token")
        if not token:
            return None
        return db().execute(
            "SELECT * FROM devices WHERE user_id=? AND token_hash=? AND trusted=1",
            (user_id, sha256(token)),
        ).fetchone()

    def log_event(**kw):
        cols = ", ".join(kw)
        marks = ", ".join("?" for _ in kw)
        cur = db().execute(f"INSERT INTO login_events({cols}) VALUES ({marks})", tuple(kw.values()))
        db().commit()
        return cur.lastrowid

    def is_admin_authenticated():
        user = current_user()
        if not user or user["role"] != "admin":
            return False
        stage = session.get("stage")
        if stage == "connected":
            return active_portal_session() is not None
        return stage == "assessed" and session.get("decision") == "allow"

    # ------------------------------------------------------- template plumbing
    @app.context_processor
    def inject_globals():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return {
            "institution": app.config["INSTITUTION_NAME"],
            "slogan": app.config["SLOGAN"],
            "ssid": app.config["WIFI_SSID"],
            "show_test_controls": app.config["SHOW_TEST_CONTROLS"],
            "csrf_token": session["_csrf"],
            "show_admin_link": is_admin_authenticated(),
        }

    @app.template_filter("fmt_time")
    def fmt_time(ts):
        return datetime.fromtimestamp(ts, tz).strftime("%H:%M")

    @app.template_filter("fmt_dt")
    def fmt_dt(ts):
        return datetime.fromtimestamp(ts, tz).strftime("%d %b, %H:%M")

    @app.template_filter("from_json_failed")
    def from_json_failed(features_json):
        try:
            return int(json.loads(features_json)["failed_attempts"])
        except (TypeError, ValueError, KeyError):
            return 0

    @app.template_filter("fmt_duration")
    def fmt_duration(seconds):
        sec = max(0, int(seconds))
        m, s = divmod(sec, 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h}h {m:02d}m {s:02d}s"
        if m > 0:
            return f"{m}m {s:02d}s"
        return f"{s}s"

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token") or ""
            expected = session.get("_csrf", "")
            if not sent or not expected or not secrets.compare_digest(sent, expected):
                abort(400)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(400)
    def bad_request(_e):
        flash("That request could not be verified. Please try again.", "warning")
        return redirect(url_for("login"))

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(app.static_folder, "favicon.svg", mimetype="image/svg+xml")

    # ------------------------------------------------------------------ step 1
    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html", tab=request.args.get("tab", "login"))

        ident = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")
        ip = client_ip()
        now = time.time()
        user = db().execute(
            "SELECT * FROM users WHERE identifier=? OR lower(email)=?", (ident, ident)
        ).fetchone()
        log_ident = user["identifier"] if user else ident[:64]

        if user and user["blocked_at"]:
            flash("This account has been blocked. Please contact an administrator.", "danger")
            return render_template("login.html", tab="login"), 423

        failures = count_failures(db(), log_ident, app.config["FAILED_WINDOW_MINUTES"], now)
        if user and user["role"] != "admin" and failures >= app.config["LOCKOUT_FAILED"]:
            if failures == app.config["LOCKOUT_FAILED"]:      # raise the alert once
                database.add_alert(db(), "Account lockout (brute force)", "high", log_ident, ip,
                                   f"{failures} failed logins in {app.config['FAILED_WINDOW_MINUTES']} min")
                log_event(identifier=log_ident, ts=now, ip=ip, result="bad_password")
            flash(f"Too many failed attempts. Try again in {app.config['FAILED_WINDOW_MINUTES']} minutes.", "danger")
            return render_template("login.html", tab="login"), 429

        valid = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password) and user is not None
        if not valid:
            new_failures = failures + 1
            decision = "block" if new_failures >= app.config["LOCKOUT_FAILED"] else None
            log_event(user_id=user["id"] if user else None, identifier=log_ident, ts=now, ip=ip,
                      result="bad_password", decision=decision,
                      outcome="denied" if decision == "block" else "pending")
            if decision == "block":
                if user and user["role"] != "admin":
                    db().execute("UPDATE users SET blocked_at=?, block_reason=? WHERE id=?",
                                 (now, "Too many failed password attempts", user["id"]))
                    db().commit()
                    database.add_alert(db(), "Account blocked after failed passwords", "high", log_ident, ip,
                                       f"{new_failures} failed password attempts in {app.config['FAILED_WINDOW_MINUTES']} minutes")
                    flash("This account has been blocked. Please contact an administrator.", "danger")
                    return render_template("login.html", tab="login"), 423
                database.add_alert(db(), "Suspicious administrator login", "high", log_ident, ip,
                                   f"{new_failures} failed administrator password attempts")
                flash("Incorrect email/number or password.", "danger")
                return render_template("login.html", tab="login"), 401
            database.add_alert(db(), "Suspicious login detected", "medium", log_ident, ip,
                               f"Incorrect password attempt {new_failures} of {app.config['LOCKOUT_FAILED']}")
            flash("Incorrect email/number or password.", "danger")
            return render_template("login.html", tab="login"), 401

        # Password OK -> start a fresh session that is NOT yet authorised.
        session.clear()
        session.permanent = True
        session["_csrf"] = secrets.token_urlsafe(32)
        session["uid"] = user["id"]
        session["stage"] = "pw_ok"
        session["otp_verified"] = False
        if app.config["SHOW_TEST_CONTROLS"]:
            session["sim_new_location"] = request.form.get("sim_location") == "new"
            session["sim_hour"] = request.form.get("sim_hour") or None
        return redirect(url_for("device"))

    @app.route("/signup", methods=["POST"])
    def signup():
        name = request.form.get("full_name", "").strip()
        ident = request.form.get("identifier", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = None
        if len(name) < 2:
            error = "Enter your full name."
        elif not IDENT_RE.match(ident):
            error = "Student/staff number must be 3-64 characters (letters, numbers, . _ @ + -)."
        elif not EMAIL_RE.match(email):
            error = "Enter a valid email address for verification codes."
        else:
            error = validate_password(password)
        if error:
            flash(error, "danger")
            return render_template("login.html", tab="signup"), 400
        if db().execute("SELECT 1 FROM users WHERE identifier=? OR lower(email)=?",
                                      (ident, email)).fetchone():
            # Don't reveal whether the account exists — show the same success message
            flash("Account created. Log in to connect.", "success")
            return redirect(url_for("login"))
        db().execute(
            "INSERT INTO users(identifier,email,full_name,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
            (ident, email, name, generate_password_hash(password), "user", time.time()),
        )
        db().commit()
        flash("Account created. Log in to connect.", "success")
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ step 2
    @app.route("/device", methods=["GET", "POST"])
    @require_stage("pw_ok")
    def device():
        user = current_user()
        known = recognise_device(user["id"])
        if known:                                     # trusted device: skip registration + OTP
            session["device_id"] = known["id"]
            session["stage"] = "device_ok"
            return redirect(url_for("security_check"))

        info = parse_user_agent(request.user_agent.string)
        ip = client_ip()
        if request.method == "POST":
            db().execute("DELETE FROM devices WHERE user_id=? AND trusted=0", (user["id"],))
            cur = db().execute(
                "INSERT INTO devices(user_id,name,os,browser,trusted,first_ip,created_at) VALUES (?,?,?,?,0,?,?)",
                (user["id"], info["name"], info["os"], info["browser"], ip, time.time()),
            )
            db().commit()
            session["device_id"] = cur.lastrowid
            _start_otp(user, "register")
            return redirect(url_for("mfa"))
        return render_template("device.html", info=info, ip=ip, email=mask_email(user["email"]))

    def _start_otp(user, purpose):
        count = session.get("otp_resend_count", 0) + 1
        session["otp_resend_count"] = count
        code = create_otp(db(), user["id"], purpose)
        send_otp(user["email"], user["full_name"], code)
        session["stage"] = "otp_pending"
        session["otp_purpose"] = purpose

    # ------------------------------------------------------------------ step 3
    @app.route("/mfa", methods=["GET", "POST"])
    @require_stage("otp_pending")
    def mfa():
        user = current_user()
        purpose = session.get("otp_purpose", "register")
        if request.method == "POST":
            code = "".join(ch for ch in request.form.get("code", "") if ch.isdigit())
            status, left = verify_otp(db(), user["id"], purpose, code)
            if status == "ok":
                session["otp_verified"] = True
                if purpose == "register":
                    token = secrets.token_urlsafe(32)
                    db().execute(
                        "UPDATE devices SET token_hash=?, trusted=1, last_seen=? WHERE id=? AND user_id=?",
                        (sha256(token), time.time(), session["device_id"], user["id"]),
                    )
                    db().commit()
                    session["stage"] = "device_ok"
                    resp = redirect(url_for("security_check"))
                    resp.set_cookie("device_token", token, max_age=365 * 24 * 3600, httponly=True,
                                    samesite="Lax", secure=request.is_secure)
                    return resp
                session["stage"] = "assessed"            # step-up passed
                session["decision"] = "allow"
                db().execute("UPDATE login_events SET decision='allow' WHERE id=? AND user_id=?",
                             (session.get("event_id"), user["id"]))
                db().commit()
                return redirect(url_for("result"))
            if status == "locked":
                now = time.time()
                ip = client_ip()
                if user["role"] != "admin":
                    db().execute("UPDATE users SET blocked_at=?, block_reason=? WHERE id=?",
                                 (now, "Too many incorrect verification codes", user["id"]))
                log_event(user_id=user["id"], identifier=user["identifier"], ts=now, ip=ip,
                          result="bad_otp", decision="block", outcome="denied")
                threat = "Account blocked after OTP failures" if user["role"] != "admin" else "Administrator OTP failures"
                database.add_alert(db(), threat, "high", user["identifier"], ip,
                                   f"{app.config['OTP_MAX_ATTEMPTS']} wrong codes for '{purpose}' verification")
                session.clear()
                flash("This account has been blocked. Please contact an administrator." if user["role"] != "admin" else "Too many incorrect codes. Please log in again.", "danger")
                return redirect(url_for("login"))
            if status == "expired" or status == "none":
                flash("That code has expired. Request a new one.", "warning")
            else:
                database.add_alert(db(), "Suspicious OTP failure", "medium", user["identifier"], client_ip(),
                                   f"Incorrect verification code for '{purpose}'. {left} attempt(s) left")
                flash(f"Incorrect code. {left} attempt(s) left.", "danger")
            return redirect(url_for("mfa"))

        return render_template(
            "mfa.html", email=mask_email(user["email"]), purpose=purpose,
            wait=otp_resend_wait(db(), user["id"]),
        )

    @app.route("/mfa/resend", methods=["POST"])
    @require_stage("otp_pending")
    def mfa_resend():
        user = current_user()
        if session.get("otp_resend_count", 0) >= app.config["OTP_MAX_RESENDS"]:
            flash("Maximum verification codes reached. Please log in again.", "danger")
            session.clear()
            return redirect(url_for("login"))
        if otp_resend_wait(db(), user["id"]) > 0:
            flash("Please wait before requesting another code.", "warning")
        else:
            _start_otp(user, session.get("otp_purpose", "register"))
            flash("A new code has been sent.", "success")
        return redirect(url_for("mfa"))

    # ------------------------------------------------------------------ step 4
    @app.route("/security-check")
    @require_stage("device_ok", "assessed")
    def security_check():
        if session["stage"] == "assessed":
            return redirect(url_for("result"))
        return render_template("checking.html")

    @app.route("/api/risk-assess", methods=["POST"])
    @require_stage("device_ok")
    def api_risk_assess():
        user = current_user()
        dev = db().execute("SELECT * FROM devices WHERE id=? AND user_id=? AND trusted=1",
                           (session.get("device_id"), user["id"])).fetchone()
        if not dev:
            abort(403)
        ip, now, cfg = client_ip(), time.time(), app.config

        feats, checks, ctx = build_features(
            db(), user, dev, ip, now, tz, cfg,
            sim_hour=session.get("sim_hour"), sim_new_location=session.get("sim_new_location", False),
        )
        risk = model.predict_risk(feats)
        if risk >= cfg["RISK_BLOCK"]:
            decision = "block"
        elif risk >= cfg["RISK_STEP_UP"]:
            # Device registration proves device ownership; it does not clear a risk finding.
            decision = "step_up"
        else:
            decision = "allow"

        event_id = log_event(
            user_id=user["id"], identifier=user["identifier"], ts=now, ip=ip, ip_prefix=ctx["ip_prefix"],
            result="assessed", hour=ctx["hour"], time_label=ctx["time_label"],
            features_json=json.dumps(feats), checks_json=json.dumps(checks), risk=risk,
            decision=decision, outcome="denied" if decision == "block" else "pending",
            device_id=dev["id"], location_label=ctx["location_label"],
        )
        db().execute("UPDATE devices SET last_seen=? WHERE id=?", (now, dev["id"]))
        db().commit()

        detail = ", ".join(f"{FEATURE_LABELS[k]}={v:g}" for k, v in feats.items())
        if decision == "block":
            database.add_alert(db(), "Blocked high-risk login", "high", user["identifier"], ip,
                               f"risk {risk:.0%}; {detail}")
        elif risk >= cfg["RISK_STEP_UP"]:
            high_risk = risk >= cfg["RISK_HIGH_ALERT"]
            threat = "High-risk login flagged" if high_risk else "Suspicious login (step-up required)"
            severity = "high" if high_risk else "medium"
            database.add_alert(db(), threat, severity, user["identifier"], ip,
                               f"risk {risk:.0%}; additional verification required; {detail}")
        elif feats["location_anomaly"] >= 1.0:
            database.add_alert(db(), "New location detected", "medium", user["identifier"], ip,
                               f"{ctx['location_label']}; risk {risk:.0%}")

        session["stage"] = "assessed"
        session["decision"] = decision
        session["event_id"] = event_id
        return jsonify({"checks": checks, "decision": decision})

    # ------------------------------------------------------------------ steps 5/6
    @app.route("/result")
    @require_stage("assessed")
    def result():
        user = current_user()
        ev = db().execute("SELECT * FROM login_events WHERE id=? AND user_id=?",
                          (session.get("event_id"), user["id"])).fetchone()
        dev = db().execute("SELECT * FROM devices WHERE id=?", (ev["device_id"],)).fetchone() if ev else None
        if not ev or not dev:
            return redirect(url_for("login"))
        decision = session.get("decision")
        ctx = {"ev": ev, "dev": dev, "ip": ev["ip"], "risk_pct": round(ev["risk"] * 100)}
        if decision == "allow":
            ctx["now"] = time.time()
            return render_template("granted.html", **ctx)
        return render_template("suspicious.html", blocked=(decision == "block"),
                               email=mask_email(user["email"]), **ctx)

    @app.route("/stepup", methods=["POST"])
    @require_stage("assessed")
    def stepup():
        if session.get("decision") != "step_up":
            return redirect(url_for("result"))
        _start_otp(current_user(), "stepup")
        return redirect(url_for("mfa"))

    @app.route("/connect", methods=["POST"])
    @require_stage("assessed")
    def connect():
        if session.get("decision") != "allow":
            abort(403)
        user = current_user()
        ev = db().execute("SELECT * FROM login_events WHERE id=? AND user_id=?",
                          (session.get("event_id"), user["id"])).fetchone()
        if not ev:
            abort(403)
        cur = db().execute("INSERT INTO sessions(user_id,device_id,ip,risk,started_at) VALUES (?,?,?,?,?)",
                           (user["id"], ev["device_id"], ev["ip"], ev["risk"], time.time()))
        db().execute("UPDATE login_events SET outcome='granted' WHERE id=?", (ev["id"],))
        db().commit()
        session["sid"] = cur.lastrowid
        session["stage"] = "connected"
        # A real deployment calls the controller/RADIUS/firewall here to authorise ev["ip"].
        return redirect(url_for("connected"))

    @app.route("/connected")
    @require_stage("connected")
    def connected():
        user = current_user()
        sid = session.get("sid")
        sess = db().execute("SELECT * FROM sessions WHERE id=? AND user_id=?", (sid, user["id"])).fetchone() if sid and user else None
        dev = None
        if sess and sess["device_id"]:
            dev = db().execute("SELECT * FROM devices WHERE id=?", (sess["device_id"],)).fetchone()
        elif session.get("device_id"):
            dev = db().execute("SELECT * FROM devices WHERE id=?", (session.get("device_id"),)).fetchone()
        ip = sess["ip"] if sess else client_ip()
        started_at = sess["started_at"] if sess else time.time()
        return render_template(
            "connected.html",
            user=user,
            sess=sess,
            dev=dev,
            ip=ip,
            started_at=started_at,
            now=time.time(),
            masked_email=mask_email(user["email"]),
        )

    @app.route("/api/session-status")
    def api_session_status():
        if session.get("stage") != "connected" or not session.get("uid"):
            return jsonify({"active": False}), 401
        return jsonify({"active": active_portal_session() is not None})

    @app.route("/session-ended")
    def session_ended():
        session.clear()
        flash("Your Wi-Fi session was ended by an administrator.", "warning")
        return redirect(url_for("login"))

    @app.route("/logout", methods=["POST"])
    def logout():
        if session.get("sid"):
            db().execute("UPDATE sessions SET ended_at=? WHERE id=? AND ended_at IS NULL",
                         (time.time(), session["sid"]))
            db().commit()
        session.clear()
        flash("You have been disconnected.", "info")
        return redirect(url_for("login"))

    @app.route("/cancel", methods=["POST"])
    def cancel():
        if session.get("event_id") and session.get("uid"):
            db().execute("UPDATE login_events SET outcome='denied' WHERE id=? AND user_id=? AND outcome='pending'",
                         (session["event_id"], session["uid"]))
            db().commit()
        session.clear()
        return redirect(url_for("login"))

    # --------------------------------------------------------- forgot password
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "GET":
            return render_template("forgot_password.html", stage="request")
        ident = request.form.get("identifier", "").strip().lower()
        if not ident:
            flash("Enter your student/staff number or email.", "danger")
            return render_template("forgot_password.html", stage="request"), 400
        user = db().execute(
            "SELECT * FROM users WHERE identifier=? OR lower(email)=?", (ident, ident)
        ).fetchone()
        if not user:
            # Don't reveal whether the account exists — same UX either way
            flash("If an account exists, a verification code has been sent.", "info")
            return render_template("forgot_password.html", stage="request")
        if user["blocked_at"]:
            flash("This account is blocked. Contact an administrator.", "danger")
            return render_template("forgot_password.html", stage="request"), 423
        # Start OTP for password reset
        code = create_otp(db(), user["id"], "reset")
        send_otp(user["email"], user["full_name"], code)
        session.clear()
        session.permanent = True
        session["_csrf"] = secrets.token_urlsafe(32)
        session["reset_uid"] = user["id"]
        session["reset_stage"] = "verify"
        session["otp_resend_count"] = 1
        flash("A verification code has been sent to your email.", "info")
        return redirect(url_for("reset_password"))

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        uid = session.get("reset_uid")
        stage = session.get("reset_stage")
        if not uid or stage not in ("verify", "set_password"):
            flash("Please start the password reset process again.", "warning")
            return redirect(url_for("forgot_password"))
        user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for("login"))

        if request.method == "GET":
            if stage == "verify":
                return render_template("reset_password.html", stage="verify",
                                       email=mask_email(user["email"]),
                                       wait=otp_resend_wait(db(), user["id"]))
            return render_template("reset_password.html", stage="set_password")

        # POST — either OTP verification or new password submission
        if stage == "verify":
            code = "".join(ch for ch in request.form.get("code", "") if ch.isdigit())
            status, left = verify_otp(db(), user["id"], "reset", code)
            if status == "ok":
                session["reset_stage"] = "set_password"
                return render_template("reset_password.html", stage="set_password")
            if status == "locked":
                session.clear()
                flash("Too many incorrect codes. Please try again.", "danger")
                return redirect(url_for("forgot_password"))
            if status in ("expired", "none"):
                flash("That code has expired. Request a new one.", "warning")
            else:
                flash(f"Incorrect code. {left} attempt(s) left.", "danger")
            return redirect(url_for("reset_password"))

        # stage == "set_password"
        new_password = request.form.get("password", "")
        error = validate_password(new_password)
        if error:
            flash(error, "danger")
            return render_template("reset_password.html", stage="set_password")
        db().execute("UPDATE users SET password_hash=? WHERE id=?",
                     (generate_password_hash(new_password), uid))
        db().commit()
        session.clear()
        flash("Password updated successfully. Log in with your new password.", "success")
        return redirect(url_for("login"))

    @app.route("/reset-password/resend", methods=["POST"])
    def reset_resend():
        uid = session.get("reset_uid")
        if not uid or session.get("reset_stage") != "verify":
            return redirect(url_for("forgot_password"))
        if session.get("otp_resend_count", 0) >= app.config["OTP_MAX_RESENDS"]:
            flash("Maximum verification codes reached. Please start again.", "danger")
            session.clear()
            return redirect(url_for("forgot_password"))
        user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not user:
            return redirect(url_for("forgot_password"))
        if otp_resend_wait(db(), user["id"]) > 0:
            flash("Please wait before requesting another code.", "warning")
        else:
            session["otp_resend_count"] = session.get("otp_resend_count", 0) + 1
            code = create_otp(db(), user["id"], "reset")
            send_otp(user["email"], user["full_name"], code)
            flash("A new code has been sent.", "success")
        return redirect(url_for("reset_password"))

    # ----------------------------------------------------------- shared helpers
    def _unblock_and_resolve(ident):
        """Unblock a user and clear their failed login attempts. Returns True if user was found."""
        db().execute("UPDATE users SET blocked_at=NULL, block_reason=NULL "
                     "WHERE identifier=? OR lower(email)=lower(?)", (ident, ident))
        db().execute("UPDATE login_events SET result='resolved_attempt' "
                     "WHERE (identifier=? OR lower(identifier)=lower(?)) "
                     "AND result IN ('bad_password', 'bad_otp')", (ident, ident))
        db().execute("UPDATE alerts SET status='Resolved' "
                     "WHERE (user_identifier=? OR lower(user_identifier)=lower(?)) "
                     "AND status IN ('Open', 'Investigating')", (ident, ident))
        db().commit()

    def _admin_audit(action, detail=""):
        """Log an admin action for accountability."""
        admin_user = current_user()
        admin_ident = admin_user["identifier"] if admin_user else "unknown"
        database.add_alert(
            db(), f"Admin: {action}", "medium", admin_ident, client_ip(),
            detail or action, status="Resolved",
        )

    # ---------------------------------------------------------------- health
    @app.route("/health")
    def health_check():
        return jsonify({"status": "ok", "ts": time.time()})

    # ------------------------------------------------------------------ admin
    @app.route("/admin")
    def admin():
        if not is_admin_authenticated():
            flash("Admin access requires an administrator account that has completed sign-in.", "warning")
            return redirect(url_for("login"))
        q = lambda sql, *a: db().execute(sql, a).fetchone()[0]
        selected_day = max(0, min(int(request.args.get("day", "0") or 0), 6))
        start = time.time() - (selected_day + 1) * 86400
        end = start + 86400
        stats = {
            "total_users": q("SELECT COUNT(*) FROM users"),
            "active_sessions": q("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL"),
            "blocked": q("SELECT COUNT(*) FROM users WHERE blocked_at IS NOT NULL"),
            "flagged_sessions": q(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL AND risk>=?",
                app.config["RISK_STEP_UP"],
            ),
            "threats": q("SELECT COUNT(*) FROM alerts WHERE status IN ('Open', 'Investigating')"),
        }
        alerts = db().execute(
            "SELECT a.*, u.blocked_at AS user_blocked_at, u.block_reason AS user_block_reason "
            "FROM alerts a "
            "LEFT JOIN users u ON u.identifier = a.user_identifier OR lower(u.email) = lower(a.user_identifier) "
            "ORDER BY a.ts DESC LIMIT 20"
        ).fetchall()
        active_sessions = db().execute(
            "SELECT s.*, u.identifier, u.full_name, u.email, d.name AS device_name "
            "FROM sessions s JOIN users u ON u.id=s.user_id "
            "LEFT JOIN devices d ON d.id=s.device_id "
            "WHERE s.ended_at IS NULL ORDER BY s.started_at DESC LIMIT 25"
        ).fetchall()
        blocked_users = db().execute(
            "SELECT u.*, "
            "(SELECT COUNT(*) FROM login_events le WHERE (le.identifier=u.identifier OR le.user_id=u.id) AND le.result IN ('bad_password', 'bad_otp')) AS fail_count "
            "FROM users u WHERE u.blocked_at IS NOT NULL ORDER BY u.blocked_at DESC"
        ).fetchall()
        rows = db().execute(
            "SELECT CAST(strftime('%H', datetime(ts, 'unixepoch', 'localtime')) AS INTEGER) AS hour, COUNT(*) AS count "
            "FROM login_events WHERE ts>=? AND ts<? GROUP BY hour ORDER BY hour",
            (start, end),
        ).fetchall()
        by_hour = {r["hour"]: r["count"] for r in rows}
        activity = [{"hour": h, "label": f"{h:02d}:00", "count": by_hour.get(h, 0)} for h in range(24)]
        return render_template(
            "admin.html",
            stats=stats,
            alerts=alerts,
            metrics=model.metrics,
            labels=FEATURE_LABELS,
            admin=current_user(),
            active_sessions=active_sessions,
            blocked_users=blocked_users,
            activity=activity,
            selected_day=selected_day,
            risk_step_up=app.config["RISK_STEP_UP"],
            admin_session_id=session.get("sid"),
            now=time.time(),
        )

    @app.route("/admin/sessions/<int:sid>/kick", methods=["POST"])
    def admin_kick_session(sid):
        if not is_admin_authenticated():
            abort(403)
        row = db().execute(
            "SELECT s.*, u.identifier FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.ended_at IS NULL",
            (sid,),
        ).fetchone()
        if not row:
            return redirect(url_for("admin"))
        now = time.time()
        db().execute("UPDATE sessions SET ended_at=?, ended_by=?, end_reason=? WHERE id=?",
                     (now, "admin", "Removed by administrator", sid))
        db().commit()
        _admin_audit("Kicked session", f"Ended session #{sid} for user '{row['identifier']}', RF risk: {row['risk'] or 0:.0%}")
        flash("Device session ended.", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/alerts/<int:alert_id>/status", methods=["POST"])
    def admin_alert_status(alert_id):
        if not is_admin_authenticated():
            abort(403)
        raw_status = (request.form.get("status") or "").strip()
        action = (request.form.get("action") or "").strip()
        alert = db().execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not alert:
            abort(404)

        is_dismiss_or_unblock = (
            action == "unblock_now"
            or "dismiss" in raw_status.lower()
            or "unblock" in raw_status.lower()
        )
        if raw_status in ("Open", "Investigating", "Resolved"):
            new_status = raw_status
        elif is_dismiss_or_unblock:
            new_status = "Dismissed"
        else:
            abort(400)

        db().execute("UPDATE alerts SET status=? WHERE id=?", (new_status, alert_id))

        ident = alert["user_identifier"]
        if ident and (is_dismiss_or_unblock or new_status in ("Resolved", "Dismissed")):
            _unblock_and_resolve(ident)
            _admin_audit("Alert resolved + unblock", f"Alert #{alert_id} -> '{new_status}', unblocked '{ident}'")
            flash(f"Alert #{alert_id} updated to '{new_status}'. Account '{ident}' unblocked and failed login attempts resolved.", "success")
        else:
            db().commit()
            _admin_audit("Alert status change", f"Alert #{alert_id} -> '{new_status}'")
            flash(f"Alert #{alert_id} mitigation state updated to '{new_status}'.", "info")

        return redirect(url_for("admin"))

    @app.route("/admin/users/<ident>/unblock", methods=["POST"])
    def admin_unblock_user(ident):
        if not is_admin_authenticated():
            abort(403)
        _unblock_and_resolve(ident)
        _admin_audit("Unblocked user", f"Unblocked account '{ident}' and resolved failed attempts")
        flash(f"User account '{ident}' has been unblocked and failed login attempts resolved.", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/resolve-attempts", methods=["POST"])
    def admin_resolve_attempts():
        if not is_admin_authenticated():
            abort(403)
        ident = (request.form.get("identifier") or "").strip()
        if not ident:
            flash("User identifier required.", "warning")
            return redirect(url_for("admin"))
        _unblock_and_resolve(ident)
        _admin_audit("Resolved attempts", f"Cleared failed login attempts and lockout for '{ident}'")
        flash(f"Failed login attempts resolved and account lockout cleared for '{ident}'.", "success")
        return redirect(url_for("admin"))

    return app


def _ensure_admin(app):
    """Create an administrator on first run with a random password printed once."""
    conn = database.get_db()
    if conn.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        return
    password = secrets.token_urlsafe(9)
    conn.execute(
        "INSERT INTO users(identifier,email,full_name,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
        ("admin", "admin@example.com", "Portal Administrator", generate_password_hash(password), "admin", time.time()),
    )
    conn.commit()
    print("\n" + "=" * 62)
    print(" First run: administrator account created")
    print(f"   login:    admin")
    print(f"   password: {password}")
    print(" (shown once - the admin signs in through the normal portal, MFA included)")
    print("   Configure SMTP settings before using email verification with real users.")
    print("=" * 62 + "\n")


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
