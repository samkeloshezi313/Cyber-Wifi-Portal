"""Turn a login attempt + the user's history into the Random Forest's inputs.

Deliberately NOT used as features: MAC addresses. They are trivially spoofed and
modern phones randomise them per network, so a "registered MAC" is not a reliable
identity. Devices are recognised by a random token stored in an HttpOnly cookie
(only its hash is kept in the database).
"""
import time
from datetime import datetime

MIN_HISTORY = 3          # successful logins needed before "usual" hours/networks mean anything
NEUTRAL = 0.3            # value used while a profile is still being built


def ip_prefix(ip: str) -> str:
    if ":" in ip:                                   # IPv6: first 4 groups
        return ":".join(ip.split(":")[:4])
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def _hour_distance(a: int, b: int) -> int:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def count_failures(db, identifier: str, minutes: int, now: float | None = None) -> int:
    now = now or time.time()
    return db.execute(
        "SELECT COUNT(*) FROM login_events WHERE identifier=? AND result='bad_password' AND ts>=?",
        (identifier, now - minutes * 60),
    ).fetchone()[0]


def device_trust_score(db, device_id: int) -> float:
    n = db.execute(
        "SELECT COUNT(*) FROM login_events WHERE device_id=? AND outcome='granted'", (device_id,)
    ).fetchone()[0]
    return min(1.0, 0.5 + 0.05 * n)


def build_features(db, user, device, ip, now, tz, cfg, sim_hour=None, sim_new_location=False):
    """Return (features, checks, context).

    features: dict fed to the model
    checks:   list of human-readable results for the "Checking your connection" screen
    context:  values stored with the event / shown on the suspicious-login screen
    """
    dt = datetime.fromtimestamp(now, tz)
    hour = dt.hour if sim_hour in (None, "") else int(sim_hour)
    time_label = f"{hour:02d}:{dt.minute:02d}"
    prefix = ip_prefix(ip)

    history = db.execute(
        "SELECT hour, ip_prefix FROM login_events WHERE user_id=? AND outcome='granted'",
        (user["id"],),
    ).fetchall()
    n = len(history)

    # 1) login time frequency
    if n < MIN_HISTORY:
        time_rarity = NEUTRAL
    else:
        near = sum(1 for r in history if _hour_distance(r["hour"], hour) <= 1)
        time_rarity = round(1 - near / n, 3)

    # 2) location anomaly
    known = {r["ip_prefix"] for r in history}
    if sim_new_location:
        location_anomaly, location_label = 1.0, "Unfamiliar network"
    elif n < MIN_HISTORY:
        location_anomaly, location_label = NEUTRAL, "Not enough history yet"
    elif prefix in known:
        location_anomaly, location_label = 0.0, "Usual network"
    else:
        location_anomaly, location_label = 1.0, "New network"

    # 3) failed logins in the recent window
    failed = count_failures(db, user["identifier"], cfg["FAILED_WINDOW_MINUTES"], now)

    # 4) device trust
    trust = device_trust_score(db, device["id"])

    # 5) login velocity (this attempt + assessed attempts in last 10 minutes)
    recent = db.execute(
        "SELECT COUNT(*) FROM login_events WHERE user_id=? AND result='assessed' AND ts>=?",
        (user["id"], now - 600),
    ).fetchone()[0]
    velocity = 1 + recent

    features = {
        "time_rarity": float(time_rarity),
        "failed_attempts": float(min(failed, 8)),
        "device_trust": float(round(trust, 3)),
        "location_anomaly": float(location_anomaly),
        "login_velocity": float(min(velocity, 9)),
    }

    checks = [
        {
            "key": "location", "label": "Location check",
            "status": "ok" if location_anomaly < 0.5 else "bad",
            "detail": location_label,
        },
        {
            "key": "device", "label": "Device check",
            "status": "ok" if trust >= 0.7 else "warn",
            "detail": device["name"] + ("" if trust >= 0.7 else " (recently registered)"),
        },
        {
            "key": "time", "label": "Login time analysis",
            "status": "ok" if time_rarity < 0.5 else "warn",
            "detail": f"{time_label}" + ("" if time_rarity < 0.5 else " is unusual for this account"),
        },
        {
            "key": "behaviour", "label": "Behaviour pattern",
            "status": "ok" if failed <= 1 and velocity <= 2 else ("bad" if failed >= 3 else "warn"),
            "detail": f"{failed} failed attempt(s), {velocity} login(s) in 10 min",
        },
    ]
    context = {
        "hour": hour,
        "time_label": time_label,
        "ip_prefix": prefix,
        "location_label": location_label,
        "failed": int(failed),
    }
    return features, checks, context
