"""Fill the dashboard with sample operational data for local testing.

    python seed_sample.py          # add sample data
    python seed_sample.py --reset  # remove data created by this script

Sample users are named sample0001, sample0002, ... and cannot log in.
"""
import random
import secrets
import sys
import time

from werkzeug.security import generate_password_hash

import db as database
from app import create_app

TARGET_USERS, ACTIVE, BLOCKED, HIGH_ALERTS = 1248, 892, 27, 5
TYPES_HIGH = ["Blocked high-risk login", "Account lockout (brute force)", "OTP attempts exhausted"]
TYPES_MED = ["Suspicious login (step-up required)", "Multiple failed logins", "New location detected"]


def reset(conn):
    ids = [r[0] for r in conn.execute("SELECT id FROM users WHERE identifier LIKE 'sample%'")]
    for uid in ids:
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM login_events WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.execute("DELETE FROM alerts WHERE user_identifier LIKE 'sample%'")
    conn.commit()
    print(f"Removed {len(ids)} sample users and their data.")


def seed(conn):
    rng = random.Random(7)
    now = time.time()
    unusable = generate_password_hash(secrets.token_hex(16))
    have = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    existing = conn.execute("SELECT COUNT(*) FROM users WHERE identifier LIKE 'sample%'").fetchone()[0]
    need = max(0, TARGET_USERS - have)
    for i in range(existing + 1, existing + need + 1):
        conn.execute(
            "INSERT INTO users(identifier,email,full_name,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
            (
                f"sample{i:04d}",
                f"sample{i:04d}@example.com",
                f"Sample User {i}",
                unusable,
                "user",
                now - rng.randint(0, 90) * 86400,
            ),
        )
    users = [(r[0], r[1]) for r in conn.execute("SELECT id, identifier FROM users WHERE identifier LIKE 'sample%'")]
    ids = [u[0] for u in users]
    for uid in rng.sample(ids, min(ACTIVE, len(ids))):
        conn.execute(
            "INSERT INTO sessions(user_id,ip,started_at) VALUES (?,?,?)",
            (uid, f"10.20.{rng.randint(0, 20)}.{rng.randint(2, 250)}", now - rng.randint(60, 8 * 3600)),
        )
    for _ in range(BLOCKED):
        uid, ident = rng.choice(users)
        conn.execute(
            "INSERT INTO login_events(user_id,identifier,ts,ip,result,decision,outcome,risk,hour,time_label)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                uid,
                ident,
                now - rng.randint(300, 86000),
                f"196.45.{rng.randint(1, 250)}.{rng.randint(2, 250)}",
                "assessed",
                "block",
                "denied",
                round(rng.uniform(0.86, 0.99), 3),
                3,
                "03:15",
            ),
        )
    for n in range(HIGH_ALERTS + 8):
        high = n < HIGH_ALERTS
        database.add_alert(
            conn,
            rng.choice(TYPES_HIGH if high else TYPES_MED),
            "high" if high else "medium",
            rng.choice(users)[1],
            f"196.45.{rng.randint(1, 250)}.{rng.randint(2, 250)}",
            "sample data",
            ts=now - rng.randint(300, 80000),
            status=rng.choice(["Open", "Open", "Investigating", "Resolved"]),
        )
    conn.commit()
    print(
        f"Seeded: {conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]} users, "
        f"{conn.execute('SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL').fetchone()[0]} active sessions."
    )


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        conn = database.get_db()
        reset(conn) if "--reset" in sys.argv else seed(conn)
