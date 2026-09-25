# Risk-Based Adaptive Wi-Fi Captive Portal

Flask + SQLite + Tailwind CSS, with a **scikit-learn Random Forest** (`RandomForestClassifier`)
that scores every login and decides whether to let the user in, ask for an extra OTP, or block.

## Run it

```bash
python -m venv venv
venv\Scripts\activate          # Windows   (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
python app.py                  # open http://localhost:5000
```

* First run trains the Random Forest (a few seconds) and creates an **admin** account. Its password is
  printed **once** in the terminal.
* The pages load Tailwind from its CDN, so the browser needs internet access.
* Configure `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_FROM` before using email OTPs with real users.
  Without SMTP, OTPs are written only to the local server log.

## Try the flow

1. **Sign Up**, then **Login**.
2. **Step 2 Device Registration**: new browser/device is registered (a random token is stored in an HttpOnly cookie).
3. **Step 3 MFA**: 6-digit email OTP.
4. **Step 4 Security Check**: the Random Forest scores the login (`/api/risk-assess`).
5. **Step 5** one of:
   * **Access Granted**: green badge, session details, *Continue to Wi-Fi*.
   * **Suspicious Login Detected**: red banner, breakdown, *Send OTP / Verify Identity* (step-up).
   * Blocked (very high risk): same screen without the OTP button.

Return logins from a registered device skip steps 2 and 3 and only get an OTP when the model says the login is risky
(that is the "adaptive" part). Log in as `admin`, finish the flow, then open the dashboard from the granted/connected page.

Optional test controls can be enabled with `SHOW_TEST_CONTROLS=1` in a controlled environment.

## Decision policy

| Random Forest P(suspicious) | Action |
|---|---|
| below 0.40 | Allow |
| 0.40 to 0.85 | Step-up OTP (skipped if the user just entered an OTP to register the device) |
| 0.85 or above | Block and raise a high-severity alert |

Change with `RISK_STEP_UP` / `RISK_BLOCK` (environment variables or `config.py`).

## Model inputs (`features.py`)

| Feature | Meaning |
|---|---|
| `time_rarity` | How unusual this hour is for this user (login time frequency) |
| `failed_attempts` | Failed logins for the account in the last 15 minutes |
| `device_trust` | 0.5 for a newly registered device, rising with successful use |
| `location_anomaly` | Whether the /24 network has been seen in this user's granted logins |
| `login_velocity` | Logins in the last 10 minutes |

**MAC addresses are deliberately not used.** They are easy to spoof and phones randomise them per network.

## Files

```
app.py            routes and the login state machine
ml_engine.py      Random Forest training, saving, prediction
features.py       builds model inputs from login history
utils.py          OTP, password rules, device parsing, email
db.py, config.py  SQLite schema, settings
train_model.py    retrain and print metrics
seed_sample.py    optional sample data for dashboard testing
templates/        login, device, mfa, checking, granted, suspicious, connected, admin
```

## Security measures included

Password hashing (scrypt), OTPs stored only as HMACs with 5-minute expiry, 5 attempts and 60 s resend cooldown,
account lockout after 8 failures in 15 minutes, CSRF tokens on every POST, server-side stage checks (steps can't be skipped),
constant-time-ish handling of unknown usernames, security headers, admin access only after the full MFA flow.

## Deployment Notes

* The initial Random Forest model is bootstrapped from generated behavioural data. Retrain with real, labelled logs
  before treating scores as production security evidence.
* **Location** is the network prefix, not GPS or geo-IP.
* **Email OTP** requires SMTP settings for real delivery.
* **No real network enforcement yet.** *Continue to Wi-Fi* only records a session. A real deployment must call your
  controller/RADIUS/firewall (UniFi, MikroTik, CoovaChilli, pfSense...) to authorise the client, and should run over HTTPS
  with WPA2/WPA3-Enterprise so the portal can't be cloned by an evil-twin access point.
* Personal data (IP, device, location, login times) is processed: plan consent, retention and access controls (POPIA).
