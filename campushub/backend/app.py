from flask import Flask, jsonify, make_response, request, redirect
from dotenv import load_dotenv
from urllib.parse import urlencode
from google.oauth2 import id_token  # validate Google ID tokens
from google.auth.transport import requests as grequests
from collections import defaultdict
import secrets
import time
import os
import requests  # needed to call Google OAuth token endpoint
import logging

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
FRONTEND_AFTER_LOGIN = os.getenv(
    "FRONTEND_AFTER_LOGIN",
    "https://127.0.0.1:5173/",
)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://127.0.0.1:5173")

app = Flask(__name__)

# secret key for signing cookies (not for login itself)
app.config["SECRET_KEY"] = os.getenv("SESSION_SECRET", secrets.token_hex(16))

# In-memory stores (dev only)
SESSIONS = {}  # sid -> {email, name, google_id, exp, csrf?}
SESSION_COOKIE_NAME = "campushub.sid"
NOTES = []  # each element is {id, owner_id, content}
NEXT_NOTE_ID = 1

# In-memory rate limiting (per IP + path)
RATE_LIMIT_WINDOW = 10        # seconds (kept small for testing)
RATE_LIMIT_MAX_REQUESTS = 5   # max requests per window
_REQUEST_LOG = defaultdict(list)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# --------------------------
# Helpers
# --------------------------


def set_secure_cookie(resp, sid, max_age=1800):
    """Set a secure, HTTP-only session cookie."""
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        sid,
        max_age=max_age,   # cookie expires in 30 minutes
        httponly=True,     # not accessible to JS (prevents XSS theft)
        secure=True,       # only sent over HTTPS
        samesite="None",   # allow cross-site for frontend on different port
        path="/",
    )


def current_user():
    """Return current user dict based on session cookie, or None."""
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid:
        return None

    sess = SESSIONS.get(sid)
    if not sess:
        return None

    if sess["exp"] < time.time():
        # session expired
        SESSIONS.pop(sid, None)
        return None

    return {
        "email": sess["email"],
        "name": sess.get("name"),
        "google_id": sess.get("google_id"),
    }


def generate_csrf(session):
    token = secrets.token_hex(32)
    session["csrf"] = token
    return token


def require_csrf():
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid or sid not in SESSIONS:
        return False

    sess = SESSIONS[sid]
    sent = request.headers.get("x-csrf-token")

    if not sent or "csrf" not in sess or sent != sess["csrf"]:
        return False
    return True


# --------------------------
# Rate limiting
# --------------------------

@app.before_request
def apply_rate_limit():
    # Skip static files (if any)
    path = request.path
    if path.startswith("/static"):
        return

    ip = request.remote_addr or "unknown"
    key = f"{ip}:{path}"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    timestamps = _REQUEST_LOG[key]
    # keep only timestamps inside the window
    timestamps = [t for t in timestamps if t >= window_start]
    _REQUEST_LOG[key] = timestamps

    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        logging.warning("Rate limit exceeded for IP=%s path=%s", ip, path)
        return jsonify({"error": "Too many requests"}), 429

    # record this request
    timestamps.append(now)

# CSRF token endpoint
@app.route("/csrf", methods=["GET"])
def get_csrf():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    sid = request.cookies.get(SESSION_COOKIE_NAME)
    sess = SESSIONS[sid]
    token = generate_csrf(sess)
    return jsonify({"csrf_token": token})

# Auth routes (Google OAuth)
@app.route("/login/google", methods=["GET"])
def login_google():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",  # enables refresh tokens
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params))


@app.route("/oauth/callback", methods=["GET"])
def oauth_callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Missing code"}), 400

    # exchange code for tokens
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    tok = requests.post("https://oauth2.googleapis.com/token", data=token_data).json()

    if "id_token" not in tok:
        return jsonify({"error": "No ID token returned", "details": tok}), 400

    # verify the id token
    try:
        claims = id_token.verify_oauth2_token(
            tok["id_token"],
            grequests.Request(),
            GOOGLE_CLIENT_ID,
        )
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 400

    # create user session
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = {
        "email": claims.get("email"),
        "name": claims.get("name"),
        "google_id": claims.get("sub"),
        "exp": time.time() + 1800,  # expires in 30 mins
    }

    logging.info("LOGIN success email=%s google_id=%s", claims.get("email"), claims.get("sub"))

    # attach session cookie and redirect
    resp = make_response(redirect(FRONTEND_AFTER_LOGIN))
    set_secure_cookie(resp, sid)
    return resp


@app.route("/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(user)

# INVALIDATE SESSION & CLEAR COOKIE
@app.route("/logout")
def logout():
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    sess = SESSIONS.pop(sid, None) if sid in SESSIONS else None

    logging.info("LOGOUT email=%s", (sess or {}).get("email"))

    # clears the cookie in browser
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(SESSION_COOKIE_NAME, "", expires=0, path="/")
    return resp

# Notes API (CRUD)
@app.route("/api/notes", methods=["GET"])
def get_notes():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = user["google_id"]
    user_notes = [n for n in NOTES if n["owner_id"] == user_id]
    return jsonify(user_notes)


@app.route("/api/notes", methods=["POST"])
def create_note():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if not require_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    global NEXT_NOTE_ID

    data = request.get_json() or {}
    content = (data.get("content") or "").strip()

    if not content:
        return jsonify({"error": "Content is required"}), 400

    if len(content) > 1000:
        return jsonify({"error": "Note too long"}), 400

    new_note = {
        "id": NEXT_NOTE_ID,
        "owner_id": user["google_id"],
        "content": content,
    }
    NOTES.append(new_note)
    NEXT_NOTE_ID += 1

    logging.info(
        "NOTE CREATE user=%s google_id=%s note_id=%s",
        user["email"],
        user["google_id"],
        new_note["id"],
    )

    return jsonify(new_note), 201


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
def update_note(note_id):
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if not require_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    data = request.get_json() or {}
    content = (data.get("content") or "").strip()

    if not content:
        return jsonify({"error": "Content is required"}), 400

    if len(content) > 1000:
        return jsonify({"error": "Note too long"}), 400

    for note in NOTES:
        if note["id"] == note_id:
            if note["owner_id"] != user["google_id"]:
                return jsonify({"error": "Forbidden"}), 403
            note["content"] = content

            logging.info(
                "NOTE UPDATE user=%s google_id=%s note_id=%s",
                user["email"],
                user["google_id"],
                note_id,
            )

            return jsonify(note)

    return jsonify({"error": "Not found"}), 404


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if not require_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    for i, note in enumerate(NOTES):
        if note["id"] == note_id:
            if note["owner_id"] != user["google_id"]:
                return jsonify({"error": "Forbidden"}), 403

            NOTES.pop(i)

            logging.info(
                "NOTE DELETE user=%s google_id=%s note_id=%s",
                user["email"],
                user["google_id"],
                note_id,
            )

            return jsonify({"ok": True})

    return jsonify({"error": "Not found"}), 404

# Security headers + CORS
@app.after_request
def apply_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"

    # --- CORS for frontend on 127.0.0.1:5173 ---
    origin = request.headers.get("Origin")
    if origin == FRONTEND_ORIGIN:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, x-csrf-token"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        resp.headers["Vary"] = "Origin"
    return resp


if __name__ == "__main__":
    app.run(
        ssl_context=("cert.pem", "key.pem"),  # our local self-signed certs
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
