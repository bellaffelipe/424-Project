from flask import Flask, jsonify, make_response, request, redirect
import secrets, time, os
from urllib.parse import urlencode

from dotenv import load_dotenv
import requests #needed to call google oauth token endpoint
from google.oauth2 import id_token # validate google id tokens
from google.auth.transport import requests as grequests

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
FRONTEND_AFTER_LOGIN = os.getenv("FRONTEND_AFTER_LOGIN", "https://127.0.0.1:5000/me")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://127.0.0.1:5173")

app = Flask(__name__)

#set secret key for session signing not for login session
app.config["SECRET_KEY"] = os.getenv("SESSION_SECRET", secrets.token_hex(16))

SESSIONS = {} # in-memory session store--for development only
SESSION_COOKIE_NAME = "campushub.sid" # name of the session cookie that stores the session ID
NOTES = [] # each element is {id, owner id, content}
NEXT_NOTE_ID = 1

#HELPER THAT SETS A SECURE SESSION COOKIE
def set_secure_cookie(resp, sid, max_age=1800):
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        sid,
        max_age=max_age, #cookie expires in 30 minutes
        httponly=True, #not accessible via JavaScript so prevents XSS
        secure=True, #only sent over HTTPS
        samesite="None",
        path="/", #cookie is sent for all paths
    )
  
#HELPER THAT GETS THE CURRENT USER BASED ON THE SESSION COOKIE  
def current_user():
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid:
      return None
    
    sess = SESSIONS.get(sid)
    if not sess:
        return None
      
    if sess["exp"] < time.time():
        SESSIONS.pop(sid, None) #remove expired session
        return None
      
    return {
      "email": sess["email"],
      "name": sess.get("name"),
      "google_id": sess.get("google_id"),
    }
  
#route for google oauth
@app.route("/login/google", methods=["GET"])
def login_google():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline", #enables refresh tokens
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params))

# route for google aout callback- where google sends user 
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

  #verify the id token
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
        "exp": time.time() + 1800, #expires in 30 mins
    }
    #attach session cookie and redirect
    resp = make_response(redirect(FRONTEND_AFTER_LOGIN))
    set_secure_cookie(resp, sid)
    return resp

#who is logged in
@app.route("/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(user)
  
#INVALIDATE SESSION & CLEAR COOKIE
@app.route("/logout")
def logout():
  sid = request.cookies.get(SESSION_COOKIE_NAME)
  if sid in SESSIONS:
    SESSIONS.pop(sid, None)
  
  #clears the cookie in browser
  resp = make_response(jsonify({"ok": True}))
  resp.set_cookie(SESSION_COOKIE_NAME, "", expires=0, path="/")
  return resp

def generate_csrf(session):
    token = secrets.token_hex(32)
    session["csrf"] = token
    return token

@app.route("/csrf", methods = ["GET"])
def get_csrf():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    sid = request.cookies.get(SESSION_COOKIE_NAME)
    sess = SESSIONS[sid]
    token = generate_csrf(sess)
    return jsonify({"csrf_token": token})

def require_csrf():
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid or sid not in SESSIONS:
        return False
    
    sess = SESSIONS[sid]
    sent = request.headers.get("x-csrf-token")

    if not sent or "csrf" not in sess or sent != sess["csrf"]:
        return False
    return True

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

    data = request.get_json()
    content = data.get("content", "")

    # simple validation
    if len(content) > 1000:
        return jsonify({"error": "Note too long"}), 400

    new_note = {
        "id": NEXT_NOTE_ID,
        "owner_id": user["google_id"],
        "content": content,
    }
    NOTES.append(new_note)
    NEXT_NOTE_ID += 1

    return jsonify(new_note), 201

@app.route("/api/notes/<int:note_id>", methods=["PUT"])
def update_note(note_id):
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if not require_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 403

    data = request.get_json()
    content = data.get("content", "")

    for note in NOTES:
        if note["id"] == note_id:
            if note["owner_id"] != user["google_id"]:
                return jsonify({"error": "Forbidden"}), 403
            note["content"] = content
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
            return jsonify({"ok": True})

    return jsonify({"error": "Not found"}), 404

#RUN THE APP USING HTTPS
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
        ssl_context=("cert.pem", "key.pem"), #our local self-signed certs
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
