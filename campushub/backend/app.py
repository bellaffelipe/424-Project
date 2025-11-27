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

app = Flask(__name__)

#set secret key for session signing not for login session
app.config["SECRET_KEY"] = os.getenv("SESSION_SECRET", secrets.token_hex(16))

SESSIONS = {} # in-memory session store--for development only
SESSION_COOKIE_NAME = "campushub.sid" # name of the session cookie that stores the session ID

#HELPER THAT SETS A SECURE SESSION COOKIE
def set_secure_cookie(resp, sid, max_age=1800):
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        sid,
        max_age=max_age, #cookie expires in 30 minutes
        httponly=True, #not accessible via JavaScript so prevents XSS
        secure=True, #only sent over HTTPS
        samesite='Lax', #prevents CSRF in most cases
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

#RUN THE APP USING HTTPS
if __name__ == "__main__":
    app.run(
        ssl_context=("cert.pem", "key.pem"), #our local self-signed certs
        host="127.0.0.1",
        port=5000,
        debug=True,
    )