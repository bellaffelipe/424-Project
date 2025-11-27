from flask import Flask, jsonify, make_response, request
import secrets
import time

app = Flask(__name__)

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
      
    return {"email": sess["email"]}
  
#temporary dev login route for testing purposes only - going to implement google oauth
@app.route("/dev/login", methods=["GET", "POST"])
def dev_login():
  sid = secrets.token_urlsafe(32)
  SESSIONS[sid] = {
    "email": "dev@campus.edu",
    "exp": time.time() + 1800
  }
  
  resp = make_response(jsonify({"ok": True}))
  set_secure_cookie(resp, sid)
  return resp

# CHECK WHO IS LOGGED IN
@app.route("/me", methods=["GET"])
def me():
  user = current_user()
  if not user:
    return jsonify({"error": "Unauthorized"}), 401
  return jsonify(user)

#INVALIDATE SESSION & CLEAR COOKIE
@app.route("/logout", methods=["GET", "POST"])
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