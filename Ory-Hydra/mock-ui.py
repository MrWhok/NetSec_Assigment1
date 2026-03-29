from flask import Flask, render_template, request, redirect
import requests
import os

app = Flask(__name__)

# Hydra Admin URL (Internal Docker name)
HYDRA_ADMIN_URL = os.getenv("HYDRA_ADMIN_URL", "http://hydra:4445")

@app.route('/login', methods=['GET'])
def login_get():
    # 1. Get the challenge from the URL
    challenge = request.args.get('login_challenge')
    
    # 2. Ask Hydra for details about this login request
    resp = requests.get(f"{HYDRA_ADMIN_URL}/admin/oauth2/auth/requests/login?login_challenge={challenge}")
    data = resp.json()

    # If user is already authenticated in Hydra, just skip to skip
    if data.get('skip'):
        return accept_login(challenge, data['subject'])

    return f'''
        <form method="post">
            <input type="hidden" name="challenge" value="{challenge}">
            Username: <input type="text" name="user"><br>
            Password: <input type="password" name="password"><br>
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/login', methods=['POST'])
def login_post():
    challenge = request.form.get('challenge')
    username = request.form.get('user')
    password = request.form.get('password')

    # --- THIS IS THE LDAP GAP ---
    # Right now: Hardcoded check.
    # Future: Use 'ldap3' library to check against Windows AD.
    if username == "admin" and password == "password":
        return accept_login(challenge, username)
    
    return "Invalid Credentials", 401

def accept_login(challenge, user_id):
    # 3. Tell Hydra the login was successful
    body = {
        "subject": user_id, # This becomes the 'sub' claim in the JWT
        "remember": True,
        "remember_for": 3600
    }
    resp = requests.put(
        f"{HYDRA_ADMIN_URL}/admin/oauth2/auth/requests/login/accept?login_challenge={challenge}",
        json=body
    )
    # 4. Hydra gives us a redirect URL to send the user back to Hydra
    return redirect(resp.json()['redirect_to'])

@app.route('/consent', methods=['GET'])
def consent():
    challenge = request.args.get('consent_challenge')
    
    # In a real app, you'd ask "Do you allow this app to see your email?"
    # Here, we just say YES to everything.
    body = {
        "grant_scope": ["openid", "offline", "profile", "email"],
        "remember": True,
        "remember_for": 3600,
    }
    resp = requests.put(
        f"{HYDRA_ADMIN_URL}/admin/oauth2/auth/requests/consent/accept?consent_challenge={challenge}",
        json=body
    )
    return redirect(resp.json()['redirect_to'])

if __name__ == "__main__":
    app.run(port=3000)