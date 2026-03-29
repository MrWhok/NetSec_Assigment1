from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
app.secret_key = 'secret'

oauth = OAuth(app)

oauth.register(
    name='ory_hydra', 
    client_id='96c9a364-e39b-49d5-854a-dce591e151e2', # NOTE: DAPETIN DARI HYDRA CLI PAKE SCRIPT SHELL YG ADA
    client_secret='FHObD3N74HhZgPk48Ynv5kBMaW', # NOTE: SAMA
    server_metadata_url='http://hydra:4444/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

@app.route('/')
def home():
    return '<a href="/login">Login</a>'

@app.route('/login')
def login():
    # 2. Use 'ory_hydra' (the name from register) and localhost for your redirect
    redirect_uri = url_for('callback', _external=True)
    return oauth.ory_hydra.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    # 3. Use 'ory_hydra' here as well
    token = oauth.ory_hydra.authorize_access_token()
    
    # NOTE: Hydra's default 'userinfo' usually uses 'sub' for the user ID. 
    # 'preferred_username' might not be there unless your Mock UI specifically sends it.
    user = token.get('userinfo')
    return f"""
    <h1>Profile</h1>
    <p>User ID (Subject): {user.get('sub')}</p>
    <p>Email: {user.get('email', 'No email provided')}</p>
    <hr>
    <a href="/">Home</a>
    """

if __name__ == "__main__":
    # Ensure this matches the port in your redirect_uri (5000)
    app.run(port=5000, host="0.0.0.0")