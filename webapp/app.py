from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os
import urllib3
urllib3.disable_warnings()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'secret')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'web-app')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', '')
KEYCLOAK_SERVER_METADATA_URL = os.getenv(
    'KEYCLOAK_SERVER_METADATA_URL',
    'http://123.456.78.90:8080/realms/master/.well-known/openid-configuration'
)
KEYCLOAK_SCOPE = os.getenv('KEYCLOAK_SCOPE', 'openid profile email')
KEYCLOAK_VERIFY_TLS = os.getenv('KEYCLOAK_VERIFY_TLS', 'false').lower() == 'true'
KEYCLOAK_CALLBACK_URL = os.getenv('KEYCLOAK_CALLBACK_URL', 'http://123.456.78.90:5000/callback')
APP_PORT = int(os.getenv('APP_PORT', '5000'))
APP_HOST = os.getenv('APP_HOST', '0.0.0.0')

oauth = OAuth(app)

oauth.register(
    name='keycloak',
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=KEYCLOAK_CLIENT_SECRET,
    server_metadata_url=KEYCLOAK_SERVER_METADATA_URL,
    client_kwargs={'scope': KEYCLOAK_SCOPE, 'verify': KEYCLOAK_VERIFY_TLS}
)

@app.route('/')
def home():
    return '<a href="/login">Login</a>'

@app.route('/login')
def login():
    return oauth.keycloak.authorize_redirect(KEYCLOAK_CALLBACK_URL)

@app.route('/callback')
def callback():
    token = oauth.keycloak.authorize_access_token()
    user = token['userinfo']
    return f"""
    <h1>Profile</h1>
    <p>Username: {user.get('preferred_username', 'N/A')}</p>
    <p>Email: {user.get('email', 'N/A')}</p>
    <p>Name: {user.get('name', 'N/A')}</p>
    """

app.run(port=APP_PORT, host=APP_HOST)