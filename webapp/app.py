from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import json
import os
from pathlib import Path
import urllib3
from dotenv import load_dotenv
urllib3.disable_warnings()

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'secret')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'web-app')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', '')
KEYCLOAK_SERVER_METADATA_URL = os.getenv(
    'KEYCLOAK_SERVER_METADATA_URL',
    'https://20.194.14.146:8443/auth/realms/master/.well-known/openid-configuration'
)
KEYCLOAK_SCOPE = os.getenv('KEYCLOAK_SCOPE', 'openid profile email')
KEYCLOAK_VERIFY_TLS = os.getenv('KEYCLOAK_VERIFY_TLS', 'false').lower() == 'true'
KEYCLOAK_CALLBACK_URL = os.getenv('KEYCLOAK_CALLBACK_URL', 'http://20.194.14.146:5000/callback')
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

    id_token_claims = {}
    parse_error = None
    if token.get('id_token'):
        try:
            id_token_claims = oauth.keycloak.parse_id_token(token)
        except Exception as err:
            parse_error = str(err)

    user = id_token_claims or token.get('userinfo', {})

    claims_json = json.dumps(id_token_claims, indent=2, ensure_ascii=False) if id_token_claims else '{}'
    token_json = json.dumps(token, indent=2, ensure_ascii=False)

    return f"""
    <h1>Profile</h1>
    <p>Username: {user.get('preferred_username', 'N/A')}</p>
    <p>Email: {user.get('email', 'N/A')}</p>
    <p>Name: {user.get('name', 'N/A')}</p>
    <h2>ID Token Claims (JWT Payload)</h2>
    <pre>{claims_json}</pre>
    <h2>Token Response (Semua Data Diterima)</h2>
    <pre>{token_json}</pre>
    <p style="color: red;">{f'Gagal parse id_token: {parse_error}' if parse_error else ''}</p>
    """

app.run(port=APP_PORT, host=APP_HOST)