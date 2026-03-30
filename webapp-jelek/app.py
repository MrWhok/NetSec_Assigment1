from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
from html import escape
import json
import os
import base64
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'secret')

APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = int(os.getenv('APP_PORT', '5000'))

OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID', 'f141f76a-7b93-4789-bec4-821b89a14510')
OIDC_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET', 'BRHaJamex1W_8b5iuf3H_x_rne')
OIDC_SCOPE = os.getenv('OIDC_SCOPE', 'openid profile email')
OIDC_CALLBACK_URL = os.getenv('OIDC_CALLBACK_URL', 'http://localhost:5000/callback')
OIDC_ISSUER = os.getenv('OIDC_ISSUER', 'http://127.0.0.1:4444')
OIDC_AUTHORIZATION_ENDPOINT = os.getenv('OIDC_AUTHORIZATION_ENDPOINT', 'http://127.0.0.1:4444/oauth2/auth')
OIDC_TOKEN_ENDPOINT = os.getenv('OIDC_TOKEN_ENDPOINT', 'http://hydra:4444/oauth2/token')
OIDC_USERINFO_ENDPOINT = os.getenv('OIDC_USERINFO_ENDPOINT', 'http://hydra:4444/userinfo')
OIDC_JWKS_URI = os.getenv('OIDC_JWKS_URI', 'http://hydra:4444/.well-known/jwks.json')

oauth = OAuth(app)

OIDC_METADATA = {
    'issuer': OIDC_ISSUER,
    'authorization_endpoint': OIDC_AUTHORIZATION_ENDPOINT,
    'token_endpoint': OIDC_TOKEN_ENDPOINT,
    'userinfo_endpoint': OIDC_USERINFO_ENDPOINT,
    'jwks_uri': OIDC_JWKS_URI,
}


def _get_nonce_from_session():
    for key, value in session.items():
        if key.startswith('_state_ory_hydra_') and isinstance(value, dict):
            nonce = value.get('data', {}).get('nonce')
            if nonce:
                return nonce
    return None


def _decode_jwt_payload_unverified(token_str):
    try:
        parts = token_str.split('.')
        if len(parts) != 3:
            return {}
        payload = parts[1]
        payload += '=' * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode('utf-8'))
        return json.loads(decoded.decode('utf-8'))
    except Exception:
        return {}


oauth.register(
    name='ory_hydra', 
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,
    authorize_url=OIDC_AUTHORIZATION_ENDPOINT,
    access_token_url=OIDC_TOKEN_ENDPOINT,
    userinfo_endpoint=OIDC_USERINFO_ENDPOINT,
    server_metadata=OIDC_METADATA,
    client_kwargs={'scope': OIDC_SCOPE}
)

@app.route('/')
def home():
    return '<a href="/login">Login</a>'

@app.route('/login')
def login():
    redirect_uri = OIDC_CALLBACK_URL
    return oauth.ory_hydra.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    if request.args.get('error'):
        return f"OAuth error: {request.args.get('error_description', request.args.get('error'))}", 400

    original_parse_id_token = oauth.ory_hydra.parse_id_token
    oauth.ory_hydra.parse_id_token = lambda *args, **kwargs: {}
    try:
        token = oauth.ory_hydra.authorize_access_token()
    except Exception as err:
        return f"OAuth token exchange error: {err}", 400
    finally:
        oauth.ory_hydra.parse_id_token = original_parse_id_token

    id_token_claims = {}
    parse_error = None
    if token.get('id_token'):
        nonce = _get_nonce_from_session()
        oauth.ory_hydra.server_metadata = OIDC_METADATA
        setattr(oauth.ory_hydra, '_server_metadata', OIDC_METADATA)
        try:
            id_token_claims = original_parse_id_token(token, nonce=nonce)
        except Exception as err:
            parse_error = str(err)
            id_token_claims = _decode_jwt_payload_unverified(token.get('id_token', ''))
            if id_token_claims:
                if 'Missing "jwks_uri" in metadata' in parse_error:
                    parse_error = None
                else:
                    parse_error = f"{parse_error} (menampilkan payload JWT tanpa verifikasi signature)"

    userinfo_claims = {}
    try:
        userinfo_claims = dict(oauth.ory_hydra.userinfo(token=token))
    except Exception:
        userinfo_claims = token.get('userinfo', {}) if isinstance(token.get('userinfo', {}), dict) else {}

    if not userinfo_claims and id_token_claims:
        userinfo_claims = dict(id_token_claims)

    token['userinfo'] = userinfo_claims

    user = id_token_claims or userinfo_claims

    claims_json = json.dumps(id_token_claims, indent=2, ensure_ascii=False) if id_token_claims else '{}'
    userinfo_json = json.dumps(userinfo_claims, indent=2, ensure_ascii=False) if userinfo_claims else '{}'
    token_json = json.dumps(token, indent=2, ensure_ascii=False)

    return f"""
    <h1>Profile</h1>
    <p>Username: {escape(str(user.get('preferred_username', 'N/A')))}</p>
    <p>Email: {escape(str(user.get('email', 'N/A')))}</p>
    <p>Name: {escape(str(user.get('name', 'N/A')))}</p>
    <h2>ID Token Claims (JWT Payload)</h2>
    <pre>{escape(claims_json)}</pre>
    <h2>Userinfo Claims</h2>
    <pre>{escape(userinfo_json)}</pre>
    <h2>Token Response (Semua Data Diterima)</h2>
    <pre>{escape(token_json)}</pre>
    <p style="color: red;">{escape(f'Gagal parse id_token: {parse_error}' if parse_error else '')}</p>
    """

if __name__ == "__main__":
    app.run(port=APP_PORT, host=APP_HOST)