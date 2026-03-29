from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'secret'

oauth = OAuth(app)

oauth.register(
    name='keycloak',
    client_id='web-app',
    client_secret='JaX1JKaSFCncTrGdgDaYhJldSMuEceSA', # harusny di env aowkoakoakaokaok cuek
    server_metadata_url='http://20.194.14.146:8081/realms/Assignment1/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

@app.route('/')
def home():
    return '<a href="/login">Login</a>'

@app.route('/login')
def login():
    return oauth.keycloak.authorize_redirect('http://20.194.14.146:5000/callback')

@app.route('/callback')
def callback():
    token = oauth.keycloak.authorize_access_token()
    user = token['userinfo']
    return f"""
    <h1>Profile</h1>
    <p>Username: {user['preferred_username']}</p>
    <p>Email: {user['email']}</p>
    """

app.run(port=5000,host="0.0.0.0")