from flask import Flask, request, redirect
import requests
import os
import uuid
import ssl
from urllib.parse import urlparse
from ldap3 import Server, Connection, ALL, SUBTREE, LEVEL, Tls

app = Flask(__name__)

# Hydra Admin URL (Internal Docker name)
HYDRA_ADMIN_URL = os.getenv("HYDRA_ADMIN_URL", "http://hydra:4445")
LDAP_URI = os.getenv("LDAP_URI", "ldaps://openldap:636")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=lab,dc=local")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "cn=admin,dc=lab,dc=local")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "adminpassword")
LDAP_USER_SEARCH_BASE = os.getenv("LDAP_USER_SEARCH_BASE", LDAP_BASE_DN)
LDAP_USERNAME_ATTRIBUTE = os.getenv("LDAP_USERNAME_ATTRIBUTE", "sAMAccountName")
LDAP_UUID_ATTRIBUTE = os.getenv("LDAP_UUID_ATTRIBUTE", "objectGUID")
LDAP_USER_OBJECT_CLASS = os.getenv("LDAP_USER_OBJECT_CLASS", "user")
LDAP_SEARCH_SCOPE = os.getenv("LDAP_SEARCH_SCOPE", "LEVEL").upper()
LDAP_USER_FILTER = os.getenv("LDAP_USER_FILTER", "")
LDAP_SKIP_TLS_VERIFY = os.getenv("LDAP_SKIP_TLS_VERIFY", "true").lower() == "true"
LDAP_UPN_SUFFIX = os.getenv("LDAP_UPN_SUFFIX", "lab.local")


def build_identity(username):
    normalized = (username or "").strip().lower()
    subject = str(uuid.uuid5(uuid.NAMESPACE_URL, f"netsec-demo:{normalized}"))
    return {
        "subject": subject,
        "preferred_username": normalized,
        "email": f"{normalized}@example.local" if normalized else None,
        "name": normalized,
    }


def _ldap_server():
    parsed = urlparse(LDAP_URI)
    host = parsed.hostname or LDAP_URI.replace("ldaps://", "").replace("ldap://", "")
    port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
    use_ssl = parsed.scheme == "ldaps"
    verify_mode = ssl.CERT_NONE if LDAP_SKIP_TLS_VERIFY else ssl.CERT_REQUIRED
    tls = Tls(validate=verify_mode)
    return Server(host, port=port, get_info=ALL, use_ssl=use_ssl, tls=tls)


def _scope_value():
    return LEVEL if LDAP_SEARCH_SCOPE == "LEVEL" else SUBTREE


def _default_filter(username):
    return (
        f"(&(objectClass={LDAP_USER_OBJECT_CLASS})"
        f"(|({LDAP_USERNAME_ATTRIBUTE}={username})(userPrincipalName={username})(mail={username})))"
    )


def _attr_first(entry, attr_name):
    values = entry.entry_attributes_as_dict.get(attr_name)
    if isinstance(values, list):
        return values[0] if values else None
    return values


def _guid_to_str(raw_guid):
    if isinstance(raw_guid, (bytes, bytearray)) and len(raw_guid) == 16:
        return str(uuid.UUID(bytes_le=bytes(raw_guid)))
    return str(raw_guid) if raw_guid else None


def _bind_candidates(username):
    candidates = [username]
    if "@" not in username and LDAP_UPN_SUFFIX:
        candidates.append(f"{username}@{LDAP_UPN_SUFFIX}")
    seen = set()
    ordered = []
    for item in candidates:
        if item and item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def authenticate_ldaps(username, password):
    if not username or not password:
        return None

    server = _ldap_server()
    search_filter = LDAP_USER_FILTER.format(username=username) if LDAP_USER_FILTER else _default_filter(username)
    last_error = None

    for bind_user in _bind_candidates(username):
        try:
            with Connection(server, user=bind_user, password=password, auto_bind=True) as user_conn:
                user_conn.search(
                    search_base=LDAP_USER_SEARCH_BASE,
                    search_filter=search_filter,
                    search_scope=_scope_value(),
                    attributes=[LDAP_USERNAME_ATTRIBUTE, "cn", "mail", "displayName", LDAP_UUID_ATTRIBUTE],
                )

                if user_conn.entries:
                    entry = user_conn.entries[0]
                    uid = _attr_first(entry, LDAP_USERNAME_ATTRIBUTE) or username
                    cn = _attr_first(entry, "cn") or uid
                    mail = _attr_first(entry, "mail") or f"{uid}@example.local"
                    display_name = _attr_first(entry, "displayName") or cn
                    subject_id = _guid_to_str(_attr_first(entry, LDAP_UUID_ATTRIBUTE))
                    return {
                        "username": str(uid),
                        "email": str(mail),
                        "name": str(display_name),
                        "subject_id": subject_id,
                    }

                return {
                    "username": username,
                    "email": f"{username}@example.local",
                    "name": username,
                    "subject_id": None,
                }
        except Exception as err:
            last_error = str(err)

    try:
        with Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True) as admin_conn:
            admin_conn.search(
                search_base=LDAP_USER_SEARCH_BASE,
                search_filter=search_filter,
                search_scope=_scope_value(),
                attributes=[LDAP_USERNAME_ATTRIBUTE, "cn", "mail", "displayName", LDAP_UUID_ATTRIBUTE],
            )

            if not admin_conn.entries:
                return None

            entry = admin_conn.entries[0]
            user_dn = entry.entry_dn

            with Connection(server, user=user_dn, password=password, auto_bind=True):
                uid = _attr_first(entry, LDAP_USERNAME_ATTRIBUTE) or username
                cn = _attr_first(entry, "cn") or uid
                mail = _attr_first(entry, "mail") or f"{uid}@example.local"
                display_name = _attr_first(entry, "displayName") or cn
                subject_id = _guid_to_str(_attr_first(entry, LDAP_UUID_ATTRIBUTE))

                return {
                    "username": str(uid),
                    "email": str(mail),
                    "name": str(display_name),
                    "subject_id": subject_id,
                }
    except Exception as err:
        last_error = str(err)

    if last_error:
        print(f"[LDAP] Authentication failed for {username}: {last_error}")

    return None

@app.route('/login', methods=['GET'])
def login_get():
    challenge = request.args.get('login_challenge')
    
    resp = requests.get(f"{HYDRA_ADMIN_URL}/admin/oauth2/auth/requests/login?login_challenge={challenge}")
    data = resp.json()

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

    ldap_user = authenticate_ldaps(username, password)
    if ldap_user:
        return accept_login(challenge, ldap_user)
    
    return "Invalid Credentials", 401

def accept_login(challenge, principal):
    principal_name = principal.get("username") if isinstance(principal, dict) else principal
    identity = build_identity(principal_name)
    if isinstance(principal, dict):
        identity["subject"] = principal.get("subject_id") or identity["subject"]
        identity["preferred_username"] = principal.get("username") or identity["preferred_username"]
        identity["email"] = principal.get("email") or identity["email"]
        identity["name"] = principal.get("name") or identity["name"]

    body = {
        "subject": identity["subject"],
        "context": {
            "preferred_username": identity["preferred_username"],
            "email": identity["email"],
            "name": identity["name"],
        },
        "remember": True,
        "remember_for": 3600
    }
    resp = requests.put(
        f"{HYDRA_ADMIN_URL}/admin/oauth2/auth/requests/login/accept?login_challenge={challenge}",
        json=body
    )
    return redirect(resp.json()['redirect_to'])

@app.route('/consent', methods=['GET'])
def consent():
    challenge = request.args.get('consent_challenge')
    consent_request = requests.get(
        f"{HYDRA_ADMIN_URL}/admin/oauth2/auth/requests/consent?consent_challenge={challenge}"
    ).json()
    login_context = consent_request.get("context", {})

    id_token_claims = {
        "preferred_username": login_context.get("preferred_username"),
        "email": login_context.get("email"),
        "name": login_context.get("name"),
    }
    id_token_claims = {k: v for k, v in id_token_claims.items() if v}

    body = {
        "grant_scope": consent_request.get("requested_scope", []),
        "grant_access_token_audience": consent_request.get("requested_access_token_audience", []),
        "session": {
            "id_token": id_token_claims,
            "access_token": id_token_claims,
        },
        "remember": True,
        "remember_for": 3600,
    }
    resp = requests.put(
        f"{HYDRA_ADMIN_URL}/admin/oauth2/auth/requests/consent/accept?consent_challenge={challenge}",
        json=body
    )
    return redirect(resp.json()['redirect_to'])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)