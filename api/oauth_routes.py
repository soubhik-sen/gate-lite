# oauth_routes.py
import os, time
import httpx
from fastapi import APIRouter, Request, Response, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pkce import new_code_verifier, to_code_challenge_s256

router = APIRouter()

# ---- Config (envs) ----
HYDRA_PUBLIC = os.getenv("HYDRA_PUBLIC", "http://hydra-public:4444").rstrip("/")
CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "gate-client")
CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")  # optional: confidential clients
REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:3000/callback")  # your callback
SCOPE = os.getenv("OAUTH_SCOPE", "openid offline")  # include 'offline' if you want refresh_token
AUDIENCE = os.getenv("OAUTH_AUDIENCE")  # optional: if configured in Hydra

# ---- Simple in-memory state store (replace with Redis/SuperTokens session etc.) ----
# key: state, value: (code_verifier, created_at)
_STATE = {}

def _save_state(state: str, verifier: str):
    _STATE[state] = (verifier, time.time())

def _pop_state(state: str):
    v = _STATE.pop(state, None)
    # Optional TTL cleanup here
    return v

@router.get("/oauth/login")
def oauth_login():
    # 1) Generate PKCE
    code_verifier = new_code_verifier()
    code_challenge = to_code_challenge_s256(code_verifier)

    # 2) Create state (and optionally nonce for ID token)
    state = new_code_verifier(16)  # reuse generator for randomness
    _save_state(state, code_verifier)

    # 3) Build Hydra authorize URL
    # Note: response_type=code for Authorization Code (with PKCE)
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if AUDIENCE:
        params["audience"] = AUDIENCE

    # 4) Redirect to Hydra /oauth2/auth
    q = "&".join(f"{k}={httpx.QueryParams({k:v})[k]}" for k, v in params.items())
    return RedirectResponse(url=f"{HYDRA_PUBLIC}/oauth2/auth?{q}", status_code=302)

@router.get("/oauth/callback")
def oauth_callback(code: str, state: str):
    # 1) Retrieve verifier for this state
    st = _pop_state(state)
    if not st:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    code_verifier, _created = st

    # 2) Exchange code + code_verifier at Hydra /oauth2/token
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier,
    }

    # For confidential clients, authenticate; for public, omit:
    auth = (CLIENT_ID, CLIENT_SECRET) if CLIENT_SECRET else None

    with httpx.Client(timeout=8.0) as client:
        resp = client.post(f"{HYDRA_PUBLIC}/oauth2/token", data=data, auth=auth)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {e.response.text}")

    tokens = resp.json()
    # tokens = { access_token, id_token?, refresh_token?, token_type, expires_in, ... }

    # 3) (Optional) Create your app session here (e.g., SuperTokens) and store tokens securely.
    #    Example placeholder:
    #    session.create(user_id=..., access_token=tokens["access_token"], refresh=tokens.get("refresh_token"))

    # 4) Redirect back to your frontend (or return tokens if this is an API-only flow)
    return tokens  # For debugging; in prod, redirect to your app and set cookies

@router.post("/oauth/refresh")
def oauth_refresh(refresh_token: str):
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Missing refresh_token")
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    }
    auth = (CLIENT_ID, CLIENT_SECRET) if CLIENT_SECRET else None
    with httpx.Client(timeout=8.0) as client:
        r = client.post(f"{HYDRA_PUBLIC}/oauth2/token", data=data, auth=auth)
        r.raise_for_status()
        return r.json()
