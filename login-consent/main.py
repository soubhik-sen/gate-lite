"""
FastAPI service acting as the login and consent front-end for Ory Hydra.
It uses Supertokens for authentication and drives Hydra's OAuth2 login and
consent challenges.
"""

import os
import httpx
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.framework.fastapi import get_middleware
from supertokens_python.recipe import session, emailpassword
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.session import SessionContainer

# --- replace the ENV block at the top with this ---
ENV = os.getenv("ENV", "dev")
API_DOMAIN = os.getenv("API_DOMAIN", "http://login-consent:8000").rstrip("/")     # inside docker
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "http://localhost:3000").rstrip("/")         # your real web app origin
HYDRA_ADMIN_URL = os.getenv("HYDRA_ADMIN_URL", "http://hydra:4445").rstrip("/")

# Support either var name; prefer SUPERTOKENS_CONNECTION_URI but fall back to SUPERTOKENS_CORE_URI
_SUPERTOKENS_URI = os.getenv("SUPERTOKENS_CONNECTION_URI") or os.getenv("SUPERTOKENS_CORE_URI") or "http://supertokens:3567"
SUPERTOKENS_CONNECTION_URI = _SUPERTOKENS_URI

COOKIE_DOMAIN: Optional[str] = os.getenv("COOKIE_DOMAIN") or None

IS_DEV = ENV != "prod"
COOKIE_SECURE = not IS_DEV
COOKIE_SAMESITE = "lax" if IS_DEV else "none"


# Init Supertokens (email-password + session) just for the login UI app
init(
    app_info=InputAppInfo(
        app_name="Gate Login/Consent",
        api_domain=API_DOMAIN,
        website_domain=WEB_ORIGIN,
        api_base_path="/auth",
        website_base_path="/auth",
    ),
    supertokens_config=SupertokensConfig(connection_uri=SUPERTOKENS_CONNECTION_URI),
    framework="fastapi",
    recipe_list=[
        emailpassword.init(),
        session.init(
            anti_csrf="VIA_TOKEN",
            cookie_domain=COOKIE_DOMAIN,
            cookie_secure=COOKIE_SECURE,
            cookie_same_site=COOKIE_SAMESITE,
        ),
    ],
)

app = FastAPI(title="Gate Login & Consent")
app.add_middleware(get_middleware())  # ST first
app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEB_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["front-token", "anti-csrf", "rid", "st-auth-mode"],
)

# 1) HYDRA LOGIN endpoint
# Hydra redirects the browser to GET /login?login_challenge=...
@app.get("/login")
async def login_ui(request: Request, login_challenge: str):
    """Render or auto-accept Hydra's login challenge.

    Parameters:
        request: Incoming FastAPI request used to check for an existing session.
        login_challenge: Challenge string received from Hydra.

    Sequence of Hydra calls:
        Sends a PUT request to ``/oauth2/auth/requests/login/accept`` when a
        Supertokens session already exists.

    Side Effects:
        Redirects the browser to the ``redirect_to`` URL supplied by Hydra or
        returns JSON instructing the client to initiate login.
    """
    # If user already has a Supertokens session, accept login immediately
    session_: SessionContainer | None = await session.get_session(request, session_required=False)
    if session_:
        user_id = session_.get_user_id()
        async with httpx.AsyncClient() as client:
            r = await client.put(
                f"{HYDRA_ADMIN_URL}/oauth2/auth/requests/login/accept",
                json={
                    "subject": user_id,
                    "remember": True,
                    "remember_for": 3600,
                },
                params={"login_challenge": login_challenge},
                timeout=10,
            )
            r.raise_for_status()
            redirect_to = r.json()["redirect_to"]
        return RedirectResponse(redirect_to)

    # Otherwise render your login page (for demo, redirect to Supertokens hosted UI or return JSON)
    return JSONResponse({"login_challenge": login_challenge, "action": "please sign in via /auth"})

# After user signs in (via Supertokens), your frontend should call:
# POST /login/accept with the login_challenge to finalize
@app.post("/login/accept")
async def login_accept(login_challenge: str = Form(...), session_: SessionContainer = Depends(verify_session())):
    """Finalize Hydra's login request after user authentication.

    Parameters:
        login_challenge: The challenge string initially provided by Hydra.
        session_: Verified Supertokens session for the authenticated user.

    Sequence of Hydra calls:
        Issues a PUT request to ``/oauth2/auth/requests/login/accept`` to mark
        the login as successful.

    Side Effects:
        Redirects the user agent to Hydra's ``redirect_to`` URL to continue the
        OAuth2 authorization flow.
    """
    user_id = session_.get_user_id()
    async with httpx.AsyncClient() as client:
        r = await client.put(
            f"{HYDRA_ADMIN_URL}/oauth2/auth/requests/login/accept",
            json={"subject": user_id, "remember": True, "remember_for": 3600},
            params={"login_challenge": login_challenge},
            timeout=10,
        )
        r.raise_for_status()
        redirect_to = r.json()["redirect_to"]
    return RedirectResponse(redirect_to)

# 2) HYDRA CONSENT endpoint
# Hydra redirects browser to GET /consent?consent_challenge=...
@app.get("/consent")
async def consent_ui(consent_challenge: str, session_: SessionContainer = Depends(verify_session())):
    """Handle Hydra's consent challenge for an authenticated user.

    Parameters:
        consent_challenge: Challenge string provided by Hydra.
        session_: Verified Supertokens session for the current user.

    Sequence of Hydra calls:
        1. GET ``/oauth2/auth/requests/consent`` to obtain scopes and audience.
        2. PUT ``/oauth2/auth/requests/consent/accept`` to grant consent.

    Side Effects:
        Auto-approves all requested scopes and audiences and embeds the user id
        in the ID and access tokens before redirecting back to Hydra.
    """
    user_id = session_.get_user_id()

    # In a real app, you'd render scopes/claims for the user to approve.
    # This demo auto-approves whatever Hydra requests. Production deployments
    # should present a consent screen and persist user decisions or restrict
    # auto-approval to trusted clients.
    async with httpx.AsyncClient() as client:
        # Get requested scopes / audience
        getr = await client.get(
            f"{HYDRA_ADMIN_URL}/oauth2/auth/requests/consent",
            params={"consent_challenge": consent_challenge},
            timeout=10,
        )
        getr.raise_for_status()
        body = getr.json()
        requested_scope = body.get("requested_scope", [])
        requested_audience = body.get("requested_access_token_audience", [])

        # Auto-approve the consent request by echoing back Hydra's requested
        # scopes and audiences. Replace or augment this in production to honour
        # the user's actual selections.
        putr = await client.put(
            f"{HYDRA_ADMIN_URL}/oauth2/auth/requests/consent/accept",
            params={"consent_challenge": consent_challenge},
            json={
                "grant_scope": requested_scope,
                "grant_access_token_audience": requested_audience,
                "remember": True,
                "remember_for": 3600,
                "session": {
                    # Optionally add custom claims to ID/Access tokens:
                    "id_token": {"uid": user_id},
                    "access_token": {"uid": user_id},
                },
            },
            timeout=10,
        )
        putr.raise_for_status()
        redirect_to = putr.json()["redirect_to"]

    return RedirectResponse(redirect_to)
# --- append at the END of the file (new routes) ---

# 3) LOGOUT endpoints (Hydra expects these to exist per hydra.yml)
# Hydra will hit GET /logout?logout_challenge=... first
@app.get("/logout")
async def hydra_logout(logout_challenge: str, request: Request):
    """
    Hydra back-channel logout: accept logout and redirect where Hydra says.
    If a SuperTokens session exists, we revoke it.
    """
    # Revoke ST session if present (no error if absent)
    session_: SessionContainer | None = await session.get_session(request, session_required=False)
    if session_:
        await session_.revoke_session()

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.put(
            f"{HYDRA_ADMIN_URL}/oauth2/auth/requests/logout/accept",
            params={"logout_challenge": logout_challenge},
        )
        r.raise_for_status()
        redirect_to = r.json()["redirect_to"]

    return RedirectResponse(redirect_to)

# This is where Hydra will redirect after logout accept (as configured in hydra.yml: urls.post_logout_redirect)
@app.get("/loggedout")
async def logged_out():
    return JSONResponse({"ok": True, "message": "You are logged out."})

# 4) Dev helper: whoami (quick session check)
@app.get("/whoami")
async def whoami(request: Request):
    session_: SessionContainer | None = await session.get_session(request, session_required=False)
    if not session_:
        return JSONResponse({"loggedIn": False})
    return JSONResponse({"loggedIn": True, "userId": session_.get_user_id()})
