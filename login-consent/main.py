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

ENV = os.getenv("ENV", "dev")
API_DOMAIN = os.getenv("API_DOMAIN", "http://localhost:3002").rstrip("/")
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "http://localhost:3000").rstrip("/")
HYDRA_ADMIN_URL = os.getenv("HYDRA_ADMIN_URL", "http://localhost:4445").rstrip("/")
SUPERTOKENS_CONNECTION_URI = os.getenv("SUPERTOKENS_CONNECTION_URI", "http://localhost:3567")
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
    user_id = session_.get_user_id()

    # In a real app, you’d render scopes/claims for the user to approve.
    # For baseline, auto-approve requested scopes.
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

        # Accept consent
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
