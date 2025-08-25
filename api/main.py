import os
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# SuperTokens imports
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session, emailpassword, emailverification
from supertokens_python.framework.fastapi import get_middleware
#from supertokens_python.framework.fastapi import FastAPISuperTokensFramework
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session import InputErrorHandlers
from .token_verify import verify_bearer

# ----- Configuration from environment -----
# ======== Environment (adjust defaults to your setup) ========
ENV = os.getenv("ENV", "dev")  # dev | prod

ISSUER = os.getenv("ISSUER", "http://localhost:3001").rstrip("/")
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "http://localhost:3000").rstrip("/")
CORE_URI = os.getenv("SUPERTOKENS_CORE", "http://localhost:3567")
COOKIE_DOMAIN: Optional[str] = os.getenv("COOKIE_DOMAIN") or None

API_BASE_PATH = os.getenv("API_BASE_PATH", "/auth")
WEBSITE_BASE_PATH = os.getenv("WEBSITE_BASE_PATH", "/auth")

# Anti-CSRF mode:
#   - "VIA_TOKEN" is the safest default for modern SPAs.
#   - Leave None to use library defaults if you prefer.
ANTI_CSRF_MODE = os.getenv("ANTI_CSRF_MODE", "VIA_TOKEN")  # VIA_TOKEN | None

# SameSite / Secure cookies (prod should be secure + samesite='none' when cross-site)
IS_DEV = ENV != "prod"
COOKIE_SECURE = not IS_DEV  # secure cookies only in prod (must be HTTPS)
COOKIE_SAMESITE = "lax" if IS_DEV else "none"  # 'lax' for dev, 'none' for cross-site prod

# ----- FastAPI app -----
app = FastAPI(title="Gate-Lite API")

# ----- SuperTokens init (runs once at import) -----
# ======== Supertokens init ========
def _error_handlers() -> InputErrorHandlers:
    # Optional: centralize session errors for cleaner 401s
    def on_unauthorised(_, __, ___):
        # Map ST unauthorised to a cleaner FastAPI error if you want
        raise HTTPException(status_code=401, detail="Unauthorised")

    def on_try_refresh_token(_, __, ___):
        raise HTTPException(status_code=401, detail="try refresh token")

    def on_token_theft_detected(_, __, ___, ____):
        # Optional: customize token theft response
        raise HTTPException(status_code=401, detail="token theft detected")

    return InputErrorHandlers(
        on_unauthorised=on_unauthorised,
        on_try_refresh_token=on_try_refresh_token,
        on_token_theft_detected=on_token_theft_detected,
    )

init(
    app_info=InputAppInfo(
        app_name="Gate-Lite",
        api_domain=ISSUER,
        website_domain=WEB_ORIGIN,
        api_base_path=API_BASE_PATH,  # built-in endpoints exposed here
        website_base_path=WEBSITE_BASE_PATH,   # frontend uses same base
    ),
    supertokens_config=SupertokensConfig(connection_uri=CORE_URI),
    framework="fastapi",
    recipe_list=[
        emailpassword.init(),   # signup / signin / reset password
        emailverification.init(mode="OPTIONAL"),
        session.init(
            anti_csrf=ANTI_CSRF_MODE,  # "VIA_TOKEN" recommended for SPA setups
            cookie_domain=COOKIE_DOMAIN,  # None in dev; set in prod
            cookie_secure=COOKIE_SECURE,  # True in prod (HTTPS required)
            cookie_same_site=COOKIE_SAMESITE,  # 'none' for cross-site in prod
            error_handlers=_error_handlers(),
        ),
    ],
)

# SuperTokens middleware
app.add_middleware(get_middleware())

# CORS so browser can send cookies to API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEB_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "front-token",      # used by ST frontend SDKs
        "anti-csrf",
        "rid",
        "st-auth-mode",
    ],
)



# ----- Routes -----
@app.get("/ping")
def ping():
    return {"ok": True}

# Protected route (requires valid session)
@app.get("/me")
async def me(session_: SessionContainer = Depends(verify_session())):
    return {"userId": session_.get_user_id()}

@app.get("/secure")
def secure_endpoint(claims=Depends(verify_bearer)):
    return {"sub": claims["sub"], "scopes": claims.get("scope")}

# Logout route (kills current session)
@app.post("/logout")
async def logout(session_: SessionContainer = Depends(verify_session())):
    await session_.revoke_session()
    return {"status": "signedOut"}
