import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

# SuperTokens imports
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import session, emailpassword
from supertokens_python.framework.fastapi import get_middleware
#from supertokens_python.framework.fastapi import FastAPISuperTokensFramework
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python.recipe.session import SessionContainer

# ----- Configuration from environment -----
ISSUER = os.getenv("ISSUER", "http://localhost:3001").rstrip("/")
WEB_ORIGIN = os.getenv("WEB_ORIGIN", "http://localhost:3000").rstrip("/")
CORE_URI = os.getenv("SUPERTOKENS_CORE", "http://localhost:3567")

# ----- FastAPI app -----
app = FastAPI(title="FastAPI + SuperTokens (Toy)")

# ----- SuperTokens init (runs once at import) -----
init(
    app_info=InputAppInfo(
        app_name="Toy App",
        api_domain=ISSUER,
        website_domain=WEB_ORIGIN,
        api_base_path="/auth",  # built-in endpoints exposed here
    ),
    supertokens_config=SupertokensConfig(connection_uri=CORE_URI),
    framework="fastapi",
    recipe_list=[
        emailpassword.init(),   # signup / signin / reset password
        session.init(),         # session management
    ],
)



# CORS so browser can send cookies to API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEB_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SuperTokens middleware
app.add_middleware(get_middleware())

# ----- Routes -----
@app.get("/ping")
def ping():
    return {"ok": True}

# Protected route (requires valid session)
@app.get("/me")
async def me(session_: SessionContainer = Depends(verify_session())):
    return {"userId": session_.get_user_id()}

# Logout route (kills current session)
@app.post("/logout")
async def logout(session_: SessionContainer = Depends(verify_session())):
    await session_.revoke_session()
    return {"status": "signedOut"}
