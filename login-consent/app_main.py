# app_main.py  (login-consent)  — minimal, version-agnostic for current docs
import os
from fastapi import FastAPI
import logging  
from fastapi import Depends

from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.session.framework.fastapi import verify_session
from supertokens_python import init, SupertokensConfig, InputAppInfo
from supertokens_python.recipe import thirdparty, session
from supertokens_python import get_all_cors_headers
from fastapi.middleware.cors import CORSMiddleware
from supertokens_python.recipe.thirdparty.provider import (
    ProviderInput, ProviderConfig, ProviderClientConfig,
)
from supertokens_python.framework.fastapi import get_middleware  as st_get_middleware


WEB_ORIGIN = os.getenv("WEB_ORIGIN", "http://localhost:3000").rstrip("/") 


logger = logging.getLogger("login.consent")
# 1) INIT FIRST (order matters)
init(
    app_info=InputAppInfo(
        app_name="LoginConsent",
        #framework=["fastapi", "flask", "django"],
        api_domain="http://localhost:3002",   # direct test; switch to 8000 when using Gate
        api_base_path="/auth",                # single-segment (reliable)
        website_base_path="/auth",
        website_domain="http://localhost:3000",
    ),
    #supertokens_config=SupertokensConfig(connection_uri="http://supertokens:3567"),
    supertokens_config=SupertokensConfig(connection_uri="https://try.supertokens.io"),
    framework="fastapi",
    recipe_list=[
        session.init(),
        thirdparty.init(
            sign_in_and_up_feature=thirdparty.SignInAndUpFeature(
                providers=[
                    ProviderInput(
                        config=ProviderConfig(
                            third_party_id="google",
                            clients=[
                                ProviderClientConfig(
                                    client_id=os.getenv("GOOGLE_CLIENT_ID") or "test",
                                    client_secret=os.getenv("GOOGLE_CLIENT_SECRET") or "test",
                                )
                            ],
                        )
                    )
                ]
            )
        ),
        
    ],
    mode='asgi'
)
logger.info("All init done")
print("all init done")
# 2) APP + MIDDLEWARE (FastAPI integration)
app = FastAPI(title="LoginConsent")

mw_class = st_get_middleware()
print(">>> ST mw class:", mw_class, "from", mw_class.__module__)
app.add_middleware(mw_class)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[WEB_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type"] + get_all_cors_headers(),
    expose_headers=["front-token", "anti-csrf", "rid", "st-auth-mode"],
)

print("MIDDLEWARES =>", [m.cls.__name__ for m in app.user_middleware])

logger.info("MW attached")
print("MW attached")
# 3) Simple probe
@app.get("/whoami")
def whoami():
    return {"ok": True}
@app.get("/__routes")
def list_routes():
    return [
        {"path": r.path, "methods": sorted(list(getattr(r, "methods", [])))}
        for r in app.routes
    ]

@app.post('/like_comment') 
async def like_comment(session: SessionContainer = Depends(verify_session())):
    user_id = session.get_user_id()

    print(user_id)
