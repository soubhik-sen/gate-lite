# oauth_routes.py (Gate façade + PKCE)
import os, time
import httpx
from fastapi import APIRouter, Request, Response, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from api.pkce import new_code_verifier, to_code_challenge_s256
from api.gate_config import settings
from api.hydra_client import hydra_create_client, delete_client, list_clients

router = APIRouter(prefix="/gate", tags=["gate"])

# ---------- PKCE login settings (frontend flow) ----------
CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "gate-client")
CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")  # optional (confidential clients)
REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:3000/callback")
SCOPE = os.getenv("OAUTH_SCOPE", "openid offline")
AUDIENCE = os.getenv("OAUTH_AUDIENCE")  # optional
HYDRA_LOCAL = os.getenv("HYDRA_PUBLIC_URL")
HYDRA_LOCAL_ADMIN = os.getenv("HYDRA_ADMIN_URL")

# Simple in-memory state (replace with Redis/session later)
_STATE = {}
def _save_state(state: str, verifier: str): _STATE[state] = (verifier, time.time())
def _pop_state(state: str): return _STATE.pop(state, None)

# ---------- Helpers ----------
def _safe_headers(src: httpx.Response):
    blocked = {"content-encoding","transfer-encoding","connection"}
    return {k: v for k, v in src.headers.items() if k.lower() not in blocked}

def _client():
    return httpx.AsyncClient(timeout=20.0, follow_redirects=True)
# ---------- Health ----------
@router.get("/health")
async def health():
    return {"ok": True}

# ---------- Public OIDC/JWKS (rewritten to Gate) ----------
@router.get("/.well-known/jwks.json")
async def gate_jwks():
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(f"{settings.HYDRA_PUBLIC_URL}/.well-known/jwks.json")
    return JSONResponse(r.json(), status_code=r.status_code)

@router.get("/.well-known/openid-configuration")
async def gate_oidc_discovery():
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(f"{settings.HYDRA_PUBLIC_URL}/.well-known/openid-configuration")
    data = r.json()
    data.update({
        "issuer":                 settings.GATE_ISSUER,
        "authorization_endpoint": f"{settings.GATE_BASE_URL}/gate/oauth/authorize",   # optional to implement later
        "token_endpoint":         f"{settings.GATE_BASE_URL}/gate/oauth/token",
        "jwks_uri":               f"{settings.GATE_BASE_URL}/gate/.well-known/jwks.json",
        "userinfo_endpoint":      f"{settings.GATE_BASE_URL}/gate/oauth/userinfo",    # add proxy later if needed
        "introspection_endpoint": f"{settings.GATE_BASE_URL}/gate/oauth/introspect",
        "revocation_endpoint":    f"{settings.GATE_BASE_URL}/gate/oauth/revoke",
    })
    return JSONResponse(data, status_code=r.status_code)

# ---------- Token/introspect/revoke (proxy to Hydra public) ----------
@router.post("/oauth/token")
async def gate_token(request: Request):
    fwd_headers = {
        "content-type": "application/x-www-form-urlencoded"
    }
    auth = request.headers.get("authorization")
    if auth:
        fwd_headers["authorization"] = auth
    form = await request.form()
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(f"{HYDRA_LOCAL}/oauth2/token",
                         data=form,
                         headers=fwd_headers)
    return Response(content=r.content, status_code=r.status_code, headers=_safe_headers(r))

@router.post("/oauth/introspect")
async def gate_introspect(request: Request):
    form = await request.form()
    auth = request.headers.get("Authorization")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if auth: headers["Authorization"] = auth
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(f"http://hydra:4445/admin/oauth2/introspect", data=form, headers=headers)
    return Response(content=r.content, status_code=r.status_code, headers=_safe_headers(r))

@router.post("/oauth/revoke")
async def gate_revoke(request: Request):
    form = await request.form()
    auth = request.headers.get("Authorization")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if auth: headers["Authorization"] = auth
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(f"{settings.HYDRA_PUBLIC_URL}/oauth2/revoke", data=form, headers=headers)
    return Response(content=r.content, status_code=r.status_code, headers=_safe_headers(r))

# ---------- Admin client management (keep private via network) ----------
@router.get("/admin/clients")
async def admin_list_clients():
    try:
        return await list_clients()
    except httpx.RequestError as e:
        return JSONResponse({"error": "upstream_unreachable",
                             "target": f"{settings.HYDRA_ADMIN_URL}/clients",
                             "detail": str(e)}, status_code=502)

@router.post("/admin/clients")
async def admin_create_client(payload: dict):
    # async with _client() as c:
    #     r = await c.post(f"{settings.HYDRA_ADMIN_URL}/clients", json=payload)
    # return Response(content=r.content, status_code=r.status_code, headers=_safe_headers(r))
    return await hydra_create_client(payload)
@router.delete("/admin/clients/{client_id}")
async def admin_delete_client(client_id: str):
    return await delete_client(client_id)

# ---------- PKCE browser flow (Gate-facing) ----------
@router.get("/oauth/login")
def oauth_login():
    code_verifier = new_code_verifier()
    code_challenge = to_code_challenge_s256(code_verifier)
    state = new_code_verifier(16)
    _save_state(state, code_verifier)

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

    q = "&".join(f"{k}={httpx.QueryParams({k:v})[k]}" for k, v in params.items())
    return RedirectResponse(url=f"{settings.HYDRA_PUBLIC_URL}/oauth2/auth?{q}", status_code=302)

@router.get("/oauth/callback")
def oauth_callback(code: str, state: str):
    st = _pop_state(state)
    if not st:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    code_verifier, _created = st

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier,
    }
    auth = (CLIENT_ID, CLIENT_SECRET) if CLIENT_SECRET else None
    with httpx.Client(timeout=8.0) as client:
        resp = client.post(f"{settings.HYDRA_PUBLIC_URL}/oauth2/token", data=data, auth=auth)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {e.response.text}")
    return resp.json()

@router.post("/oauth/refresh")
def oauth_refresh(refresh_token: str):
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Missing refresh_token")
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": CLIENT_ID}
    auth = (CLIENT_ID, CLIENT_SECRET) if CLIENT_SECRET else None
    with httpx.Client(timeout=8.0) as client:
        r = client.post(f"{settings.HYDRA_PUBLIC_URL}/oauth2/token", data=data, auth=auth)
        r.raise_for_status()
        return r.json()
