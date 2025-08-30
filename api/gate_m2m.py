import os, httpx
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header, status
from pydantic import BaseModel, constr
from api.gate_config import load_client_registry

router = APIRouter(prefix="/gate", tags=["gate"])

HYDRA_PUBLIC_URL = os.getenv("HYDRA_PUBLIC_URL", "http://hydra:4444").rstrip("/")
TOKEN_URL = f"{HYDRA_PUBLIC_URL}/oauth2/token"

# Require a Gate API key for callers (rotate via env/secret)
GATE_API_KEY = os.getenv("GATE_API_KEY")

def _auth_guard(x_api_key: Optional[str]):
    if not GATE_API_KEY:
        # For dev, you may allow missing key; for prod, enforce it.
        return
    if not x_api_key or x_api_key != GATE_API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid gate api key")

class M2MRequest(BaseModel):
    # Logical client name in the registry (e.g., "sacred", "analytics")
    client: constr(strip_whitespace=True, min_length=1)
    # Requested scopes (space-separated). Gate will clamp to allowed_scopes.
    scope: Optional[constr(strip_whitespace=True, min_length=1)] = None
    # Optional audience if you use it in Hydra. If omitted, registry's default applies.
    audience: Optional[constr(strip_whitespace=True, min_length=1)] = None

def _clamp_scopes(requested: List[str], allowed: List[str]) -> List[str]:
    if not requested:
        return []
    allowed_set = set(allowed)
    return [s for s in requested if s in allowed_set]

@router.post("/token")
async def broker_m2m_token(body: M2MRequest, x_api_key: Optional[str] = Header(default=None, convert_underscores=False)):
    _auth_guard(x_api_key)

    registry = load_client_registry()
    entry = registry.get(body.client)
    if not entry:
        raise HTTPException(400, "unknown client")

    client_id = entry.get("id")
    client_secret = entry.get("secret")
    if not client_id or not client_secret:
        raise HTTPException(500, "client misconfigured (no id/secret)")

    # Determine scopes
    allowed_scopes = entry.get("allowed_scopes") or []
    default_scope = entry.get("default_scope") or ""
    req_scopes = (body.scope or default_scope or "").split()
    final_scopes = _clamp_scopes(req_scopes, allowed_scopes)
    if not final_scopes and allowed_scopes:
        # No overlap => deny
        raise HTTPException(403, "requested scopes not allowed")

    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if final_scopes:
        data["scope"] = " ".join(final_scopes)
    aud = body.audience or entry.get("audience")
    if aud:
        data["audience"] = aud

    try:
        async with httpx.AsyncClient(timeout=10) as cli:
            r = await cli.post(TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            r.raise_for_status()
            return r.json()
    except httpx.HTTPStatusError as e:
        # propagate Hydra error text for quick diagnosis, but hide secrets
        raise HTTPException(e.response.status_code, e.response.text)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"hydra unreachable: {e}")
