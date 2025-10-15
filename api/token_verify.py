# api/token_verify.py
import time, httpx
from functools import lru_cache
from jose import jwt, JWTError
from fastapi import Header, HTTPException
from api.gate_config import settings

# Verify against Gate's façade
ISSUER   = settings.GATE_ISSUER               # today may still be hydra issuer; ok
JWKS_URL = f"{settings.GATE_BASE_URL}/gate/.well-known/jwks.json"
AUDIENCE = "gate-api"  # set/keep if you want audience enforcement

@lru_cache(maxsize=1)
def _load_jwks():
    r = httpx.get(JWKS_URL, timeout=5.0)
    r.raise_for_status()
    return r.json()

def _decode(token: str, jwks: dict):
    # python-jose can select the correct key from a JWKS dict (with "keys":[...])
    return jwt.decode(
        token,
        jwks,
        algorithms=["RS256"],
        audience=None,                   # set to AUDIENCE if you want hard enforcement
        options={"verify_aud": False},   # flip to True + audience=AUDIENCE to enforce
    )

def verify_bearer(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split()[1]

    try:
        # 1st attempt with cached JWKS
        claims = _decode(token, _load_jwks())
    except JWTError:
        # Possible key rotation: refresh JWKS once and retry
        _load_jwks.cache_clear()
        try:
            claims = _decode(token, _load_jwks())
        except Exception:
            raise HTTPException(status_code=401, detail="invalid token")
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")

    # Issuer + exp checks
    if claims.get("iss") != ISSUER:
        raise HTTPException(status_code=401, detail="bad issuer")
    if claims.get("exp", 0) < time.time():
        raise HTTPException(status_code=401, detail="expired")

    # Optional audience enforcement
    # aud = claims.get("aud")
    # if AUDIENCE and (not aud or (isinstance(aud, list) and AUDIENCE not in aud) or (isinstance(aud, str) and aud != AUDIENCE)):
    #     raise HTTPException(status_code=401, detail="bad audience")

    return claims
