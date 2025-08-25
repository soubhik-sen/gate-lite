# api/token_verify.py
import time, httpx, json
from functools import lru_cache
from jose import jwt
from fastapi import Header, HTTPException

HYDRA_ISSUER = "http://localhost:4444"  # HYDRA_ISSUER you used
JWKS_URL = f"{HYDRA_ISSUER}/.well-known/jwks.json"
AUDIENCE = "gate-api"  # set this as your client audience if you use it

@lru_cache(maxsize=1)
def _jwks():
    r = httpx.get(JWKS_URL, timeout=5)
    r.raise_for_status()
    return r.json()

def verify_bearer(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split()[1]
    try:
        claims = jwt.decode(token, _jwks(), algorithms=["RS256"], options={"verify_aud": False})
        # Optionally enforce aud:
        # if AUDIENCE not in claims.get("aud", []): raise ...
        if claims["iss"] != HYDRA_ISSUER:
            raise HTTPException(status_code=401, detail="bad issuer")
        if claims.get("exp", 0) < time.time():
            raise HTTPException(status_code=401, detail="expired")
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail="invalid token")
