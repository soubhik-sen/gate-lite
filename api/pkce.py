# pkce.py
import os, secrets, hashlib, base64

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def new_code_verifier(nbytes: int = 32) -> str:
    # 43–128 chars: generate securely, then base64url without padding
    return _b64url(secrets.token_bytes(nbytes))

def to_code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)
