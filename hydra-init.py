# hydra-init.py
import os, time, json, urllib.request, urllib.error, urllib.parse

ADMIN = os.environ["HYDRA_ADMIN_URL"].rstrip("/")
CID   = os.environ["GATE_CLIENT_ID"]
CSEC  = os.environ["GATE_CLIENT_SECRET"]
REDIR = os.environ["GATE_REDIRECT_URI"]

def http(method, url, data=None, max_redirects=5):
    headers = {}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    for _ in range(max_redirects + 1):
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            # follow redirects (keep method & body on 307/308)
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get("Location")
                if not loc:
                    raise
                # absolute-ize relative locations
                url = urllib.parse.urljoin(url, loc)
                # For 303, switch to GET (RFC) and drop body
                if e.code == 303:
                    method, body, headers = "GET", None, {}
                # For 301/302, many clients switch to GET; keep method to be safe unless you prefer GET
                elif e.code in (301, 302) and method not in ("GET", "HEAD"):
                    # choose behavior: keep method or switch to GET
                    # method, body, headers = "GET", None, {}
                    pass
                continue
            else:
                return e.code, e.read()
    raise SystemExit(f"too many redirects for {url}")

def wait_ready():
    for _ in range(180):
        try:
            code, _ = http("GET", f"{ADMIN}/health/ready")
            if code == 200:
                print("hydra-admin is ready")
                return
        except Exception:
            pass
        print("waiting for hydra-admin...")
        time.sleep(2)
    raise SystemExit("hydra-admin not ready in time")

def seed_client():
    # DELETE existing
    code, body = http("DELETE", f"{ADMIN}/clients/{CID}")
    if code not in (200, 204, 404):
        raise SystemExit(f"delete failed: {code} {body[:200]!r}")

    payload = {
        "client_id": CID,
        "client_secret": CSEC,
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        "response_types": ["code"],
        "redirect_uris": [REDIR],
        "scope": "openid offline"
    }
    code, body = http("POST", f"{ADMIN}/clients", payload)
    if code not in (200, 201):
        raise SystemExit(f"create failed: {code} {body[:200]!r}")
    print("created client", CID)

if __name__ == "__main__":
    wait_ready()
    seed_client()
