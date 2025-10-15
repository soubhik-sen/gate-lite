# hydra_client.py (Gate)
import os, httpx, logging

ADMIN = os.getenv("HYDRA_ADMIN_URL", "http://hydra:4445").rstrip("/")

async def hydra_create_client(payload: dict):
    async with httpx.AsyncClient(
        base_url=ADMIN, timeout=5.0, trust_env=False, follow_redirects=False
    ) as c:
        # optional: health check
        r = await c.get("/health/ready"); r.raise_for_status()

        # call the CORRECT v2 path
        r = await c.post("/admin/clients", json=payload, headers={"Content-Type": "application/json"})

        # defensive: handle any weird relative/empty-host redirects
        if r.status_code in (301, 302, 303, 307, 308):
            loc = (r.headers.get("location") or "").strip()
            if loc.startswith("/"):
                r = await c.post(loc, json=payload, headers={"Content-Type":"application/json"})
            elif loc.startswith("http:///"):  # buggy empty-host redirect
                r = await c.post("/admin/clients", json=payload, headers={"Content-Type":"application/json"})

        r.raise_for_status()
        return r.json()

async def list_clients():
    async with httpx.AsyncClient(base_url=ADMIN, timeout=5.0, trust_env=False) as c:
        r = await c.get("/admin/clients")
        r.raise_for_status()
        return r.json()

async def delete_client(client_id: str):
    async with httpx.AsyncClient(base_url=ADMIN, timeout=5.0, trust_env=False) as c:
        r = await c.delete(f"/admin/clients/{client_id}")
        r.raise_for_status()
        return {"deleted": client_id}