import os, json
from typing import Dict, List, Optional, TypedDict

class ClientCfg(TypedDict, total=False):
    id: str
    secret: str
    allowed_scopes: List[str]
    default_scope: str
    audience: str

def _load_from_env_json(env_key: str) -> Optional[Dict[str, ClientCfg]]:
    raw = os.getenv(env_key)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception as e:
        raise RuntimeError(f"Invalid JSON in {env_key}: {e}")

def _load_from_file(path: str) -> Optional[Dict[str, ClientCfg]]:
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_client_registry() -> Dict[str, ClientCfg]:
    """
    Load registry from, in order of preference:
    1) GATE_CLIENTS_JSON (env, JSON string)
    2) GATE_CLIENTS_FILE (env, file path mounted as secret)
    """
    cfg = _load_from_env_json("GATE_CLIENTS_JSON")
    if cfg:
        return cfg
    file_path = os.getenv("GATE_CLIENTS_FILE", "")
    cfg = _load_from_file(file_path)
    if cfg:
        return cfg
    raise RuntimeError("No client registry found. Set GATE_CLIENTS_JSON or GATE_CLIENTS_FILE")

# --- Append below your existing code in gate_config.py ---

class Settings:
    # Gate public base (what clients hit)
    GATE_BASE_URL = os.getenv("GATE_BASE_URL", "http://localhost:8000").rstrip("/")

    # Internal Hydra endpoints (Docker-internal)
    HYDRA_PUBLIC_URL = os.getenv("HYDRA_PUBLIC_URL", "http://hydra:4444").rstrip("/")
    HYDRA_ADMIN_URL  = os.getenv("HYDRA_ADMIN_URL",  "http://hydra:4445").rstrip("/")

    # What we want to advertise as the issuer (can be Hydra for now; later switch to Gate domain)
    GATE_ISSUER = os.getenv("GATE_ISSUER", "http://hydra-public:4444").rstrip("/")

settings = Settings()

