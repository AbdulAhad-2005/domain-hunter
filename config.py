from pathlib import Path

import yaml

_DEFAULT_PATH = Path(__file__).parent / "config.yaml"

# Which config.yaml keys must be present (and truthy) for a given service
# to count as "configured". Mirrors config.yaml.example.
#
# Censys note: the Platform API authenticates with a single bearer PAT
# (censys_personal_access_token), not an API ID + secret pair -- that
# two-part scheme was the old Legacy Search API and doesn't apply here.
# censys_organization_id is optional/recommended (not required for has()):
# per Censys's docs it just scopes billing/entitlements, and Free-tier
# accounts don't have one at all.
_SERVICE_KEYS = {
    "shodan": ["shodan_api_key"],
    "censys": ["censys_personal_access_token"],
    "securitytrails": ["securitytrails_api_key"],
    "whoisxml": ["whoisxml_api_key"],
    "whoxy": ["whoxy_api_key"],
    "builtwith": ["builtwith_api_key"],
    "google_search": ["google_search_api_key", "google_search_cx"],
    "llm": ["llm_provider", "llm_api_key"],
}


class APIConfig:
    def __init__(self, data: dict):
        self._data = data or {}

    @classmethod
    def load(cls, path: str | Path = _DEFAULT_PATH) -> "APIConfig":
        path = Path(path)
        if not path.exists():
            return cls({})
        with open(path, "r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f) or {})

    def has(self, service: str) -> bool:
        """True if every key required for `service` is present and truthy (in config or env)."""
        required = _SERVICE_KEYS.get(service, [f"{service}_api_key"])
        return all(self.get(key) for key in required)

    def get(self, key: str, default=None):
        import os
        val = self._data.get(key)
        if val is not None and str(val).strip():
            return val
        env_val = os.environ.get(key.upper()) or os.environ.get(key)
        return env_val if env_val is not None and str(env_val).strip() else default
