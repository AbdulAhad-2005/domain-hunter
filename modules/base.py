from abc import ABC, abstractmethod

from config import APIConfig
from core.models import Finding


class ReconModule(ABC):
    name: str
    requires_key: str | None = None  # e.g. "shodan"; None if fully free

    # False only for modules with NO free path at all (e.g. ai_hunt.py, which
    # is pure LLM hypothesis generation) -- lets the runner skip them entirely
    # with a clear log line when their key is missing, rather than running a
    # free "tier" that doesn't exist. Modules that degrade to a free fallback
    # (the common case) leave this True.
    has_free_fallback: bool = True

    # False for modules that only do recon on the seed domain itself and never
    # produce associated-domain Findings (e.g. whois_lookup.py, fingerprint.py)
    # -- lets the runner report "recon only" instead of a misleading "0 found".
    produces_findings: bool = True

    def __init__(self, config: APIConfig):
        self.config = config
        self.enabled_tier = "paid" if self.requires_key and config.has(self.requires_key) else "free"

    @abstractmethod
    def run(self, domain: str) -> list[Finding]:
        ...
