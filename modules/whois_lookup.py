import logging

import requests

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"
_TIMEOUT = 15


class WhoisLookupModule(ReconModule):
    """Forward WHOIS/RDAP lookup on the seed domain only.

    Per PROJECT_OVERVIEW.md 4.1, this is recon on the seed domain, not a
    discovery method — it does NOT produce "associated domain" Findings.
    `run()` always returns []; the parsed record (registrant org/email,
    registrar, creation date, nameservers) is stored on self.record for a
    future reverse_whois.py (paid/keyed: WhoisXML, DomainTools, ViewDNS) to
    pivot on.

    Uses RDAP (structured JSON over HTTPS, via the public rdap.org bootstrap
    redirector) rather than raw port-43 WHOIS — RDAP responses are far less
    fragile to parse than free-text WHOIS, which varies per registry/
    registrar, and rdap.org needs no key. Coverage gap: RDAP isn't deployed
    for every ccTLD yet, so some seed domains will legitimately come back
    empty — that's an honest result, not a bug. A raw-WHOIS fallback (e.g.
    python-whois) is a reasonable future addition if a specific ccTLD's lack
    of RDAP coverage turns out to matter.
    """

    name = "whois_lookup"
    requires_key = None
    produces_findings = False

    def __init__(self, config):
        super().__init__(config)
        self.record: dict = {}

    def run(self, domain: str) -> list[Finding]:
        logger.info("whois_lookup: querying RDAP for %s", domain)
        data = self._query_rdap(domain)
        if data is None:
            logger.info("whois_lookup: no RDAP data available for %s", domain)
            self.record = {}
            return []

        self.record = {
            "registrar": self._find_registrar(data),
            "registrant_org": self._find_registrant_field(data, "org"),
            "registrant_email": self._find_registrant_field(data, "email"),
            "creation_date": self._find_event_date(data, "registration"),
            "nameservers": [
                ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")
            ],
        }
        return []

    def _query_rdap(self, domain: str) -> dict | None:
        try:
            resp = requests.get(
                _RDAP_BOOTSTRAP_URL.format(domain=domain),
                timeout=_TIMEOUT,
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("whois_lookup: RDAP query failed for %s: %s", domain, exc)
            return None

    @staticmethod
    def _find_registrar(data: dict) -> str | None:
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                return WhoisLookupModule._vcard_value(entity, "fn")
        return None

    @staticmethod
    def _find_registrant_field(data: dict, field: str) -> str | None:
        """Registrant vcard `field` (org/email). Privacy-redacted records
        commonly omit the registrant role or the field entirely — None either
        way, which the caller treats as a normal, honest outcome."""
        for entity in data.get("entities", []):
            if "registrant" in entity.get("roles", []):
                value = WhoisLookupModule._vcard_value(entity, field)
                if value:
                    return value
        return None

    @staticmethod
    def _vcard_value(entity: dict, field: str) -> str | None:
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            return None
        for item in vcard[1]:
            if item and item[0] == field:
                value = item[3]
                if isinstance(value, list):
                    value = value[0] if value else None
                return value
        return None

    @staticmethod
    def _find_event_date(data: dict, action: str) -> str | None:
        for event in data.get("events", []):
            if event.get("eventAction") == action:
                return event.get("eventDate")
        return None
