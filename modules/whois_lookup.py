import logging
from urllib.parse import quote_plus

import requests
import tldextract

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"
_TIMEOUT = 15

# WHOIS privacy / registrar / forwarding apexes: when a seed uses privacy
# protection the registrant is the privacy service, and reverse WHOIS on it
# would return thousands of unrelated domains.
_REGISTRAR_DOMAINS = frozenset({
    "enom.com", "enom.net", "whoisguard.com", "whoisprivacyservices.com",
    "domainsbyproxy.com", "privacyprotect.org", "contactprivacy.com",
    "withheldforprivacy.com", "perfectprivacy.com", "namecheap.com",
    "namesilo.com", "godaddy.com", "web.com", "squarespace.com",
    "google.com", "googleapis.com", "cloudflare.com", "redactedforprivacy.com",
    "dataprotected.com", "privatewhois.net", "hostedemail.com", "forwardemail.net",
})


class WhoisLookupModule(ReconModule):
    """Forward WHOIS/RDAP lookup on the seed domain with optional Whoxy reverse WHOIS.

    Free tier: Forward lookup via RDAP (rdap.org) on the seed domain only.
    Populates self.record (registrant org/email, registrar, creation date,
    nameservers) for downstream corroboration without emitting findings.

    Paid tier (whoxy_api_key configured or WHOXY_API_KEY env): Queries Whoxy for
    structured WHOIS data and executes reverse WHOIS pivoting across registrant
    email, company name, and full name (filtering registrar privacy proxies),
    producing high-confidence associated domain findings.
    """

    name = "whois_lookup"
    requires_key = "whoxy"
    has_free_fallback = True

    def __init__(self, config):
        super().__init__(config)
        self.record: dict = {}
        self.produces_findings = self.enabled_tier == "paid"

    def run(self, domain: str) -> list[Finding]:
        if self.enabled_tier == "paid":
            api_key = self.config.get("whoxy_api_key")
            findings = self._query_whoxy(domain, api_key)
            if self.record:
                return findings
            # Fall back to RDAP for self.record if Whoxy was empty or failed
            logger.info("whois_lookup: Whoxy returned no record for %s, falling back to RDAP", domain)

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

    def _query_whoxy(self, domain: str, api_key: str) -> list[Finding]:
        whoxy_data = self._whoxy_whois(domain, api_key)
        if not whoxy_data:
            return []

        contact = whoxy_data.get("registrant_contact", {})
        email = contact.get("email_address", "").strip()
        org = contact.get("company_name", "").strip()
        name = contact.get("full_name", "").strip()

        self.record = {
            "registrar": whoxy_data.get("domain_registrar", {}).get("registrar_name"),
            "registrant_org": org or None,
            "registrant_email": email or None,
            "creation_date": whoxy_data.get("create_date"),
            "nameservers": [
                ns.strip() for ns in whoxy_data.get("name_servers", []) if ns.strip()
            ],
        }

        queries = []
        if email and "@" in email:
            queries.append(("email", email))
        if org and len(org) >= 3:
            queries.append(("company", org))
        if name and len(name) >= 3:
            queries.append(("name", name))

        findings: list[Finding] = []
        seen: set[str] = set()

        for field_name, value in queries:
                        low = value.lower()
            if (
                any(w in low for w in ("privacy", "proxy", "redacted", "protected", "withheld", "whoisguard"))
                or low.split("@")[-1] in _REGISTRAR_DOMAINS
            ):
                continue
            url = f"https://api.whoxy.com/?key={api_key}&reverse=whois&{field_name}={quote_plus(value)}&mode=domains"
            try:
                resp = requests.get(url, timeout=_TIMEOUT)
                if not resp.ok:
                    continue
                data = resp.json()
            except (requests.RequestException, ValueError) as exc:
                logger.debug("whois_lookup: Whoxy reverse WHOIS failed for %s=%s: %s", field_name, value, exc)
                continue

            for d in data.get("domains_list", []):
                val = str(d).strip().lower()
                if not val:
                    continue
                ext = tldextract.extract(val)
                if not (ext.domain and ext.suffix):
                    continue
                rd = f"{ext.domain}.{ext.suffix}"
                if rd == domain or rd in seen:
                    continue
                if rd in _REGISTRAR_DOMAINS:
                    continue
                seen.add(rd)
                findings.append(
                    Finding(
                        seed_domain=domain,
                        associated_domain=rd,
                        method="reverse_whois",
                        evidence=f"same WHOIS registrant ({field_name}: {value}) as {domain}",
                        raw_data={"field": field_name, "value": value},
                        confidence="high",
                    )
                )

        return findings

    def _whoxy_whois(self, domain: str, api_key: str) -> dict | None:
        url = f"https://api.whoxy.com/?key={api_key}&whois={quote_plus(domain)}"
        try:
            resp = requests.get(url, timeout=_TIMEOUT)
            if not resp.ok:
                return None
            data = resp.json()
            if data.get("status") != 1:
                return None
            return data.get("whois_data", {})
        except (requests.RequestException, ValueError) as exc:
            logger.warning("whois_lookup: Whoxy query failed for %s: %s", domain, exc)
            return None

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
