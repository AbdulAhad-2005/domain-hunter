import logging

import requests

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_CRTSH_URL = "https://crt.sh/"
_TIMEOUT = 30


class CertsModule(ReconModule):
    """Certificate transparency search via crt.sh (free, no key required).

    crt.sh's JSON output doesn't expose the certificate Subject's Organization
    field, only the CN/SAN identities. So instead of an org-name pivot, this
    module flags domains that co-occur with the seed domain in the SAN list of
    the same certificate — a company doesn't usually put a stranger's domain
    on its own multi-domain cert.

    Censys is the spec'd paid/keyed upgrade for this module (PROJECT_OVERVIEW.md
    4.1) but is NOT wired up here yet. Confirmed against Censys's own docs
    (docs.censys.com, checked 2026-07-07): the Platform API's free tier only
    exposes single-item LOOKUP endpoints (get host, get certificate, get web
    property, and their bulk "retrieve multiple" variants) — no search/query
    endpoints. Certificate data is visible on the free tier but "not all is
    searchable"; full certificate search, including by organization field
    (the actual capability this module would want), requires the Starter tier
    or higher. So there is no free Censys path for a cert-org-field pivot —
    Censys integration, when built, will need a paid key and should be an
    additive upgrade alongside crt.sh, not a replacement for it. The free path
    stays crt.sh + Shodan (Shodan's free-tier favicon search, once
    fingerprint.py's Shodan step exists) only.

    Auth note for that future work: Censys Platform API uses a single bearer
    Personal Access Token (Authorization: Bearer <token>), not the legacy
    API ID + Secret pair — see config.py's censys_personal_access_token /
    censys_organization_id.
    """

    name = "certs"
    requires_key = None

    def run(self, domain: str) -> list[Finding]:
        logger.info("certs: querying crt.sh for certificates matching %%.%s", domain)
        rows = self._query_crtsh(domain)
        if not rows:
            logger.info("certs: no crt.sh results for %s", domain)
            return []

        findings = []
        seen = {domain}
        for row in rows:
            names = self._extract_names(row)

            # crt.sh's identity search does fuzzy/substring matching and can return
            # certs that don't actually reference our domain at all (e.g. querying
            # "%.stripe.com" surfaces "admin--stripe.com"). Only trust rows that
            # genuinely list the seed domain (or a subdomain of it) as one of their
            # own SANs — that's what makes the *other* SANs meaningful evidence.
            if not any(n == domain or n.endswith(f".{domain}") for n in names):
                continue

            cert_id = row.get("id")
            for name in names:
                if name in seen or self._same_registrable_domain(domain, name) or not self._looks_like_hostname(name):
                    continue
                seen.add(name)
                findings.append(Finding(
                    seed_domain=domain,
                    associated_domain=name,
                    method="cert_san_match",
                    evidence=(
                        f"Appears alongside {domain} in the SAN list of the same "
                        f"certificate (crt.sh id {cert_id})"
                    ),
                    raw_data=row,
                    confidence="medium",
                ))
        return findings

    def _query_crtsh(self, domain: str) -> list[dict]:
        try:
            resp = requests.get(
                _CRTSH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("certs: crt.sh query failed for %s: %s", domain, exc)
            return []

    @staticmethod
    def _extract_names(row: dict) -> set[str]:
        raw = row.get("name_value", "")
        return {n.strip().lstrip("*.").lower() for n in raw.splitlines() if n.strip()}

    @staticmethod
    def _same_registrable_domain(domain: str, name: str) -> bool:
        """True if `name` is the seed domain itself or a subdomain of it."""
        return name == domain or name.endswith(f".{domain}")

    @staticmethod
    def _looks_like_hostname(name: str) -> bool:
        """Filters out non-hostname SAN entries crt.sh can include, e.g. rfc822Name
        (email address) SANs like "sys@stripe.com"."""
        return "@" not in name and "." in name
