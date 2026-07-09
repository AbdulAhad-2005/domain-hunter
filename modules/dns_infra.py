import logging
import re

import dns.exception
import dns.resolver
import tldextract

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_TIMEOUT = 10

# Hostnames under these domains show up in MX/SPF records for huge numbers of
# unrelated organizations (shared mail/ESP providers), so they're not evidence
# of common ownership the way a same-org self-hosted mail domain would be.
# mgovcloud.in/nic.in added after testing against hal-india.co.in: NIC
# (National Informatics Centre) runs shared email infrastructure for the
# entire Indian government, so HAL sharing it with mgovcloud.in isn't
# evidence of a HAL-mgovcloud.in relationship any more than sharing Outlook
# is -- confirmed via NIC's own docs (mgovcloud.in hosts NICeMail, used
# across Central/State government ministries and departments).
_KNOWN_PROVIDER_DOMAINS = {
    "google.com", "googlemail.com", "outlook.com", "protection.outlook.com",
    "office365.com", "microsoft.com", "zoho.com", "mailgun.org", "sendgrid.net",
    "amazonses.com", "mimecast.com", "proofpoint.com", "pphosted.com",
    "mailchimp.com", "sparkpostmail.com", "postmarkapp.com", "messagelabs.com",
    "mgovcloud.in", "nic.in",
}


class DNSInfraModule(ReconModule):
    """NS/MX/TXT(SPF) recon on the seed domain.

    The real payoff of this technique (per PROJECT_OVERVIEW.md 4.1, "shared DNS
    infrastructure") is comparing two domains' NS/MX/SPF footprints against each
    other — that needs a second, already-known domain to compare against, which
    this module doesn't have on its own. So `run()` stores the seed's own record
    set on `self.records`, cleanly shaped for a future overlap-detection module
    to read after calling `run()` on two or more domains.

    In the meantime it still surfaces one real signal on its own: SPF
    `include:` targets and MX hostnames that point at a domain other than the
    seed and aren't a known third-party mail/ESP provider — that can mean
    centralized, self-hosted mail infrastructure shared across an
    organization's own domains.
    """

    name = "dns_infra"
    requires_key = None

    def __init__(self, config):
        super().__init__(config)
        self.records: dict = {}

    def run(self, domain: str) -> list[Finding]:
        logger.info("dns_infra: querying NS, MX, TXT records for %s", domain)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _TIMEOUT

        ns_records = self._query(resolver, domain, "NS")
        mx_records = self._query(resolver, domain, "MX")
        txt_records = self._query(resolver, domain, "TXT")

        spf_record = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
        spf_includes = self._parse_spf_includes(spf_record) if spf_record else []

        self.records = {
            "ns": ns_records,
            "mx": mx_records,
            "txt": txt_records,
            "spf_includes": spf_includes,
        }

        findings = []
        findings.extend(self._mx_candidates(domain, mx_records))
        findings.extend(self._spf_candidates(domain, spf_includes))
        return findings

    def _query(self, resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list[str]:
        try:
            answer = resolver.resolve(domain, rtype)
            # TXT records come back from dnspython wrapped in literal quotes
            # (e.g. '"v=spf1 ..."') — strip them so downstream string matching works.
            return [str(r).strip('"').rstrip(".") for r in answer]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            logger.warning("dns_infra: %s does not exist (NXDOMAIN)", domain)
            return []
        except dns.exception.DNSException as exc:
            logger.warning("dns_infra: %s lookup failed for %s: %s", rtype, domain, exc)
            return []

    @staticmethod
    def _parse_spf_includes(spf_record: str) -> list[str]:
        return re.findall(r"include:([\w.-]+)", spf_record)

    def _mx_candidates(self, domain: str, mx_records: list[str]) -> list[Finding]:
        findings = []
        for mx in mx_records:
            host = mx.split()[-1].rstrip(".")  # "10 mail.example.com" -> "mail.example.com"
            host_domain = self._registrable_guess(host)
            if host_domain and host_domain != domain and not self._is_known_provider(host_domain):
                findings.append(Finding(
                    seed_domain=domain,
                    associated_domain=host_domain,
                    method="mx_overlap",
                    evidence=f"{domain}'s MX record points to {host}, hosted on {host_domain}",
                    raw_data={"mx_record": mx},
                    confidence="low",
                ))
        return findings

    def _spf_candidates(self, domain: str, spf_includes: list[str]) -> list[Finding]:
        findings = []
        for include in spf_includes:
            if (
                include != domain
                and not include.endswith(f".{domain}")
                and not self._is_known_provider(include)
            ):
                findings.append(Finding(
                    seed_domain=domain,
                    associated_domain=include,
                    method="spf_include",
                    evidence=f"{domain}'s SPF record includes {include}",
                    raw_data={"spf_include": include},
                    confidence="low",
                ))
        return findings

    @staticmethod
    def _is_known_provider(host_domain: str) -> bool:
        return any(
            host_domain == provider or host_domain.endswith(f".{provider}")
            for provider in _KNOWN_PROVIDER_DOMAINS
        )

    @staticmethod
    def _registrable_guess(hostname: str) -> str | None:
        """Registrable (eTLD+1) domain via the public suffix list, so multi-part
        TLDs like .net.pk or .co.uk resolve correctly (e.g. zmail.ptcl.net.pk ->
        ptcl.net.pk, not the bare suffix net.pk)."""
        ext = tldextract.extract(hostname)
        if not ext.domain or not ext.suffix:
            return None
        return f"{ext.domain}.{ext.suffix}"
