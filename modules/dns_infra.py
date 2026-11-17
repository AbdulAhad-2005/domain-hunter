import logging
import re

import dns.exception
import dns.resolver
import tldextract

from core.models import Finding
from modules.base import ReconModule
from modules.corroboration import _brand_tokens, _shares_brand_token

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
        logger.info("dns_infra: querying NS, MX, TXT, DMARC records for %s", domain)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _TIMEOUT

        ns_records = self._query(resolver, domain, "NS")
        mx_records = self._query(resolver, domain, "MX")
        txt_records = self._query(resolver, domain, "TXT")
        dmarc_records = self._query(resolver, f"_dmarc.{domain}", "TXT")

        spf_record = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
        spf_includes = self._parse_spf_includes(spf_record) if spf_record else []
        dmarc_rua = self._parse_dmarc_rua(dmarc_records)

        self.records = {
            "ns": ns_records,
            "mx": mx_records,
            "txt": txt_records,
            "spf_includes": spf_includes,
            "dmarc_rua": dmarc_rua,
        }

        brand_tokens = _brand_tokens(domain)

        findings = []
        findings.extend(self._mx_candidates(domain, mx_records, brand_tokens))
        findings.extend(self._spf_candidates(domain, spf_includes, brand_tokens))
        findings.extend(self._dmarc_candidates(domain, dmarc_rua, brand_tokens))
        return findings

    @staticmethod
    def _parse_dmarc_rua(dmarc_records: list[str]) -> list[str]:
        rua_domains = []
        for txt in dmarc_records:
            if not txt.lower().startswith("v=dmarc1"):
                continue
            for part in txt.split(";"):
                part = part.strip()
                if part.lower().startswith("rua="):
                    for uri in part.split("=", 1)[1].split(","):
                        uri = uri.strip().removeprefix("mailto:")
                        if "@" in uri:
                            host = uri.split("@")[-1].strip().lower()
                            if host and host not in rua_domains:
                                rua_domains.append(host)
        return rua_domains

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

    def _mx_candidates(self, domain: str, mx_records: list[str], brand_tokens: list[str]) -> list[Finding]:
        findings = []
        for mx in mx_records:
            host = mx.split()[-1].rstrip(".")  # "10 mail.example.com" -> "mail.example.com"
            host_domain = self._registrable_guess(host)
            if not host_domain or host_domain == domain or self._is_known_provider(host_domain):
                continue

            # Affiliation gate: self-hosted infra sharing the brand token is a genuine sister domain.
            # External providers/relays that don't share the brand token are third parties, not sisters.
            if not _shares_brand_token(host_domain, brand_tokens):
                continue

            findings.append(Finding(
                seed_domain=domain,
                associated_domain=host_domain,
                method="self_hosted_mail",
                evidence=f"Self-hosted mail infra: {domain}'s MX points to {host} ({host_domain}) sharing brand token",
                raw_data={"mx_record": mx, "shares_brand": True},
                confidence="high",
            ))
        return findings

    def _spf_candidates(self, domain: str, spf_includes: list[str], brand_tokens: list[str]) -> list[Finding]:
        findings = []
        for include in spf_includes:
            if (
                include == domain
                or include.endswith(f".{domain}")
                or self._is_known_provider(include)
            ):
                continue

            inc_domain = self._registrable_guess(include) or include
            if inc_domain == domain or self._is_known_provider(inc_domain):
                continue

            if not _shares_brand_token(inc_domain, brand_tokens):
                continue

            findings.append(Finding(
                seed_domain=domain,
                associated_domain=inc_domain,
                method="self_hosted_spf",
                evidence=f"Self-hosted SPF infra: {domain}'s SPF includes {include} ({inc_domain}) sharing brand token",
                raw_data={"spf_include": include, "shares_brand": True},
                confidence="high",
            ))
        return findings

    def _dmarc_candidates(self, domain: str, dmarc_rua: list[str], brand_tokens: list[str]) -> list[Finding]:
        findings = []
        for rua in dmarc_rua:
            rua_domain = self._registrable_guess(rua) or rua
            if (
                rua_domain == domain
                or rua_domain.endswith(f".{domain}")
                or self._is_known_provider(rua_domain)
            ):
                continue

            if not _shares_brand_token(rua_domain, brand_tokens):
                continue

            findings.append(Finding(
                seed_domain=domain,
                associated_domain=rua_domain,
                method="self_hosted_dmarc",
                evidence=f"Self-hosted DMARC reporting: {domain}'s DMARC rua points to {rua} sharing brand token",
                raw_data={"dmarc_rua": rua, "shares_brand": True},
                confidence="high",
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
