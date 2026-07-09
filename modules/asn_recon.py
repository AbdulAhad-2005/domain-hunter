import logging

import dns.exception
import dns.resolver
import requests

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"
_TIMEOUT = 15


class ASNReconModule(ReconModule):
    """ASN / IP block ownership recon via bgpview.io (free, no key).

    Resolves the seed domain's A record(s), then asks bgpview.io which ASN
    and IP prefix (CIDR block) each IP belongs to.

    Judgment call: bgpview has no hostname/reverse-DNS data, so there's no
    way to turn "same ASN" into a list of *other domains* without actively
    reverse-DNS-sweeping someone else's IP space — which this tool doesn't do
    (no active scanning, CLAUDE.md rule 4). So the seed's own announced CIDR
    block is surfaced as the discovered asset instead (low confidence — it's
    infrastructure metadata about the seed itself, not independent evidence
    of a second organization asset). The full ASN + prefix list is also
    stored on self.asn_info for a future module to cross-reference against
    other already-discovered domains' ASN footprints, which is where this
    technique's real signal is (two *different* domains sharing an ASN).
    """

    name = "asn_recon"
    requires_key = None

    def __init__(self, config):
        super().__init__(config)
        self.asn_info: dict = {}

    def run(self, domain: str) -> list[Finding]:
        logger.info("asn_recon: resolving A record(s) for %s, then querying bgpview.io for ASN/prefix", domain)
        ips = self._resolve_a_records(domain)
        if not ips:
            logger.info("asn_recon: no resolvable A record for %s", domain)
            return []

        findings = []
        seen_prefixes = set()
        asn_records = []
        for ip in ips:
            data = self._query_bgpview(ip)
            if data is None:
                continue
            for prefix in data.get("prefixes", []):
                cidr = prefix.get("prefix")
                asn = prefix.get("asn") or {}
                if not cidr or cidr in seen_prefixes:
                    continue
                seen_prefixes.add(cidr)
                asn_records.append({"ip": ip, "prefix": cidr, "asn": asn})

                asn_number = asn.get("asn")
                asn_name = asn.get("name") or asn.get("description") or "unknown"
                findings.append(Finding(
                    seed_domain=domain,
                    associated_domain=cidr,
                    method="asn_ip_block",
                    evidence=(
                        f"{domain} resolves to {ip}, part of {cidr}, "
                        f"announced by AS{asn_number} ({asn_name})"
                    ),
                    raw_data={"ip": ip, "prefix": prefix},
                    confidence="low",
                ))

        self.asn_info = {"ips": ips, "records": asn_records}
        return findings

    def _resolve_a_records(self, domain: str) -> list[str]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 10
            answer = resolver.resolve(domain, "A")
            return [str(r) for r in answer]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            logger.warning("asn_recon: %s does not exist (NXDOMAIN)", domain)
            return []
        except dns.exception.DNSException as exc:
            logger.warning("asn_recon: A record lookup failed for %s: %s", domain, exc)
            return []

    def _query_bgpview(self, ip: str) -> dict | None:
        try:
            resp = requests.get(_BGPVIEW_IP_URL.format(ip=ip), timeout=_TIMEOUT)
            resp.raise_for_status()
            payload = resp.json()
            if payload.get("status") != "ok":
                return None
            return payload.get("data")
        except (requests.RequestException, ValueError) as exc:
            logger.warning("asn_recon: bgpview query failed for %s: %s", ip, exc)
            return None
