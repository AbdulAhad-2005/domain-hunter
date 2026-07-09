import concurrent.futures
import logging

import dns.exception
import dns.resolver
import requests

logger = logging.getLogger(__name__)

_DNS_TIMEOUT = 4.0
_HTTP_TIMEOUT = 6.0
_MAX_WORKERS = 20
_USER_AGENT = "DomainHunter/0.1"


def check_live(domain: str) -> tuple[bool, dict]:
    """Live = DNS resolves AND responds over HTTP/HTTPS -- a factual liveness
    check, deliberately independent of relationship confidence (a domain can
    be live but unrelated, e.g. a registry operator turning up as a false
    positive, or dead but historically related, e.g. a decommissioned former
    subsidiary). Returns (is_live, detail); detail records which DNS record
    type and which HTTP scheme responded, for raw_data.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    dns_record_type = None
    for rtype in ("A", "AAAA"):
        try:
            resolver.resolve(domain, rtype)
            dns_record_type = rtype
            break
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException:
            break

    if dns_record_type is None:
        return False, {"dns_resolves": False, "http_scheme": None, "http_status": None}

    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}/",
                timeout=_HTTP_TIMEOUT,
                headers={"User-Agent": _USER_AGENT},
                allow_redirects=True,
            )
            return True, {
                "dns_resolves": True,
                "dns_record_type": dns_record_type,
                "http_scheme": scheme,
                "http_status": resp.status_code,
            }
        except requests.RequestException:
            continue

    return False, {
        "dns_resolves": True,
        "dns_record_type": dns_record_type,
        "http_scheme": None,
        "http_status": None,
    }


def check_live_many(domains: list[str], max_workers: int = _MAX_WORKERS) -> dict[str, tuple[bool, dict]]:
    """Checks many domains concurrently (independent I/O-bound lookups)."""
    results: dict[str, tuple[bool, dict]] = {}
    if not domains:
        return results
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_domain = {pool.submit(check_live, d): d for d in domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception as exc:
                logger.debug("liveness: check failed for %s: %s", domain, exc)
                results[domain] = (False, {"error": str(exc)})
    return results
