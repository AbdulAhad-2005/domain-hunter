import concurrent.futures
import logging

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 3.0
_DEFAULT_MAX_WORKERS = 30


def verify(candidate: str, timeout: float = _DEFAULT_TIMEOUT) -> tuple[bool, str | None]:
    """Checks whether `candidate` is a real, registered domain.

    Returns (True, ip) if it has an A/AAAA record. Returns (True, None) if it
    has no A/AAAA but does have NS delegation -- a legitimate domain can be
    infrastructure-only (mail/DNS zone) with nothing listening on the bare
    apex; treating that as "doesn't exist" is a real false negative (caught
    testing tld_variants.py against ptcl.net.pk, which has MX/NS records but
    no apex A/AAAA). Returns (False, None) if NXDOMAIN or unreachable.

    A short per-lookup timeout keeps bulk candidate sweeps (tld_variants,
    pattern_gen) reasonably fast even when some candidates never answer at
    all -- the default dnspython timeout can otherwise cost 8+ seconds per
    candidate, per record type checked.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    for rtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(candidate, rtype)
            return True, str(answer[0])
        except dns.resolver.NXDOMAIN:
            return False, None
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            logger.debug("dns_utils: %s lookup failed for %s: %s", rtype, candidate, exc)
            continue

    try:
        resolver.resolve(candidate, "NS")
        return True, None
    except dns.exception.DNSException:
        return False, None


def resolve_many(
    candidates: list[str], timeout: float = _DEFAULT_TIMEOUT, max_workers: int = _DEFAULT_MAX_WORKERS
) -> dict[str, str | None]:
    """Verifies many candidates concurrently (independent I/O-bound lookups).
    Returns {candidate: ip} for verified ones -- ip is None for a domain
    that's registered/delegated but has no direct A/AAAA record."""
    results: dict[str, str | None] = {}
    if not candidates:
        return results
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_candidate = {pool.submit(verify, c, timeout): c for c in candidates}
        for future in concurrent.futures.as_completed(future_to_candidate):
            verified, ip = future.result()
            if verified:
                results[future_to_candidate[future]] = ip
    return results
