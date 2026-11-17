import hashlib
import logging
import re
from dataclasses import dataclass, field

import dns.exception
import dns.resolver
import requests
import tldextract

logger = logging.getLogger(__name__)

_DNS_TIMEOUT = 4.0
_HTTP_TIMEOUT = 8.0
_USER_AGENT = "DomainHunter/0.1"
_BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"

# Generic single words that routinely show up in titles/domains and would
# otherwise become a "brand token" matching unrelated domains.
_BRAND_STOPWORDS = frozenset({
    "the", "and", "for", "new", "live", "news", "latest", "breaking", "today",
    "daily", "online", "watch", "video", "report", "update", "updates", "show",
    "home", "official", "website", "network", "group", "media", "www",
    "site", "sites", "page", "pages", "portal", "welcome", "world", "global",
    "store", "shop", "app", "apps", "mobile", "digital", "tv",
})


def _safe_tokens(text: str) -> list[str]:
    tokens = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]{2,}", text):
        cleaned = token.lower().strip("-.")
        if cleaned and cleaned not in tokens:
            tokens.append(cleaned)
    return tokens


def _seed_base_tokens(seed_root: str) -> list[str]:
    """Brand tokens from the seed's own label. Digit-led labels keep only the
    collapsed form ('1800flowers'); letter labels keep their word fragments."""
    base = seed_root.split(".")[0].lower()
    if base[:1].isdigit():
        collapsed = re.sub(r"[^a-z0-9]", "", base)
        return [collapsed] if len(collapsed) >= 3 else []
    tokens = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]{2,}", base):
        cleaned = token.strip("-.")
        if cleaned and cleaned not in tokens:
            tokens.append(cleaned)
    collapsed = re.sub(r"[^a-z0-9]", "", base)
    if collapsed and collapsed not in tokens:
        tokens.append(collapsed)
    return tokens


def _brand_tokens(seed_root: str, title_text: str = "") -> list[str]:
    tokens = list(_seed_base_tokens(seed_root))
    for token in _safe_tokens(title_text):
        if token not in tokens and token not in _BRAND_STOPWORDS and len(token) > 3:
            tokens.append(token)
    return tokens[:8]


def _shares_brand_token(domain: str, brand_tokens: list[str]) -> bool:
    """True when the candidate's label contains a seed brand token.
    Forward substring only (geo -> geoit, tesla -> teslamotors)."""
    label = domain.split(".")[0].lower()
    collapsed = re.sub(r"[^a-z0-9]", "", label)
    for token in brand_tokens:
        if len(token) >= 3 and token in collapsed:
            return True
    return False

# Substrings of shared mail/ESP and DNS-hosting providers used by huge
# numbers of unrelated organizations -- an NS/MX match against one of these
# is not evidence of common ownership (caught testing: nust.edu.pk and
# nust.info both use Outlook for mail, which is true of millions of
# unrelated domains and would otherwise have wrongly corroborated
# nust.info as "medium" confidence). Substring rather than exact-suffix
# matching because provider hostnames vary a lot (e.g. AWS Route53
# nameservers look like "ns-123.awsdns-45.com", "ns-6.awsdns-78.org", ...).
_SHARED_INFRA_MARKERS = [
    "google.com", "googlemail.com", "outlook.com", "office365.com", "microsoft.com",
    "zoho.com", "mailgun.org", "sendgrid.net", "amazonses.com", "mimecast.com",
    "proofpoint.com", "pphosted.com", "mailchimp.com", "sparkpostmail.com",
    "postmarkapp.com", "messagelabs.com",
    "cloudflare", "godaddy", "domaincontrol", "awsdns", "namecheaphosting",
    "registrar-servers", "dnsmadeeasy", "digitalocean", "azure-dns",
    "googledomains", "domains.google", "hostgator", "bluehost", "dreamhost",
    "wixdns", "squarespacedns",
    # NIC (National Informatics Centre) runs shared email/cloud infra for the
    # entire Indian government -- found testing against hal-india.co.in,
    # same class of false positive as Outlook (see dns_infra.py).
    "mgovcloud.in", "nic.in",
]


def _is_shared_infra(hostname: str) -> bool:
    return any(marker in hostname for marker in _SHARED_INFRA_MARKERS)

# Corroboration signals strong enough on their own to justify "high"
# confidence: another independent discovery method (crt.sh, Wikidata,
# site_scrape) already found this exact domain, or its WHOIS registrant
# matches the seed's. Infra-overlap signals (NS/MX/ASN/favicon) are weaker
# -- shared hosting/reseller/CDN/template reuse can produce these between
# genuinely unrelated domains -- so they only earn "medium".
STRONG_SIGNALS = {"known_domain", "whois_org"}


@dataclass
class SeedContext:
    """Everything gathered about the seed domain by other modules this run,
    used to corroborate a *candidate* domain found by tld_variants.py /
    pattern_gen.py / ai_hunt.py. A bare resolving guess is not evidence of
    common ownership (nust.com and nust.net both resolve; neither has
    anything to do with nust.edu.pk) -- corroboration is what turns a lead
    into a finding."""
    known_domains: set[str] = field(default_factory=set)
    seed_registrant_org: str | None = None
    seed_ns: set[str] = field(default_factory=set)
    seed_mx_domains: set[str] = field(default_factory=set)
    seed_asns: set[int] = field(default_factory=set)
    seed_favicon_md5: str | None = None
    seed_brand_tokens: list[str] = field(default_factory=list)


def corroborate(candidate: str, seed_domain: str, context: "SeedContext | None") -> tuple[str | None, str | None]:
    """Checks `candidate` against everything known about the seed. Returns
    (signal_key, human-readable note) on the first corroborating signal
    found, or (None, None) if nothing corroborates it -- in which case the
    caller should treat `candidate` as an unconfirmed lead, not a finding.

    Cheapest/most reliable checks run first; network-dependent checks
    (WHOIS/DNS/ASN/favicon on the *candidate*) only run if a `context` with
    something to compare against was actually supplied.
    """
    if context is None:
        return None, None

    if candidate in context.known_domains:
        return "known_domain", "independently found by another discovery method this run"

    if context.seed_registrant_org:
        org = _whois_org(candidate)
        if org and org.strip().lower() == context.seed_registrant_org.strip().lower():
            return "whois_org", f'WHOIS registrant org "{org}" matches the seed\'s'

    if context.seed_ns or context.seed_mx_domains:
        signal = _dns_overlap(candidate, context)
        if signal:
            return signal

    if context.seed_asns:
        signal = _asn_overlap(candidate, context.seed_asns)
        if signal:
            return signal

    if context.seed_favicon_md5:
        candidate_hash = _favicon_md5(candidate)
        if candidate_hash and candidate_hash == context.seed_favicon_md5:
            return "favicon_hash", "identical favicon MD5 hash to the seed"

    if context.seed_brand_tokens and _shares_brand_token(candidate, context.seed_brand_tokens):
        return "brand_token", f"candidate label matches seed brand token(s) {context.seed_brand_tokens}"

    return None, None


def _whois_org(candidate: str) -> str | None:
    # Imported lazily to avoid a hard import-time dependency loop (whois_lookup
    # doesn't import this module, but keeping the coupling one-directional and
    # explicit here is cheap insurance).
    from modules.whois_lookup import WhoisLookupModule
    from config import APIConfig

    module = WhoisLookupModule(APIConfig({}))
    try:
        module.run(candidate)
    except Exception as exc:
        logger.debug("corroboration: WHOIS check failed for %s: %s", candidate, exc)
        return None
    return module.record.get("registrant_org")


def _dns_overlap(candidate: str, context: SeedContext) -> tuple[str, str] | None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT

    try:
        ns = {str(r).rstrip(".").lower() for r in resolver.resolve(candidate, "NS")}
    except dns.exception.DNSException:
        ns = set()
    ns = {n for n in ns if not _is_shared_infra(n)}
    seed_ns = {n.lower() for n in context.seed_ns if not _is_shared_infra(n.lower())}
    shared_ns = ns & seed_ns
    if shared_ns:
        return "shared_ns", f"shares nameserver(s) {', '.join(sorted(shared_ns))} with the seed"

    try:
        mx = {str(r).split()[-1].rstrip(".").lower() for r in resolver.resolve(candidate, "MX")}
    except dns.exception.DNSException:
        mx = set()
    mx = {h for h in mx if not _is_shared_infra(h)}
    mx_domains = {_registrable(h) for h in mx if _registrable(h)}
    seed_mx_domains = {m.lower() for m in context.seed_mx_domains if not _is_shared_infra(m.lower())}
    shared_mx = mx_domains & seed_mx_domains
    if shared_mx:
        return "shared_mx", f"shares mail infrastructure ({', '.join(sorted(shared_mx))}) with the seed"

    return None


def _asn_overlap(candidate: str, seed_asns: set[int]) -> tuple[str, str] | None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    try:
        ip = str(resolver.resolve(candidate, "A")[0])
    except dns.exception.DNSException:
        return None

    try:
        resp = requests.get(_BGPVIEW_IP_URL.format(ip=ip), timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("status") != "ok":
            return None
        candidate_asns = {
            p["asn"]["asn"] for p in payload.get("data", {}).get("prefixes", [])
            if p.get("asn", {}).get("asn")
        }
    except (requests.RequestException, ValueError, KeyError) as exc:
        logger.debug("corroboration: ASN check failed for %s: %s", candidate, exc)
        return None

    shared = candidate_asns & seed_asns
    if shared:
        return "shared_asn", f"resolves within the same ASN(s) ({', '.join(f'AS{a}' for a in sorted(shared))}) as the seed"
    return None


def _favicon_md5(candidate: str) -> str | None:
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{candidate}/favicon.ico", timeout=_HTTP_TIMEOUT,
                headers={"User-Agent": _USER_AGENT},
            )
            resp.raise_for_status()
            if resp.content:
                return hashlib.md5(resp.content).hexdigest()
        except requests.RequestException:
            continue
    return None


def _registrable(hostname: str) -> str | None:
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"
