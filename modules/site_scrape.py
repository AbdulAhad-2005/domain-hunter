import logging
import time
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
import tldextract
from bs4 import BeautifulSoup

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_USER_AGENT = "DomainHunter/0.1 (OSINT recon tool; respects robots.txt)"
_REQUEST_DELAY_SECONDS = 1.0
_MAX_RELATIONSHIP_PAGES = 8
_MAX_LINKS_PER_PAGE = 300

# Path fragments and link-text keywords that suggest a page lists affiliated
# orgs, joint ventures, subsidiaries, hosted projects, or partners -- the
# fuzzy organizational-relationship categories that live in prose on the
# org's own site, not in structured data (Wikidata/WHOIS/certs).
_RELATIONSHIP_HINTS = [
    "subsidiar", "joint-venture", "jointventure", "joint_venture", "investor",
    "group-compan", "group_compan", "groupcompan", "our-compan", "ourcompan",
    "affiliat", "partner", "about-us", "aboutus", "about",
]

# Domains that show up in nearly every site's nav/footer via social links,
# widgets, or CDN embeds -- not evidence of organizational relationship.
_EXCLUDED_DOMAINS = {
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "instagram.com", "pinterest.com", "tiktok.com", "whatsapp.com", "telegram.org",
    "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
    "googletagmanager.com", "doubleclick.net", "cloudflare.com", "cloudflareinsights.com",
    "wordpress.com", "wp.com", "jquery.com", "jsdelivr.net", "cdnjs.cloudflare.com",
    "bootstrapcdn.com", "fontawesome.com", "gravatar.com", "recaptcha.net",
    "w3.org", "schema.org", "wikipedia.org", "wikimedia.org", "apple.com",
    "microsoft.com", "adobe.com",
}


class SiteScrapeModule(ReconModule):
    """Self-fetches the seed's own homepage, plus a handful of likely
    "relationship" pages (subsidiaries, joint ventures, investors, group
    companies, affiliates, partners, about), to find outbound domains the
    organization lists itself.

    This is the highest-priority fix for a real recall gap: cleanly-owned
    subsidiaries with structured ownership data show up via knowledge_recon
    (Wikidata), but affiliated orgs (alumni associations, foundations),
    hosted projects/initiatives, and joint ventures with partial/shared
    ownership often live only in PROSE on the org's own website -- Wikidata
    frequently doesn't model them at all, or files a JV under the FOREIGN
    partner's entity instead. A link the org places on its own site pointing
    at another domain is about as direct as evidence gets, so these are
    "high" confidence; evidence records the exact source URL and link text.

    Judgment call, found by testing against nust.edu.pk: the motivating case
    (nstp.pk) turned out to be linked from a homepage feature/news card, not
    a nav/footer item, and NUST has no page matching the relationship-page
    path/text hints that links it either. A nav/footer-only reading of "the
    org lists it itself" would have missed the exact case this module exists
    for. So every external link on the homepage itself is treated as a
    candidate (same as a matched relationship page), not just nav/footer --
    this is what actually surfaced nstp.pk, plus two more plausible NUST
    entities (nustholdings.pk, nhtpl.pk) the relationship-page-only approach
    never would have found. The tradeoff is more noise (one borderline
    spam-looking homepage link surfaced in testing too), but evidence always
    includes the exact anchor text, so a human reviewer can judge it --
    transparency over pre-filtering, consistent with this project's
    "evidence over assertion" philosophy (PROJECT_OVERVIEW.md 2.4).

    Known limitation, found testing against hal-india.co.in: this module
    only parses the server-rendered HTML it fetches. HAL's homepage returned
    200 with a full 20KB page but zero <a> tags of any kind (16 <script>
    tags, a classic client-side-rendered SPA signature) -- its nav is built
    by JavaScript after load, which requests+BeautifulSoup cannot see.
    Handling that would mean a headless-browser dependency (Selenium/
    Playwright), a materially bigger addition than this pass should decide
    on its own -- flagged here rather than silently added.

    Deliberately NOT a crawler: fetches the homepage plus at most
    _MAX_RELATIONSHIP_PAGES matched relationship pages, one request at a time
    with a politeness delay, and respects robots.txt for every page after the
    homepage (the homepage itself is fetched unconditionally to discover
    robots.txt/links in the first place, same as fingerprint.py already does).
    """

    name = "site_scrape"
    requires_key = None

    def run(self, domain: str) -> list[Finding]:
        logger.info("site_scrape: fetching homepage + relationship pages for %s", domain)
        base_url, home_html = self._fetch(f"https://{domain}/")
        if home_html is None:
            base_url, home_html = self._fetch(f"http://{domain}/")
        if home_html is None:
            logger.warning("site_scrape: could not fetch homepage for %s over https or http", domain)
            return []

        robots = self._load_robots(base_url)
        home_links = self._extract_links(home_html, base_url)
        relationship_pages = self._pick_relationship_pages(home_links, domain)[:_MAX_RELATIONSHIP_PAGES]
        logger.info(
            "site_scrape: found %d candidate relationship page(s) out of %d total link(s) on the homepage",
            len(relationship_pages), len(home_links),
        )

        seen = {domain}
        findings = self._candidates_from_links(home_links, domain, base_url, seen)

        for page_url in relationship_pages:
            if robots and not robots.can_fetch(_USER_AGENT, page_url):
                logger.info("site_scrape: robots.txt disallows %s, skipping", page_url)
                continue
            time.sleep(_REQUEST_DELAY_SECONDS)
            _, page_html = self._fetch(page_url)
            if page_html is None:
                continue
            page_links = self._extract_links(page_html, page_url)[:_MAX_LINKS_PER_PAGE]
            findings.extend(self._candidates_from_links(page_links, domain, page_url, seen))

        return findings

    @staticmethod
    def _candidates_from_links(
        links: list[dict], domain: str, source_page: str, seen: set[str]
    ) -> list[Finding]:
        findings = []
        for link in links:
            candidate = SiteScrapeModule._registrable_domain(link["url"])
            if (
                not candidate
                or candidate == domain
                or candidate.endswith(f".{domain}")
                or candidate in seen
                or candidate in _EXCLUDED_DOMAINS
            ):
                continue
            seen.add(candidate)
            text_note = f' (link text: "{link["text"][:80]}")' if link["text"] else ""
            findings.append(Finding(
                seed_domain=domain,
                associated_domain=candidate,
                method="site_scrape",
                evidence=f"Linked from {domain}'s own site, on the page {source_page}{text_note}",
                raw_data={"source_page": source_page, "link": link["url"], "link_text": link["text"]},
                confidence="high",
            ))
        return findings

    def _fetch(self, url: str) -> tuple[str | None, str | None]:
        try:
            resp = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": _USER_AGENT})
            resp.raise_for_status()
            return resp.url, resp.text
        except requests.RequestException as exc:
            logger.info("site_scrape: fetch failed for %s: %s", url, exc)
            return None, None

    @staticmethod
    def _load_robots(base_url: str) -> RobotFileParser | None:
        robots_url = urljoin(base_url, "/robots.txt")
        parser = RobotFileParser()
        parser.set_url(robots_url)
        try:
            parser.read()
            return parser
        except Exception as exc:
            logger.info("site_scrape: could not read robots.txt at %s: %s", robots_url, exc)
            return None

    @staticmethod
    def _extract_links(html: str, base_url: str) -> list[dict]:
        """Returns [{"url": absolute_url, "text": anchor_text}, ...]."""
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            links.append({"url": urljoin(base_url, href), "text": (a.get_text() or "").strip()})
        return links

    @staticmethod
    def _pick_relationship_pages(links: list[dict], seed_domain: str) -> list[str]:
        matched = []
        seen_urls = set()
        for link in links:
            path = urlparse(link["url"]).path.lower()
            text = link["text"].lower()
            if not any(hint in path or hint in text for hint in _RELATIONSHIP_HINTS):
                continue
            # Stay on the seed's own site for relationship pages themselves --
            # an "About" link pointing at a *different* domain isn't a page of
            # the seed's own to read, it's already a candidate in its own right.
            host = urlparse(link["url"]).netloc.split(":")[0].lower()
            if not (host == seed_domain or host.endswith(f".{seed_domain}")):
                continue
            if link["url"] not in seen_urls:
                seen_urls.add(link["url"])
                matched.append(link["url"])
        return matched

    @staticmethod
    def _registrable_domain(url: str) -> str | None:
        ext = tldextract.extract(url)
        if not ext.domain or not ext.suffix:
            return None
        return f"{ext.domain}.{ext.suffix}"
