import base64
import binascii
import hashlib
import logging
import re
from urllib.parse import quote_plus, urljoin

import requests
import tldextract
from bs4 import BeautifulSoup

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_USER_AGENT = "Mozilla/5.0 (compatible; DomainHunter/0.1)"

_GA_UA_RE = re.compile(r"UA-\d{4,10}-\d{1,4}")
_GA4_RE = re.compile(r"\bG-[A-Z0-9]{6,10}\b")
_GTM_RE = re.compile(r"\bGTM-[A-Z0-9]{4,8}\b")
_FB_PIXEL_RE = re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]")
_FB_PIXEL_URL_RE = re.compile(r"facebook\.com/tr\?id=(\d{10,20})")


class FingerprintModule(ReconModule):
    """Web fingerprinting on the seed domain's own homepage with free tracker pivoting.

    Self-fetches the homepage HTML and extracts tracking/analytics IDs (GA
    Universal/GA4, GTM, Facebook Pixel) via regex, page title, plus the favicon's
    MD5 hash.

    Pivots on extracted tracker IDs using urlscan.io's free search API (no key
    needed) to discover associated domains sharing the same tracking/analytics
    infrastructure.
    """

    name = "fingerprint"
    requires_key = None
    produces_findings = True

    def __init__(self, config):
        super().__init__(config)
        self.fingerprint: dict = {}

    def run(self, domain: str) -> list[Finding]:
        logger.info("fingerprint: fetching homepage + favicon for %s", domain)
        html, base_url = self._fetch_homepage(domain)
        if html is None:
            self.fingerprint = {}
            return []

        title = self._find_title(html)
        ga_id = self._first_match(_GA_UA_RE, html) or self._first_match(_GA4_RE, html)
        gtm_id = self._first_match(_GTM_RE, html)
        fb_pixel_id = (
            self._first_match(_FB_PIXEL_RE, html) or self._first_match(_FB_PIXEL_URL_RE, html)
        )
        favicon_md5 = self._favicon_md5(html, base_url)

        self.fingerprint = {
            "title": title,
            "ga_id": ga_id,
            "gtm_id": gtm_id,
            "fb_pixel_id": fb_pixel_id,
            "favicon_md5": favicon_md5,
        }

        tracker_ids: list[str] = []
        for pat in (_GA_UA_RE, _GA4_RE, _GTM_RE):
            for m in pat.findall(html):
                if m not in tracker_ids:
                    tracker_ids.append(m)
        for pat in (_FB_PIXEL_RE, _FB_PIXEL_URL_RE):
            for m in pat.findall(html):
                val = m if isinstance(m, str) else m[0]
                if val and val not in tracker_ids:
                    tracker_ids.append(val)

        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for tid in tracker_ids[:5]:
            discovered = self._pivot_tracker_urlscan(tid, domain)
            for assoc in discovered:
                if assoc != domain and assoc not in seen_domains:
                    seen_domains.add(assoc)
                    findings.append(
                        Finding(
                            seed_domain=domain,
                            associated_domain=assoc,
                            method="tracker_pivot",
                            evidence=f"shared analytics/pixel ID {tid} with {domain}",
                            raw_data={"tracker_id": tid},
                            confidence="high",
                        )
                    )

        return findings

    def _pivot_tracker_urlscan(self, tracker_id: str, seed_domain: str) -> list[str]:
        """Query urlscan.io free search API for pages sharing this tracker ID."""
        url = f"https://urlscan.io/api/v1/search/?q=page.trackers.{quote_plus(tracker_id)}&size=20"
        try:
            resp = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": _USER_AGENT})
            if not resp.ok:
                return []
            results = resp.json().get("results", [])
            discovered: list[str] = []
            for r in results:
                page_domain = r.get("page", {}).get("domain", "")
                if not page_domain:
                    continue
                ext = tldextract.extract(page_domain.lower())
                if ext.domain and ext.suffix:
                    rd = f"{ext.domain}.{ext.suffix}"
                    if rd != seed_domain and rd not in discovered:
                        discovered.append(rd)
            return discovered
        except (requests.RequestException, ValueError) as exc:
            logger.debug("fingerprint: urlscan tracker pivot failed for %s: %s", tracker_id, exc)
            return []

    @staticmethod
    def _find_title(html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        title_tag = soup.find("title")
        return title_tag.get_text().strip() if title_tag else ""

    def _fetch_homepage(self, domain: str) -> tuple[str | None, str | None]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/"
            try:
                resp = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": _USER_AGENT})
                resp.raise_for_status()
                return resp.text, resp.url
            except requests.RequestException as exc:
                logger.info("fingerprint: %s fetch failed: %s", url, exc)
        logger.warning("fingerprint: could not fetch homepage for %s over https or http", domain)
        return None, None

    @staticmethod
    def _first_match(pattern: re.Pattern, text: str) -> str | None:
        match = pattern.search(text)
        if not match:
            return None
        return match.group(1) if match.groups() else match.group(0)

    def _favicon_md5(self, html: str, base_url: str) -> str | None:
        favicon_url = self._find_favicon_url(html, base_url)

        # Some sites inline the favicon (or a deliberately empty placeholder,
        # e.g. href="data:," to suppress the browser's default /favicon.ico
        # request) as a data: URI rather than linking a fetchable resource.
        if favicon_url.startswith("data:"):
            return self._hash_data_uri(favicon_url)

        try:
            resp = requests.get(favicon_url, timeout=_TIMEOUT, headers={"User-Agent": _USER_AGENT})
            resp.raise_for_status()
            if not resp.content:
                return None
            return hashlib.md5(resp.content).hexdigest()
        except requests.RequestException as exc:
            logger.info("fingerprint: favicon fetch failed for %s: %s", favicon_url, exc)
            return None

    @staticmethod
    def _hash_data_uri(data_uri: str) -> str | None:
        header, _, payload = data_uri.partition(",")
        if not payload:
            return None
        try:
            content = base64.b64decode(payload) if "base64" in header else payload.encode("utf-8")
        except (ValueError, binascii.Error):
            return None
        return hashlib.md5(content).hexdigest() if content else None

    @staticmethod
    def _find_favicon_url(html: str, base_url: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("link"):
            rel = link.get("rel")
            rel_str = " ".join(rel).lower() if isinstance(rel, list) else (rel or "").lower()
            href = link.get("href")
            if href and "icon" in rel_str:
                return urljoin(base_url, href)
        return urljoin(base_url, "/favicon.ico")
