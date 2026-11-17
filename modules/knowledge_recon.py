import logging
import re
import time
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from core.models import Finding
from modules.base import ReconModule
from modules.corroboration import _brand_tokens, _shares_brand_token

logger = logging.getLogger(__name__)

_TIMEOUT = 12
_USER_AGENT = "DomainHunter/0.1 (OSINT recon tool)"

_FINANCIAL_INSTITUTION_WORDS = (
    "investment", "asset management", "capital management", "hedge fund",
    "mutual fund", "pension fund", "sovereign wealth fund", "private equity",
    "venture capital", "wealth management", "index fund", "fund manager",
    "financial services",
)
_HUMAN_QID = "Q5"
_WIKI_SELF = frozenset({
    "wikipedia.org", "wikimedia.org", "wiktionary.org", "wikidata.org", "creativecommons.org"
})

_AFFILIATION_ROW_LABELS = frozenset({
    "website", "websites", "official website", "homepage", "url",
    "owner", "owned by", "parent", "parent company", "parent organisation",
    "parent organization", "subsidiaries", "subsidiary",
})


class KnowledgeReconModule(ReconModule):
    """Organizational-relationship recon via Wikidata & Wikipedia (free, no key).

    Replaces fragile, timeout-prone SPARQL queries with the fast Wikidata Action
    API (wbsearchentities + batched wbgetentities) and Wikipedia infobox parsing.

    Features:
      1. Multi-tier entity resolution (seed domain, homepage title, brand token),
         verifying that the entity's own P856 (official website) matches the seed.
      2. Traversal of corporate hierarchy:
         - P355: subsidiary
         - P749: parent organization
         - P127: owned by (filtered to reject financial funds/human shareholders)
      3. Chases related entities to their own P856 official websites.
      4. Wikipedia Infobox parsing for verified corporate affiliation rows
         (website, owner, parent, subsidiaries) with stock-exchange filter.
    """

    name = "knowledge_recon"
    requires_key = None

    def __init__(self, config):
        super().__init__(config)
        self.entity_label: str | None = None
        self.entity_qid: str | None = None

    def run(self, domain: str) -> list[Finding]:
        logger.info("knowledge_recon: querying Wikidata & Wikipedia for %s", domain)
        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT})

        brand_tokens = _brand_tokens(domain)
        brand = brand_tokens[0] if brand_tokens else domain.split(".")[0]

        findings: list[Finding] = []
        seen = {domain}

        # Step 1: Wikidata corporate hierarchy traversal
        wikidata_sites = self._wikidata_affiliated_sites(session, domain, brand)
        for related_domain, context in wikidata_sites.items():
            if related_domain not in seen:
                seen.add(related_domain)
                findings.append(Finding(
                    seed_domain=domain,
                    associated_domain=related_domain,
                    method="knowledge_graph_wikidata",
                    evidence=context,
                    raw_data={"source": "wikidata", "domain": related_domain},
                    confidence="high",
                ))

        # Step 2: Wikipedia infobox relationship parsing
        wiki_sites = self._wikipedia_infobox_sites(session, domain, brand_tokens)
        for related_domain, context in wiki_sites.items():
            if related_domain not in seen:
                seen.add(related_domain)
                findings.append(Finding(
                    seed_domain=domain,
                    associated_domain=related_domain,
                    method="wikipedia_infobox",
                    evidence=context,
                    raw_data={"source": "wikipedia_infobox", "domain": related_domain},
                    confidence="high",
                ))

        return findings

    # --------------------------------------------------------------------------
    # Wikidata Action API methods
    # --------------------------------------------------------------------------
    def _wikidata_affiliated_sites(
        self, session: requests.Session, seed_root: str, brand: str
    ) -> dict[str, str]:
        """Resolves seed to Wikidata entity, then pulls subsidiaries (P355),
        parents (P749), and verified controlling entities (P127), mapping each
        to its P856 official website."""
        entity = None
        for query in (seed_root, brand):
            query = query.strip()
            if not query:
                continue
            qids = self._wikidata_entity_ids(session, query)
            if not qids:
                continue
            candidates = self._wikidata_entities(session, qids)
            for qid in qids:
                cand = candidates.get(qid)
                if not cand:
                    continue
                own_roots = {
                    self._registrable_domain(u)
                    for u in self._wikidata_claim_strings(cand, "P856")
                }
                if seed_root in own_roots:
                    entity = cand
                    self.entity_qid = qid
                    self.entity_label = cand.get("labels", {}).get("en", {}).get("value", qid)
                    break
            if entity:
                break

        if entity is None:
            logger.info("knowledge_recon: no verified Wikidata entity found matching P856 for %s", seed_root)
            return {}

        unconditional_ids = self._wikidata_claim_ids(entity, "P355") + self._wikidata_claim_ids(entity, "P749")
        p127_ids = set(self._wikidata_claim_ids(entity, "P127"))
        related_ids = list(dict.fromkeys(unconditional_ids + list(p127_ids)))
        if not related_ids:
            return {}

        time.sleep(0.2)  # Wikidata rate-limit politeness
        related = self._wikidata_entities(session, related_ids)

        sites: dict[str, str] = {}
        for related_qid, related_entity in related.items():
            if related_qid in p127_ids and self._is_untrusted_p127_target(related_entity):
                continue
            rel_label = related_entity.get("labels", {}).get("en", {}).get("value", related_qid)
            for url in self._wikidata_claim_strings(related_entity, "P856"):
                rd = self._registrable_domain(url)
                if rd and rd != seed_root and rd not in sites:
                    sites[rd] = f"Wikidata: {rel_label} ({related_qid}), subsidiary/parent of {self.entity_label or seed_root}"
        return sites

    def _wikidata_entity_ids(self, session: requests.Session, query: str, limit: int = 5) -> list[str]:
        try:
            resp = session.get(
                "https://www.wikidata.org/w/api.php",
                params={"action": "wbsearchentities", "search": query, "language": "en", "format": "json", "limit": limit},
                timeout=_TIMEOUT,
            )
            hits = resp.json().get("search", []) if resp.ok else []
            return [h["id"] for h in hits if h.get("id")]
        except Exception as exc:
            logger.debug("knowledge_recon: wbsearchentities failed for %s: %s", query, exc)
            return []

    def _wikidata_entities(self, session: requests.Session, qids: list[str]) -> dict[str, dict]:
        if not qids:
            return {}
        try:
            resp = session.get(
                "https://www.wikidata.org/w/api.php",
                params={
                    "action": "wbgetentities",
                    "ids": "|".join(qids[:50]),
                    "props": "claims|labels|descriptions",
                    "languages": "en",
                    "format": "json",
                },
                timeout=_TIMEOUT,
            )
            if not resp.ok:
                return {}
            return resp.json().get("entities", {})
        except Exception as exc:
            logger.debug("knowledge_recon: wbgetentities batch failed: %s", exc)
            return {}

    @staticmethod
    def _wikidata_claim_ids(entity: dict, prop: str) -> list[str]:
        out = []
        for claim in entity.get("claims", {}).get(prop, []):
            try:
                out.append(claim["mainsnak"]["datavalue"]["value"]["id"])
            except (KeyError, TypeError):
                continue
        return out

    @staticmethod
    def _wikidata_claim_strings(entity: dict, prop: str) -> list[str]:
        out = []
        for claim in entity.get("claims", {}).get(prop, []):
            try:
                val = claim["mainsnak"]["datavalue"]["value"]
                if isinstance(val, str) and val.strip():
                    out.append(val.strip())
            except (KeyError, TypeError):
                continue
        return out

    @staticmethod
    def _is_untrusted_p127_target(entity: dict) -> bool:
        """True when P127 (owned by) is a human or an institutional financial fund."""
        p31 = {
            c["mainsnak"]["datavalue"]["value"].get("id", "")
            for c in entity.get("claims", {}).get("P31", [])
            if "datavalue" in c.get("mainsnak", {})
        }
        if _HUMAN_QID in p31:
            return True
        text = " ".join([
            entity.get("labels", {}).get("en", {}).get("value", ""),
            entity.get("descriptions", {}).get("en", {}).get("value", ""),
        ]).lower()
        return any(word in text for word in _FINANCIAL_INSTITUTION_WORDS)

    # --------------------------------------------------------------------------
    # Wikipedia Infobox parsing
    # --------------------------------------------------------------------------
    def _wikipedia_infobox_sites(
        self, session: requests.Session, seed_root: str, brand_tokens: list[str]
    ) -> dict[str, str]:
        """Resolves Wikipedia article via OpenSearch and extracts domains from
        affiliation rows in the Infobox (website, owner, parent, subsidiaries)."""
        brand = brand_tokens[0] if brand_tokens else seed_root.split(".")[0]
        html = self._fetch_wikipedia_article(session, seed_root, brand)
        if not html:
            return {}

        soup = BeautifulSoup(html, "html.parser")
        infobox = soup.find("table", class_="infobox")
        if not infobox:
            return {}

        all_box_text = infobox.get_text(" ", strip=True).lower()
        is_seed_entity = (
            seed_root in all_box_text
            or any(_shares_brand_token(seed_root, [bt]) and bt in all_box_text for bt in brand_tokens)
        )
        if not is_seed_entity:
            return {}

        sites: dict[str, str] = {}
        for row in infobox.find_all("tr"):
            header = row.find("th")
            label = header.get_text(" ", strip=True).lower() if header else ""
            if label not in _AFFILIATION_ROW_LABELS:
                continue

            for a in row.find_all("a", href=True):
                host = urlparse(a["href"]).hostname
                if not host:
                    continue
                rd = self._registrable_domain(host)
                if rd and rd != seed_root and rd not in _WIKI_SELF and rd not in sites:
                    sites[rd] = f"Wikipedia infobox '{label}' row"

            # Domain regex search in the row text
            for host in re.findall(r"(?:https?://)?(?:www\.)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})", row.get_text(" ", strip=True)):
                rd = self._registrable_domain(host)
                if rd and rd != seed_root and rd not in _WIKI_SELF and rd not in sites:
                    sites[rd] = f"Wikipedia infobox '{label}' row"

        return sites

    def _fetch_wikipedia_article(self, session: requests.Session, seed_root: str, brand: str) -> str:
        for query in (seed_root, brand):
            try:
                resp = session.get(
                    "https://en.wikipedia.org/w/api.php",
                    params={"action": "opensearch", "search": query, "limit": 1, "namespace": 0, "format": "json"},
                    timeout=_TIMEOUT,
                )
                urls = resp.json()[3] if resp.ok else []
                if urls:
                    page = session.get(urls[0], timeout=_TIMEOUT)
                    if page.ok:
                        return page.text
            except Exception as exc:
                logger.debug("knowledge_recon: Wikipedia opensearch failed for %s: %s", query, exc)
        return ""

    @staticmethod
    def _registrable_domain(url_or_host: str) -> str | None:
        if not url_or_host:
            return None
        parsed = urlparse(url_or_host if "://" in url_or_host else f"//{url_or_host}")
        host = (parsed.hostname or url_or_host).strip("./").lower()
        ext = tldextract.extract(host)
        if not ext.domain or not ext.suffix:
            return None
        return f"{ext.domain}.{ext.suffix}"
