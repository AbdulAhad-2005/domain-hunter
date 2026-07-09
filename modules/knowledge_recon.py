import logging
import re
from urllib.parse import urlparse

import requests

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_SPARQL_URL = "https://query.wikidata.org/sparql"
_TIMEOUT = 20
_USER_AGENT = "DomainHunter/0.1 (OSINT recon tool)"

_QID_RE = re.compile(r"^Q\d+$")

_ENTITY_QUERY = """
SELECT DISTINCT ?item ?itemLabel ?website ?isOrg WHERE {{
  VALUES ?website {{ {uri_values} }}
  ?item wdt:P856 ?website .
  BIND(EXISTS {{ ?item wdt:P31/wdt:P279* wd:Q43229 }} AS ?isOrg)
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
ORDER BY DESC(?isOrg)
"""

_RELATIONS_QUERY = """
SELECT DISTINCT ?relation ?related ?relatedLabel ?website WHERE {{
  {{ wd:{qid} wdt:P355 ?related . BIND("subsidiary" AS ?relation) }}
  UNION {{ ?related wdt:P127 wd:{qid} . BIND("owned_by" AS ?relation) }}
  UNION {{ wd:{qid} wdt:P1830 ?related . BIND("owned_by" AS ?relation) }}
  UNION {{ ?related wdt:P749 wd:{qid} . BIND("parent_organization" AS ?relation) }}
  UNION {{ wd:{qid} wdt:P1056 ?related . BIND("product" AS ?relation) }}
  UNION {{ ?related wdt:P178 wd:{qid} . BIND("developer_of" AS ?relation) }}
  UNION {{ ?related wdt:P1416 wd:{qid} . BIND("affiliated_with" AS ?relation) }}
  OPTIONAL {{ ?related wdt:P856 ?website }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
"""

# Other entities (besides the seed) that co-own a related entity via P127/P749
# -- surfaces the partner side of a joint venture (e.g. "HAL 49% + BAE 40%"
# style JVs are frequently only documented under the FOREIGN partner's own
# Wikidata entity/site, not the target's, so this at least names who to look
# at next rather than silently dropping the relationship).
_CO_OWNERS_QUERY = """
SELECT DISTINCT ?owner ?ownerLabel WHERE {{
  {{ wd:{related_qid} wdt:P127 ?owner }} UNION {{ wd:{related_qid} wdt:P749 ?owner }}
  FILTER(?owner != wd:{seed_qid})
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
"""

_RELATION_VERBS = {
    "subsidiary": "has subsidiary",
    "owned_by": "owns",
    "parent_organization": "is parent organization of",
    "product": "produces",
    "developer_of": "is developer of",
    "affiliated_with": "is affiliated with",
}

# Ownership-type relations where a co-owner check is worth the extra query --
# "product"/"developer_of"/"affiliated_with" don't have a meaningful
# ownership-percentage/partner concept.
_OWNERSHIP_RELATIONS = {"subsidiary", "owned_by", "parent_organization"}


class KnowledgeReconModule(ReconModule):
    """Organizational-relationship recon via Wikidata (free, no key).

    Finds the Wikidata entity whose official website (P856) matches the seed
    domain, then pulls structured relationships -- subsidiary (P355), owned
    by (P127/P1830), parent organization (P749), product/material produced
    (P1056), developer (P178, reverse), affiliated organization (P1416,
    reverse, for alumni associations/foundations/affiliated bodies) -- and
    maps each related entity to its own P856 official website.

    This is the module built to catch the class of associated domains the
    infrastructure-based modules (certs, dns_infra, tld_variants,
    pattern_gen) structurally cannot: domains linked by organizational
    knowledge rather than shared hosting/DNS/certs, e.g. a telecom's mobile
    subsidiary (ufone.com for ptcl.com.pk) or a research org's product
    (bosslinux.in for cdac.in). Every Finding traces back to a specific
    Wikidata statement (stored in raw_data), so confidence is "high" -- this
    is a sourced, structured relationship, not a guess.

    Joint ventures with partial/shared ownership are NOT rejected for being
    less than wholly-owned -- P127/P749 just need to include the seed's QID
    among possibly several. When a related entity has ownership-type relation
    (subsidiary/owned_by/parent_organization), a second lightweight query
    checks for OTHER co-owners of that same entity and names them in the
    evidence (e.g. "co-owned with: BAE Systems") -- Wikidata frequently files
    a JV under the FOREIGN partner's entity rather than the target's, so
    surfacing the partner name points a human at where to look next, even
    though following the partner's own graph/site is out of scope here.

    Entity resolution is deliberately narrow: only a P856 back-reference to
    the exact seed domain, not a name search. A name-based fallback
    (wbsearchentities) would catch more orgs that aren't in Wikidata with a
    matching official-website statement, but risks silently picking a
    different, same-named entity with no way to verify the match -- a real
    risk given this module's whole point is reporting only *confirmed*
    relationships. "No Wikidata entity found" is logged and returned as an
    honest empty result rather than guessed at.

    Even a same-URL match isn't automatically unambiguous: testing against
    cdac.in initially matched Q136504968 ("PARAM Siddhi-AI", a supercomputer
    CDAC built) instead of Q3519908 (CDAC itself), because the product's own
    P856 statement is also set to cdac.in and SPARQL result order isn't
    otherwise defined. Fixed by ordering matches so an entity that is
    (transitively) `instance of` organization (Q43229) in Wikidata's own
    class hierarchy is preferred over one that isn't, rather than hardcoding
    a list of "organization-like" P31 values.

    Adding P1416 (affiliated_with) surfaced a second bug: NUST's constituent
    schools (e.g. NUST School of Mechanical and Manufacturing Engineering)
    are P1416-affiliated with NUST itself, and their P856 websites are
    subdomains of nust.edu.pk (smme.nust.edu.pk etc.) -- not a separate
    associated domain, just part of the seed's own site. Now excluded via the
    same "is it a subdomain of the seed" check certs.py/dns_infra.py already
    use, rather than treating every related-entity website as automatically
    distinct from the seed.
    """

    name = "knowledge_recon"
    requires_key = None

    def __init__(self, config):
        super().__init__(config)
        self.entity_label: str | None = None

    def run(self, domain: str) -> list[Finding]:
        logger.info("knowledge_recon: querying Wikidata for entity with official website matching %s", domain)
        qid, entity_label = self._find_entity(domain)
        if qid is None:
            logger.info(
                "knowledge_recon: no Wikidata entity found with official website matching %s", domain
            )
            return []
        self.entity_label = entity_label

        rows = self._query_relations(qid)
        findings = []
        seen = {domain}
        for row in rows:
            website = row.get("website", {}).get("value")
            if not website:
                continue
            related_domain = self._extract_domain(website)
            if (
                not related_domain
                or related_domain in seen
                or related_domain.endswith(f".{domain}")
            ):
                continue
            seen.add(related_domain)

            relation = row["relation"]["value"]
            related_label = row.get("relatedLabel", {}).get("value", row["related"]["value"])
            related_qid = row["related"]["value"].rsplit("/", 1)[-1]
            verb = _RELATION_VERBS.get(relation, relation)

            co_owners = []
            if relation in _OWNERSHIP_RELATIONS:
                co_owners = self._query_co_owners(related_qid, qid)
            jv_note = f" (also co-owned by: {', '.join(co_owners)} -- check that side's own site/Wikidata too)" if co_owners else ""

            findings.append(Finding(
                seed_domain=domain,
                associated_domain=related_domain,
                method=f"knowledge_graph_{relation}",
                evidence=(
                    f"Wikidata: {entity_label} ({qid}) {verb} {related_label} ({related_qid}), "
                    f"whose official website (P856) is {website}{jv_note}"
                ),
                raw_data={
                    "seed_qid": qid,
                    "related_qid": related_qid,
                    "relation": relation,
                    "website": website,
                    "co_owners": co_owners,
                },
                confidence="high",
            ))
        return findings

    def _query_co_owners(self, related_qid: str, seed_qid: str) -> list[str]:
        if not (_QID_RE.match(related_qid) and _QID_RE.match(seed_qid)):
            return []
        rows = self._sparql(_CO_OWNERS_QUERY.format(related_qid=related_qid, seed_qid=seed_qid))
        return [r["ownerLabel"]["value"] for r in rows if r.get("ownerLabel", {}).get("value")]

    def _find_entity(self, domain: str) -> tuple[str | None, str | None]:
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            logger.warning("knowledge_recon: unexpected domain format %r, skipping", domain)
            return None, None

        # P856 (official website) comes back from wdt: as an RDF IRI, not a
        # typed literal -- confirmed by querying a known entity (PTCL,
        # Q7125719) directly and checking the JSON binding's "type" field.
        # A `"..."^^xsd:anyURI` literal VALUES match silently returns zero
        # rows against it.
        uri_values = " ".join(f"<{uri}>" for uri in self._candidate_uris(domain))
        query = _ENTITY_QUERY.format(uri_values=uri_values)
        rows = self._sparql(query)
        if not rows:
            return None, None
        item_uri = rows[0]["item"]["value"]
        qid = item_uri.rsplit("/", 1)[-1]
        label = rows[0].get("itemLabel", {}).get("value", qid)
        return qid, label

    @staticmethod
    def _candidate_uris(domain: str) -> list[str]:
        """Exact P856 (official website) URL variants to match against.
        Wikidata's own SPARQL endpoint is too slow for a CONTAINS scan across
        every P856 statement on the public query.wikidata.org service (hit a
        real 20s+ timeout testing this) -- an exact VALUES match against the
        handful of plausible URL forms is fast, since it hits an index."""
        domain = domain.lower()
        return [
            f"{scheme}://{prefix}{domain}{suffix}"
            for scheme in ("https", "http")
            for prefix in ("", "www.")
            for suffix in ("", "/")
        ]

    def _query_relations(self, qid: str) -> list[dict]:
        if not _QID_RE.match(qid):
            logger.warning("knowledge_recon: unexpected QID format %r, skipping", qid)
            return []
        return self._sparql(_RELATIONS_QUERY.format(qid=qid))

    def _sparql(self, query: str) -> list[dict]:
        try:
            resp = requests.get(
                _SPARQL_URL,
                params={"query": query, "format": "json"},
                headers={"Accept": "application/sparql-results+json", "User-Agent": _USER_AGENT},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json().get("results", {}).get("bindings", [])
        except (requests.RequestException, ValueError) as exc:
            logger.warning("knowledge_recon: SPARQL query failed: %s", exc)
            return []

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        parsed = urlparse(url)
        netloc = parsed.netloc or urlparse(f"//{url}").netloc
        host = netloc.split(":")[0].lower().strip("/")
        if host.startswith("www."):
            host = host[4:]
        return host or None
