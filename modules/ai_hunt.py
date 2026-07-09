import json
import logging
import re
import time

import requests

from core.models import Finding
from modules.base import ReconModule

logger = logging.getLogger(__name__)

_TIMEOUT = 60
_MAX_RETRIES = 2
_RETRY_BACKOFF_SECONDS = 3

# Defaults, used when config.yaml doesn't set llm_model. Model names go stale
# -- these are current as of this module's writing, override via llm_model if
# your account doesn't have access to one of these or a newer one exists.
# gemini-2.0-flash and the "-latest" alias were both replaced after a real
# failure: a user's config.yaml had llm_model explicitly set to
# gemini-2.5-flash, which Google's API now rejects with a 404 ("no longer
# available") despite still listing it via ListModels -- confirmed
# gemini-3.5-flash actually works against the same key.
_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-3.5-flash",
}

# Plausible-hostname shape check -- not a full RFC 1035 validator, just enough
# to reject non-domain junk (empty strings, sentences, markdown artifacts).
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

_PROMPT_TEMPLATE = """You are assisting an OSINT domain-discovery tool. Given a seed \
organization, propose plausible ADDITIONAL domains that might be owned or operated by \
the same organization, across these categories:
- TLD/spelling variants of the seed's own name
- Wholly-owned subsidiaries, brands, or products
- Joint ventures with partial or shared ownership -- name the partner organization(s) \
and the approximate ownership split if you know it, e.g. "49% seed + 40% partner + 11% other"
- Affiliated organizations that aren't owned subsidiaries: alumni or affiliate \
associations, foundations or trusts, hosted national projects/initiatives, training or \
research arms

Some of these entities genuinely have no standalone domain of their own (e.g. a joint \
venture that only operates under a parent's portal) -- if so, still name the entity but \
leave its domain as an empty string rather than inventing one you're not confident \
actually exists. "This entity exists but has no dedicated domain" is a useful, correct \
answer, not something to paper over.

You are a HYPOTHESIS GENERATOR ONLY. Every suggestion you make will be independently \
verified (DNS resolution, cross-referenced against other sources) before anything is \
trusted -- so include anything plausible even if uncertain, but do not fabricate \
specific facts (e.g. a relationship, an ownership split, or a domain name) you have no \
basis for.

Seed domain: {domain}
Organization name (if known): {org_name}
Already-known associated domains (do not just repeat these): {known_domains}

Respond with ONLY a single JSON object, no markdown formatting, no commentary, \
matching exactly this shape:
{{
  "tld_variants": ["<domain>", ...],
  "subsidiaries_brands_products": [
    {{"name": "<entity name>", "domain": "<domain or empty string>", "relationship": "<short description, e.g. 'mobile subsidiary', 'product'>"}}
  ],
  "joint_ventures": [
    {{"name": "<entity name>", "domain": "<domain or empty string>", "partners": "<ownership split and partner name(s), e.g. 'HAL 49% + BAE 40%'>"}}
  ],
  "affiliated_orgs": [
    {{"name": "<entity name>", "domain": "<domain or empty string>", "category": "<one of: alumni_association, foundation_trust, hosted_project, training_research_arm>"}}
  ]
}}
If you have no plausible suggestions for a field, use an empty list for it."""


class AIHuntModule(ReconModule):
    """LLM-assisted hypothesis generation, keyed/optional. Per PROJECT_OVERVIEW.md
    4.6 and CLAUDE.md rule 3, this is verify-only and non-negotiable: the LLM's
    role is suggesting candidate names/relationships, never asserting a
    Finding directly.

    Pipeline per suggestion: LLM proposes -> DNS liveness check (annotates,
    does not filter) -> relationship corroboration (sets confidence) ->
    always recorded. A suggestion is only ever dropped for being malformed
    (not a plausible domain string) or a pure duplicate -- never for being
    dead. A real former subsidiary that no longer resolves is still a valid,
    recorded finding (e.g. the paknet.com.pk case from the motivating test).

    Category scope widened beyond wholly-owned subsidiaries/brands/products
    to also prompt for: joint ventures with partial/shared ownership (the
    partner org and approximate split, e.g. "HAL 49% + BAE 40%", if the model
    knows it) and affiliated organizations that aren't owned subsidiaries at
    all (alumni/affiliate associations, foundations/trusts, hosted national
    projects, training/research arms) -- these are the categories Wikidata
    tends to model poorly or not at all (a JV is frequently only documented
    under the FOREIGN partner's own entity) and that don't have a structured
    ownership graph to query in the first place. Corroboration does NOT
    reject a suggestion for being a JV / partial ownership rather than wholly
    owned -- nothing in _corroborate() checks ownership percentage, only
    whether the relationship itself is independently confirmed.

    Some named entities genuinely have no standalone domain (e.g. a JV that
    only operates under a parent's portal). The prompt asks the model to
    leave the domain empty rather than invent one in that case; the parser
    counts and logs these ("no_domain" in self.last_stats) instead of
    dropping them silently or fabricating a Finding for them -- per the spec,
    "found the entity, no dedicated domain" is a correct outcome, not
    something this module can represent as a Finding (which requires an
    actual associated_domain), so it stays in telemetry rather than output.

    Confidence tiers -- the spec names two explicit tiers (resolves+
    corroborated -> high; uncorroborated, resolving or not -> low) and one
    combination is left unstated: corroborated but NOT currently resolving.
    Judgment call: "medium" -- a corroborated relationship is real signal
    independent of today's liveness (paknet.com.pk again: a genuine former
    PTCL subsidiary, dead, shouldn't be bucketed with a pure unconfirmed LLM
    guess), but "high" per the spec's literal wording requires both.

    Corroboration sources actually implemented:
    - Cross-check against domains already found by OTHER modules this run
      (passed in via known_domains) -- if knowledge_recon (Wikidata) or any
      other method already independently surfaced the same domain, that's
      real corroboration.
    - A fresh WHOIS registrant-org match: RDAP-lookup the suggested domain
      itself and compare its registrant org to the seed's (reuses
      WhoisLookupModule).
    "Corporate registry" corroboration (OpenCorporates/SEC EDGAR) is NOT
    implemented -- corporate.py doesn't exist yet in this codebase.

    NOT implemented: cross-provider agreement as an extra corroboration
    signal. The task marks this optional, but config.yaml's schema only has
    a single llm_provider/llm_api_key pair -- doing this properly needs a
    schema change (e.g. a list of provider configs), which felt like a
    bigger unrequested decision than this pass should make silently.

    Deviation from the strict single-argument ReconModule contract: this is
    the only module that needs context from OTHER modules' results (seed org
    name, domains found so far) to do its job, per the spec's own design
    ("org name from whois_lookup/knowledge_recon, and findings so far"). A
    pure run(domain) can't carry that. run() takes optional keyword args
    (still safely callable as just run(domain)) and main.py's runner --
    not core/aggregator.py, which remains fully source-agnostic -- is what
    sequences ai_hunt last and passes the extra context through.

    Provider-agnostic via plain HTTP (no provider SDK dependencies): supports
    anthropic, openai, gemini, and custom (any OpenAI-chat-completions-
    compatible endpoint via llm_base_url). Skipped entirely, with a clear log
    line, if llm_provider/llm_api_key aren't both set -- this module has no
    free fallback (has_free_fallback = False), unlike every other module.
    """

    name = "ai_hunt"
    requires_key = "llm"
    has_free_fallback = False

    def __init__(self, config):
        super().__init__(config)
        self.last_stats: dict = {}

    def run(
        self,
        domain: str,
        org_name: str | None = None,
        known_domains: list[str] | None = None,
        seed_registrant_org: str | None = None,
    ) -> list[Finding]:
        provider = self.config.get("llm_provider")
        api_key = self.config.get("llm_api_key")
        if not provider or not api_key:
            logger.info("ai_hunt: SKIPPED — no llm_provider/llm_api_key configured")
            return []

        known_domains = known_domains or []
        logger.info("ai_hunt: querying %s for hypothesis generation on %s", provider, domain)

        try:
            raw = self._call_llm_with_retry(provider, api_key, domain, org_name, known_domains)
        except Exception as exc:
            logger.warning("ai_hunt: LLM call failed: %s", exc)
            return []

        proposals, no_domain_count = self._parse_proposals(raw)
        logger.info(
            "ai_hunt: LLM proposed %d candidate(s) with a domain (%d entities named with no domain to check)",
            len(proposals), no_domain_count,
        )

        from modules._dns_utils import verify as dns_verify

        findings = []
        resolved_count = 0
        corroborated_count = 0
        seen = {domain.lower()}
        known_domains_lower = {d.lower() for d in known_domains}

        for entity_name, candidate, relationship in proposals:
            candidate = candidate.strip().lower().rstrip(".")
            if not candidate or not _DOMAIN_RE.match(candidate) or candidate in seen:
                logger.debug("ai_hunt: dropping malformed/duplicate suggestion %r", candidate)
                continue
            seen.add(candidate)

            # Same NS-inclusive "live" definition as tld_variants/pattern_gen:
            # True for a registered/delegated domain even with no direct
            # A/AAAA (e.g. infra-only), not just "has an IP".
            live, _ip = dns_verify(candidate, timeout=5)
            if live:
                resolved_count += 1

            corroborated, note = self._corroborate(candidate, known_domains_lower, seed_registrant_org)
            if corroborated:
                corroborated_count += 1

            if corroborated and live:
                confidence = "high"
            elif corroborated:
                confidence = "medium"
            else:
                confidence = "low"

            relationship_desc = relationship or "associated domain"
            if corroborated:
                evidence = (
                    f'LLM-suggested {relationship_desc} ("{entity_name}"), {note}. '
                    f"{'Resolves' if live else 'Does not currently resolve'} "
                    f"(checked at generation time)."
                )
            else:
                evidence = (
                    f"LLM-asserted relationship, not independently confirmed: suggested "
                    f'{relationship_desc} ("{entity_name}"). '
                    f"{'Resolves' if live else 'Does not currently resolve'} "
                    f"(checked at generation time)."
                )

            findings.append(Finding(
                seed_domain=domain,
                associated_domain=candidate,
                method="ai_hunt",
                evidence=evidence,
                raw_data={
                    "llm_provider": provider,
                    "llm_entity_name": entity_name,
                    "llm_relationship": relationship,
                    "resolved_at_generation": live,
                    "corroborated": corroborated,
                    "corroboration_note": note,
                },
                confidence=confidence,
            ))

        self.last_stats = {
            "proposed": len(proposals),
            "no_domain": no_domain_count,
            "resolved": resolved_count,
            "corroborated": corroborated_count,
            "high": sum(1 for f in findings if f.confidence == "high"),
            "medium": sum(1 for f in findings if f.confidence == "medium"),
            "low": sum(1 for f in findings if f.confidence == "low"),
        }
        logger.info(
            "ai_hunt: proposed %d (+%d entity/ies with no domain) → %d resolved → %d corroborated → "
            "%d high / %d medium / %d low",
            self.last_stats["proposed"], no_domain_count, resolved_count, corroborated_count,
            self.last_stats["high"], self.last_stats["medium"], self.last_stats["low"],
        )
        return findings

    def _corroborate(
        self, candidate: str, known_domains_lower: set[str], seed_registrant_org: str | None
    ) -> tuple[bool, str | None]:
        if candidate in known_domains_lower:
            return True, "independently found by another discovery method this run"

        if seed_registrant_org:
            org = self._whois_org(candidate)
            if org and org.strip().lower() == seed_registrant_org.strip().lower():
                return True, f'WHOIS registrant org "{org}" matches the seed\'s'

        return False, None

    def _whois_org(self, candidate: str) -> str | None:
        from modules.whois_lookup import WhoisLookupModule

        module = WhoisLookupModule(self.config)
        try:
            module.run(candidate)
        except Exception as exc:
            logger.debug("ai_hunt: WHOIS corroboration check failed for %s: %s", candidate, exc)
            return None
        return module.record.get("registrant_org")

    def _call_llm_with_retry(
        self, provider: str, api_key: str, domain: str, org_name: str | None, known_domains: list[str]
    ) -> str:
        """Retries on 503 (server overloaded) only -- a real, expected failure
        mode for shared cloud LLM APIs under load, caught live: Gemini
        returned 503 "currently experiencing high demand" on a model that
        worked moments later. Does NOT retry on 429 (quota/rate-limit
        exhaustion) or 404 (bad model name) -- those won't resolve by
        themselves within a few seconds, so retrying just wastes time before
        the same clear error surfaces."""
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self._call_llm(provider, api_key, domain, org_name, known_domains)
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 503 and attempt < _MAX_RETRIES:
                    wait = _RETRY_BACKOFF_SECONDS * (attempt + 1)
                    logger.info(
                        "ai_hunt: %s overloaded (503), retrying in %ds (attempt %d/%d)",
                        provider, wait, attempt + 1, _MAX_RETRIES,
                    )
                    time.sleep(wait)
                    last_exc = exc
                    continue
                raise
        raise last_exc

    def _call_llm(
        self, provider: str, api_key: str, domain: str, org_name: str | None, known_domains: list[str]
    ) -> str:
        base_url = self.config.get("llm_base_url")
        model = self.config.get("llm_model") or _DEFAULT_MODELS.get(provider)
        prompt = _PROMPT_TEMPLATE.format(
            domain=domain,
            org_name=org_name or "unknown",
            known_domains=", ".join(known_domains) if known_domains else "none yet",
        )

        if provider == "anthropic":
            return self._call_anthropic(api_key, model, prompt)
        if provider == "openai":
            return self._call_openai_compatible(base_url or "https://api.openai.com/v1", api_key, model, prompt)
        if provider == "gemini":
            return self._call_gemini(api_key, model, prompt)
        if provider == "custom":
            if not base_url:
                raise ValueError("llm_provider is 'custom' but llm_base_url is not set")
            return self._call_openai_compatible(base_url, api_key, model or "gpt-4o-mini", prompt)
        raise ValueError(f"unknown llm_provider: {provider!r}")

    def _call_anthropic(self, api_key: str, model: str, prompt: str) -> str:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]

    def _call_openai_compatible(self, base_url: str, api_key: str, model: str, prompt: str) -> str:
        resp = requests.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _call_gemini(self, api_key: str, model: str, prompt: str) -> str:
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": api_key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json"},
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    @staticmethod
    def _parse_proposals(raw: str) -> tuple[list[tuple[str, str, str | None]], int]:
        """Returns ((entity_name, domain, relationship) tuples, count of named
        entities with no domain proposed). Tolerates models wrapping JSON in a
        markdown code fence, and trailing content after the JSON object,
        despite being told to respond with ONLY JSON -- both observed live
        from real providers (Gemini appended ~100 extra lines of text after a
        valid JSON object; json.loads() rejects that outright with "Extra
        data" even though the JSON itself parses fine).

        An entity named with no domain (e.g. a JV that only operates under a
        parent's portal) is NOT a parse failure -- per the spec, "found the
        entity, no dedicated domain" is a correct outcome. It's counted and
        logged by the caller, not silently dropped or given a fake domain."""
        text = raw.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if "\n" in text:
                first_line, rest = text.split("\n", 1)
                text = rest if first_line.strip().lower() in ("json", "") else text

        try:
            data, _end = json.JSONDecoder().raw_decode(text.strip())
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning("ai_hunt: failed to parse LLM JSON output: %s", exc)
            return [], 0

        proposals: list[tuple[str, str, str | None]] = []
        no_domain_count = 0

        for candidate in data.get("tld_variants") or []:
            if isinstance(candidate, str) and candidate:
                proposals.append((candidate, candidate, "TLD/name variant"))

        for item in data.get("subsidiaries_brands_products") or []:
            no_domain_count += AIHuntModule._collect_entity(item, item.get("relationship") if isinstance(item, dict) else None, proposals)

        for item in data.get("joint_ventures") or []:
            partners = item.get("partners") if isinstance(item, dict) else None
            relationship = f"joint venture ({partners})" if partners else "joint venture"
            no_domain_count += AIHuntModule._collect_entity(item, relationship, proposals)

        for item in data.get("affiliated_orgs") or []:
            category = (item.get("category") if isinstance(item, dict) else None) or "affiliated organization"
            no_domain_count += AIHuntModule._collect_entity(item, category.replace("_", " "), proposals)

        return proposals, no_domain_count

    @staticmethod
    def _collect_entity(
        item: dict, relationship: str | None, proposals: list[tuple[str, str, str | None]]
    ) -> int:
        """Appends (name, domain, relationship) to `proposals` if `item` names
        a domain. Returns 1 if `item` names an entity but no domain (to be
        tallied as a "found, no domain" note), else 0."""
        if not isinstance(item, dict):
            return 0
        name = item.get("name")
        domain = (item.get("domain") or "").strip()
        if not domain:
            if name:
                logger.info(
                    'ai_hunt: LLM named entity "%s" (%s) with no dedicated domain -- noted, not a finding',
                    name, relationship or "unspecified relationship",
                )
                return 1
            return 0
        proposals.append((name or domain, domain, relationship))
        return 0
