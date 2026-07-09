import logging

import tldextract

from core.models import Finding
from modules.base import ReconModule
from modules._dns_utils import resolve_many
from modules.corroboration import STRONG_SIGNALS, SeedContext, corroborate

logger = logging.getLogger(__name__)

# Generic words/abbreviations orgs commonly tack onto their own brand label
# when naming a subsidiary, regional arm, or product line.
_SUFFIXES = [
    "group", "holdings", "global", "inc", "intl", "international",
    "online", "digital", "tech", "solutions", "services", "systems",
    "mobile", "telecom", "media", "labs", "cloud", "connect", "pay",
]
_PREFIXES = ["my", "get", "go", "the"]

_GENERIC_TLDS = ["com", "net", "org", "co"]


class PatternGenModule(ReconModule):
    """Rule-based domain-name variant generation from the seed's own label.

    Glues common corporate suffixes/prefixes (group, holdings, mobile, pay,
    ...) onto the seed's label and checks whether the result resolves. This
    is a much weaker signal than tld_variants.py's same-label-different-TLD
    check: here the label itself is also changed, so a hit is only a
    generated string that happens to resolve -- not evidence of any actual
    naming convention the organization uses, and NOT evidence of common
    ownership by itself (same principle as tld_variants.py: resolving is not
    confirmation). A resolving candidate is only promoted to a real finding
    (medium/high) if it also picks up a corroborating signal (shared WHOIS
    registrant, shared NS/MX/ASN/favicon, or independently found by another
    module this run -- see modules/corroboration.py); otherwise it's recorded
    as a "low"-confidence, explicitly-labelled unconfirmed lead.
    """

    name = "pattern_gen"
    requires_key = None

    def run(self, domain: str, seed_context: SeedContext | None = None) -> list[Finding]:
        ext = tldextract.extract(domain)
        label = ext.domain
        if not label:
            return []

        cc = ext.suffix.split(".")[-1] if ext.suffix else None
        generated_labels = self._generate_labels(label)

        all_candidates: set[str] = set()
        for gen_label in generated_labels:
            tlds = set(_GENERIC_TLDS)
            if cc:
                tlds.add(cc)
            label_candidates = {f"{gen_label}.{tld}" for tld in tlds}
            label_candidates.discard(domain)
            all_candidates |= label_candidates

        logger.info(
            "pattern_gen: checking %d generated candidates (%d labels) for %s",
            len(all_candidates), len(generated_labels), domain,
        )
        all_resolved = resolve_many(sorted(all_candidates))

        findings = []
        for candidate, ip in sorted(all_resolved.items()):
            gen_label = tldextract.extract(candidate).domain
            status = f"resolves (to {ip})" if ip else "is registered/delegated (NS present, no direct A/AAAA)"
            signal, note = corroborate(candidate, domain, seed_context)

            if signal:
                confidence = "high" if signal in STRONG_SIGNALS else "medium"
                evidence = (
                    f'{candidate} is a generated candidate ("{label}" + pattern -> "{gen_label}") '
                    f"that {status}, and is corroborated: {note}."
                )
            else:
                confidence = "low"
                evidence = (
                    f'{candidate} is a generated candidate ("{label}" + pattern -> "{gen_label}") '
                    f"that {status} — UNCONFIRMED — just a guessed name that happens to be "
                    f"registered, with no corroborating signal of common ownership."
                )

            findings.append(Finding(
                seed_domain=domain,
                associated_domain=candidate,
                method="pattern_gen",
                evidence=evidence,
                raw_data={
                    "seed_label": label, "generated_label": gen_label, "resolved_ip": ip,
                    "corroboration_signal": signal, "corroboration_note": note,
                },
                confidence=confidence,
            ))
        return findings

    @staticmethod
    def _generate_labels(label: str) -> set[str]:
        labels = {f"{label}{suffix}" for suffix in _SUFFIXES}
        labels |= {f"{label}-{suffix}" for suffix in _SUFFIXES}
        labels |= {f"{prefix}{label}" for prefix in _PREFIXES}
        return labels
