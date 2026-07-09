import logging

import tldextract

from core.models import Finding
from modules.base import ReconModule
from modules._dns_utils import resolve_many
from modules.corroboration import STRONG_SIGNALS, SeedContext, corroborate

logger = logging.getLogger(__name__)

_GENERIC_TLDS = ["com", "net", "org", "co", "io", "biz", "info"]
_CCTLD_PATTERNS = [
    "{label}.{cc}",
    "{label}.co.{cc}",
    "{label}.com.{cc}",
    "{label}.net.{cc}",
    "{label}.org.{cc}",
    "{label}.gov.{cc}",
]


class TLDVariantsModule(ReconModule):
    """Checks the seed's organization label across common TLDs/ccTLDs.

    Catches same-brand domains registered under a different TLD (e.g. an org
    on ptcl.com.pk also holding ptcl.net.pk). But resolving is NOT evidence of
    common ownership by itself -- nust.com and nust.net both resolve and have
    nothing to do with nust.edu.pk; they just belong to unrelated third
    parties who happen to hold the same label. So a resolving variant is only
    promoted to a real finding (medium/high confidence) if it also picks up a
    corroborating signal (shared WHOIS registrant, shared NS/MX/ASN/favicon,
    or independently found by another module this run -- see
    modules/corroboration.py). Without corroboration it's recorded as a
    "low"-confidence, explicitly-labelled unconfirmed lead rather than a
    finding -- dropped entirely only if it doesn't resolve at all (nothing to
    even corroborate).
    """

    name = "tld_variants"
    requires_key = None

    def run(self, domain: str, seed_context: SeedContext | None = None) -> list[Finding]:
        ext = tldextract.extract(domain)
        label = ext.domain
        if not label:
            return []

        candidates = self._generate_candidates(label, ext.suffix)
        candidates.discard(domain)

        logger.info("tld_variants: checking %d TLD/ccTLD candidates for label %r", len(candidates), label)
        resolved = resolve_many(sorted(candidates))

        findings = []
        for candidate, ip in sorted(resolved.items()):
            status = f"resolves (to {ip})" if ip else "is registered/delegated (NS present, no direct A/AAAA)"
            signal, note = corroborate(candidate, domain, seed_context)

            if signal:
                confidence = "high" if signal in STRONG_SIGNALS else "medium"
                evidence = (
                    f'{candidate} shares the label "{label}" with {domain}, {status}, '
                    f"and is corroborated: {note}."
                )
            else:
                confidence = "low"
                evidence = (
                    f'{candidate} shares the label "{label}" with {domain} and {status} — '
                    f"TLD variant resolves but ownership UNCONFIRMED — may be unrelated "
                    f"(no corroborating signal found; could be the same org, an unrelated "
                    f"org with the same name, or a squatted/parked domain)."
                )

            findings.append(Finding(
                seed_domain=domain,
                associated_domain=candidate,
                method="tld_variant",
                evidence=evidence,
                raw_data={
                    "label": label, "resolved_ip": ip,
                    "corroboration_signal": signal, "corroboration_note": note,
                },
                confidence=confidence,
            ))
        return findings

    def _generate_candidates(self, label: str, suffix: str) -> set[str]:
        candidates = {f"{label}.{tld}" for tld in _GENERIC_TLDS}
        if suffix:
            cc = suffix.split(".")[-1]
            candidates.update(pattern.format(label=label, cc=cc) for pattern in _CCTLD_PATTERNS)
        return candidates
