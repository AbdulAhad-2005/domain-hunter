from collections import defaultdict
from dataclasses import dataclass, field

from core.liveness import check_live_many
from core.models import Finding

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_RANK_TO_CONFIDENCE = {rank: name for name, rank in _CONFIDENCE_RANK.items()}
_MAX_RANK = max(_CONFIDENCE_RANK.values())


@dataclass
class AggregatedFinding:
    """One merged output row for a single associated domain (section 3's CSV/XLSX row)."""
    seed_domain: str
    associated_domain: str
    method: str
    evidence: str
    confidence: str
    sources_agreeing: int
    findings: list[Finding] = field(default_factory=list)
    # Factual liveness (DNS + HTTP/HTTPS), independent of relationship
    # confidence -- see core/liveness.py. Populated by aggregate() unless
    # check_liveness=False.
    live: bool = False
    live_detail: dict = field(default_factory=dict)


def aggregate(findings: list[Finding], check_liveness: bool = True) -> list[AggregatedFinding]:
    """Group findings by associated domain, boost confidence when independent
    methods agree on the same domain (section 5.3), and -- once, here, on the
    final deduped list, not per-module -- check which domains are currently
    live."""
    by_domain: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_domain[finding.associated_domain].append(finding)

    aggregated = []
    for domain, group in by_domain.items():
        methods = sorted({f.method for f in group})
        sources_agreeing = len(methods)

        best_rank = max(_CONFIDENCE_RANK[f.confidence] for f in group)
        if sources_agreeing >= 2:
            best_rank = min(best_rank + 1, _MAX_RANK)
        confidence = _RANK_TO_CONFIDENCE[best_rank]

        seed_domain = group[0].seed_domain
        method = "+".join(methods)
        evidence = "; ".join(dict.fromkeys(f.evidence for f in group))

        aggregated.append(AggregatedFinding(
            seed_domain=seed_domain,
            associated_domain=domain,
            method=method,
            evidence=evidence,
            confidence=confidence,
            sources_agreeing=sources_agreeing,
            findings=group,
        ))

    if check_liveness and aggregated:
        live_results = check_live_many([a.associated_domain for a in aggregated])
        for a in aggregated:
            is_live, detail = live_results.get(a.associated_domain, (False, {}))
            a.live = is_live
            a.live_detail = detail

    aggregated.sort(key=lambda a: (-_CONFIDENCE_RANK[a.confidence], -a.sources_agreeing, a.associated_domain))
    return aggregated
