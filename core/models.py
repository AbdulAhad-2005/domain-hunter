from dataclasses import dataclass


@dataclass
class Finding:
    seed_domain: str
    associated_domain: str
    method: str            # e.g. "favicon_hash", "cert_san_match"
    evidence: str           # human-readable explanation
    raw_data: dict          # underlying data, for debugging/re-verification
    confidence: str         # "high" | "medium" | "low"
