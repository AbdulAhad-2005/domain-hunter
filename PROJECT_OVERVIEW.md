# Domain Hunter

**An open-source OSINT tool for discovering domains associated with a target domain — free by default, smarter with your own API keys.**

---

## 1. Purpose

Domain Hunter takes a single seed domain (e.g. `example.com`) and discovers other domains likely owned or operated by the same organization — subsidiaries, regional sites, shadow IT, forgotten staging domains, sister brands, phishing-adjacent lookalikes, and infrastructure siblings.

It exists because this kind of discovery is currently a manual, tribal-knowledge process: an analyst juggles ten browser tabs across crt.sh, Shodan, WHOIS lookups, and BuiltWith, copy-pasting results into a spreadsheet by hand. Domain Hunter automates the well-known techniques, runs them consistently, and outputs a structured, evidenced result set.

**Primary use case:** general-purpose OSINT reconnaissance — attack surface mapping, brand/asset discovery, due diligence, and pentest scoping support.

**Explicitly not:** an active scanner. It queries third-party data sources about domains; it does not port-scan, crawl aggressively, or touch infrastructure it doesn't own. Anything found should still be validated against an engagement's actual rules of engagement before being treated as in-scope.

---

## 2. Design Philosophy

1. **Free by default.** Every core technique has a no-API-key path. A user with zero accounts, zero budget, and zero setup should still get useful results on the first run.
2. **Better with keys, never worse without them.** API keys are optional upgrades to existing modules, not gates. A module without its key simply falls back to its free method, or skips with a clear log line — it never blocks the run.
3. **Bring your own key, not a subscription.** This project does not sell tiers, does not monetize, and does not proxy anyone's paid API access. If a user already pays for Shodan, SecurityTrails, or an LLM API, they can drop the key into a config file and get richer results. That's the entire model.
4. **Evidence over assertion.** Every finding states *how* it was found and *what data* supports it, so a human can judge credibility rather than trust a black box.
5. **Cross-validation increases confidence, not volume.** A domain flagged by two independent methods is more trustworthy than a domain flagged once — the tool should reflect that in its output, not just list everything flatly.
6. **Fail gracefully, module by module.** A rate-limited or broken data source should degrade that one module, not crash the whole run.

---

## 3. What the Tool Outputs

A CSV (default) or Excel file with one row per associated domain found, for example:

| Associated Domain | Method | Evidence | Confidence | Sources Agreeing |
|---|---|---|---|---|
| `example-corp.io` | Certificate org pivot | Same certificate organization field: "Example Corp Ltd" (crt.sh) | High | 2 |
| `exampleapp.net` | Favicon hash match | Identical favicon MD5 hash `a3f8e2...` | Medium | 1 |
| `example-hr.com` | Reverse WHOIS | Same registrant email `admin@example.com` | High | 1 |
| `exampleinc.com` | AI hypothesis (verified) | LLM-suggested variant, confirmed live via DNS resolution | Low | 1 |

Excel output additionally includes a summary sheet (counts by method, by confidence tier) and highlights high-confidence rows.

---

## 4. Discovery Methods

Grouped by data source category. Each entry notes whether it needs an API key.

### 4.1 Certificate & DNS-based

| Technique | Free path | Paid/keyed upgrade |
|---|---|---|
| Certificate transparency search | `crt.sh` public JSON endpoint — search by domain and by certificate organization field | Censys API — richer metadata, faster queries, historical depth |
| Shared SSL cert serials/issuers | Cross-reference certs pulled from crt.sh | Censys bulk cert search |
| Reverse WHOIS (registrant email/org/phone) | Limited — historical WHOIS scraping where legally accessible | WhoisXML API, DomainTools, ViewDNS — actual reverse WHOIS indexes |
| Shared DNS infrastructure (NS/MX/SPF/TXT overlap) | Direct DNS queries via `dnspython`, no key needed | — |
| Passive DNS / historical A-records | crt.sh SAN history as a weak proxy | SecurityTrails, RiskIQ/PassiveTotal, Farsight DNSDB |
| ASN / IP block ownership | `bgpview.io` free API | Shodan/Censys bulk IP-range search |

### 4.2 Web-based fingerprinting

| Technique | Free path | Paid/keyed upgrade |
|---|---|---|
| Favicon hash matching | Self-fetch favicon, compute MurmurHash3, free-tier Shodan search | Shodan paid tier, Censys, FofaSearch |
| Analytics/Tag ID pivoting (GA, GTM, FB Pixel, Hotjar) | Self-fetch page source, regex-extract IDs, manual cross-reference | DNSlytics, SpyOnWeb, BuiltWith API |
| Shared ad/tracking IDs (AdSense pub-ID, Google Ads conversion ID) | Self-fetch + extraction | Same as above |
| Tech stack fingerprinting | Self-fetch headers/HTML, simple signature matching | Wappalyzer API, BuiltWith API |
| Shared hosting / reverse IP | Free reverse-IP lookups (HackerTarget has a limited free API) | ViewDNS, Shodan |

### 4.3 Corporate / legal record based

| Technique | Free path | Paid/keyed upgrade |
|---|---|---|
| Trademark databases | USPTO TESS (free), WIPO Global Brand DB (free) | — |
| Corporate registries | OpenCorporates free tier, SEC EDGAR (free, US public companies) | OpenCorporates paid tier for non-US depth |
| Subsidiary disclosure in filings | SEC EDGAR full-text search (free) | — |

### 4.4 Search engine & OSINT dorking

| Technique | Free path | Paid/keyed upgrade |
|---|---|---|
| Footer copyright text matching, brand dorking | Skipped by default (raw scraping is fragile and ToS-risky) | Google Custom Search API or Bing Search API (both have small free tiers, used instead of scraping) |
| LinkedIn "Affiliated pages" | Manual/documented as a technique; not automated in v1 (ToS restrictions on LinkedIn scraping) | — |
| Crunchbase / PitchBook subsidiary data | Not automated in v1 | Crunchbase API (paid) |
| Job posting domain leakage | Not automated in v1 — documented as a manual technique | — |

### 4.5 Email & communication-based

| Technique | Free path | Paid/keyed upgrade |
|---|---|---|
| MX record overlap | Direct DNS query, free | — |
| SPF `include:` chain analysis | Direct DNS TXT query, free | — |
| Email header analysis | Manual input mode (user pastes headers) | — |
| Breach corpus cross-reference | Not automated by default (sensitive data handling) | Have I Been Pwned API (if user has key) |

### 4.6 AI-assisted hypothesis generation

The final pass, run only if the user supplies an LLM API key (Anthropic, Gemini, OpenAI, or any OpenAI-compatible endpoint).

**Critical design constraint: the LLM never produces a "finding" directly.** It is used purely as a *hypothesis generator* — given the seed domain, company name, and everything already confirmed, it suggests plausible additional domain name patterns (regional TLDs, product sub-brands, likely subsidiary names). Every suggestion is then independently verified by the tool itself (DNS resolution at minimum, ideally cross-checked against certificate/WHOIS data) before it's allowed into the output. This is non-configurable — it protects the tool from ever shipping a hallucinated domain as fact, regardless of who forks it or how it's invoked.

---

## 5. Architecture

```
domain-hunter/
├── README.md                 # quickstart, free-vs-paid feature matrix
├── PROJECT_OVERVIEW.md        # this document
├── LICENSE                    # MIT or Apache-2.0
├── config.yaml.example        # template for API keys (gitignored when filled in)
├── requirements.txt
├── main.py                    # CLI entrypoint (argparse)
├── config.py                  # loads config.yaml, exposes has("service") checks
├── modules/
│   ├── base.py                 # ReconModule abstract base class
│   ├── certs.py                 # crt.sh + optional Censys
│   ├── dns_infra.py             # NS/MX/SPF/TXT overlap, passive DNS
│   ├── whois_recon.py           # reverse WHOIS (free-limited / WhoisXML / DomainTools)
│   ├── fingerprint.py           # favicon hash, GA/GTM/Pixel ID, tech stack
│   ├── asn_recon.py             # BGP/ASN IP block domains
│   ├── dorking.py               # Google/Bing Search API (keyed only, no scraping)
│   ├── corporate.py             # OpenCorporates, SEC EDGAR
│   └── ai_hunt.py                # LLM hypothesis generation + mandatory verification
├── core/
│   ├── models.py                 # Finding dataclass
│   ├── aggregator.py             # dedup, merge, cross-validate confidence
│   └── exporter.py               # CSV / XLSX writer
├── tests/
└── docs/
    └── SOURCES.md                 # per-source rate limits, ToS notes, setup instructions
```

### 5.1 Module contract

Every module — regardless of free or keyed — implements the same interface, so the aggregator and CLI never need to know which tier actually ran:

```python
class ReconModule(ABC):
    name: str
    requires_key: str | None = None  # e.g. "shodan"; None if fully free

    def __init__(self, config: APIConfig):
        self.config = config
        self.enabled_tier = "paid" if self.requires_key and config.has(self.requires_key) else "free"

    @abstractmethod
    def run(self, domain: str) -> list[Finding]:
        ...
```

### 5.2 Data model

```python
@dataclass
class Finding:
    seed_domain: str
    associated_domain: str
    method: str            # e.g. "favicon_hash", "cert_org_pivot"
    evidence: str           # human-readable explanation
    raw_data: dict          # underlying data, for debugging/re-verification
    confidence: str         # "high" | "medium" | "low"
```

### 5.3 Aggregation logic

Findings are grouped by associated domain. If two or more *independent* methods flag the same domain, confidence is boosted — this is where free vs. paid data quality differences surface naturally, without special-casing tiers anywhere in the aggregation code itself.

### 5.4 Config

```yaml
# config.yaml.example
shodan_api_key: null
censys_api_id: null
censys_api_secret: null
securitytrails_api_key: null
whoisxml_api_key: null
builtwith_api_key: null
google_search_api_key: null
google_search_cx: null
llm_provider: null        # "anthropic" | "gemini" | "openai" | "custom"
llm_api_key: null
llm_base_url: null         # for custom OpenAI-compatible endpoints
```

Modules check `config.has("shodan")` etc. and log a clear, non-fatal message when a key is absent (`"Shodan key not configured — using free favicon search fallback"`).

---

## 6. CLI Usage (planned)

```bash
# Fully free run, no config needed
python main.py --domain example.com

# Select specific modules
python main.py --domain example.com --modules certs,dns,fingerprint

# With keys configured in config.yaml, richer results automatically
python main.py --domain example.com --output findings.xlsx

# Only report medium-confidence-and-above findings
python main.py --domain example.com --confidence-min medium

# Verbose logging to see which modules ran on free vs. paid tier
python main.py --domain example.com --verbose
```

---

## 7. Roadmap

**v0.1 (initial working release)**
- Core `Finding` model, aggregator, CSV/XLSX exporter
- `certs.py` (crt.sh, no key required)
- `dns_infra.py` (NS/MX/SPF/TXT overlap, no key required)
- Basic CLI

**v0.2**
- `fingerprint.py` (favicon hashing, tech stack fingerprinting)
- `asn_recon.py` (bgpview.io)
- `corporate.py` (OpenCorporates, SEC EDGAR)

**v0.3**
- Keyed upgrades: Shodan, Censys, SecurityTrails, WhoisXML
- `dorking.py` via Google/Bing Search API

**v0.4**
- `ai_hunt.py` with mandatory verification pipeline
- Confidence-boosting cross-validation across all modules

**v1.0**
- Documentation pass (`docs/SOURCES.md` covering every source's rate limits and ToS)
- Test coverage for aggregation logic
- Packaging for `pip install`

---

## 8. Responsible Use Notes

- This tool only queries public/third-party data sources about a domain — it does not perform active scanning of discovered domains.
- Discovering that a domain is likely related to an organization does **not** mean it is authorized for further testing. In a pentest context, always confirm scope against the actual engagement rules of engagement before acting on any finding.
- Some data sources (LinkedIn, Google search scraping) have restrictive Terms of Service around automated access. The tool avoids raw scraping where ToS is a concern, preferring official APIs even on the free tier, and `docs/SOURCES.md` documents this per-source so contributors don't inadvertently violate a source's ToS when adding new modules.
- Breach-data cross-referencing is intentionally not automated by default, given the sensitivity of that data category.

---

## 9. Licensing

Recommended: **MIT** or **Apache-2.0** — both are permissive, widely understood in the security tooling community, and place no restriction on commercial or non-commercial use by downstream users. No monetization, paid tier, or hosted service is planned for this project; it is offered as free and open-source software.
