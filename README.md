# Domain Hunter

**An open-source OSINT tool for discovering domains associated with a target domain — free by default, smarter with your own API keys.**

Domain Hunter takes a seed domain (e.g. `example.com`) and finds other domains likely owned, operated, or affiliated with the same organization: subsidiaries, joint ventures, sister brands, hosted projects, and shared infrastructure. Every result states *how* it was found and *what evidence* supports it — nothing is asserted without a reason.

See [METHODOLOGY.md](METHODOLOGY.md) for a full breakdown of how each discovery module works, and [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) for the original design spec.

---

## Install

```bash
pip install -r requirements.txt
cp config.yaml.example config.yaml   # optional — only needed for keyed modules
```

`config.yaml` is where you put your own API keys (Censys, Shodan, an LLM provider, etc.). It's gitignored — never commit it. Every module works with zero keys configured; keys just unlock richer results on modules that support them.

## Quickstart

```bash
# Free run, all no-key modules, CSV output
python main.py --domain example.com

# Excel output, with a summary sheet
python main.py --domain example.com --output findings.xlsx

# Only specific modules
python main.py --domain example.com --modules certs,dns,knowledge_recon,site_scrape

# Only report medium-confidence-and-above findings
python main.py --domain example.com --confidence-min medium

# Debug-level logging (per-module query detail) / quiet (warnings only)
python main.py --domain example.com --verbose
python main.py --domain example.com --quiet
```

By default, output is written to a timestamped file: `findings_<domain>_<timestamp>.csv`. Pass `--output` to override.

## Output

Each row is one associated domain, with:

| Column | Meaning |
|---|---|
| Associated Domain | The discovered domain |
| Method | Which module(s) found it |
| Evidence | Human-readable explanation, always citing the actual source |
| Confidence | `high` / `medium` / `low` — see METHODOLOGY.md for how this is set |
| Sources Agreeing | How many independent methods flagged this domain |
| Live | Whether it currently resolves and responds over HTTP/HTTPS — **independent of confidence**; a domain can be live but unrelated, or dead but historically related |

Console output additionally shows a per-module timing/status summary and the same findings table live, as the run happens.

## Modules

Run with `--modules name1,name2,...` (default: all of them). Free unless noted.

| Name | What it does |
|---|---|
| `certs` | Certificate transparency search via crt.sh (SAN co-occurrence) |
| `dns` | NS/MX/TXT(SPF) recon on the seed; surfaces non-provider MX/SPF targets |
| `asn` | ASN/IP block ownership via bgpview.io |
| `tld_variants` | Seed's label checked across common TLDs/ccTLDs, corroboration-gated |
| `pattern_gen` | Rule-based label variants (+group, +mobile, etc.), corroboration-gated |
| `knowledge_recon` | Wikidata: subsidiary/owned-by/parent/product/developer/affiliation relationships |
| `site_scrape` | Self-scrapes the seed's own homepage + relationship pages for org-listed links |
| `whois_lookup` | RDAP recon on the seed (registrant org/email, registrar) — feeds other modules, produces no findings itself |
| `fingerprint` | GA/GTM/Pixel IDs + favicon hash on the seed — feeds other modules, produces no findings itself |
| `ai_hunt` | **Keyed** (needs `llm_provider`/`llm_api_key` in config.yaml) — LLM hypothesis generation, every suggestion independently verified before being recorded. Skipped entirely with no key configured. |

`certs`/`dns`/`asn`/`knowledge_recon` also have a paid/keyed upgrade path (Censys, WhoisXML, etc.) documented in PROJECT_OVERVIEW.md §4 — not required for normal use.

## Responsible use

This tool queries public/third-party data sources about a domain. It does **not** port-scan, brute-force, or actively probe infrastructure you don't own. Finding that a domain is likely associated with an organization does not mean it's authorized for further testing — always confirm scope against actual engagement rules before acting on any result.
