# Domain Hunter — Agent Instructions

## Spec

The full project design lives in `PROJECT_OVERVIEW.md`, in this same directory. **Read it before starting any task in this repo.** It defines:

- Purpose and design philosophy (§1–2)
- Exact output format (§3)
- Every discovery method, grouped by free vs. paid/keyed tier (§4)
- Module architecture and folder structure (§5)
- The `Finding` data model and `ReconModule` base class contract (§5.1–5.2)
- Aggregation/confidence logic (§5.3)
- CLI shape (§6)
- Build roadmap, v0.1 through v1.0 (§7)
- Responsible-use constraints (§8)

Treat `PROJECT_OVERVIEW.md` as the source of truth for structure, naming, and scope. If a request conflicts with it, flag the conflict rather than silently picking one side.

## Non-negotiable working rules

1. **Free-first, always.** Every module must work with zero API keys configured, using its free-tier method. A missing key degrades a module to its free fallback (or a clear skip with a log message) — it never blocks the run and never raises an unhandled error.
2. **No monetization, ever.** This is free, open-source software. Never add telemetry, usage tracking, license gating, "pro" tiers, or anything that phones home. Users bring their own API keys for services they already pay for; the tool itself is not a product.
3. **AI hypothesis module is verify-only.** In `ai_hunt.py`, LLM output must never be written directly to a `Finding`. Every LLM-suggested domain must be independently verified (at minimum, DNS resolution) before it can become a `Finding`. This is not configurable and must not be relaxed even if asked.
4. **No active scanning.** This tool queries third-party data sources about domains. It does not port-scan, brute-force, or actively probe infrastructure the user doesn't own. If a feature request drifts toward active scanning, pause and confirm with the user first.
5. **Module contract.** Every new data-source module implements the `ReconModule` abstract base class from `core/base.py` (see spec §5.1) and returns a `list[Finding]`. Keep this consistent so the aggregator never needs source-specific logic.
6. **Respect ToS.** Do not add raw scraping of sources with restrictive Terms of Service (e.g. Google search results, LinkedIn). Prefer official APIs, even on free tiers. Document rate limits and ToS notes for any new source in `docs/SOURCES.md`.
7. **Ask before adding dependencies.** New pip/npm packages need explicit sign-off first — list what you want to add and why before running the install.
8. **Small, reviewable steps.** Prefer building one module or one function at a time over large multi-file sweeps. Make a checkpoint commit after each working increment so changes are easy to review and roll back.
9. **No secrets in code or commits.** API keys live only in `config.yaml` (gitignored). Never hardcode a key, never commit `config.yaml` itself — only `config.yaml.example` with `null` placeholders.

## Current status

Check the roadmap in `PROJECT_OVERVIEW.md` §7 for what's built vs. planned. Update that section's checkboxes (or add a `## Progress` note here) as milestones complete, so future sessions know where things stand without re-deriving it.

## Commands

```bash
pip install -r requirements.txt

python main.py --domain example.com                          # free run, CSV output
python main.py --domain example.com --output findings.xlsx    # Excel output
python main.py --domain example.com --confidence-min medium   # filter low-confidence findings
python main.py --domain example.com --verbose                 # see per-module tier (free/paid) and skips
```

No test runner or lint command established yet (v0.1 has no `tests/` content — that's a v1.0 roadmap item per spec §7).
