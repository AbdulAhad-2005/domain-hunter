import argparse
import logging
import re
import sys
import time
from datetime import datetime

from config import APIConfig
from core.aggregator import aggregate
from core.exporter import export_csv, export_xlsx
from modules.ai_hunt import AIHuntModule
from modules.asn_recon import ASNReconModule
from modules.certs import CertsModule
from modules.corroboration import SeedContext, _brand_tokens
from modules.dns_infra import DNSInfraModule
from modules.fingerprint import FingerprintModule
from modules.knowledge_recon import KnowledgeReconModule
from modules.pattern_gen import PatternGenModule
from modules.site_scrape import SiteScrapeModule
from modules.tld_variants import TLDVariantsModule
from modules.whois_lookup import WhoisLookupModule

logger = logging.getLogger(__name__)

AVAILABLE_MODULES = {
    "certs": CertsModule,
    "dns": DNSInfraModule,
    "asn": ASNReconModule,
    "tld_variants": TLDVariantsModule,
    "pattern_gen": PatternGenModule,
    "knowledge_recon": KnowledgeReconModule,
    "site_scrape": SiteScrapeModule,
    "whois_lookup": WhoisLookupModule,
    "fingerprint": FingerprintModule,
    "ai_hunt": AIHuntModule,
}

# Some modules need results from others before they can do their job, so
# execution happens in three stages rather than in --modules order:
#  1. Base modules -- run independently, in any order.
#  2. tld_variants / pattern_gen -- need a SeedContext (seed's WHOIS/DNS/ASN/
#     favicon + every domain already found) to corroborate a resolving
#     variant before treating it as a real finding (see
#     modules/corroboration.py) rather than "resolves, therefore related".
#  3. ai_hunt -- needs the org name and every domain found by everything
#     else, per its own design (PROJECT_OVERVIEW.md 4.6). Always runs last.
_CONTEXT_DEPENDENT = {"tld_variants", "pattern_gen"}
_AI_HUNT = "ai_hunt"

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Domain Hunter — discover domains associated with a seed domain"
    )
    parser.add_argument("--domain", required=True, help="Seed domain, e.g. example.com")
    parser.add_argument(
        "--modules",
        default=",".join(AVAILABLE_MODULES),
        help=f"Comma-separated modules to run (available: {', '.join(AVAILABLE_MODULES)})",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path (.csv or .xlsx). Default: findings_<domain>_<timestamp>.csv",
    )
    parser.add_argument(
        "--confidence-min",
        choices=["low", "medium", "high"],
        default="low",
        help="Only report findings at or above this confidence tier",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true", help="Debug-level logging")
    verbosity.add_argument("--quiet", action="store_true", help="Warnings and errors only")
    return parser.parse_args()


def _default_output_path(domain: str) -> str:
    safe_domain = re.sub(r"[^A-Za-z0-9.]", "_", domain)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    return f"findings_{safe_domain}_{timestamp}.csv"


def _mx_domain(mx_record: str) -> str | None:
    import tldextract

    host = mx_record.split()[-1].rstrip(".")
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _build_seed_context(findings: list, instances: dict, domain: str = "") -> SeedContext:
    """Gathers everything found about the seed itself by the base-stage
    modules, for tld_variants/pattern_gen to corroborate a resolving variant
    against (see modules/corroboration.py)."""
    whois_inst = instances.get("whois_lookup")
    dns_inst = instances.get("dns")
    asn_inst = instances.get("asn")
    fp_inst = instances.get("fingerprint")

    seed_mx_domains = set()
    if dns_inst is not None:
        for mx in dns_inst.records.get("mx", []):
            d = _mx_domain(mx)
            if d:
                seed_mx_domains.add(d)

    seed_asns = set()
    if asn_inst is not None:
        for record in asn_inst.asn_info.get("records", []):
            asn_number = (record.get("asn") or {}).get("asn")
            if asn_number:
                seed_asns.add(asn_number)

    title = ""
    if fp_inst is not None and getattr(fp_inst, "fingerprint", None):
        title = fp_inst.fingerprint.get("title") or ""

    seed_brand_tokens = _brand_tokens(domain, title) if domain else []

    return SeedContext(
        known_domains={f.associated_domain for f in findings},
        seed_registrant_org=whois_inst.record.get("registrant_org") if whois_inst else None,
        seed_ns=set(dns_inst.records.get("ns", [])) if dns_inst else set(),
        seed_mx_domains=seed_mx_domains,
        seed_asns=seed_asns,
        seed_favicon_md5=fp_inst.fingerprint.get("favicon_md5") if fp_inst else None,
        seed_brand_tokens=seed_brand_tokens,
    )


def _run_module(name: str, config: APIConfig, domain: str, **run_kwargs) -> dict:
    """Runs one module, returning its telemetry record + findings + the
    module instance itself (so callers can pull recon-only data off it, e.g.
    whois_lookup's .record). Never raises -- a module exception is caught and
    reported as a FAILED status so one broken module can't take down the run
    (per CLAUDE.md rule 1)."""
    module = AVAILABLE_MODULES[name](config)

    if module.requires_key and not config.has(module.requires_key) and not module.has_free_fallback:
        logger.warning(
            "%s: SKIPPED — no %s key configured and this module has no free fallback",
            name, module.requires_key,
        )
        return {
            "name": name, "status": f"SKIPPED (no {module.requires_key} key)",
            "elapsed": 0.0, "count": 0, "findings": [], "instance": module,
        }

    logger.info("Starting %s (%s tier)", module.name, module.enabled_tier)
    start = time.time()
    try:
        findings = module.run(domain, **run_kwargs)
        elapsed = time.time() - start
        if not module.produces_findings:
            logger.info("%s completed in %.1fs — recon only, no associated-domain findings", name, elapsed)
            status = "OK (recon only)"
        else:
            logger.info("%s completed in %.1fs — %d finding(s)", name, elapsed, len(findings))
            status = "OK"
        return {
            "name": name, "status": status, "elapsed": elapsed,
            "count": len(findings), "findings": findings, "instance": module,
        }
    except Exception as exc:
        elapsed = time.time() - start
        logger.exception("%s: FAILED after %.1fs", name, elapsed)
        return {
            "name": name, "status": f"FAILED — {exc}", "elapsed": elapsed,
            "count": 0, "findings": [], "instance": module,
        }


def _col_width(header: str, values: list[str], padding: int = 2) -> int:
    return max(len(header), *(len(v) for v in values)) + padding if values else len(header) + padding


def _print_summary_table(module_runs: list[dict]) -> None:
    print("\n=== Module Summary ===")
    name_w = _col_width("Module", [r["name"] for r in module_runs])
    status_w = _col_width("Status", [r["status"] for r in module_runs])
    print(f"{'Module':<{name_w}}{'Status':<{status_w}}{'Elapsed':<10}{'Findings':<10}")
    for r in module_runs:
        print(f"{r['name']:<{name_w}}{r['status']:<{status_w}}{r['elapsed']:<10.1f}{r['count']:<10}")


def _print_findings_table(aggregated) -> None:
    print("\n=== Findings ===")
    if not aggregated:
        print("(none)")
        return
    domain_w = _col_width("Domain", [f.associated_domain for f in aggregated])
    method_w = _col_width("Method", [f.method for f in aggregated])
    print(f"{'Domain':<{domain_w}}{'Method':<{method_w}}{'Confidence':<12}{'Live':<6}")
    for f in aggregated:
        live = "Yes" if f.live else "No"
        print(f"{f.associated_domain:<{domain_w}}{f.method:<{method_w}}{f.confidence:<12}{live:<6}")


def main():
    args = parse_args()
    level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    requested = [m.strip() for m in args.modules.split(",") if m.strip()]
    unknown = [m for m in requested if m not in AVAILABLE_MODULES]
    if unknown:
        print(
            f"Unknown module(s): {', '.join(unknown)}. Available: {', '.join(AVAILABLE_MODULES)}",
            file=sys.stderr,
        )
        sys.exit(1)

    config = APIConfig.load()
    findings = []
    module_runs = []
    instances = {}

    base_modules = [m for m in requested if m not in _CONTEXT_DEPENDENT and m != _AI_HUNT]
    context_modules = [m for m in requested if m in _CONTEXT_DEPENDENT]

    for name in base_modules:
        result = _run_module(name, config, args.domain)
        module_runs.append(result)
        findings.extend(result["findings"])
        instances[name] = result["instance"]

    if context_modules:
        seed_context = _build_seed_context(findings, instances, domain=args.domain)
        for name in context_modules:
            result = _run_module(name, config, args.domain, seed_context=seed_context)
            module_runs.append(result)
            findings.extend(result["findings"])

    if _AI_HUNT in requested:
        # ai_hunt runs last: give it the org name and domains already found by
        # every other module, per its own design (see modules/ai_hunt.py).
        whois_inst = instances.get("whois_lookup")
        kr_run = next((r for r in module_runs if r["name"] == "knowledge_recon"), None)
        seed_registrant_org = whois_inst.record.get("registrant_org") if whois_inst else None
        org_name = seed_registrant_org
        if kr_run is not None and kr_run["instance"].entity_label:
            org_name = kr_run["instance"].entity_label

        result = _run_module(
            _AI_HUNT, config, args.domain,
            org_name=org_name,
            known_domains=[f.associated_domain for f in findings],
            seed_registrant_org=seed_registrant_org,
        )
        module_runs.append(result)
        findings.extend(result["findings"])

    aggregated = aggregate(findings)
    min_rank = _CONFIDENCE_RANK[args.confidence_min]
    aggregated = [f for f in aggregated if _CONFIDENCE_RANK[f.confidence] >= min_rank]

    output_path = args.output or _default_output_path(args.domain)
    if output_path.endswith(".xlsx"):
        export_xlsx(aggregated, output_path)
    else:
        export_csv(aggregated, output_path)

    _print_summary_table(module_runs)
    _print_findings_table(aggregated)
    print(f"\nWrote {len(aggregated)} finding(s) to {output_path}")


if __name__ == "__main__":
    main()
