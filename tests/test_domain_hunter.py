import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from config import APIConfig
from core.models import Finding
from modules.corroboration import (
    _BRAND_STOPWORDS,
    SeedContext,
    _brand_tokens,
    _shares_brand_token,
    corroborate,
)
from modules.dns_infra import DNSInfraModule
from modules.fingerprint import FingerprintModule
from modules.knowledge_recon import KnowledgeReconModule
from modules.site_scrape import SiteScrapeModule
from modules.whois_lookup import _REGISTRAR_DOMAINS, WhoisLookupModule


# ==============================================================================
# 1. Brand Tokens & Affiliation Gating
# ==============================================================================
def test_shares_brand_token():
    assert _shares_brand_token("geoit.tv", ["geo"])
    assert _shares_brand_token("teslamotors.com", ["tesla"])
    assert not _shares_brand_token("google.com", ["careem"])
    assert not _shares_brand_token("amazonses.com", ["careem"])
    assert not _shares_brand_token("outlook.com", ["nust"])


def test_brand_stopwords():
    tokens = _brand_tokens("example.com", "Welcome to the Official Site | Latest News")
    for word in ("site", "official", "latest", "news", "welcome", "the"):
        assert word not in tokens
    assert not _shares_brand_token("sitemaps.org", tokens)


def test_corroborate_with_brand_tokens():
    ctx = SeedContext(
        known_domains={"known.com"},
        seed_brand_tokens=["acme"],
    )
    sig, note = corroborate("known.com", "acme.com", ctx)
    assert sig == "known_domain"

    sig, note = corroborate("acmepay.com", "acme.com", ctx)
    assert sig == "brand_token"
    assert "acme" in note

    sig, note = corroborate("unrelated.com", "acme.com", ctx)
    assert sig is None
    assert note is None


# ==============================================================================
# 2. DNS Infra Affiliation Filtering
# ==============================================================================
def test_dns_infra_filters_third_party_providers():
    config = APIConfig({})
    mod = DNSInfraModule(config)

    def mock_query(resolver, qdomain, rtype):
        if rtype == "MX":
            return ["10 aspmx.l.google.com.", "20 mail.careemlogistics.com."]
        if rtype == "TXT" and "_dmarc" in qdomain:
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@careem.com,mailto:re@rua.agari.com"]
        if rtype == "TXT":
            return ["v=spf1 include:_spf.google.com include:mailgun.org include:careemmail.com ~all"]
        return []

    with patch.object(mod, "_query", side_effect=mock_query):
        findings = mod.run("careem.com")

    associated = {f.associated_domain for f in findings}
    # Third party providers must be excluded
    assert "google.com" not in associated
    assert "mailgun.org" not in associated
    assert "agari.com" not in associated

    # Brand-sharing self-hosted infrastructure must be retained
    assert "careemlogistics.com" in associated
    assert "careemmail.com" in associated


# ==============================================================================
# 3. Site Scrape Brand Gating
# ==============================================================================
def test_site_scrape_categorization_and_filtering():
    config = APIConfig({})
    mod = SiteScrapeModule(config)

    html_homepage = """
    <html>
        <head><title>Acme Global Corp</title></head>
        <body>
            <a href="https://acmestore.com">Store</a>
            <a href="https://twitter.com/acme">Twitter</a>
            <a href="https://google.com">Google</a>
            <a href="https://partner-portal.net">Partner</a>
            <a href="/investors">Investors</a>
        </body>
    </html>
    """

    html_relationship = """
    <html>
        <body>
            <p>Our parent company is <a href="https://holdings-group.com">Holdings Group</a></p>
        </body>
    </html>
    """

    def mock_get(url, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        if "investors" in url:
            mock_resp.text = html_relationship
            mock_resp.url = url
        elif "robots.txt" in url:
            mock_resp.text = "Sitemap: https://acme.com/sitemap.xml\nDisallow: /admin"
            mock_resp.url = url
        elif "sitemap.xml" in url:
            mock_resp.text = "<urlset><url><loc>https://acmeapp.com/download</loc></url></urlset>"
            mock_resp.url = url
        else:
            mock_resp.text = html_homepage
            mock_resp.url = "https://acme.com/"
        return mock_resp

    with patch("requests.get", side_effect=mock_get):
        findings = mod.run("acme.com")

    by_domain = {f.associated_domain: f for f in findings}

    # Brand-matching link: medium confidence
    assert "acmestore.com" in by_domain
    assert by_domain["acmestore.com"].method == "site_scrape_brand"
    assert by_domain["acmestore.com"].confidence == "medium"

    # Relationship page link: low confidence
    assert "holdings-group.com" in by_domain
    assert by_domain["holdings-group.com"].method == "site_scrape_relationship"
    assert by_domain["holdings-group.com"].confidence == "low"

    # Robots/sitemap brand match: medium confidence
    assert "acmeapp.com" in by_domain

    # Unrelated outbound links without brand token must be dropped
    assert "twitter.com" not in by_domain
    assert "google.com" not in by_domain
    assert "partner-portal.net" not in by_domain


# ==============================================================================
# 4. Knowledge Recon: Wikidata Action API & Wikipedia
# ==============================================================================
def _make_entity(label, p856=None, p355=None, p749=None, p127=None, instance_of=None, description=""):
    def claims(prop, values):
        if not values:
            return []
        res = []
        for v in values:
            if isinstance(v, dict):
                res.append({"mainsnak": {"datavalue": {"value": v}}})
            else:
                res.append({"mainsnak": {"datavalue": {"value": v}}})
        return res

    return {
        "labels": {"en": {"value": label}},
        "descriptions": {"en": {"value": description}},
        "claims": {
            "P856": claims("P856", p856),
            "P355": claims("P355", [{"id": q} for q in p355] if p355 else None),
            "P749": claims("P749", [{"id": q} for q in p749] if p749 else None),
            "P127": claims("P127", [{"id": q} for q in p127] if p127 else None),
            "P31": claims("P31", [{"id": q} for q in instance_of] if instance_of else None),
        },
    }


def test_knowledge_recon_wikidata_traversal_and_filtering():
    config = APIConfig({})
    mod = KnowledgeReconModule(config)

    entities = {
        "Q1": _make_entity("Seed Co", p856=["https://seed.com"], p355=["Q2"], p749=["Q3"], p127=["Q4", "Q5", "Q6"]),
        "Q2": _make_entity("Subsidiary Co", p856=["https://subsidiary.com"]),
        "Q3": _make_entity("Parent Group", p856=["https://parentgroup.com"]),
        # Q4 is an investment fund / financial services company -> must be excluded
        "Q4": _make_entity("Vanguard Fund", p856=["https://vanguard.com"], description="investment management company"),
        # Q5 is a human shareholder (Q5 instance of human) -> must be excluded
        "Q5": _make_entity("John Founder", p856=["https://personalblog.com"], instance_of=["Q5"]),
        # Q6 is a genuine corporate holding foundation -> must be kept
        "Q6": _make_entity("Holding Foundation", p856=["https://holdingfoundation.org"]),
    }

    def mock_get(url, params=None, *args, **kwargs):
        params = params or {}
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        if "action" in params:
            if params["action"] == "wbsearchentities":
                resp.json.return_value = {"search": [{"id": "Q1"}]}
            elif params["action"] == "wbgetentities":
                ids = params["ids"].split("|")
                resp.json.return_value = {
                    "entities": {qid: entities[qid] for qid in ids if qid in entities}
                }
            elif params["action"] == "opensearch":
                resp.json.return_value = ["seed", [], [], []]
        return resp

    with patch.object(requests.Session, "get", side_effect=mock_get):
        findings = mod.run("seed.com")

    by_domain = {f.associated_domain: f for f in findings}

    assert "subsidiary.com" in by_domain
    assert "parentgroup.com" in by_domain
    assert "holdingfoundation.org" in by_domain

    # Financial firm and human shareholder are filtered out
    assert "vanguard.com" not in by_domain
    assert "personalblog.com" not in by_domain


def test_knowledge_recon_unverified_entity_rejected():
    config = APIConfig({})
    mod = KnowledgeReconModule(config)

    # Q99 does not have P856 matching seed.com
    entities = {
        "Q99": _make_entity("Unrelated Co", p856=["https://unrelated.com"], p355=["Q100"]),
        "Q100": _make_entity("Other Co", p856=["https://other.com"]),
    }

    def mock_get(url, params=None, *args, **kwargs):
        resp = MagicMock()
        resp.ok = True
        params = params or {}
        if params.get("action") == "wbsearchentities":
            resp.json.return_value = {"search": [{"id": "Q99"}]}
        elif params.get("action") == "wbgetentities":
            resp.json.return_value = {"entities": entities}
        elif params.get("action") == "opensearch":
            resp.json.return_value = ["seed", [], [], []]
        return resp

    with patch.object(requests.Session, "get", side_effect=mock_get):
        findings = mod.run("seed.com")

    assert len(findings) == 0


# ==============================================================================
# 5. Fingerprint & Tracker Pivoting
# ==============================================================================
def test_fingerprint_tracker_pivot():
    config = APIConfig({})
    mod = FingerprintModule(config)

    homepage_html = """
    <html>
        <head><title>My Company</title></head>
        <body>
            <script>
                (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;})(window,document,'script','//www.google-analytics.com/analytics.js','ga');
                ga('create', 'UA-12345678-1', 'auto');
            </script>
            <script>
                (function(w,d,s,l,i){w[l]=w[l]||[];})(window,document,'script','dataLayer','GTM-ABC1234');
            </script>
        </body>
    </html>
    """

    def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        if "urlscan.io" in url:
            resp.json.return_value = {
                "results": [
                    {"page": {"domain": "app.mycompany-portal.com"}},
                    {"page": {"domain": "mycompany.eu"}},
                    {"page": {"domain": "mycompany.com"}},  # same as seed
                ]
            }
        else:
            resp.text = homepage_html
            resp.url = "https://mycompany.com/"
            resp.content = b""
        return resp

    with patch("requests.get", side_effect=mock_get):
        findings = mod.run("mycompany.com")

    associated = {f.associated_domain for f in findings}
    assert "mycompany-portal.com" in associated
    assert "mycompany.eu" in associated
    assert "mycompany.com" not in associated  # seed domain excluded
    assert all(f.method == "tracker_pivot" for f in findings)
    assert all(f.confidence == "high" for f in findings)


# ==============================================================================
# 6. Whois Lookup & Whoxy Reverse WHOIS
# ==============================================================================
def test_whois_lookup_whoxy_reverse():
    config = APIConfig({"whoxy_api_key": "test_whoxy_key"})
    mod = WhoisLookupModule(config)
    assert mod.enabled_tier == "paid"
    assert mod.produces_findings is True

    whoxy_whois_resp = {
        "status": 1,
        "whois_data": {
            "domain_registrar": {"registrar_name": "MarkMonitor"},
            "create_date": "2010-01-01",
            "name_servers": ["ns1.seed.com", "ns2.seed.com"],
            "registrant_contact": {
                "full_name": "Seed Admin",
                "company_name": "Seed Corporation",
                "email_address": "domains@seed.com",
            },
        },
    }

    whoxy_reverse_resp = {
        "status": 1,
        "total_domains": 3,
        "domains_list": [
            "seed-internal.net",
            "seed-payments.com",
            "privacyprotect.org",  # In _REGISTRAR_DOMAINS -> must be excluded
            "seed.com",            # Seed domain -> must be excluded
        ],
    }

    def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        if "reverse=whois" in url:
            resp.json.return_value = whoxy_reverse_resp
        else:
            resp.json.return_value = whoxy_whois_resp
        return resp

    with patch("requests.get", side_effect=mock_get):
        findings = mod.run("seed.com")

    associated = {f.associated_domain for f in findings}
    assert "seed-internal.net" in associated
    assert "seed-payments.com" in associated
    assert "privacyprotect.org" not in associated
    assert "seed.com" not in associated
    assert all(f.method == "reverse_whois" for f in findings)
    assert all(f.confidence == "high" for f in findings)


# ==============================================================================
# 7. Config Environment Variable Fallback
# ==============================================================================
def test_config_env_fallback():
    cfg = APIConfig({})
    assert not cfg.has("whoxy")

    with patch.dict(os.environ, {"WHOXY_API_KEY": "env_whoxy_secret"}):
        assert cfg.has("whoxy")
        assert cfg.get("whoxy_api_key") == "env_whoxy_secret"


# ==============================================================================
# 8. Wikipedia Infobox Parsing
# ==============================================================================
def test_wikipedia_infobox_parsing():
    config = APIConfig({})
    mod = KnowledgeReconModule(config)

    html_infobox = """
    <html>
        <body>
            <table class="infobox vcard">
                <tr>
                    <th scope="row">Website</th>
                    <td><a class="external text" href="https://acme.com">acme.com</a></td>
                </tr>
                <tr>
                    <th scope="row">Owner</th>
                    <td><a href="/wiki/Acme_Holdings">Acme Holdings LLC</a> (<a class="external" href="https://acmeholdings.net">acmeholdings.net</a>)</td>
                </tr>
                <tr>
                    <th scope="row">Traded as</th>
                    <td><a href="https://nasdaq.com/market-activity/stocks/acme">NASDAQ: ACME</a></td>
                </tr>
            </table>
        </body>
    </html>
    """

    def mock_get(url, params=None, *args, **kwargs):
        resp = MagicMock()
        resp.ok = True
        params = params or {}
        if params.get("action") == "opensearch":
            resp.json.return_value = ["acme", ["Acme Corp"], [""], ["https://en.wikipedia.org/wiki/Acme_Corp"]]
        elif "en.wikipedia.org/wiki/" in url:
            resp.text = html_infobox
        else:
            resp.json.return_value = {"search": [], "entities": {}}
        return resp

    with patch.object(requests.Session, "get", side_effect=mock_get):
        findings = mod.run("acme.com")

    by_domain = {f.associated_domain: f for f in findings}
    assert "acmeholdings.net" in by_domain
    assert by_domain["acmeholdings.net"].method == "wikipedia_infobox"
    # Stock exchange site must be excluded
    assert "nasdaq.com" not in by_domain


# ==============================================================================
# 9. Free-Tier Fallbacks
# ==============================================================================
def test_whois_lookup_rdap_free_tier():
    config = APIConfig({})
    mod = WhoisLookupModule(config)
    assert mod.enabled_tier == "free"
    assert mod.produces_findings is False

    mock_rdap = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy"]]],
            },
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["org", {}, "text", "Acme Corporation"],
                    ["email", {}, "text", "admin@acme.com"],
                ]],
            },
        ],
        "events": [{"eventAction": "registration", "eventDate": "2015-05-01"}],
        "nameservers": [{"ldhName": "ns1.acme.com"}, {"ldhName": "ns2.acme.com"}],
    }

    with patch.object(mod, "_query_rdap", return_value=mock_rdap):
        findings = mod.run("acme.com")

    assert findings == []
    assert mod.record["registrar"] == "GoDaddy"
    assert mod.record["registrant_org"] == "Acme Corporation"
    assert mod.record["registrant_email"] == "admin@acme.com"


def test_fingerprint_no_trackers():
    config = APIConfig({})
    mod = FingerprintModule(config)

    html_plain = "<html><head><title>No Trackers</title></head><body>Hello World</body></html>"
    with patch.object(mod, "_fetch_homepage", return_value=(html_plain, "https://notrackers.com/")):
        findings = mod.run("notrackers.com")

    assert findings == []
    assert mod.fingerprint["title"] == "No Trackers"
    assert mod.fingerprint["ga_id"] is None

