#!/usr/bin/env python3
"""vulnresearch - CVE / product-version vulnerability research for detection engineers.

Stdlib only. Sources: NVD 2.0, CISA KEV, CISA ADP SSVC (via CVE.org), FIRST EPSS,
GitHub (repo search + nomi-sec/PoC-in-GitHub), GitHub Security Advisories, OSV.dev,
Exploit-DB (GitLab CSV mirror), Reddit (RSS search), X (optional, via `xurl` CLI if
authenticated), AlienVault OTX, Shodan CVEDB, GreyNoise, VirusTotal, and ThreatFox
(optional API keys).

Usage:
  vulnresearch.py CVE-2021-44228 [CVE-...]
  vulnresearch.py --product "Apache Tomcat" --version 9.0.30 [--limit 10]
  options: --format table|markdown|json|csv   --no-social

Env (optional): GITHUB_TOKEN, NVD_API_KEY, GREYNOISE_API_KEY, VIRUSTOTAL_API_KEY,
THREATFOX_API_KEY. AlienVault OTX and Shodan CVEDB need no key.
"""
import argparse, csv, html as html_lib, io, ipaddress, json, math, os, re, shutil, subprocess, sys, textwrap, time
import urllib.parse, urllib.request, urllib.error
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path


def _apply_env_file(path):
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def load_repo_env():
    """Load an optional .env without overriding process env.

    Two layouts are supported so keys work both in the development repo and
    once installed as a Hermes skill:
      - installed skill: <skills-dir>/<category>/vuln-research/scripts/
        vulnresearch.py -> the skill's own directory (1 parent up) may hold
        a user-placed .env, since there is no repository root to find there.
      - repo checkout: skills/vuln-research/scripts/vulnresearch.py ->
        repository root .env is 3 parents up.
    Both are checked (skill dir first, since it's closer to where a user
    installing the skill would actually drop a .env); neither overrides
    variables already exported in the environment.
    """
    here = Path(__file__).resolve()
    candidates = [here.parents[1] / ".env", here.parents[3] / ".env"]
    for path in candidates:
        try:
            if path.is_file():
                _apply_env_file(path)
        except OSError:
            continue


load_repo_env()

UA = "vulnresearch/0.1 (+https://github.com/; detection-engineering)"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss?cve="
CVEORG = "https://cveawg.mitre.org/api/cve/"
POCGH = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{y}/{cve}.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

COLUMNS = ["CVE ID", "Name", "Description", "Affected Products", "Exploit Available Online",
           "Chatter Level", "IoCs", "App Type", "Auth", "Vector", "CVSS", "ITW Exploitation"]

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_XURL_OUTPUT_BYTES = 2 * 1024 * 1024
RESPONSE_TOO_LARGE = -2
SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "apikey", "x-apikey", "key", "cookie", "cookie2"
})
_nvd_request_times = deque()


def _origin(url):
    parsed = urllib.parse.urlsplit(url)
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects without forwarding credentials to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        if _origin(req.full_url) != _origin(newurl):
            for name in list(redirected.headers):
                if name.lower() in SENSITIVE_HEADERS:
                    redirected.remove_header(name)
            for name in list(redirected.unredirected_hdrs):
                if name.lower() in SENSITIVE_HEADERS:
                    redirected.remove_header(name)
        return redirected


_URL_OPENER = urllib.request.build_opener(SafeRedirectHandler())


def _pace_nvd():
    """Enforce NVD's rolling 30-second limits for keyed and unkeyed requests."""
    limit = 50 if os.environ.get("NVD_API_KEY") else 5
    now = time.monotonic()
    while _nvd_request_times and now - _nvd_request_times[0] >= 30.0:
        _nvd_request_times.popleft()
    if len(_nvd_request_times) >= limit:
        delay = 30.0 - (now - _nvd_request_times[0])
        if delay > 0:
            time.sleep(delay)
        now = time.monotonic()
        while _nvd_request_times and now - _nvd_request_times[0] >= 30.0:
            _nvd_request_times.popleft()
    _nvd_request_times.append(now)


def http(url, headers=None, timeout=25, retries=2):
    h = {"User-Agent": UA}
    h.update(headers or {})
    if any(name.lower() in SENSITIVE_HEADERS and value for name, value in h.items()):
        if urllib.parse.urlsplit(url).scheme.lower() != "https":
            raise ValueError("credential-bearing HTTP requests require HTTPS")
    for i in range(retries + 1):
        try:
            if (urllib.parse.urlsplit(url).hostname or "").lower() == "services.nvd.nist.gov":
                _pace_nvd()
            with _URL_OPENER.open(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                declared = r.headers.get("Content-Length") if getattr(r, "headers", None) else None
                if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                    return RESPONSE_TOO_LARGE, b""
                body = r.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    return RESPONSE_TOO_LARGE, b""
                return r.status, body
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and i < retries:
                time.sleep(6 * (i + 1)); continue
            return e.code, b""
        except Exception:
            if i < retries:
                time.sleep(2); continue
            return 0, b""
    return 0, b""


def jget(url, headers=None):
    return json_result(url, headers)[0]


def json_result(url, headers=None):
    """Return decoded JSON and a source-safe error string without hiding failures."""
    code, body = http(url, headers)
    if code != 200:
        detail = "response exceeded size limit" if code == RESPONSE_TOO_LARGE else (
            f"HTTP {code}" if code else "network error")
        return None, detail
    try:
        return json.loads(body), None
    except (ValueError, UnicodeDecodeError):
        return None, "invalid JSON"


# ---------------- core data ----------------
_kev = None
def kev_index_result():
    global _kev
    if _kev is None:
        d, error = json_result(KEV)
        if error:
            return {}, f"CISA KEV {error}"
        try:
            _kev = {v["cveID"].upper(): v for v in d.get("vulnerabilities", [])}
        except (AttributeError, KeyError, TypeError):
            return {}, "CISA KEV malformed response"
    return _kev, None


def kev_index():
    """Compatibility wrapper returning only the cached KEV mapping."""
    return kev_index_result()[0]


def nvd_headers():
    k = os.environ.get("NVD_API_KEY")
    return {"apiKey": k} if k else {}


def nvd_cve_result(cve):
    d, error = json_result(f"{NVD}?cveId={cve}", nvd_headers())
    if error:
        return None, f"NVD {error}"
    try:
        v = d.get("vulnerabilities") or []
        if not isinstance(v, list):
            raise TypeError
        if not v:
            return None, None
        item = v[0]
        candidate = item["cve"]
        if not _valid_nvd_cve(candidate) or candidate["id"].upper() != cve.upper():
            raise TypeError
        return candidate, None
    except (AttributeError, KeyError, TypeError):
        return None, "NVD malformed response"


def nvd_cve(cve):
    """Compatibility wrapper returning only the NVD CVE object."""
    return nvd_cve_result(cve)[0]


def nvd_product_search(product, version, limit):
    """Fetch every NVD result page before sorting/filtering; report partial failures."""
    q = urllib.parse.quote(product.strip())
    items, start, total, error = [], 0, None, None
    while total is None or start < total:
        url = f"{NVD}?keywordSearch={q}&resultsPerPage=250&startIndex={start}"
        d, page_error = json_result(url, nvd_headers())
        if page_error:
            error = f"NVD product search {page_error} at startIndex {start}"
            break
        try:
            page = d.get("vulnerabilities")
            page_total = d.get("totalResults")
            page_start = d.get("startIndex")
            page_size = d.get("resultsPerPage")
        except AttributeError:
            error = f"NVD product search malformed response at startIndex {start}"
            break
        pagination_values = (page_total, page_start, page_size)
        if (any(isinstance(value, bool) or not isinstance(value, int) for value in pagination_values)
                or page_total < 0 or page_start != start or page_size < 0
                or (page_total > start and page_size == 0)
                or (total is not None and page_total != total)):
            error = f"NVD product search invalid pagination at startIndex {start}"
            break
        if total is None:
            total = page_total
        if not isinstance(page, list) or any(not isinstance(item, dict) or not _valid_nvd_cve(item.get("cve"))
                                             for item in page):
            error = f"NVD product search malformed response at startIndex {start}"
            break
        if len(page) > page_size or start + len(page) > total:
            error = f"NVD product search invalid pagination at startIndex {start}"
            break
        items.extend(page)
        if not page:
            if start < total:
                error = f"NVD product search returned an empty page at startIndex {start}"
            break
        start += len(page)
    out = []
    ver = (version or "").strip()
    items = sorted(items, key=lambda x: x["cve"].get("published", ""), reverse=True)
    for item in items:
        c = item["cve"]
        if ver and not version_matches(c, product, ver):
            continue
        out.append(c["id"])
        if len(out) >= limit:
            break
    total = total if total is not None and total >= 0 else 0
    return out, total, error is None and start >= total, error


def _vt(v):
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.\-_]", v))


def _cmp(a, b):
    try:
        ta, tb = _vt(a), _vt(b)
        return (ta > tb) - (ta < tb)
    except TypeError:
        return (a > b) - (a < b)


def _valid_nvd_node(node):
    if not isinstance(node, dict):
        return False
    matches = node.get("cpeMatch", [])
    children = node.get("nodes", [])
    if not isinstance(matches, list) or not isinstance(children, list):
        return False
    for match in matches:
        if not isinstance(match, dict) or not isinstance(match.get("criteria"), str):
            return False
        if "vulnerable" in match and not isinstance(match["vulnerable"], bool):
            return False
        for key in ("versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding"):
            if key in match and not isinstance(match[key], str):
                return False
    return all(_valid_nvd_node(child) for child in children)


def _valid_cve_id(value):
    return isinstance(value, str) and CVE_RE.fullmatch(value) is not None


def _valid_cvss_data(data):
    """Validate every CVSS scalar consumed by classification and rendering."""
    if not isinstance(data, dict):
        return False
    string_fields = ("version", "baseSeverity", "vectorString", "attackVector", "accessVector",
                     "privilegesRequired", "authentication", "userInteraction")
    if any(field in data and not isinstance(data[field], str) for field in string_fields):
        return False
    if "baseScore" in data:
        score = data["baseScore"]
        if (isinstance(score, bool) or not isinstance(score, (int, float))
                or not math.isfinite(score) or not 0 <= score <= 10):
            return False
    return True


def _valid_nvd_cve(cve):
    """Validate NVD fields consumed by this module before trusting the record."""
    if not isinstance(cve, dict) or not _valid_cve_id(cve.get("id")):
        return False
    if "published" in cve and not isinstance(cve["published"], str):
        return False
    descriptions = cve.get("descriptions", [])
    configurations = cve.get("configurations", [])
    metrics = cve.get("metrics", {})
    if (not isinstance(descriptions, list) or not isinstance(configurations, list)
            or not isinstance(metrics, dict)):
        return False
    if any(not isinstance(item, dict)
           or not isinstance(item.get("lang"), str)
           or not isinstance(item.get("value"), str) for item in descriptions):
        return False
    for config in configurations:
        if not isinstance(config, dict) or not isinstance(config.get("nodes", []), list):
            return False
        if not all(_valid_nvd_node(node) for node in config.get("nodes", [])):
            return False
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key, [])
        if (not isinstance(values, list)
                or any(not isinstance(value, dict)
                       or ("type" in value and not isinstance(value["type"], str))
                       or not _valid_cvss_data(value.get("cvssData"))
                       or ("baseSeverity" in value and not isinstance(value["baseSeverity"], str))
                       for value in values)):
            return False
    return True


def _configuration_matches(c):
    """Yield all CPE match objects, including NVD's nested node form."""
    def walk(node):
        yield from node.get("cpeMatch", [])
        for child in node.get("nodes", []):
            yield from walk(child)
    for cfg in c.get("configurations", []):
        for node in cfg.get("nodes", []):
            yield from walk(node)


def _name_tokens(value):
    return {token for token in re.split(r"[^a-z0-9]+", value.lower().replace("\\_", "_")) if token}


def _parse_cpe23(criteria):
    """Split CPE 2.3 fields while decoding backslash-escaped characters."""
    if not isinstance(criteria, str):
        return []
    parts, current, escaped = [], [], False
    for char in criteria:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def _cpe_product_matches(criteria, product):
    parts = _parse_cpe23(criteria)
    if len(parts) < 6:
        return False
    wanted = _name_tokens(product)
    candidate = _name_tokens(urllib.parse.unquote(parts[3]) + " " + urllib.parse.unquote(parts[4]))
    return bool(wanted) and wanted.issubset(candidate)


def version_matches(c, product, ver):
    """True if any CPE match in NVD config covers `ver` (exact or range). Falls back to text."""
    matches = list(_configuration_matches(c))
    for m in matches:
        if not m.get("vulnerable") or not _cpe_product_matches(m.get("criteria", ""), product):
            continue
        parts = _parse_cpe23(m["criteria"])
        if len(parts) < 6:
            continue
        cv = parts[5]
        if cv not in ("*", "-"):
            if cv == ver:
                return True
            continue
        lo_i, lo_e = m.get("versionStartIncluding"), m.get("versionStartExcluding")
        hi_i, hi_e = m.get("versionEndIncluding"), m.get("versionEndExcluding")
        if not any([lo_i, lo_e, hi_i, hi_e]):
            return True
        ok = True
        if lo_i and _cmp(ver, lo_i) < 0: ok = False
        if lo_e and _cmp(ver, lo_e) <= 0: ok = False
        if hi_i and _cmp(ver, hi_i) > 0: ok = False
        if hi_e and _cmp(ver, hi_e) >= 0: ok = False
        if ok:
            return True
    if not matches:  # fresh CVE with no CPE enrichment: require product and version in prose
        description = json.dumps(c.get("descriptions", [])).lower()
        return ver.lower() in description and _name_tokens(product).issubset(_name_tokens(description))
    return False


def cvss(c):
    m = c.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            best = next((x for x in m[key] if x.get("type") == "Primary"), m[key][0])
            d = best["cvssData"]
            sev = d.get("baseSeverity") or best.get("baseSeverity", "")
            return {"version": d.get("version"), "score": d.get("baseScore"), "severity": sev,
                    "vector": d.get("vectorString", ""), "av": d.get("attackVector") or d.get("accessVector"),
                    "pr": d.get("privilegesRequired") or ({"NONE": "NONE"}.get(d.get("authentication"), d.get("authentication"))),
                    "ui": d.get("userInteraction")}
    return None


def cna_fallback_result(cve):
    """Return parsed CVE.org fallback data and an explicit source error."""
    d, error = json_result(CVEORG + cve)
    res = {"cvss": None, "ssvc_exploitation": None, "title": None, "desc": None, "affected": []}
    if error:
        if error == "HTTP 404":
            return res, None
        return res, f"CVE.org {error}"
    if not isinstance(d, dict) or not isinstance(d.get("containers", {}), dict):
        return res, "CVE.org malformed response"
    metadata = d.get("cveMetadata")
    if (not isinstance(metadata, dict) or not _valid_cve_id(metadata.get("cveId"))
            or metadata["cveId"].upper() != cve.upper()):
        return res, "CVE.org malformed response"
    cont = d.get("containers", {})
    cna = cont.get("cna", {})
    adp = cont.get("adp", [])
    if not isinstance(cna, dict) or not isinstance(adp, list):
        return res, "CVE.org malformed response"

    descriptions = cna.get("descriptions", [])
    affected_items = cna.get("affected", [])
    blocks = [cna] + adp
    if (not isinstance(descriptions, list)
            or any(not isinstance(item, dict)
                   or not isinstance(item.get("lang"), str)
                   or not isinstance(item.get("value"), str) for item in descriptions)
            or not isinstance(affected_items, list)
            or any(not isinstance(item, dict) for item in affected_items)
            or any(not isinstance(block, dict) for block in blocks)):
        return res, "CVE.org malformed response"
    for item in affected_items:
        versions = item.get("versions", [])
        if (not isinstance(versions, list)
                or any(not isinstance(version, dict)
                       or not isinstance(version.get("version", ""), str) for version in versions)):
            return res, "CVE.org malformed response"
    for block in blocks:
        metrics = block.get("metrics", [])
        if not isinstance(metrics, list) or any(not isinstance(metric, dict) for metric in metrics):
            return res, "CVE.org malformed response"
        for metric in metrics:
            if any(key in metric and not isinstance(metric[key], dict)
                   for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0")):
                return res, "CVE.org malformed response"
            if any(key in metric and not _valid_cvss_data(metric[key])
                   for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0")):
                return res, "CVE.org malformed response"
            if "other" in metric:
                other = metric["other"]
                if not isinstance(other, dict):
                    return res, "CVE.org malformed response"
                content = other.get("content", {})
                if not isinstance(content, dict):
                    return res, "CVE.org malformed response"
                options = content.get("options", [])
                if not isinstance(options, list) or any(not isinstance(option, dict) for option in options):
                    return res, "CVE.org malformed response"
                if any("Exploitation" in option and not isinstance(option["Exploitation"], str)
                       for option in options):
                    return res, "CVE.org malformed response"

    res["title"] = cna.get("title")
    for de in descriptions:
        if de["lang"].startswith("en"):
            res["desc"] = de["value"]; break
    for a in affected_items:
        vers = ",".join(v.get("version", "") for v in a.get("versions", [])[:4])
        res["affected"].append(f"{a.get('vendor','?')} {a.get('product','?')} {vers}".strip())
    for block in blocks:
        for met in block.get("metrics", []):
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if k in met and not res["cvss"]:
                    d2 = met[k]
                    res["cvss"] = {"version": d2.get("version"), "score": d2.get("baseScore"),
                                   "severity": d2.get("baseSeverity"), "vector": d2.get("vectorString", ""),
                                   "av": d2.get("attackVector"), "pr": d2.get("privilegesRequired"),
                                   "ui": d2.get("userInteraction")}
            other = met.get("other", {})
            if other.get("type") == "ssvc":
                for o in other.get("content", {}).get("options", []):
                    if "Exploitation" in o:
                        res["ssvc_exploitation"] = o["Exploitation"]
    return res, None


def cna_fallback(cve):
    """Compatibility wrapper returning only parsed CNA fallback data."""
    return cna_fallback_result(cve)[0]


def epss_result(cve):
    """Return EPSS probabilities plus an explicit transport or schema error."""
    d, error = json_result(EPSS + cve)
    if error:
        return None, f"FIRST EPSS {error}"
    if not isinstance(d, dict) or not isinstance(d.get("data"), list) or len(d["data"]) != 1:
        return None, "FIRST EPSS malformed response"
    record = d["data"][0]
    if (not isinstance(record, dict) or not _valid_cve_id(record.get("cve"))
            or record["cve"].upper() != cve.upper()):
        return None, "FIRST EPSS malformed response"
    try:
        values = {name: float(record[name]) for name in ("epss", "percentile")}
    except (KeyError, TypeError, ValueError, OverflowError):
        return None, "FIRST EPSS malformed response"
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in values.values()):
        return None, "FIRST EPSS malformed response"
    return values, None


def epss(cve):
    """Compatibility wrapper returning only validated EPSS values."""
    return epss_result(cve)[0]


# ---------------- indicators ----------------
def greynoise_iocs(cve):
    """Return GreyNoise scanner IPs associated with a CVE when GNQL access is configured.

    The public /v1/cve endpoint only confirms that GreyNoise knows the vulnerability; it
    does not expose scanner IPs. GNQL (API key/entitlement required) supplies the IoCs.
    """
    public = jget(f"https://api.greynoise.io/v1/cve/{cve}")
    key = os.environ.get("GREYNOISE_API_KEY") or os.environ.get("GN_API_KEY")
    result = {"public_cve_record": bool(public), "queried": False, "ips": [], "error": None}
    if not key:
        result["error"] = "GreyNoise API key missing (set GREYNOISE_API_KEY); public CVE endpoint has no IP indicators"
        return result
    query = urllib.parse.quote(f"cve:{cve}")
    code, body = http(f"https://api.greynoise.io/v3/gnql?query={query}&size=50",
                      {"key": key})
    result["queried"] = True
    if code != 200:
        result["error"] = f"GreyNoise GNQL HTTP {code} (key may lack GNQL entitlement)"
        return result
    try:
        data = json.loads(body)
    except ValueError:
        result["error"] = "GreyNoise returned invalid JSON"
        return result
    if not isinstance(data, dict) or not isinstance(data.get("data", []), list):
        result["error"] = "GreyNoise returned malformed JSON"
        return result
    meta = data.get("request_metadata", {})
    items = data.get("data", [])
    if not isinstance(meta, dict):
        result["error"] = "GreyNoise returned malformed JSON"
        return result
    restricted_fields = meta.get("restricted_fields", [])
    if (not isinstance(restricted_fields, list)
            or any(not isinstance(field, str) for field in restricted_fields)):
        result["error"] = "GreyNoise returned malformed JSON"
        return result
    restricted = set(restricted_fields)
    if "cve" in restricted:
        result["error"] = "GreyNoise plan restricts the CVE field; GNQL results were not used"
        return result
    for item in items[:50]:
        if not isinstance(item, dict):
            result["ips"] = []
            result["error"] = "GreyNoise returned malformed JSON"
            return result
        ip = item.get("ip")
        intel = item.get("internet_scanner_intelligence", {})
        if not isinstance(intel, dict):
            result["ips"] = []
            result["error"] = "GreyNoise returned malformed JSON"
            return result
        cves = intel.get("cves", [])
        tags = intel.get("tags", [])
        if (not isinstance(cves, list) or any(not isinstance(value, str) for value in cves)
                or not isinstance(tags, list)
                or any(not isinstance(tag, (str, dict)) for tag in tags)
                or (ip is not None and not isinstance(ip, str))
                or any(value is not None and not isinstance(value, str)
                       for value in (intel.get("classification"), intel.get("last_seen")))):
            result["ips"] = []
            result["error"] = "GreyNoise returned malformed JSON"
            return result
        if any(isinstance(tag, dict)
               and any(tag.get(key) is not None and not isinstance(tag.get(key), str)
                       for key in ("name", "slug")) for tag in tags):
            result["ips"] = []
            result["error"] = "GreyNoise returned malformed JSON"
            return result
        linked_cves = {value.upper() for value in cves}
        # Defence against a provider silently ignoring a restricted/unsupported filter.
        if not ip or cve.upper() not in linked_cves:
            continue
        try:
            if not ipaddress.ip_address(ip).is_global:
                continue
        except ValueError:
            continue
        result["ips"].append({"ip": ip, "classification": intel.get("classification"),
                              "last_seen": intel.get("last_seen"),
                              "tags": [(t.get("name") or t.get("slug")) if isinstance(t, dict) else t
                                       for t in tags[:5]]})
    return result


def _analysis_stats(value):
    """Return normalized non-negative VT counters, or None for malformed stats."""
    if value is None:
        value = {}
    if not isinstance(value, dict):
        return None
    normalized = {}
    for name in ("malicious", "suspicious", "harmless"):
        raw = value.get(name, 0)
        if isinstance(raw, bool):
            return None
        if isinstance(raw, int) and raw >= 0:
            normalized[name] = raw
        elif isinstance(raw, str) and re.fullmatch(r"\s*\d+\s*", raw):
            normalized[name] = int(raw)
        else:
            return None
    return normalized


_EDB_CACHE_TTL = 6 * 3600
_EDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


def _edb_cache_path():
    return Path(os.environ.get("TMPDIR", "/tmp")) / "vulnresearch_edb_cache.csv"


def exploitdb_lookup(cve):
    """Search Exploit-DB's public CSV index (GitLab mirror) for a CVE.

    No API key: Exploit-DB has no public search API, so this fetches/caches the
    maintained files_exploits.csv (mirrors the exploitdb repo) and greps the CVE
    tag column. Cached locally for _EDB_CACHE_TTL seconds to avoid refetching ~10MB.
    """
    result = {"queried": False, "hits": [], "error": None}
    cache = _edb_cache_path()
    body = None
    try:
        if cache.is_file() and time.time() - cache.stat().st_mtime < _EDB_CACHE_TTL:
            body = cache.read_bytes()
    except OSError:
        body = None
    if body is None:
        try:
            req = urllib.request.Request(_EDB_CSV_URL, headers={"User-Agent": UA})
            with _URL_OPENER.open(req, timeout=40) as r:
                body = r.read(40 * 1024 * 1024 + 1)
            if len(body) > 40 * 1024 * 1024:
                result["error"] = "Exploit-DB response exceeded size limit"
                return result
        except urllib.error.HTTPError as e:
            result["error"] = f"Exploit-DB HTTP {e.code}"
            return result
        except Exception:
            result["error"] = "Exploit-DB network error"
            return result
        try:
            cache.write_bytes(body)
        except OSError:
            pass
    result["queried"] = True
    try:
        text = body.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        needle = cve.upper()
        for row in reader:
            codes = (row.get("codes") or "").upper()
            if needle not in codes.split(";") and needle not in codes:
                continue
            edb_id = (row.get("id") or "").strip()
            if not edb_id.isdigit():
                continue
            result["hits"].append({
                "edb_id": edb_id,
                "title": sanitize_text((row.get("description") or "").strip())[:160],
                "type": (row.get("type") or "").strip(),
                "platform": (row.get("platform") or "").strip(),
                "verified": (row.get("verified") or "") == "1",
                "url": f"https://www.exploit-db.com/exploits/{edb_id}",
            })
    except (csv.Error, UnicodeDecodeError):
        result["error"] = "Exploit-DB CSV malformed"
        result["hits"] = []
    return result


def otx_pulses(cve):
    """Return AlienVault OTX pulse count/tags for a CVE. Public endpoint, no key."""
    result = {"queried": False, "pulse_count": 0, "tags": [], "top_pulses": [], "error": None}
    d, error = json_result(f"https://otx.alienvault.com/api/v1/indicators/cve/{cve}/general")
    if error:
        result["error"] = f"OTX {error}"
        return result
    result["queried"] = True
    if not isinstance(d, dict) or not isinstance(d.get("pulse_info", {}), dict):
        result["error"] = "OTX malformed response"
        return result
    info = d.get("pulse_info", {})
    pulses = info.get("pulses", [])
    count = info.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or not isinstance(pulses, list):
        result["error"] = "OTX malformed response"
        return result
    result["pulse_count"] = count
    tags, names = set(), []
    for p in pulses[:20]:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if isinstance(name, str) and name:
            names.append(name)
        for tag in p.get("tags", []) if isinstance(p.get("tags", []), list) else []:
            if isinstance(tag, str):
                tags.add(tag)
    result["tags"] = sorted(tags)[:10]
    result["top_pulses"] = names[:5]
    return result


def shodan_cvedb(cve):
    """Cross-check CVSS/EPSS/KEV via Shodan's free, unauthenticated CVEDB endpoint."""
    result = {"queried": False, "cvss": None, "epss": None, "kev": None,
              "ransomware": None, "error": None}
    d, error = json_result(f"https://cvedb.shodan.io/cve/{cve}")
    if error:
        result["error"] = f"Shodan CVEDB {error}"
        return result
    result["queried"] = True
    if not isinstance(d, dict):
        result["error"] = "Shodan CVEDB malformed response"
        return result
    cvss_v = d.get("cvss")
    epss_v = d.get("epss")
    kev_v = d.get("kev")
    if (cvss_v is not None and (isinstance(cvss_v, bool) or not isinstance(cvss_v, (int, float)))
            or (epss_v is not None and (isinstance(epss_v, bool) or not isinstance(epss_v, (int, float))))
            or (kev_v is not None and not isinstance(kev_v, bool))):
        result["error"] = "Shodan CVEDB malformed response"
        return result
    result["cvss"] = cvss_v
    result["epss"] = epss_v
    result["kev"] = kev_v
    result["ransomware"] = d.get("ransomware_campaign") if isinstance(d.get("ransomware_campaign"), (str, type(None))) else None
    return result


def threatfox_iocs(cve):
    """Search ThreatFox (abuse.ch) for C2/malware IOCs tagged with a CVE.

    Requires THREATFOX_API_KEY (free signup); without it the source is skipped
    like GreyNoise/VirusTotal rather than silently omitted.
    """
    result = {"queried": False, "iocs": [], "error": None}
    key = os.environ.get("THREATFOX_API_KEY")
    if not key:
        result["error"] = "THREATFOX_API_KEY missing"
        return result
    payload = json.dumps({"query": "taginfo", "tag": cve.upper(), "limit": 50}).encode()
    try:
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/", data=payload,
            headers={"Content-Type": "application/json", "User-Agent": UA, "Auth-Key": key})
        with _URL_OPENER.open(req, timeout=25) as r:
            body = r.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as e:
        result["error"] = f"ThreatFox HTTP {e.code}"
        return result
    except Exception:
        result["error"] = "ThreatFox network error"
        return result
    result["queried"] = True
    try:
        d = json.loads(body)
    except ValueError:
        result["error"] = "ThreatFox returned invalid JSON"
        return result
    if not isinstance(d, dict):
        result["error"] = "ThreatFox malformed response"
        return result
    if d.get("query_status") != "ok":
        result["error"] = f"ThreatFox query_status={d.get('query_status')}"
        return result
    data = d.get("data", [])
    if not isinstance(data, list):
        result["error"] = "ThreatFox malformed response"
        return result
    for item in data[:30]:
        if not isinstance(item, dict):
            continue
        ioc_value = item.get("ioc")
        ioc_type = item.get("ioc_type")
        if not isinstance(ioc_value, str) or not isinstance(ioc_type, str):
            continue
        result["iocs"].append({
            "ioc": ioc_value, "type": ioc_type,
            "malware": item.get("malware_printable"),
            "confidence": item.get("confidence_level"),
            "first_seen": item.get("first_seen"),
        })
    return result


def osv_dev(cve):
    """Fetch OSV.dev's record for a CVE. Keyless, no rate-limit key needed.

    OSV aggregates open-source ecosystem advisories (PyPI, npm, Go, crates.io,
    Maven, etc.) and republishes each one under its own GHSA/OSV id while also
    indexing by CVE alias, so this covers package-manager-specific fix/affected
    version data that NVD's CPE matching often lacks.
    """
    result = {"queried": False, "found": False, "severity": None, "affected": [],
              "references": [], "aliases": [], "error": None}
    d, error = json_result(f"https://api.osv.dev/v1/vulns/{cve}")
    if error:
        if error == "HTTP 404":
            result["queried"] = True
            return result
        result["error"] = f"OSV.dev {error}"
        return result
    result["queried"] = True
    if not isinstance(d, dict):
        result["error"] = "OSV.dev malformed response"
        return result
    aliases = d.get("aliases", [])
    if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
        result["error"] = "OSV.dev malformed response"
        return result
    result["found"] = True
    result["aliases"] = aliases
    sev = d.get("severity", [])
    if isinstance(sev, list):
        for s in sev:
            if isinstance(s, dict) and isinstance(s.get("score"), str):
                result["severity"] = s["score"]
                break
    affected = d.get("affected", [])
    if isinstance(affected, list):
        for a in affected[:8]:
            if not isinstance(a, dict):
                continue
            pkg = a.get("package", {})
            if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
                eco = pkg.get("ecosystem", "")
                result["affected"].append(f"{eco}:{pkg['name']}".strip(":"))
    refs = d.get("references", [])
    if isinstance(refs, list):
        for r in refs[:5]:
            if isinstance(r, dict) and isinstance(r.get("url"), str):
                result["references"].append(r["url"])
    return result


def github_advisory(cve):
    """Look up the GitHub Security Advisory (GHSA) record for a CVE.

    Uses the keyless REST search (api.github.com/advisories?cve_id=...), not
    the GraphQL API which requires a token. GITHUB_TOKEN raises the rate limit
    if already configured for github_exploits, reused here too.
    """
    result = {"queried": False, "found": False, "ghsa_id": None, "severity": None,
              "summary": None, "cwes": [], "url": None, "error": None}
    d, error = json_result(f"https://api.github.com/advisories?cve_id={cve}", gh_headers())
    if error:
        result["error"] = f"GitHub Advisories {error}"
        return result
    result["queried"] = True
    if not isinstance(d, list) or any(not isinstance(item, dict) for item in d):
        result["error"] = "GitHub Advisories malformed response"
        return result
    if not d:
        return result
    item = d[0]
    ghsa_id = item.get("ghsa_id")
    if not isinstance(ghsa_id, str):
        result["error"] = "GitHub Advisories malformed response"
        return result
    result["found"] = True
    result["ghsa_id"] = ghsa_id
    result["severity"] = item.get("severity") if isinstance(item.get("severity"), str) else None
    result["summary"] = item.get("summary") if isinstance(item.get("summary"), str) else None
    result["url"] = item.get("html_url") if isinstance(item.get("html_url"), str) else None
    cwes = item.get("cwes", [])
    if isinstance(cwes, list):
        for c in cwes[:5]:
            if isinstance(c, dict) and isinstance(c.get("cwe_id"), str):
                result["cwes"].append(c["cwe_id"])
    return result


def virustotal_iocs(cve):
    """Search VirusTotal for CVE-linked file objects and community comments.

    VT's public API always requires a key. The generic /search endpoint can return
    files and comments; premium Intelligence may expose more results than a public key.
    """
    key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
    result = {"queried": False, "files": [], "comments": [], "other": [], "error": None}
    if not key:
        result["error"] = "VIRUSTOTAL_API_KEY missing"
        return result
    url = "https://www.virustotal.com/api/v3/search?query=" + urllib.parse.quote(cve) + "&limit=40"
    code, body = http(url, {"x-apikey": key, "Accept": "application/json"})
    result["queried"] = True
    if code != 200:
        result["error"] = f"VirusTotal search HTTP {code}"
        return result
    try:
        data = json.loads(body)
    except ValueError:
        result["error"] = "VirusTotal returned invalid JSON"
        return result
    if not isinstance(data, dict) or not isinstance(data.get("data", []), list):
        result["error"] = "VirusTotal returned malformed JSON"
        return result
    parsed_items = {"files": [], "comments": [], "other": []}

    def malformed():
        result["error"] = "VirusTotal returned malformed JSON"
        return result

    for item in data.get("data", []):
        if not isinstance(item, dict) or not isinstance(item.get("attributes", {}), dict):
            return malformed()
        typ, ident, attrs = item.get("type"), item.get("id", ""), item.get("attributes", {})
        if not isinstance(typ, str) or not isinstance(ident, str):
            return malformed()
        if typ == "file":
            meaningful_name = attrs.get("meaningful_name")
            names = attrs.get("names", [])
            tags = attrs.get("tags", [])
            if (meaningful_name is not None and not isinstance(meaningful_name, str)
                    or not isinstance(names, list)
                    or any(not isinstance(name, str) for name in names)
                    or not isinstance(tags, list)
                    or any(not isinstance(tag, str) for tag in tags)
                    or ("sha256" in attrs and not isinstance(attrs["sha256"], str))):
                return malformed()
            sha256 = attrs.get("sha256") or ident
            if not re.fullmatch(r"[0-9a-fA-F]{64}", str(sha256)):
                continue
            stats = _analysis_stats(attrs.get("last_analysis_stats"))
            if stats is None:
                continue
            parsed_items["files"].append({
                "sha256": sha256.lower(),
                "name": meaningful_name or (names or [None])[0],
                "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0), "tags": tags[:8],
            })
        elif typ == "comment":
            text = attrs.get("text", "")
            if not isinstance(text, str):
                return malformed()
            text = re.sub(r"\s+", " ", text).strip()
            parsed_items["comments"].append({"id": ident, "text": text[:300],
                                              "date": attrs.get("date"), "votes": attrs.get("votes")})
        elif typ in ("ip_address", "domain", "url"):
            value = attrs.get("url") if typ == "url" else ident
            if not isinstance(value, str):
                return malformed()
            stats = _analysis_stats(attrs.get("last_analysis_stats"))
            if stats is None:
                continue
            relevant = cve.lower() in json.dumps(attrs, sort_keys=True).lower()
            suspicious = stats["malicious"] + stats["suspicious"] > 0
            valid = False
            if typ == "ip_address":
                try:
                    valid = ipaddress.ip_address(value).is_global
                except ValueError:
                    valid = False
            elif typ == "domain":
                valid = bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", str(value)))
            else:
                url_parts = urllib.parse.urlsplit(str(value))
                report_hosts = {"nvd.nist.gov", "www.virustotal.com", "virustotal.com", "github.com", "cve.org"}
                valid = (url_parts.scheme in ("http", "https") and bool(url_parts.hostname)
                         and url_parts.hostname.lower() not in report_hosts)
            if valid and relevant and suspicious:
                parsed_items["other"].append({"type": typ, "value": value})
    result.update(parsed_items)
    return result


def comment_iocs(text):
    """Extract concrete hashes and public IPs from an untrusted VT comment."""
    found = []
    seen = set()
    for value in re.findall(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])", text):
        value = value.lower()
        kind = {64: "SHA-256", 40: "SHA-1", 32: "MD5"}[len(value)]
        if value not in seen:
            found.append((kind, value)); seen.add(value)
    for value in re.findall(r"(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])", text):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_global and value not in seen:
            found.append(("IPv4", value)); seen.add(value)
    return found


def ioc_summary(gn, vt, tf=None):
    """Return actual indicators only, each with a one-line source/context."""
    tf = tf or {"queried": False, "iocs": [], "error": None}
    items, seen = [], set()

    def add(kind, value, context):
        label = str(kind).lower()
        if label == "sha-256" and not re.fullmatch(r"[0-9a-fA-F]{64}", str(value or "")):
            return
        if label in ("ipv4", "ip_address"):
            try:
                if not ipaddress.ip_address(str(value)).is_global:
                    return
            except ValueError:
                return
        key = (label, str(value).lower())
        if not value or key in seen:
            return
        seen.add(key)
        items.append(f"- {kind}: {value} — {context}")

    for entry in gn.get("ips", [])[:10]:
        context = "GreyNoise scanner associated with the CVE"
        if entry.get("classification"):
            context += f"; classification={entry['classification']}"
        if entry.get("last_seen"):
            context += f"; last_seen={entry['last_seen']}"
        if entry.get("tags"):
            context += "; tags=" + ", ".join(map(str, entry["tags"][:5]))
        add("IPv4", entry.get("ip"), context)

    for entry in vt.get("files", [])[:10]:
        context = "VirusTotal CVE-linked file"
        if entry.get("name"):
            context += f"; name={entry['name']}"
        context += f"; detections={entry.get('malicious', 0)} malicious/{entry.get('suspicious', 0)} suspicious"
        if entry.get("tags"):
            context += "; tags=" + ", ".join(map(str, entry["tags"][:5]))
        add("SHA-256", entry.get("sha256"), context)

    for entry in vt.get("other", [])[:10]:
        add(entry.get("type", "Indicator"), entry.get("value"),
            f"VirusTotal CVE-linked {entry.get('type', 'indicator')} search result")

    for entry in tf.get("iocs", [])[:15]:
        kind_map = {"ip:port": "IPv4", "md5_hash": "MD5", "sha256_hash": "SHA-256",
                    "sha1_hash": "SHA-1", "url": "URL", "domain": "Domain"}
        value = entry.get("ioc")
        kind = kind_map.get(entry.get("type"), entry.get("type") or "Indicator")
        if kind == "IPv4" and isinstance(value, str) and ":" in value:
            value = value.split(":", 1)[0]
        context = "ThreatFox (abuse.ch) malware/C2 IOC tagged with the CVE"
        if entry.get("malware"):
            context += f"; malware={entry['malware']}"
        if entry.get("confidence") is not None:
            context += f"; confidence={entry['confidence']}"
        if entry.get("first_seen"):
            context += f"; first_seen={entry['first_seen']}"
        add(kind, value, context)

    for comment in vt.get("comments", [])[:20]:
        text = comment.get("text", "")
        context = "VirusTotal community comment (unverified): " + re.sub(r"\s+", " ", text).strip()[:160]
        for kind, value in comment_iocs(text):
            add(kind, value, context)

    if items:
        return "\n".join(items)

    coverage = []
    if gn.get("error"):
        coverage.append(f"GreyNoise unavailable: {gn['error']}")
    elif gn.get("queried"):
        coverage.append("GreyNoise returned no validated CVE-linked scanner IPs")
    else:
        coverage.append("GreyNoise not queried: API key required")
    if vt.get("error"):
        coverage.append(f"VirusTotal unavailable: {vt['error']}")
    elif vt.get("queried"):
        coverage.append("VirusTotal returned no CVE-linked IPs or hashes")
    else:
        coverage.append("VirusTotal not queried: API key required")
    if tf.get("error"):
        coverage.append(f"ThreatFox unavailable: {tf['error']}")
    elif tf.get("queried"):
        coverage.append("ThreatFox returned no CVE-tagged IOCs")
    return "No validated IoCs returned. " + "; ".join(coverage)


# ---------------- exploit / social ----------------
def gh_headers():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    h = {"Accept": "application/vnd.github+json"}
    if t:
        h["Authorization"] = f"Bearer {t}"
    return h


def github_exploits(cve):
    repos = {}
    errors = []
    malformed_payload = False

    def valid_repo(item, require_name=False):
        if not isinstance(item, dict) or not isinstance(item.get("html_url"), str) or not item["html_url"]:
            return False
        if require_name and not isinstance(item.get("full_name"), str):
            return False
        stars = item.get("stargazers_count", 0)
        created = item.get("created_at", "")
        return (not isinstance(stars, bool) and isinstance(stars, int) and stars >= 0
                and isinstance(created, str))

    y = cve.split("-")[1]
    poc, poc_error = json_result(POCGH.format(y=y, cve=cve.upper()))
    if poc_error and "HTTP 404" not in poc_error:
        errors.append(f"PoC index {poc_error}")
    if poc is not None and not isinstance(poc, list):
        errors.append("PoC index malformed response")
        malformed_payload = True
        poc = []
    if any(not valid_repo(item) for item in poc or []):
        errors.append("PoC index malformed response")
        malformed_payload = True
    else:
        for r in poc or []:
            repos[r["html_url"]] = {"url": r["html_url"], "stars": r.get("stargazers_count", 0),
                                    "created": r.get("created_at", "")[:10]}
    d, gh_error = json_result(
        f"https://api.github.com/search/repositories?q={cve}+in:name,description,readme&sort=stars&per_page=30",
        gh_headers())
    if gh_error:
        errors.append(f"GitHub search {gh_error}")
    if d is not None and not isinstance(d, dict):
        errors.append("GitHub search malformed response")
        malformed_payload = True
        d = {}
    d = d or {}
    gh_items = d.get("items", [])
    if not isinstance(gh_items, list):
        errors.append("GitHub search malformed response")
        malformed_payload = True
        gh_items = []
    if any(not valid_repo(item, require_name=True) for item in gh_items):
        errors.append("GitHub search malformed response")
        malformed_payload = True
    else:
        for r in gh_items:
            # Drop awesome-lists/scanners that merely mention the CVE: require the id in repo name.
            if cve.lower() not in r["full_name"].lower().replace("_", "-"):
                continue
            repos.setdefault(r["html_url"], {"url": r["html_url"], "stars": r.get("stargazers_count", 0),
                                             "created": r.get("created_at", "")[:10]})
    if malformed_payload:
        repos.clear()
    lst = sorted(repos.values(), key=lambda x: -x["stars"])
    return {"count": len(lst), "top": lst[:5], "total_stars": sum(x["stars"] for x in lst),
            "error": "; ".join(errors) or None}


def reddit(cve):
    code, body = http(f"https://www.reddit.com/search.rss?q=%22{cve}%22&sort=new&limit=50",
                      {"User-Agent": "Mozilla/5.0 vulnresearch/0.1"})
    if code != 200:
        return {"ok": False, "count": 0, "exploit_posts": [], "top": [], "error": f"Reddit HTTP {code}"}
    ns = {"a": "http://www.w3.org/2005/Atom"}
    posts = []
    try:
        for e in ET.fromstring(body).findall("a:entry", ns):
            t = (e.findtext("a:title", "", ns) or "")
            link = e.find("a:link", ns)
            posts.append({"title": t, "url": link.get("href") if link is not None else "",
                          "date": (e.findtext("a:updated", "", ns) or "")[:10]})
    except ET.ParseError:
        return {"ok": False, "count": 0, "exploit_posts": [], "top": [], "error": "Reddit invalid XML"}
    kw = re.compile(r"\b(poc|exploit|proof[- ]of[- ]concept|rce|weaponi[sz]ed|metasploit|nuclei)\b", re.I)
    return {"ok": True, "count": len(posts), "exploit_posts": [p for p in posts if kw.search(p["title"])][:5],
            "top": posts[:5], "error": None}


def x_posts(cve):
    """Query X through xurl and return data or a structured failure status."""
    def failure(status, error):
        return {"ok": False, "status": status, "count": 0, "engagement": 0,
                "exploit_mentions": [], "error": error}

    if not shutil.which("xurl"):
        return failure("xurl_missing", "xurl executable not found")
    allowed = ("HOME", "PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "TMPDIR",
               "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
    child_env = {name: os.environ[name] for name in allowed if name in os.environ}
    try:
        completed = subprocess.run(["xurl", "search", f'"{cve}" -is:retweet', "-n", "100"],
                                   capture_output=True, text=True, timeout=60, env=child_env)
    except subprocess.TimeoutExpired:
        return failure("timeout", "xurl request timed out")
    except OSError as exc:
        return failure("command_error", f"xurl execution failed: {exc}")
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    stderr = completed.stderr if isinstance(completed.stderr, str) else ""
    if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > MAX_XURL_OUTPUT_BYTES:
        return failure("output_too_large", "xurl captured output exceeded size limit")
    if completed.returncode != 0:
        detail = sanitize_text((stderr or stdout or "xurl exited non-zero").strip())[:300]
        auth_markers = ("auth", "unauthor", "forbidden", "401", "403", "credential", "login")
        status = "auth_error" if any(marker in detail.lower() for marker in auth_markers) else "command_error"
        return failure(status, f"xurl failed (exit {completed.returncode}): {detail}")
    try:
        d = json.loads(stdout)
    except (TypeError, ValueError):
        return failure("malformed_json", "xurl returned malformed JSON")
    if not isinstance(d, dict):
        return failure("malformed_json", "xurl returned malformed JSON")
    if d.get("errors"):
        detail = sanitize_text(json.dumps(d["errors"], ensure_ascii=True))[:300]
        return failure("api_error", f"X API error: {detail}")
    tw = d.get("data")
    if not isinstance(tw, list) or any(not isinstance(tweet, dict) for tweet in tw):
        return failure("malformed_json", "xurl returned malformed JSON")
    kw = re.compile(r"\b(poc|exploit|github\.com|rce|weaponi[sz]ed|in the wild|itw)\b", re.I)
    engagement = 0
    mentions = []
    for tweet in tw:
        metrics = tweet.get("public_metrics") or {}
        if not isinstance(metrics, dict):
            return failure("malformed_json", "xurl returned malformed JSON")
        for name in ("like_count", "retweet_count", "reply_count"):
            value = metrics.get(name, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return failure("malformed_json", "xurl returned malformed JSON")
            engagement += value
        text, ident = tweet.get("text", ""), tweet.get("id")
        if not isinstance(text, str) or (ident is not None and not isinstance(ident, (str, int))):
            return failure("malformed_json", "xurl returned malformed JSON")
        if ident is not None and kw.search(text) and len(mentions) < 5:
            mentions.append(f"https://x.com/i/status/{ident}")
    return {"ok": True, "status": "ok", "count": len(tw), "engagement": engagement,
            "exploit_mentions": mentions, "error": None}


def chatter_level(gh, rd, xx, otx=None):
    """Score 0-100 -> None/Low/Medium/High/Very High. X weighted highest when available."""
    s = 0.0
    if xx is not None and (xx.get("ok") is True or "status" not in xx):
        s += min(xx["count"], 100) * 0.4 + min(xx["engagement"] / 50, 20)
    s += min(rd["count"], 50) * 0.4
    s += min(gh["count"], 40) * 0.5 + min(gh["total_stars"] / 100, 10)
    if otx and otx.get("queried"):
        s += min(otx.get("pulse_count", 0), 50) * 0.3
    s = min(round(s), 100)
    lvl = "None" if s == 0 else "Low" if s < 10 else "Medium" if s < 30 else "High" if s < 60 else "Very High"
    return lvl, s


# ---------------- classification ----------------
WEB = re.compile(r"\b(web|http|https|url|html|xss|cross-site|csrf|sql injection|sqli|ssrf|rest api|"
                 r"wordpress|plugin for wordpress|php|jsp|servlet|browser|cookie|endpoint|graphql|"
                 r"web interface|admin panel|portal|tomcat|nginx|iis|apache http|jenkins|confluence|jira|exchange)\b", re.I)
MOBILE = re.compile(r"\b(android|ios|iphone|ipad|mobile app|apk)\b", re.I)
THICK = re.compile(r"\b(windows|desktop|client application|installer|\.exe|office|word|excel|"
                   r"outlook|acrobat|reader|macos|driver|kernel)\b", re.I)
NETDEV = re.compile(r"\b(router|firewall|vpn|gateway|switch|firmware|iot|plc|scada|netscaler|fortios|"
                    r"pan-os|ios xe|appliance)\b", re.I)


def app_type(c, desc):
    parts = set()
    for match in _configuration_matches(c) if c else []:
        p = _parse_cpe23(match.get("criteria", ""))
        if len(p) > 2:
            parts.add(p[2])
    if MOBILE.search(desc): return "Mobile"
    if WEB.search(desc): return "Web"
    if NETDEV.search(desc) or parts == {"h"} or parts == {"o", "h"}: return "Others (Network/Hardware/Firmware)"
    if THICK.search(desc): return "Thick Client"
    if parts == {"o"}: return "Others (OS)"
    if "a" in parts: return "Others (Library/Server Software)"
    return "Unknown"


def auth_req(cv, desc):
    pr = (cv or {}).get("pr")
    if pr in ("NONE",): return "Unauthenticated"
    if pr in ("LOW", "HIGH", "SINGLE", "MULTIPLE"): return f"Authenticated ({pr.title()} priv)"
    if re.search(r"unauthenticated|without authentication|remote attackers", desc, re.I): return "Unauthenticated (text)"
    if re.search(r"authenticated", desc, re.I): return "Authenticated (text)"
    return "Unknown"


def vector(cv):
    av = (cv or {}).get("av")
    if not isinstance(av, str):
        return "Unknown"
    return {"NETWORK": "Network", "ADJACENT_NETWORK": "Adjacent", "ADJACENT": "Adjacent",
            "LOCAL": "Local", "PHYSICAL": "Physical"}.get(av, "Unknown")


def affected(c, limit=6):
    out = []
    for match in _configuration_matches(c) if c else []:
        if not match.get("vulnerable"):
            continue
        p = _parse_cpe23(match.get("criteria", ""))
        if len(p) < 6:
            continue
        name = f"{p[3]} {p[4]}".replace("_", " ")
        version = p[5] if p[5] not in ("*", "-") else ""
        ranges = []
        if match.get("versionStartIncluding"): ranges.append(f">={match['versionStartIncluding']}")
        if match.get("versionStartExcluding"): ranges.append(f">{match['versionStartExcluding']}")
        if match.get("versionEndIncluding"): ranges.append(f"<={match['versionEndIncluding']}")
        if match.get("versionEndExcluding"): ranges.append(f"<{match['versionEndExcluding']}")
        summary = f"{name} {version or ' '.join(ranges)}".strip()
        if summary not in out:
            out.append(summary)
    extra = len(out) - limit
    return out[:limit] + ([f"(+{extra} more)"] if extra > 0 else [])


# ---------------- research ----------------
def research(cve, social=True):
    cve = cve.upper()
    c, nvd_error = nvd_cve_result(cve)
    fb, cna_error = cna_fallback_result(cve)
    if not c and not fb["desc"]:
        if nvd_error or cna_error:
            errors = "; ".join(x for x in (nvd_error, cna_error) if x)
            return {"CVE ID": cve, "error": f"source lookup failed: {errors}"}
        return {"CVE ID": cve, "error": "not found in NVD or CVE.org"}
    desc = ""
    if c:
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    desc = re.sub(r"\s+", " ", desc or fb["desc"] or "").strip()
    cv = (cvss(c) if c else None) or fb["cvss"]
    kev, kev_error = kev_index_result()
    k = kev.get(cve)
    ep, epss_error = epss_result(cve)
    gh = github_exploits(cve) if social else {"queried": False, "status": "not_queried",
                                               "count": 0, "top": [], "total_stars": 0, "error": None}
    rd = reddit(cve) if social else {"queried": False, "status": "not_queried", "ok": False,
                                     "count": 0, "exploit_posts": [], "top": [], "error": None}
    xx = x_posts(cve) if social else None
    gn = greynoise_iocs(cve)
    vt = virustotal_iocs(cve)
    tf = threatfox_iocs(cve)
    edb = exploitdb_lookup(cve) if social else {"queried": False, "hits": [], "error": None}
    otx = otx_pulses(cve)
    sdb = shodan_cvedb(cve)
    osv = osv_dev(cve)
    ghsa = github_advisory(cve)

    name = (k or {}).get("vulnerabilityName") or fb["title"] or (desc.split(". ")[0][:90])
    exp_src = []
    if gh["count"]: exp_src.append(f"GitHub ({gh['count']} repos)")
    if edb.get("hits"): exp_src.append(f"Exploit-DB ({len(edb['hits'])} entries)")
    if rd["exploit_posts"]: exp_src.append(f"Reddit ({len(rd['exploit_posts'])} PoC posts)")
    if xx and (xx.get("ok") is True or "status" not in xx) and xx["exploit_mentions"]:
        exp_src.append(f"X ({len(xx['exploit_mentions'])} PoC posts)")
    if not social:
        exploit = "Not queried - social/exploit sources disabled (--no-social)"
    elif exp_src:
        exploit = "Yes - " + ", ".join(exp_src)
        unavailable = []
        if gh.get("error"):
            unavailable.append(f"GitHub coverage unavailable: {gh['error']}")
        if edb.get("error"):
            unavailable.append(f"Exploit-DB coverage unavailable: {edb['error']}")
        if unavailable:
            exploit += "; " + "; ".join(unavailable)
    elif gh.get("error") or edb.get("error"):
        reasons = [x for x in (
            f"GitHub unavailable: {gh['error']}" if gh.get("error") else None,
            f"Exploit-DB unavailable: {edb['error']}" if edb.get("error") else None,
        ) if x]
        exploit = "Unknown - " + "; ".join(reasons)
    else:
        exploit = "No public PoC found in successfully queried sources"

    itw_src = []
    if k:
        itw_src.append(f"CISA KEV (added {k.get('dateAdded')}"
                       + (", ransomware use" if k.get("knownRansomwareCampaignUse") == "Known" else "") + ")")
    if (fb.get("ssvc_exploitation") or "").lower() == "active":
        itw_src.append("CISA SSVC: active")
    if sdb.get("queried") and sdb.get("kev") and not k:
        itw_src.append("Shodan CVEDB: KEV-flagged (cross-check; not independently confirmed in CISA KEV feed)")
    if otx.get("queried") and otx.get("pulse_count", 0) >= 5:
        itw_src.append(f"AlienVault OTX: {otx['pulse_count']} community pulses reference this CVE (not confirmation of ITW exploitation)")
    if itw_src:
        itw = "Yes - " + "; ".join(itw_src)
    elif kev_error or cna_error:
        unavailable = []
        if kev_error:
            unavailable.append(f"CISA KEV unavailable: {kev_error}")
        if cna_error:
            unavailable.append(f"CVE.org SSVC unavailable: {cna_error}")
        itw = "Unknown - incomplete source coverage; " + "; ".join(unavailable)
    elif (fb.get("ssvc_exploitation") or "").lower() == "poc":
        itw = "Not observed in KEV (SSVC: PoC)"
    else:
        itw = "Not observed in checked CISA KEV/SSVC sources"

    if xx is None:
        x_status = "not_queried" if not social else "unknown_error"
        x_display = x_status
        x_note = None if not social else "X unavailable (unknown_error)"
        x_error = None if not social else "X returned no result"
    elif xx.get("ok") is True or "status" not in xx:
        x_status = "ok"
        x_display = str(xx["count"])
        x_note = None
        x_error = None
    else:
        x_status = xx.get("status", "unknown_error")
        x_display = x_status
        x_error = xx.get("error")
        x_note = f"X unavailable ({x_status}): {x_error or 'no detail'}"
    if social:
        chatter_errors = []
        if gh.get("error"):
            chatter_errors.append(f"GitHub unavailable: {gh['error']}")
        if rd.get("ok") is not True:
            chatter_errors.append(f"Reddit unavailable: {rd.get('error') or rd.get('status') or 'unknown error'}")
        if x_status != "ok":
            chatter_errors.append(f"X unavailable ({x_status}): {x_error or 'no detail'}")
        if chatter_errors:
            lvl, score = None, None
            chatter = "Unknown - incomplete source coverage; " + "; ".join(chatter_errors)
        else:
            lvl, score = chatter_level(gh, rd, xx, otx)
            chatter = None
    else:
        chatter_errors = []
        lvl, score = None, None
        chatter = "Not queried - social sources disabled (--no-social)"
    affected_products = "; ".join(affected(c) if c and c.get("configurations") else fb["affected"][:6]) or "See advisory"
    if osv.get("found") and osv.get("affected"):
        affected_products += "; OSV.dev packages: " + ", ".join(osv["affected"][:6])
    if nvd_error:
        affected_products += f"; NVD coverage unavailable: {nvd_error}"
    cvss_display = f"{cv['score']} {cv['severity'] or ''} (v{cv['version']})".strip() if cv else "Not scored"
    if not cv and sdb.get("queried") and isinstance(sdb.get("cvss"), (int, float)):
        cvss_display = f"{sdb['cvss']} (Shodan CVEDB cross-check; not in NVD/CVE.org)"
    if not cv and not sdb.get("cvss") and ghsa.get("found") and ghsa.get("severity"):
        cvss_display = f"Not scored (GHSA severity: {ghsa['severity']})"
    if epss_error:
        cvss_display += f"; EPSS unavailable: {epss_error}"
    return {
        "CVE ID": cve,
        "Name": name,
        "Description": desc,
        "Affected Products": affected_products,
        "Exploit Available Online": exploit,
        "Chatter Level": chatter or f"{lvl} ({score}/100; X={x_display}, Reddit={rd['count']}, GitHub={gh['count']}, OTX pulses={otx.get('pulse_count', 'n/a') if otx.get('queried') else 'not queried'})",
        "IoCs": ioc_summary(gn, vt, tf),
        "App Type": app_type(c, desc),
        "Auth": auth_req(cv, desc),
        "Vector": vector(cv),
        "CVSS": cvss_display,
        "ITW Exploitation": itw,
        "_evidence": {
            "social_status": "queried" if social else "not_queried",
            "cvss_vector": (cv or {}).get("vector"), "epss": ep, "kev": k,
            "ssvc_exploitation": fb.get("ssvc_exploitation"),
            "github_top": gh["top"], "reddit_exploit_posts": rd["exploit_posts"], "reddit_recent": rd["top"],
            "exploitdb": edb, "otx": otx, "shodan_cvedb": sdb,
            "osv_dev": osv, "github_advisory": ghsa,
            "x": xx, "x_status": x_status, "x_note": x_note, "chatter_errors": chatter_errors,
            "greynoise": gn, "virustotal": vt, "threatfox": tf,
            "source_errors": {"nvd": nvd_error, "cve_org": cna_error, "kev": kev_error,
                              "epss": epss_error, "github": gh.get("error"),
                              "reddit": rd.get("error"), "x": x_error,
                              "exploitdb": edb.get("error"), "otx": otx.get("error"),
                              "shodan_cvedb": sdb.get("error"), "threatfox": tf.get("error"),
                              "osv_dev": osv.get("error"), "github_advisory": ghsa.get("error")},
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        },
    }


# ---------------- output ----------------
_TERMINAL_ESCAPE_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]"
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def sanitize_text(value):
    """Remove terminal escapes, control bytes, and bidi overrides from provider text."""
    text = str(value)
    return _CONTROL_RE.sub("", _TERMINAL_ESCAPE_RE.sub("", text))


def _sanitize_value(value):
    if isinstance(value, dict):
        return {sanitize_text(k): _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_value(v) for v in value)
    return sanitize_text(value) if isinstance(value, str) else value


def structured_cell(value):
    """Keep cells concise; turn prose over two sentences into a bullet list."""
    text = sanitize_text(value or "Unknown").strip()
    if "\n" in text:  # caller supplied structure (for example IoC bullets)
        return "\n".join(line.strip() for line in text.splitlines() if line.strip())
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])", text) if s.strip()]
    if len(sentences) > 2:
        return "\n".join("- " + sentence for sentence in sentences)
    return re.sub(r"\s+", " ", text)


def wrap_cell(value, width):
    """Wrap cell text while preserving bullet boundaries and hanging indents."""
    output = []
    for raw in structured_cell(value).splitlines():
        bullet = raw.startswith("- ")
        body = raw[2:].strip() if bullet else raw.strip()
        first_prefix, next_prefix = ("- ", "  ") if bullet else ("", "")
        chunks = textwrap.wrap(body, width=max(1, width - len(first_prefix)),
                               break_long_words=True, break_on_hyphens=False) or [""]
        output.append(first_prefix + chunks[0])
        output.extend(next_prefix + part for part in chunks[1:])
    return output or [""]


def trunc(s, n):
    s = str(s).replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def ascii_table(rows):
    """Render one wrapped, bordered ASCII table for terminal output."""
    widths = {
        "CVE ID": 15, "Name": 17, "Description": 22, "Affected Products": 20,
        "Exploit Available Online": 17, "Chatter Level": 14, "IoCs": 22,
        "App Type": 14, "Auth": 13, "Vector": 8, "CVSS": 14,
        "ITW Exploitation": 17,
    }

    def wrap(value, width):
        return wrap_cell(value, width)

    def border(ch="-"):
        return "+" + "+".join(ch * (widths[c] + 2) for c in COLUMNS) + "+"

    def physical(logical):
        cells = [wrap(logical.get(c, "Unknown"), widths[c]) for c in COLUMNS]
        height = max(len(cell) for cell in cells)
        lines = []
        for i in range(height):
            vals = [(cell[i] if i < len(cell) else "").ljust(widths[col])
                    for cell, col in zip(cells, COLUMNS)]
            lines.append("| " + " | ".join(vals) + " |")
        return lines

    out = [border()]
    out.extend(physical({c: c for c in COLUMNS}))
    out.append(border("="))
    for idx, row in enumerate(rows):
        if "error" in row:
            row = {c: (row.get("CVE ID") if c == "CVE ID" else
                       f"ERROR: {row['error']}" if c == "Description" else "Unknown")
                   for c in COLUMNS}
        out.extend(physical(row))
        out.append(border() if idx == len(rows) - 1 else border("-"))
    return "\n".join(out)


def vertical_table(rows):
    """Render a narrow two-column ASCII table, one field per line group."""
    field_width, value_width = 25, 88
    border = "+" + "-" * (field_width + 2) + "+" + "-" * (value_width + 2) + "+"
    strong = "+" + "=" * (field_width + 2) + "+" + "=" * (value_width + 2) + "+"
    out = [border, f"| {'Field'.ljust(field_width)} | {'Value'.ljust(value_width)} |", strong]
    for row_idx, row in enumerate(rows):
        if "error" in row:
            row = {c: (row.get("CVE ID") if c == "CVE ID" else
                       f"ERROR: {row['error']}" if c == "Description" else "Unknown")
                   for c in COLUMNS}
        for col in COLUMNS:
            wrapped = wrap_cell(row.get(col), value_width)
            out.append(f"| {col.ljust(field_width)} | {wrapped[0].ljust(value_width)} |")
            for part in wrapped[1:]:
                out.append(f"| {' '.ljust(field_width)} | {part.ljust(value_width)} |")
            out.append(border)
        if row_idx != len(rows) - 1:
            out.append(strong)
    return "\n".join(out)


def plain_text(rows):
    blocks = []
    for row in rows:
        if "error" in row:
            row = {c: (row.get("CVE ID") if c == "CVE ID" else
                       f"ERROR: {row['error']}" if c == "Description" else "Unknown")
                   for c in COLUMNS}
        values = []
        for c in COLUMNS:
            value = structured_cell(row.get(c))
            values.append(f"{c}:\n{value}" if "\n" in value else f"{c}: {value}")
        blocks.append("\n".join(values))
    return "\n\n".join(blocks)


def html_table(rows):
    def esc(value):
        return html_lib.escape(str(value or "Unknown"), quote=True)

    def html_cell(value):
        value = structured_cell(value)
        lines = value.splitlines()
        if lines and all(line.startswith("- ") for line in lines):
            return '<ul style="margin:0;padding-left:20px">' + "".join(
                f'<li style="margin:0 0 6px 0">{esc(line[2:])}</li>' for line in lines
            ) + "</ul>"
        return "<br>".join(esc(line) for line in lines)

    normalized = []
    for row in rows:
        if "error" in row:
            row = {c: (row.get("CVE ID") if c == "CVE ID" else
                       f"ERROR: {row['error']}" if c == "Description" else "Unknown")
                   for c in COLUMNS}
        normalized.append(row)
    heads = "".join(f'<th style="padding:10px;text-align:left;background:#172033;color:#fff;vertical-align:top">{esc(c)}</th>' for c in COLUMNS)
    body = "".join("<tr>" + "".join(
        f'<td style="padding:10px;border-top:1px solid #d8dee9;vertical-align:top;line-height:1.45">{html_cell(row.get(c))}</td>'
        for c in COLUMNS) + "</tr>" for row in normalized)
    return ("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
            "content=\"width=device-width,initial-scale=1\"><title>Vulnerability Research</title></head>"
            "<body style=\"margin:0;background:#f5f7fa;color:#172033;font-family:Arial,sans-serif\">"
            "<main style=\"max-width:100%;padding:20px\"><div style=\"overflow-x:auto;background:#fff;"
            "border:1px solid #d8dee9;border-radius:8px\"><table style=\"border-collapse:collapse;"
            "min-width:1900px;width:100%;font-size:14px\"><thead><tr>" + heads +
            "</tr></thead><tbody>" + body + "</tbody></table></div></main></body></html>")


def _csv_cell(value):
    """Neutralize spreadsheet formulas while preserving non-formula values."""
    if isinstance(value, str) and re.match(r"\s*[=+\-@]", value):
        return "'" + value
    return value


def render(rows, fmt):
    rows = _sanitize_value(rows)
    if fmt == "json":
        return json.dumps(rows, indent=2)
    if fmt == "html":
        return html_table(rows)
    if fmt == "vertical":
        return vertical_table(rows)
    if fmt == "plain":
        return plain_text(rows)
    if fmt == "csv":
        b = io.StringIO(); w = csv.DictWriter(b, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            if "error" not in row:
                w.writerow({column: _csv_cell(row.get(column, "")) for column in COLUMNS})
        return b.getvalue()
    if fmt == "markdown":
        esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
        lines = ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
        for r in rows:
            if "error" in r:
                lines.append(f"| {r['CVE ID']} | ERROR: {r['error']} |" + " |" * (len(COLUMNS) - 2)); continue
            lines.append("| " + " | ".join(esc(trunc(r[c], 300)) for c in COLUMNS) + " |")
        return "\n".join(lines)
    return ascii_table(rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cves", nargs="*")
    ap.add_argument("--product"); ap.add_argument("--version", default="")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--format", choices=["ascii", "table", "vertical", "html", "plain", "markdown", "json", "csv"], default="ascii")
    ap.add_argument("--output", help="write rendered output to this file instead of stdout")
    ap.add_argument("--no-social", action="store_true", help="skip GitHub/Reddit/X lookups")
    a = ap.parse_args(argv)
    ids = [x.upper() for x in a.cves]
    bad = [x for x in ids if not CVE_RE.match(x)]
    if bad:
        ap.error(f"invalid CVE id(s): {bad}")
    note = None
    if a.product:
        found, total, complete, search_error = nvd_product_search(a.product, a.version, a.limit)
        coverage = "complete coverage" if complete else f"INCOMPLETE coverage: {search_error or 'pagination stopped early'}"
        note = (f"NVD keyword '{a.product}' {total} CVEs; version {a.version or 'any'}, "
                f"-> {len(found)} shown (newest first, limit {a.limit}); {coverage}")
        ids += found
    if not ids:
        if a.product and search_error:
            ap.error(search_error)
        ap.error("give CVE id(s) or --product")
    rows = []
    for cve in dict.fromkeys(ids):
        rows.append(research(cve, social=not a.no_social))
    if a.product:
        product_coverage = {"total_results": total, "complete": complete, "error": search_error}
        for row in rows:
            row.setdefault("_evidence", {})["product_search"] = product_coverage
    if note and a.format != "json":
        print(sanitize_text(note), file=sys.stderr)
    rendered = render(rows, a.format)
    if a.output:
        out_path = Path(a.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + ("" if rendered.endswith("\n") else "\n"), encoding="utf-8")
        print(str(out_path))
    else:
        print(rendered)


if __name__ == "__main__":
    main()
