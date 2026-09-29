"""Offline unit tests (no network). Run: python3 -m unittest discover -s tests"""
import contextlib, csv, io, json, os, subprocess, sys, unittest, urllib.request
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "vuln-research", "scripts"))
import vulnresearch as vr  # noqa: E402

CPE = lambda crit, **kw: {"vulnerable": True, "criteria": crit, **kw}
NVD_CVE = {
    "id": "CVE-2099-0001",
    "descriptions": [{"lang": "en", "value": "Unauthenticated remote attackers can send HTTP requests to the web interface."}],
    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
        "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attackVector": "NETWORK", "privilegesRequired": "NONE", "userInteraction": "NONE"}}]},
    "configurations": [{"nodes": [{"cpeMatch": [
        CPE("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", versionStartIncluding="9.0.0", versionEndExcluding="9.0.31")]}]}],
}


class Classify(unittest.TestCase):
    def test_cvss_fields(self):
        c = vr.cvss(NVD_CVE)
        self.assertEqual((c["score"], vr.vector(c), vr.auth_req(c, "")), (9.8, "Network", "Unauthenticated"))

    def test_auth_authenticated(self):
        self.assertTrue(vr.auth_req({"pr": "LOW"}, "").startswith("Authenticated"))

    def test_local_vector(self):
        self.assertEqual(vr.vector({"av": "LOCAL"}), "Local")

    def test_vector_is_safe_for_malformed_values(self):
        for value in ({"bad": "shape"}, [], 7, None):
            with self.subTest(value=value):
                self.assertEqual(vr.vector({"av": value}), "Unknown")

    def test_app_type(self):
        self.assertEqual(vr.app_type(NVD_CVE, NVD_CVE["descriptions"][0]["value"]), "Web")
        self.assertEqual(vr.app_type({}, "crafted APK on Android devices"), "Mobile")
        self.assertEqual(vr.app_type({}, "opening a crafted file in Microsoft Excel desktop"), "Thick Client")

    def test_version_range(self):
        self.assertTrue(vr.version_matches(NVD_CVE, "Apache Tomcat", "9.0.30"))
        self.assertFalse(vr.version_matches(NVD_CVE, "Apache Tomcat", "9.0.31"))
        self.assertFalse(vr.version_matches(NVD_CVE, "Apache Tomcat", "8.5.1"))

    def test_product_match_rejects_apache_http_server_for_tomcat(self):
        apache_httpd = dict(NVD_CVE, configurations=[{"nodes": [{"cpeMatch": [
            CPE("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                versionStartIncluding="2.4.0", versionEndExcluding="2.4.60")]}]}])
        self.assertFalse(vr.version_matches(apache_httpd, "Apache Tomcat", "2.4.58"))

    def test_product_match_walks_nested_configuration_nodes(self):
        nested = dict(NVD_CVE, configurations=[{"nodes": [{"operator": "AND", "nodes": [
            {"cpeMatch": [CPE("cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*")]},
            {"cpeMatch": [{"vulnerable": False,
                           "criteria": "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"}]}
        ]}]}])
        self.assertTrue(vr.version_matches(nested, "Apache Tomcat", "9.0.30"))

    def test_affected_and_app_type_walk_nested_configuration_nodes(self):
        nested = dict(NVD_CVE, configurations=[{"nodes": [{"operator": "AND", "nodes": [
            {"nodes": [{"cpeMatch": [CPE("cpe:2.3:h:acme:edge_router:2.0:*:*:*:*:*:*:*")]}]}
        ]}]}])
        self.assertEqual(vr.affected(nested), ["acme edge router 2.0"])
        self.assertEqual(vr.app_type(nested, ""), "Others (Network/Hardware/Firmware)")

    def test_cpe_parser_handles_escaped_colon_and_backslash(self):
        escaped = dict(NVD_CVE, configurations=[{"nodes": [{"cpeMatch": [
            CPE(r"cpe:2.3:a:example\:corp:path\\service:1.0:*:*:*:*:*:*:*")
        ]}]}])
        self.assertTrue(vr.version_matches(escaped, r"Example:Corp Path\Service", "1.0"))
        self.assertEqual(vr.affected(escaped), [r"example:corp path\service 1.0"])

    def test_chatter(self):
        z = {"count": 0, "total_stars": 0}
        self.assertEqual(vr.chatter_level(z, {"count": 0}, None)[0], "None")
        self.assertEqual(vr.chatter_level({"count": 300, "total_stars": 5000}, {"count": 50},
                                          {"count": 100, "engagement": 5000})[0], "Very High")

    def test_affected(self):
        self.assertEqual(vr.affected(NVD_CVE), ["apache tomcat >=9.0.0 <9.0.31"])


class Research(unittest.TestCase):
    @mock.patch.object(vr, "virustotal_iocs", return_value={"queried": False, "files": [], "comments": [], "other": [], "error": "missing"})
    @mock.patch.object(vr, "greynoise_iocs", return_value={"public_cve_record": True, "queried": False, "ips": [], "error": "missing"})
    @mock.patch.object(vr, "x_posts", return_value=None)
    @mock.patch.object(vr, "reddit", return_value={"ok": True, "count": 3, "exploit_posts": [{"title": "PoC"}], "top": []})
    @mock.patch.object(vr, "github_exploits", return_value={"count": 2, "top": [{"url": "u", "stars": 5}], "total_stars": 5})
    @mock.patch.object(vr, "epss_result", return_value=({"epss": 0.9, "percentile": 0.99}, None))
    @mock.patch.object(vr, "kev_index_result", return_value=({"CVE-2099-0001": {"vulnerabilityName": "Tomcat RCE",
                                                                                "dateAdded": "2099-01-01", "knownRansomwareCampaignUse": "Known"}}, None))
    @mock.patch.object(vr, "cna_fallback_result", return_value=({"cvss": None, "ssvc_exploitation": "active", "title": None, "desc": None, "affected": []}, None))
    @mock.patch.object(vr, "nvd_cve_result", return_value=(NVD_CVE, None))
    def test_row(self, *_):
        r = vr.research("cve-2099-0001")
        self.assertEqual(set(vr.COLUMNS) - set(r), set())
        self.assertEqual(r["Name"], "Tomcat RCE")
        self.assertIn("CISA KEV", r["ITW Exploitation"]); self.assertIn("ransomware", r["ITW Exploitation"])
        self.assertTrue(r["Exploit Available Online"].startswith("Yes"))
        self.assertIn("markdown" and "| CVE-2099-0001 |", vr.render([r], "markdown"))

    def test_bad_id(self):
        with self.assertRaises(SystemExit):
            vr.main(["NOT-A-CVE"])

    @mock.patch.object(vr, "virustotal_iocs", return_value={"queried": False, "files": [], "comments": [], "other": [], "error": "missing"})
    @mock.patch.object(vr, "greynoise_iocs", return_value={"queried": False, "ips": [], "error": "missing"})
    @mock.patch.object(vr, "x_posts", return_value={"ok": False, "status": "api_error", "count": 0,
                                                     "engagement": 0, "exploit_mentions": [],
                                                     "error": "X API error: unauthorized"})
    @mock.patch.object(vr, "reddit", return_value={"ok": False, "count": 0, "exploit_posts": [], "top": [], "error": "HTTP 503"})
    @mock.patch.object(vr, "github_exploits", return_value={"count": 0, "top": [], "total_stars": 0, "error": "GitHub HTTP 503"})
    @mock.patch.object(vr, "epss_result", return_value=(None, "FIRST EPSS HTTP 503"))
    @mock.patch.object(vr, "kev_index_result", return_value=({}, "CISA KEV HTTP 503"))
    @mock.patch.object(vr, "cna_fallback_result", return_value=({"cvss": None, "ssvc_exploitation": None,
                                                                  "title": None, "desc": None, "affected": []}, None))
    @mock.patch.object(vr, "nvd_cve_result", return_value=(NVD_CVE, None))
    def test_source_failures_are_not_negative_findings(self, *_):
        row = vr.research("CVE-2099-0001")
        self.assertIn("unavailable", row["Exploit Available Online"].lower())
        self.assertIn("unavailable", row["ITW Exploitation"].lower())
        self.assertEqual(row["_evidence"]["source_errors"]["github"], "GitHub HTTP 503")
        self.assertEqual(row["_evidence"]["source_errors"]["kev"], "CISA KEV HTTP 503")
        self.assertEqual(row["_evidence"]["x"]["status"], "api_error")
        self.assertIn("api_error", row["Chatter Level"])
        self.assertIn("api_error", row["_evidence"]["x_note"])
        self.assertEqual(row["_evidence"]["source_errors"]["x"], "X API error: unauthorized")
        self.assertEqual(row["_evidence"]["source_errors"]["epss"], "FIRST EPSS HTTP 503")
        self.assertIn("EPSS unavailable", row["CVSS"])
        self.assertTrue(row["Chatter Level"].startswith("Unknown - incomplete"))
        self.assertNotIn("0/100", row["Chatter Level"])
        for source in ("GitHub", "Reddit", "X"):
            self.assertIn(source, row["Chatter Level"])

    def test_each_social_source_failure_makes_chatter_incomplete(self):
        good_gh = {"count": 1, "top": [], "total_stars": 2, "error": None}
        good_rd = {"ok": True, "count": 1, "exploit_posts": [], "top": [], "error": None}
        good_x = {"ok": True, "status": "ok", "count": 1, "engagement": 2,
                  "exploit_mentions": [], "error": None}
        cases = [
            ("GitHub", {**good_gh, "count": 0, "error": "GitHub HTTP 503"}, good_rd, good_x),
            ("Reddit", good_gh, {**good_rd, "ok": False, "count": 0, "error": "Reddit HTTP 503"}, good_x),
            ("X", good_gh, good_rd, {**good_x, "ok": False, "status": "timeout", "count": 0,
                                      "engagement": 0, "error": "xurl request timed out"}),
        ]
        fallback = {"cvss": None, "ssvc_exploitation": None, "title": None, "desc": None, "affected": []}
        for source, gh, rd, xx in cases:
            with self.subTest(source=source), contextlib.ExitStack() as stack:
                patches = [
                    mock.patch.object(vr, "nvd_cve_result", return_value=(NVD_CVE, None)),
                    mock.patch.object(vr, "cna_fallback_result", return_value=(fallback, None)),
                    mock.patch.object(vr, "kev_index_result", return_value=({}, None)),
                    mock.patch.object(vr, "epss_result", return_value=(None, None)),
                    mock.patch.object(vr, "github_exploits", return_value=gh),
                    mock.patch.object(vr, "reddit", return_value=rd),
                    mock.patch.object(vr, "x_posts", return_value=xx),
                    mock.patch.object(vr, "greynoise_iocs", return_value={"queried": False, "ips": [], "error": None}),
                    mock.patch.object(vr, "virustotal_iocs", return_value={"queried": False, "files": [],
                                                                           "comments": [], "other": [], "error": None}),
                ]
                for patcher in patches:
                    stack.enter_context(patcher)
                row = vr.research("CVE-2099-0001")
            self.assertTrue(row["Chatter Level"].startswith("Unknown - incomplete"))
            self.assertIn(source, row["Chatter Level"])
            self.assertNotIn("/100", row["Chatter Level"])

    @mock.patch.object(vr, "cna_fallback_result", return_value=({"cvss": None, "ssvc_exploitation": None,
                                                                  "title": None, "desc": None, "affected": []}, "CVE.org invalid JSON"))
    @mock.patch.object(vr, "nvd_cve_result", return_value=(None, "NVD HTTP 503"))
    def test_nvd_and_cveorg_failures_are_not_not_found(self, *_):
        row = vr.research("CVE-2099-0001", social=False)
        self.assertNotIn("not found", row["error"].lower())
        self.assertIn("NVD HTTP 503", row["error"])
        self.assertIn("CVE.org invalid JSON", row["error"])

    @mock.patch.object(vr, "virustotal_iocs", return_value={"queried": False, "files": [], "comments": [], "other": [], "error": "missing"})
    @mock.patch.object(vr, "greynoise_iocs", return_value={"queried": False, "ips": [], "error": "missing"})
    @mock.patch.object(vr, "x_posts", side_effect=AssertionError("X must not be queried"))
    @mock.patch.object(vr, "reddit", side_effect=AssertionError("Reddit must not be queried"))
    @mock.patch.object(vr, "github_exploits", side_effect=AssertionError("GitHub must not be queried"))
    @mock.patch.object(vr, "epss_result", return_value=(None, None))
    @mock.patch.object(vr, "kev_index_result", return_value=({}, None))
    @mock.patch.object(vr, "cna_fallback_result", return_value=({"cvss": None, "ssvc_exploitation": None,
                                                                  "title": None, "desc": None, "affected": []}, None))
    @mock.patch.object(vr, "nvd_cve_result", return_value=(NVD_CVE, None))
    def test_no_social_reports_sources_not_queried_without_negative_findings(self, *_):
        row = vr.research("CVE-2099-0001", social=False)
        self.assertIn("not queried", row["Exploit Available Online"].lower())
        self.assertNotIn("no public poc", row["Exploit Available Online"].lower())
        self.assertIn("not queried", row["Chatter Level"].lower())
        self.assertNotIn("none", row["Chatter Level"].lower())
        self.assertNotIn("0/100", row["Chatter Level"])
        self.assertEqual(row["_evidence"]["social_status"], "not_queried")

    def test_cna_fallback_rejects_malformed_nested_items(self):
        base = {"containers": {"cna": {"descriptions": [], "affected": [], "metrics": []}, "adp": []}}
        malformed = [
            {"containers": {"cna": {"descriptions": [None], "affected": [], "metrics": []}, "adp": []}},
            {"containers": {"cna": {"descriptions": [], "affected": ["bad"], "metrics": []}, "adp": []}},
            {"containers": {"cna": {"descriptions": [], "affected": [], "metrics": [None]}, "adp": []}},
            {"containers": {"cna": base["containers"]["cna"], "adp": [None]}},
            {"containers": {"cna": base["containers"]["cna"], "adp": [{"metrics": [
                {"other": {"type": "ssvc", "content": {"options": [None]}}}
            ]}]}},
        ]
        for payload in malformed:
            with self.subTest(payload=payload), mock.patch.object(vr, "json_result", return_value=(payload, None)):
                result, error = vr.cna_fallback_result("CVE-2099-0001")
                self.assertEqual(result, {"cvss": None, "ssvc_exploitation": None,
                                          "title": None, "desc": None, "affected": []})
                self.assertEqual(error, "CVE.org malformed response")

    def test_cna_fallback_rejects_non_string_ssvc_exploitation_values(self):
        for value in (None, 1, [], {}):
            payload = {"containers": {"cna": {"descriptions": [], "affected": [], "metrics": []},
                                      "adp": [{"metrics": [{"other": {"type": "ssvc", "content": {
                                          "options": [{"Exploitation": value}]
                                      }}}]}]}}
            with self.subTest(value=value), mock.patch.object(vr, "json_result", return_value=(payload, None)):
                result, error = vr.cna_fallback_result("CVE-2099-0001")
                self.assertIsNone(result["ssvc_exploitation"])
                self.assertEqual(error, "CVE.org malformed response")

    def test_cna_fallback_rejects_invalid_id_and_cvss_scalars(self):
        valid = {"cveMetadata": {"cveId": "CVE-2099-0001"}, "containers": {"cna": {
            "descriptions": [], "affected": [], "metrics": [{"cvssV3_1": {
                "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N", "attackVector": "NETWORK",
                "privilegesRequired": "NONE", "userInteraction": "NONE"}}]}, "adp": []}}
        cases = []
        bad_id = json.loads(json.dumps(valid))
        bad_id["cveMetadata"]["cveId"] = "not-a-cve"
        cases.append(bad_id)
        for field in ("version", "baseScore", "baseSeverity", "vectorString", "attackVector", "privilegesRequired"):
            payload = json.loads(json.dumps(valid))
            payload["containers"]["cna"]["metrics"][0]["cvssV3_1"][field] = {"bad": "shape"}
            cases.append(payload)
        for payload in cases:
            with self.subTest(payload=payload), mock.patch.object(vr, "json_result", return_value=(payload, None)):
                result, error = vr.cna_fallback_result("CVE-2099-0001")
                self.assertIsNone(result["cvss"])
                self.assertEqual(error, "CVE.org malformed response")

    def test_epss_result_reports_transport_json_and_payload_errors(self):
        cases = [
            ((None, "HTTP 503"), "FIRST EPSS HTTP 503"),
            ((None, "invalid JSON"), "FIRST EPSS invalid JSON"),
            (({"data": {}}, None), "FIRST EPSS malformed response"),
            (({"data": []}, None), "FIRST EPSS malformed response"),
            (({"data": [None]}, None), "FIRST EPSS malformed response"),
            (({"data": [{"cve": "CVE-2099-0001", "epss": "nan", "percentile": "0.5"}]}, None),
             "FIRST EPSS malformed response"),
            (({"data": [{"cve": "CVE-2099-0001", "epss": "0.5", "percentile": {}}]}, None),
             "FIRST EPSS malformed response"),
            (({"data": [{"cve": "CVE-2099-9999", "epss": "0.5", "percentile": "0.6"}]}, None),
             "FIRST EPSS malformed response"),
        ]
        for response, expected in cases:
            with self.subTest(response=response), mock.patch.object(vr, "json_result", return_value=response):
                value, error = vr.epss_result("CVE-2099-0001")
                self.assertIsNone(value)
                self.assertEqual(error, expected)

    def test_epss_result_parses_finite_probabilities(self):
        payload = {"data": [{"cve": "CVE-2099-0001", "epss": "0.25", "percentile": "0.75"}]}
        with mock.patch.object(vr, "json_result", return_value=(payload, None)):
            value, error = vr.epss_result("CVE-2099-0001")
        self.assertEqual(value, {"epss": 0.25, "percentile": 0.75})
        self.assertIsNone(error)


class Indicators(unittest.TestCase):
    def test_ioc_summary(self):
        gn = {"queried": True, "ips": [{"ip": "8.8.8.8", "classification": "malicious"}]}
        vt = {"queried": True,
              "files": [{"sha256": "a" * 64, "malicious": 42}],
              "comments": [{"text": "Observed payload at 8.8.4.4 with SHA256 " + "b" * 64}], "other": []}
        out = vr.ioc_summary(gn, vt)
        self.assertIn("8.8.8.8", out)
        self.assertIn("42 malicious", out)
        self.assertIn("8.8.4.4", out)
        self.assertIn("VirusTotal community comment", out)
        self.assertTrue(all(line.startswith("- ") for line in out.splitlines()))

    @mock.patch.dict(os.environ, {}, clear=True)
    @mock.patch.object(vr, "jget", return_value={"id": "CVE-2099-0001"})
    def test_greynoise_missing_key_is_explicit(self, _):
        got = vr.greynoise_iocs("CVE-2099-0001")
        self.assertFalse(got["queried"])
        self.assertIn("API key", got["error"])

    @mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test"}, clear=True)
    @mock.patch.object(vr, "http", return_value=(200, json.dumps({"data": [
        {"type": "file", "id": "a" * 64, "attributes": {"sha256": "a" * 64,
         "meaningful_name": "poc.bin", "last_analysis_stats": {"malicious": 12}, "tags": ["exploit"]}},
        {"type": "comment", "id": "c1", "attributes": {"text": "Observed exploit payload", "date": 1}}
    ]}).encode()))
    def test_virustotal_parser(self, _):
        got = vr.virustotal_iocs("CVE-2099-0001")
        self.assertEqual(got["files"][0]["malicious"], 12)
        self.assertEqual(got["comments"][0]["text"], "Observed exploit payload")

    @mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test"}, clear=True)
    @mock.patch.object(vr, "http", return_value=(200, json.dumps({"data": [
        {"type": "file", "id": "not-a-hash", "attributes": {"sha256": "xyz"}},
        {"type": "ip_address", "id": "127.0.0.1", "attributes": {"tags": ["CVE-2099-0001"]}},
        {"type": "domain", "id": "advisories.example.com", "attributes": {"tags": ["report"]}},
        {"type": "url", "id": "u1", "attributes": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
                                                          "last_analysis_stats": {"malicious": 20},
                                                          "tags": ["CVE-2099-0001"]}},
        {"type": "domain", "id": "evil.example", "attributes": {
            "last_analysis_stats": {"malicious": 2}, "tags": ["CVE-2099-0001"]}}
    ]}).encode()))
    def test_virustotal_rejects_invalid_or_benign_indicators(self, _):
        got = vr.virustotal_iocs("CVE-2099-0001")
        self.assertEqual(got["files"], [])
        self.assertEqual(got["other"], [{"type": "domain", "value": "evil.example"}])

    @mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test"}, clear=True)
    @mock.patch.object(vr, "http", return_value=(200, json.dumps({"data": [
        {"type": "file", "id": "a" * 64, "attributes": {
            "last_analysis_stats": {"malicious": "3", "suspicious": "1", "harmless": "4"}}},
        {"type": "file", "id": "b" * 64, "attributes": {
            "last_analysis_stats": {"malicious": "not-a-number"}}},
        {"type": "domain", "id": "bad.example", "attributes": {
            "tags": ["CVE-2099-0001"], "last_analysis_stats": {"malicious": {"count": 9}}}},
        {"type": "domain", "id": "good.example", "attributes": {
            "tags": ["CVE-2099-0001"], "last_analysis_stats": {"malicious": "2"}}}
    ]}).encode()))
    def test_virustotal_coerces_numeric_stats_and_rejects_malformed_stats(self, _):
        got = vr.virustotal_iocs("CVE-2099-0001")
        self.assertEqual(got["files"], [{"sha256": "a" * 64, "name": None,
                                         "malicious": 3, "suspicious": 1, "harmless": 4, "tags": []}])
        self.assertEqual(got["other"], [{"type": "domain", "value": "good.example"}])

    @mock.patch.dict(os.environ, {"GREYNOISE_API_KEY": "test"}, clear=True)
    @mock.patch.object(vr, "http", return_value=(200, json.dumps({"request_metadata": {"restricted_fields": []}, "data": [
        {"ip": "8.8.8.8", "internet_scanner_intelligence": {
            "classification": "malicious", "last_seen": "2099-01-01",
            "cves": ["CVE-2099-0001"], "tags": [{"name": "Exploit Scanner"}]}}
    ]}).encode()))
    @mock.patch.object(vr, "jget", return_value={"id": "CVE-2099-0001"})
    def test_greynoise_parser(self, *_):
        got = vr.greynoise_iocs("CVE-2099-0001")
        self.assertEqual(got["ips"][0]["ip"], "8.8.8.8")
        self.assertEqual(got["ips"][0]["classification"], "malicious")

    @mock.patch.dict(os.environ, {"GREYNOISE_API_KEY": "test"}, clear=True)
    @mock.patch.object(vr, "http", return_value=(200, json.dumps({
        "request_metadata": {"restricted_fields": ["cve"]},
        "data": [{"ip": "203.0.113.99", "internet_scanner_intelligence": {"cves": []}}]
    }).encode()))
    @mock.patch.object(vr, "jget", return_value={"id": "CVE-2099-0001"})
    def test_greynoise_restricted_cve_drops_false_iocs(self, *_):
        got = vr.greynoise_iocs("CVE-2099-0001")
        self.assertEqual(got["ips"], [])
        self.assertIn("restricts the CVE field", got["error"])

    @mock.patch.dict(os.environ, {"GREYNOISE_API_KEY": "test"}, clear=True)
    @mock.patch.object(vr, "jget", return_value={"id": "CVE-2099-0001"})
    def test_greynoise_fails_closed_on_null_nested_payloads(self, _):
        valid = {"ip": "8.8.8.8", "internet_scanner_intelligence": {
            "cves": ["CVE-2099-0001"], "tags": []}}
        payloads = [
            {"request_metadata": None, "data": []},
            {"request_metadata": {"restricted_fields": []}, "data": [None]},
            {"request_metadata": {"restricted_fields": []}, "data": [
                {"ip": "8.8.8.8", "internet_scanner_intelligence": None}]},
            {"request_metadata": {"restricted_fields": []}, "data": [valid, None]},
        ]
        for payload in payloads:
            with self.subTest(payload=payload), mock.patch.object(
                    vr, "http", return_value=(200, json.dumps(payload).encode())):
                got = vr.greynoise_iocs("CVE-2099-0001")
                self.assertEqual(got["ips"], [])
                self.assertIn("malformed", got["error"].lower())

    @mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test"}, clear=True)
    def test_virustotal_fails_closed_on_malformed_names_tags_and_scalars(self):
        file_id = "a" * 64
        items = [
            {"type": "comment", "id": "c1", "attributes": {"text": None}},
            {"type": "file", "id": file_id, "attributes": {"names": {"bad": "shape"}}},
            {"type": "file", "id": file_id, "attributes": {"meaningful_name": 7}},
            {"type": "file", "id": file_id, "attributes": {"tags": None}},
            {"type": "file", "id": None, "attributes": {"sha256": file_id}},
        ]
        for item in items:
            valid = {"type": "file", "id": "b" * 64, "attributes": {"tags": []}}
            payload = json.dumps({"data": [valid, item]}).encode()
            with self.subTest(item=item), mock.patch.object(vr, "http", return_value=(200, payload)):
                got = vr.virustotal_iocs("CVE-2099-0001")
                self.assertEqual((got["files"], got["comments"], got["other"]), ([], [], []))
                self.assertIn("malformed", got["error"].lower())

    def test_github_fails_closed_on_null_scalar_fields(self):
        cases = [
            ([{"html_url": "https://example.test/poc", "created_at": None}], {"items": []}),
            ([{"html_url": "https://example.test/poc", "stargazers_count": None}], {"items": []}),
            ([], {"items": [{"html_url": "https://example.test/repo", "full_name": None}]}),
            ([], {"items": [{"html_url": "https://example.test/repo/CVE-2099-0001",
                               "full_name": "org/CVE-2099-0001", "created_at": None}]}),
            ([{"html_url": "https://example.test/valid", "stargazers_count": 3}],
             {"items": [{"html_url": "https://example.test/repo", "full_name": None}]}),
        ]
        for poc, search in cases:
            with self.subTest(poc=poc, search=search), mock.patch.object(
                    vr, "json_result", side_effect=[(poc, None), (search, None)]):
                got = vr.github_exploits("CVE-2099-0001")
                self.assertEqual(got["count"], 0)
                self.assertIn("malformed", got["error"].lower())

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_virustotal_missing_key_is_explicit(self):
        got = vr.virustotal_iocs("CVE-2099-0001")
        self.assertFalse(got["queried"])
        self.assertIn("API_KEY", got["error"])


class SkillContract(unittest.TestCase):
    def test_output_format_selection_contract(self):
        skill = os.path.join(os.path.dirname(__file__), "..", "skills", "vuln-research", "SKILL.md")
        with open(skill, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('use the\n`clarify` tool to ask: "Which output format do you prefer?"', text)
        for choice in ("ASCII table", "Vertical table", "HTML file", "Plain text"):
            self.assertIn(choice, text)
        self.assertIn("python3 skills/vuln-research/scripts/vulnresearch.py", text)

    def test_ascii_renderer_is_aligned_grid(self):
        row = {c: f"value for {c}" for c in vr.COLUMNS}
        out = vr.ascii_table([row])
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("+") and lines[0].endswith("+"))
        self.assertIn("| CVE ID", out)
        self.assertEqual(len({len(line) for line in lines}), 1)
        self.assertEqual(out.count("+"), 3 * (len(vr.COLUMNS) + 1))

    def test_structured_cell_bullets_more_than_two_sentences(self):
        value = vr.structured_cell("First fact. Second fact. Third fact.")
        self.assertEqual(value.splitlines(), ["- First fact.", "- Second fact.", "- Third fact."])
        self.assertEqual(vr.structured_cell("First fact. Second fact."), "First fact. Second fact.")

    def test_vertical_plain_and_html_renderers(self):
        row = {c: f"value for {c}" for c in vr.COLUMNS}
        row["Description"] = "First fact. Second fact. Third fact."
        row["IoCs"] = "- IPv4: 8.8.8.8 — test context\n- SHA-256: " + "a" * 64 + " — test file"
        vertical = vr.vertical_table([row])
        self.assertIn("| Field", vertical)
        self.assertEqual(len({len(line) for line in vertical.splitlines()}), 1)
        plain = vr.plain_text([row])
        self.assertTrue(plain.startswith("CVE ID: value for CVE ID"))
        html = vr.html_table([row])
        self.assertIn("<!doctype html>", html)
        self.assertIn("<table", html)
        self.assertIn("<ul", html)
        self.assertIn("<li", html)
        self.assertIn("value for CVE ID", html)

    def test_render_strips_terminal_control_sequences(self):
        row = {c: "safe" for c in vr.COLUMNS}
        row["Name"] = "before\x1b[31mRED\x1b[0m\x07after"
        for fmt in ("ascii", "vertical", "plain", "markdown", "json", "csv", "html"):
            rendered = vr.render([row], fmt)
            self.assertNotIn("\x1b", rendered)
            self.assertNotIn("\x07", rendered)
            self.assertIn("beforeREDafter", rendered)
    def test_csv_neutralizes_formula_cells_and_preserves_other_values(self):
        row = {c: "safe" for c in vr.COLUMNS}
        dangerous = ["=cmd", "+SUM(A1:A2)", "-1+2", "@NOW()", "  =hidden", "\t-2"]
        for column, value in zip(vr.COLUMNS, dangerous):
            row[column] = value
        row["Vector"] = "ordinary + value"
        parsed = list(csv.DictReader(io.StringIO(vr.render([row], "csv"))))[0]
        for column, value in zip(vr.COLUMNS, dangerous):
            self.assertEqual(parsed[column], "'" + value)
        self.assertEqual(parsed["Vector"], "ordinary + value")


class TransportSecurity(unittest.TestCase):
    def test_credential_headers_require_https(self):
        with self.assertRaises(ValueError):
            vr.http("http://example.test/data", {"Authorization": "Bearer secret"}, retries=0)

    def test_cross_origin_redirect_drops_credentials(self):
        handler = vr.SafeRedirectHandler()
        old = urllib.request.Request(
            "https://api.example.test/a",
            headers={"Authorization": "Bearer secret", "X-apikey": "secret", "Cookie": "sid=secret",
                     "Cookie2": "$Version=1", "Accept": "x"},
        )
        new = handler.redirect_request(old, None, 302, "Found", {}, "https://other.example.test/b")
        lowered = {k.lower(): v for k, v in new.header_items()}
        self.assertNotIn("authorization", lowered)
        self.assertNotIn("x-apikey", lowered)
        self.assertNotIn("cookie", lowered)
        self.assertNotIn("cookie2", lowered)
        self.assertEqual(lowered["accept"], "x")

    def test_http_bounds_response_body(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self, amount): return b"x" * amount
        with mock.patch.object(vr, "_URL_OPENER") as opener:
            opener.open.return_value = Response()
            code, body = vr.http("https://example.test", retries=0)
        self.assertEqual((code, body), (vr.RESPONSE_TOO_LARGE, b""))
        opener.open.assert_called_once()

    @mock.patch.dict(os.environ, {"PATH": "/bin", "HOME": "/home/test", "NVD_API_KEY": "nvd-secret",
                                  "VIRUSTOTAL_API_KEY": "vt-secret", "LANG": "C"}, clear=True)
    @mock.patch.object(vr.shutil, "which", return_value="/bin/xurl")
    @mock.patch.object(vr.subprocess, "run")
    def test_xurl_receives_allowlisted_environment_only(self, run, _):
        run.return_value = subprocess.CompletedProcess([], 0, stdout='{"data": []}', stderr="")
        vr.x_posts("CVE-2099-0001")
        child_env = run.call_args.kwargs["env"]
        self.assertEqual(child_env["HOME"], "/home/test")
        self.assertNotIn("NVD_API_KEY", child_env)
        self.assertNotIn("VIRUSTOTAL_API_KEY", child_env)

    def test_x_posts_returns_distinct_failure_statuses(self):
        cases = [
            (None, None, "xurl_missing"),
            ("/bin/xurl", subprocess.TimeoutExpired("xurl", 60), "timeout"),
            ("/bin/xurl", subprocess.CompletedProcess([], 2, stdout="", stderr="failed"), "command_error"),
            ("/bin/xurl", subprocess.CompletedProcess([], 1, stdout="", stderr="401 Unauthorized"), "auth_error"),
            ("/bin/xurl", subprocess.CompletedProcess([], 0, stdout="{", stderr=""), "malformed_json"),
            ("/bin/xurl", subprocess.CompletedProcess([], 0, stdout='{"errors":[{"detail":"denied"}]}', stderr=""),
             "api_error"),
        ]
        for executable, outcome, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(vr.shutil, "which", return_value=executable), \
                    mock.patch.object(vr.subprocess, "run", side_effect=outcome if isinstance(outcome, Exception) else None,
                                      return_value=None if isinstance(outcome, Exception) else outcome):
                result = vr.x_posts("CVE-2099-0001")
                self.assertFalse(result["ok"])
                self.assertEqual(result["status"], expected)
                self.assertTrue(result["error"])

    @mock.patch.object(vr.shutil, "which", return_value="/bin/xurl")
    def test_x_posts_rejects_oversized_captured_output(self, _):
        outcomes = [
            subprocess.CompletedProcess([], 0, stdout="x" * (vr.MAX_XURL_OUTPUT_BYTES + 1), stderr=""),
            subprocess.CompletedProcess([], 1, stdout="", stderr="x" * (vr.MAX_XURL_OUTPUT_BYTES + 1)),
        ]
        for outcome in outcomes:
            with self.subTest(stream="stdout" if outcome.stdout else "stderr"), \
                    mock.patch.object(vr.subprocess, "run", return_value=outcome):
                result = vr.x_posts("CVE-2099-0001")
                self.assertFalse(result["ok"])
                self.assertEqual(result["status"], "output_too_large")
                self.assertIn("size limit", result["error"])


class NvdBehavior(unittest.TestCase):
    def test_nvd_cve_rejects_malformed_objects_descriptions_and_configurations(self):
        malformed_cves = [
            None,
            [],
            {"id": "CVE-2099-0001", "descriptions": None, "configurations": []},
            {"id": "CVE-2099-0001", "descriptions": [None], "configurations": []},
            {"id": "CVE-2099-0001", "descriptions": [{"lang": None, "value": "x"}], "configurations": []},
            {"id": "CVE-2099-0001", "descriptions": [], "configurations": None},
            {"id": "CVE-2099-0001", "descriptions": [], "configurations": [{"nodes": [None]}]},
            {"id": "CVE-2099-0001", "descriptions": [], "configurations": [
                {"nodes": [{"cpeMatch": [None]}]}]},
            {"id": "CVE-2099-0001", "descriptions": [], "configurations": [], "metrics": None},
            {"id": "not-a-cve", "descriptions": [], "configurations": [], "metrics": {}},
        ]
        for cve in malformed_cves:
            payload = {"vulnerabilities": [{"cve": cve}]}
            with self.subTest(cve=cve), mock.patch.object(vr, "json_result", return_value=(payload, None)):
                result, error = vr.nvd_cve_result("CVE-2099-0001")
                self.assertIsNone(result)
                self.assertEqual(error, "NVD malformed response")

    def test_nvd_cve_rejects_malformed_cvss_scalars(self):
        for field in ("version", "baseScore", "baseSeverity", "vectorString", "attackVector", "privilegesRequired"):
            cve = json.loads(json.dumps(NVD_CVE))
            cve["metrics"]["cvssMetricV31"][0]["cvssData"][field] = {"bad": "shape"}
            payload = {"vulnerabilities": [{"cve": cve}]}
            with self.subTest(field=field), mock.patch.object(vr, "json_result", return_value=(payload, None)):
                result, error = vr.nvd_cve_result("CVE-2099-0001")
                self.assertIsNone(result)
                self.assertEqual(error, "NVD malformed response")

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_unkeyed_pacing_applies_to_every_nvd_request(self):
        vr._nvd_request_times.clear()
        clock = [0.0]
        sleeps = []
        def sleep(seconds):
            sleeps.append(seconds); clock[0] += seconds
        with mock.patch.object(vr.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(vr.time, "sleep", side_effect=sleep):
            for _ in range(6):
                vr._pace_nvd()
        self.assertEqual(len(sleeps), 1)
        self.assertGreaterEqual(sleeps[0], 30.0)

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "key"}, clear=True)
    def test_keyed_nvd_pacing_limits_fifty_requests_per_window(self):
        vr._nvd_request_times.clear()
        clock = [10.0]
        sleeps = []
        def sleep(seconds):
            sleeps.append(seconds); clock[0] += seconds
        with mock.patch.object(vr.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(vr.time, "sleep", side_effect=sleep):
            for _ in range(51):
                vr._pace_nvd()
        self.assertEqual(sleeps, [30.0])
        self.assertEqual(len(vr._nvd_request_times), 1)

    def test_product_search_paginates_all_results(self):
        pages = {
            0: {"totalResults": 3, "startIndex": 0, "resultsPerPage": 2, "vulnerabilities": [
                {"cve": dict(NVD_CVE, id="CVE-2099-0001", published="2099-01-01")},
                {"cve": dict(NVD_CVE, id="CVE-2099-0002", published="2099-01-02")}]},
            2: {"totalResults": 3, "startIndex": 2, "resultsPerPage": 2, "vulnerabilities": [
                {"cve": dict(NVD_CVE, id="CVE-2099-0003", published="2099-01-03")}]},
        }
        def get(url, _headers=None):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            return pages[int(query.get("startIndex", [0])[0])], None
        with mock.patch.object(vr, "json_result", side_effect=get):
            found, total, complete, error = vr.nvd_product_search("Apache Tomcat", "9.0.30", 10)
        self.assertEqual(found, ["CVE-2099-0003", "CVE-2099-0002", "CVE-2099-0001"])
        self.assertEqual(total, 3)
        self.assertTrue(complete)
        self.assertIsNone(error)

    def test_product_search_reports_incomplete_page_failure(self):
        first = {"totalResults": 2, "startIndex": 0, "resultsPerPage": 1, "vulnerabilities": [
            {"cve": dict(NVD_CVE, id="CVE-2099-0001", published="2099-01-01")}]}
        with mock.patch.object(vr, "json_result", side_effect=[(first, None), (None, "HTTP 503")]):
            found, total, complete, error = vr.nvd_product_search("Apache Tomcat", "9.0.30", 10)
        self.assertEqual(found, ["CVE-2099-0001"])
        self.assertEqual(total, 2)
        self.assertFalse(complete)
        self.assertIn("HTTP 503", error)

    def test_product_search_rejects_invalid_pagination_invariants(self):
        item1 = {"cve": dict(NVD_CVE, id="CVE-2099-0001", published="2099-01-01")}
        item2 = {"cve": dict(NVD_CVE, id="CVE-2099-0002", published="2099-01-02")}
        cases = [
            [{"totalResults": -1, "startIndex": 0, "resultsPerPage": 1, "vulnerabilities": []}],
            [{"totalResults": 1, "startIndex": 1, "resultsPerPage": 1, "vulnerabilities": [item1]}],
            [{"totalResults": 1, "startIndex": 0, "resultsPerPage": 0, "vulnerabilities": [item1]}],
            [{"totalResults": 1, "startIndex": 0, "resultsPerPage": 2,
              "vulnerabilities": [item1, item2]}],
            [{"totalResults": 2, "startIndex": 0, "resultsPerPage": 1, "vulnerabilities": [item1]},
             {"totalResults": 3, "startIndex": 1, "resultsPerPage": 1, "vulnerabilities": [item2]}],
        ]
        for pages in cases:
            with self.subTest(pages=pages), mock.patch.object(
                    vr, "json_result", side_effect=[(page, None) for page in pages]):
                _found, _total, complete, error = vr.nvd_product_search("Apache Tomcat", "9.0.30", 10)
                self.assertFalse(complete)
                self.assertIn("pagination", error.lower())


class Configuration(unittest.TestCase):
    def test_check_config_succeeds_without_optional_xurl(self):
        script = os.path.join(os.path.dirname(__file__), "..", "scripts", "check_config.py")
        env = {"PATH": "", "HOME": os.environ.get("HOME", "")}
        done = subprocess.run([sys.executable, script], capture_output=True, text=True, env=env)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_dotenv_remains_ignored(self):
        ignore = os.path.join(os.path.dirname(__file__), "..", ".gitignore")
        with open(ignore, encoding="utf-8") as fh:
            self.assertIn(".env", {line.strip() for line in fh if line.strip() and not line.startswith("#")})


if __name__ == "__main__":
    unittest.main()
