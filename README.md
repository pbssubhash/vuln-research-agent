# vuln-research-agent

An open-source vulnerability research agent for detection engineers. Give it a CVE ID
(or a product name plus version) and it returns one triage row per CVE:

| CVE ID | Name | Description | Affected Products | Exploit Available Online | Chatter Level | IoCs | App Type | Auth | Vector | CVSS | ITW Exploitation |
|---|---|---|---|---|---|---|---|---|---|---|---|

It is available in three forms, all using the same stdlib-only Python core (no pip installs):

| Form | Path | Use with |
|---|---|---|
| CLI | `skills/vuln-research/scripts/vulnresearch.py` | Terminal, CI, SOAR playbooks |
| Agent skill | `skills/vuln-research/SKILL.md` | Hermes Agent, Claude Code / Agent Skills-compatible agents |
| MCP server (tools) | `mcp/vulnresearch_mcp.py` | Any MCP client: Hermes, Claude Desktop, Cursor, VS Code |

## Data sources

| Signal | Source |
|---|---|
| Description, CPE-affected products, CVSS | NVD API 2.0, falling back to the CVE.org CNA/CISA-ADP record for fresh CVEs; OSV.dev package/ecosystem data and GitHub Security Advisory (GHSA) severity as further fallbacks |
| ITW exploitation | CISA KEV (incl. ransomware flag), CISA-ADP SSVC `Exploitation: active` |
| Exploit availability | GitHub (nomi-sec/PoC-in-GitHub index plus repo search), Exploit-DB (GitLab CSV mirror), Reddit (search RSS), X (via official `xurl` CLI) |
| Chatter level | X post count and engagement (weighted highest), Reddit post volume, GitHub repo count and stars, AlienVault OTX pulse count |
| IoCs | GreyNoise GNQL scanner IPs (key + entitlement required); VirusTotal CVE-linked file hashes, detection counts, comments, and IP/domain/URL results (key required); ThreatFox malware/C2 IOCs (key required) |
| Cross-checks | Shodan CVEDB (CVSS/EPSS/KEV, keyless) and AlienVault OTX pulse volume (keyless), both reported only as corroborating signals |
| Extra (JSON `_evidence`) | FIRST EPSS score/percentile, CVSS vector, top PoC links, full structured GreyNoise/VT/ThreatFox/OTX/Shodan/Exploit-DB results and coverage errors |

App Type, Auth and Vector come from the CVSS vector (AV/PR) plus CPE part and description keyword heuristics. Before research, the agent asks the user to choose ASCII table, vertical table, HTML file, or plain text unless the request already names a format.

## API and X setup

Copy `.env.example` to `.env` for GitHub, NVD, GreyNoise and VirusTotal keys. X uses the official xurl OAuth store rather than `.env`. Full instructions: [`docs/SETUP.md`](docs/SETUP.md).

```bash
cp .env.example .env
chmod 600 .env
python3 scripts/check_config.py
```

## Quick start

```bash
python3 skills/vuln-research/scripts/vulnresearch.py CVE-2021-44228 CVE-2024-3400
python3 skills/vuln-research/scripts/vulnresearch.py --product "Apache Tomcat" --version 9.0.30 --limit 10 --format markdown
python3 skills/vuln-research/scripts/vulnresearch.py CVE-2024-3400 --format json   # includes _evidence
```

Formats: `ascii`, `vertical`, `html`, `plain`, `markdown`, `csv`, `json`; `table` is an alias for `ascii`. Use `--output PATH` to create a file, especially with HTML.

User-facing choices:

- ASCII table: best for multi-CVE comparison in a wide terminal.
- Vertical table: best for one CVE, narrow terminals, or phone screens.
- HTML file: best for browser viewing, sharing, or printing.
- Plain text: best for email, tickets, SIEM cases, and copy/paste.

Every field is kept precise: prose over two sentences is converted to bullets. The IoCs field contains only concrete indicators, formatted as `type: value — one-line source/context`. GreyNoise results must be CVE-linked and unrestricted; VirusTotal contributes file hashes/detection counts, structured indicators, and concrete IP/hash values extracted from clearly labeled unverified community comments. Detection ideas and generic log strings do not count as IoCs.

Optional env vars:
- `GITHUB_TOKEN`: higher GitHub search limits
- `NVD_API_KEY`: 10x NVD rate limit (free key)
- `GREYNOISE_API_KEY`: GreyNoise GNQL scanner IPs associated with the CVE (requires GNQL entitlement)
- `VIRUSTOTAL_API_KEY`: VirusTotal file/comment/indicator search. Public keys may have less coverage than Intelligence.
- `THREATFOX_API_KEY`: ThreatFox (abuse.ch) malware/C2 IOCs tagged with the CVE. Free account at https://auth.abuse.ch/.

Exploit-DB, AlienVault OTX, GitHub Security Advisories, OSV.dev, and Shodan CVEDB need no key and are always queried.

Without the GreyNoise, VirusTotal, or ThreatFox key, the IoCs column says `not queried` rather than incorrectly claiming no IoCs exist. Never query sensitive/private indicators in VirusTotal; queried or submitted indicators may become visible to its community.

X support: install [`xurl`](https://github.com/xdevplatform/xurl) and run `xurl auth oauth2`
yourself. Without it, X is reported as `n/a` and the agent skill falls back to web search.

## Install as a skill

Hermes Agent:
```bash
cp -r skills/vuln-research ~/.hermes/skills/security/
```
For Claude Code and other Agent Skills-compatible agents, copy `skills/vuln-research` into that agent's skills directory.

## Install as MCP tools

```json
{
  "mcpServers": {
    "vulnresearch": { "command": "python3", "args": ["/abs/path/vuln-research-agent/mcp/vulnresearch_mcp.py"],
                      "env": { "GITHUB_TOKEN": "", "NVD_API_KEY": "", "GREYNOISE_API_KEY": "", "VIRUSTOTAL_API_KEY": "", "THREATFOX_API_KEY": "" } }
  }
}
```
Hermes (`~/.hermes/config.yaml`):
```yaml
mcp_servers:
  vulnresearch:
    command: python3
    args: [/abs/path/vuln-research-agent/mcp/vulnresearch_mcp.py]
```
Tools: `research_cve(cve_ids[], include_social, format)` and `research_product(product, version, limit, include_social, format)`.

## Tests

```bash
python3 -m unittest discover -s tests -v   # offline, mocked
```

## Caveats

- Not being in KEV does not mean a CVE hasn't been exploited. The tool reports "Not observed".
- GitHub "PoC" repos are sometimes fake or malicious. Review them before running anything.
- App Type is a heuristic. Treat it as a first pass.

## License

MIT
