# Building a vulnerability research agent that shows its work

Vulnerability triage often starts with a simple question: "What does this CVE mean for us?" The answer usually involves six browser tabs, two conflicting severity scores, a pile of GitHub repositories, and a social-media search that is hard to reproduce later.

`vuln-research-agent` packages that work into a reusable command, an Agent Skill, and an MCP server. It accepts a CVE ID or a product and version, collects evidence from public vulnerability and threat-intelligence sources, and returns the result in a consistent 12-field report.

The project is aimed at detection engineers and security operations teams. It does not scan infrastructure or run exploit code. Its job is to collect evidence, label uncertainty, and make the first triage pass repeatable.

## The idea

A CVE record answers only part of the question. NVD may tell you the affected versions and CVSS vector, but it does not reliably answer whether a usable exploit has appeared, whether defenders are discussing the issue, or whether anyone has observed exploitation.

Those answers live in different places:

- NVD and CVE.org hold the vulnerability record.
- CISA KEV and CISA ADP provide exploitation signals.
- FIRST EPSS estimates the probability of exploitation.
- GitHub and Reddit reveal public tools and practitioner discussion.
- X provides faster, noisier chatter from researchers and vendors.
- GreyNoise can identify internet scanners associated with a CVE when the account permits CVE-filtered GNQL queries.
- VirusTotal can surface linked file hashes, indicator objects, and community comments.

The agent joins these sources but does not pretend they have equal authority. A CISA KEV entry is stronger evidence of in-the-wild exploitation than a repository description. A README that says "PoC" is not proof that exploit code exists. An IP returned by an unfiltered scanner feed is not a CVE indicator.

That distinction is the core design choice.

## Architecture

The repository has one research core with three ways to invoke it:

1. The CLI works in terminals, CI jobs, and SOAR playbooks.
2. The Agent Skill tells an LLM how to validate sources, handle uncertainty, and format results.
3. The MCP server exposes `research_cve` and `research_product` to any compatible AI client.

The full diagram is in [`docs/ARCHITECTURE.txt`](ARCHITECTURE.txt). The short version is:

```text
User input
    |
    v
Agent Skill / MCP / CLI
    |
    v
CVE and product resolver
    |
    +--> NVD, CVE.org, CISA KEV, EPSS
    +--> GitHub, Reddit, X
    +--> GreyNoise, VirusTotal
    |
    v
Validation and evidence labelling
    |
    v
ASCII | Vertical | HTML | Plain text | JSON/CSV
```

The CLI is written with Python's standard library. There is no package installation step. The MCP server imports the same code, so the CLI and every connected harness use identical collection and classification logic.

## Why the validation layer matters

Threat-intelligence APIs can fail in ways that look successful.

During development, a GreyNoise GNQL request returned HTTP 200 and millions of IPs even though the account could not query the `cve` field. The response disclosed that restriction in `request_metadata.restricted_fields`. A naive integration would have labeled unrelated scanners as indicators for the requested vulnerability.

The agent now rejects the complete result whenever the provider says the CVE field was restricted. It also checks that every retained GreyNoise record explicitly contains the requested CVE. This turns a subtle data-quality failure into an honest "source unavailable" result.

The same caution applies to VirusTotal comments. Community comments are useful leads, not verified intelligence. The agent extracts only concrete public IP addresses and MD5, SHA-1, or SHA-256 values. Every extracted value carries a one-line source and context, and the output marks comment-derived indicators as unverified.

GitHub needs similar treatment. A repository can mention a CVE without containing an exploit. The agent narrows repository matches, and the skill instructs the model to inspect the strongest candidates before calling them a verified PoC. Scanners, version checkers, detection artifacts, and external-download bait are labeled separately.

## The report

Each CVE has the same fields:

- CVE ID
- Name
- Description
- Affected Products
- Exploit Available Online
- Chatter Level
- IoCs
- App Type
- Auth
- Vector
- CVSS
- ITW Exploitation

The fields are intentionally compact. One or two sentences stay as prose; longer cells become bullet lists. IoC entries use a strict form:

```text
- SHA-256: <hash> — VirusTotal file; filename=<name>; detections=12 malicious/0 suspicious
- IPv4: <address> — GreyNoise scanner associated with the CVE; classification=malicious; last_seen=<date>
```

If no indicators are returned, the report says whether the sources were queried. It does not turn missing access into a claim that no indicators exist.

Before starting research, the skill asks which presentation fits the task:

- ASCII table for comparing several CVEs in a wide terminal.
- Vertical table for a detailed single-CVE view or a narrow screen.
- HTML file for sharing, browser viewing, or printing.
- Plain text for email, tickets, and SIEM cases.

JSON and CSV remain available for automation.

## Install the core CLI

Clone or unpack the repository, then create its local secrets file:

```bash
cd /path/to/vuln-research-agent
cp .env.example .env
chmod 600 .env
```

Add the API keys you have to `.env`:

```dotenv
GITHUB_TOKEN=
NVD_API_KEY=
GREYNOISE_API_KEY=
VIRUSTOTAL_API_KEY=
```

X credentials do not belong in this file. The official `xurl` client manages its OAuth credentials in `~/.xurl`. See [`docs/SETUP.md`](SETUP.md) for the complete X application and OAuth flow.

Check the setup and run a query:

```bash
python3 scripts/check_config.py
python3 skills/vuln-research/scripts/vulnresearch.py CVE-2024-3400 --format vertical
```

## Install in Hermes Agent

Hermes can use both the skill and the MCP tools.

Install the skill:

```bash
mkdir -p ~/.hermes/skills/security
cp -R skills/vuln-research ~/.hermes/skills/security/
```

Start a new Hermes session so it discovers the skill. A request such as "Research CVE-2024-3400" will trigger the skill and ask for an output format.

To expose the deterministic lookup functions as MCP tools:

```bash
hermes mcp add vulnresearch \
  --command python3 \
  --args /absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py
hermes mcp test vulnresearch
```

Restart Hermes after adding the server. It discovers `mcp_vulnresearch_research_cve` and `mcp_vulnresearch_research_product` at startup. The MCP subprocess loads the repository `.env` automatically.

## Install in Claude Code

Claude Code supports project skills under `.claude/skills`:

```bash
mkdir -p /path/to/your-project/.claude/skills
cp -R skills/vuln-research /path/to/your-project/.claude/skills/
```

You can also add the MCP server:

```bash
claude mcp add --transport stdio vulnresearch -- \
  python3 /absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py
```

Restart Claude Code or begin a new session after installing the skill.

## Install in OpenAI Codex

Codex discovers repository skills under `.agents/skills`:

```bash
mkdir -p /path/to/your-project/.agents/skills
cp -R skills/vuln-research /path/to/your-project/.agents/skills/
```

For MCP, register the stdio server using Codex's MCP command:

```bash
codex mcp add vulnresearch -- \
  python3 /absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py
```

Codex stores MCP configuration in `~/.codex/config.toml`. The CLI and IDE extension share that configuration.

## Install in Cursor

Create `.cursor/mcp.json` in a project, or use Cursor's global MCP settings:

```json
{
  "mcpServers": {
    "vulnresearch": {
      "command": "python3",
      "args": ["/absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py"]
    }
  }
}
```

Restart Cursor, open its MCP settings, and confirm that the two tools appear. Cursor supports `envFile` for stdio servers, but it is not required here because the research core reads the repository `.env` itself.

## Install in VS Code

Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "vulnresearch": {
      "type": "stdio",
      "command": "python3",
      "args": ["/absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py"]
    }
  }
}
```

Use the MCP server management commands in VS Code to start the server and inspect its tools.

## Install in Claude Desktop

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vulnresearch": {
      "command": "python3",
      "args": ["/absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py"]
    }
  }
}
```

Quit and reopen Claude Desktop. Local MCP servers run as child processes over standard input/output.

## Install in Gemini CLI

Add the server to `~/.gemini/settings.json` or a project's `.gemini/settings.json`:

```json
{
  "mcpServers": {
    "vulnresearch": {
      "command": "python3",
      "args": ["/absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py"]
    }
  }
}
```

Restart Gemini CLI and list its discovered MCP servers or tools.

## Use it from any other harness

Any client that supports local MCP stdio can launch:

```text
command: python3
args: /absolute/path/vuln-research-agent/mcp/vulnresearch_mcp.py
```

Clients without MCP support can run the CLI and consume JSON:

```bash
python3 skills/vuln-research/scripts/vulnresearch.py \
  CVE-2024-3400 --format json
```

That fallback matters. The research core is not locked to an agent framework, and the skill is not required for automation. A shell, a SOAR workflow, or a scheduled CI job can use the same evidence model.

## What the agent does not claim

The output is a triage artifact, not an incident verdict. CISA KEV coverage is authoritative for its own catalog but is not a complete record of exploitation worldwide. EPSS is a probability model, not evidence of exploitation. GreyNoise scanner IPs show observed probing, not successful compromise. VirusTotal comments may be wrong. Public exploit repositories can contain malware.

Those limits belong in the result, beside the evidence they qualify. Hiding them in documentation would make the table easier to read and easier to misuse.

## Contributing

The code uses only Python's standard library. Offline tests cover CVSS parsing, version ranges, output renderers, IoC extraction, GreyNoise restriction handling, and the skill's format-selection contract:

```bash
python3 -m unittest discover -s tests -v
```

Useful contributions include additional source adapters, stronger product-version matching, improved PoC verification, and detection-rule output that preserves the same evidence discipline.
