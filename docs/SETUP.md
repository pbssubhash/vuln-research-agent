# API and X setup

The CLI automatically reads `.env` from the repository root. Environment variables already exported by the shell take precedence. `.env` is git-ignored.

## 1. Create the local API-key file

From the repository root:

```bash
cp .env.example .env
chmod 600 .env
```

Open `.env` in a local text editor and place each key after its `=`. Do not paste keys into chat, issues, commits, CI output or screenshots.

```dotenv
GITHUB_TOKEN=
NVD_API_KEY=
GREYNOISE_API_KEY=
VIRUSTOTAL_API_KEY=
```

Keys are optional individually. Missing GreyNoise or VirusTotal credentials produce `not queried`, not a false `no IoCs found` result.

### GitHub

1. Open https://github.com/settings/personal-access-tokens/new.
2. Create a fine-grained token restricted to public repositories, with metadata/read-only access. The tool only searches public repository metadata.
3. Put it in `GITHUB_TOKEN=`.

### NVD

1. Request a free key at https://nvd.nist.gov/developers/request-an-api-key.
2. Put it in `NVD_API_KEY=`.

### GreyNoise

1. Create/sign into GreyNoise at https://viz.greynoise.io/.
2. Open https://viz.greynoise.io/account/api-key and create/copy an API key.
3. Confirm your plan includes GNQL access. The unauthenticated CVE endpoint returns vulnerability metadata only; it does not provide scanner IP indicators.
4. Put the key in `GREYNOISE_API_KEY=`.

### VirusTotal

1. Create/sign into VirusTotal at https://www.virustotal.com/.
2. Open https://www.virustotal.com/gui/my-apikey.
3. Put the key in `VIRUSTOTAL_API_KEY=`.

The public API is rate-limited and may return fewer CVE search results than VirusTotal Intelligence. Never query private, confidential or PII-bearing indicators: VirusTotal warns that queried or submitted indicators may become visible to its community.

## 2. Create and configure an X API application

The agent uses X's official `xurl` CLI with OAuth 2.0 Authorization Code + PKCE. X currently uses consumption-based billing, so enable billing/credits in the Developer Console before testing recent-post search.

### Create the X app

1. Sign in at https://developer.x.com/ and open the Developer Console.
2. Create a project/app (or select an existing app).
3. Enrol the project in X API pay-per-use/production access and add billing credit if prompted. Search requests can fail with `CreditsDepleted`, `client-forbidden` or `client-not-enrolled` without this.
4. Open the app's **User authentication settings** and enable OAuth 2.0.
5. Choose **Web app, automated app or bot**. Do not select Native App; xurl users commonly hit `unauthorized_client` with that type.
6. Give it read permission. Read-only is enough for this research agent.
7. Add this exact callback/redirect URI:

   `http://localhost:8080/callback`

8. Add any valid website URL required by the form (your repository URL is suitable).
9. Save, then copy the OAuth 2.0 **Client ID** and **Client Secret**. Do not put these in `.env` or share them in chat.

### Install xurl

Linux/macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/xdevplatform/xurl/main/install.sh | bash
xurl --version
```

Alternative installations are documented at https://github.com/xdevplatform/xurl.

### Register the app and authorise your X account

Run these yourself in a trusted terminal. They accept secrets and must not be run through an LLM session:

```bash
xurl auth apps add vuln-research --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET
xurl auth oauth2 --app vuln-research
xurl auth default vuln-research
```

The OAuth flow opens a browser. Approve the requested read access. xurl requests `offline.access`, stores the refresh token under `~/.xurl`, and refreshes access tokens automatically.

For a remote/headless server:

```bash
xurl auth oauth2 --app vuln-research --headless
```

Open the displayed URL locally, approve it, then paste the resulting redirect URL/code into xurl's masked terminal flow—not into chat.

If X returns `UsernameNotFound`, retry with your handle:

```bash
xurl auth oauth2 --app vuln-research YOUR_X_USERNAME
```

### Verify X without exposing secrets

```bash
xurl auth status
xurl whoami
xurl search '"CVE-2024-3400" -is:retweet' -n 3
```

Do not use `xurl --verbose`; it can expose authorization headers. Never read or commit `~/.xurl`.

## 3. Verify the vulnerability agent

```bash
python3 scripts/check_config.py
python3 skills/vuln-research/scripts/vulnresearch.py CVE-2024-3400 --format json
```

Inspect the JSON:

- `_evidence.x` should be non-null after xurl authentication.
- `_evidence.greynoise.queried` should be `true` when the key and GNQL entitlement work.
- `_evidence.virustotal.queried` should be `true` when the VT key works.
- The top-level `IoCs` cell should identify the source and never conflate scanner IPs with confirmed compromise infrastructure.

## 4. CI and MCP

For CI, store the four `.env` values as repository/organisation secrets and expose them as environment variables. Never commit a generated `.env`.

For MCP clients, either launch the server from the repository (so `.env` auto-loads), or inject the same environment variables in the MCP server configuration. X still uses the OS user's `~/.xurl` OAuth store; the MCP process must run under that same user/HOME.
