#!/usr/bin/env python3
"""Minimal stdlib MCP server (stdio, JSON-RPC 2.0) exposing vulnresearch as tools.

Works with any MCP client (Hermes, Claude Desktop, Cursor, etc.):
  {"command": "python3", "args": ["/path/to/mcp/vulnresearch_mcp.py"]}

Tools:
  research_cve(cve_ids: [str], include_social: bool=True, format: str="markdown")
  research_product(product: str, version: str="", limit: int=10, include_social: bool=True, format: str="markdown")
"""
import contextlib, io, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills", "vuln-research", "scripts"))
import vulnresearch as vr  # noqa: E402

PROTO = "2024-11-05"
FMT = {"type": "string", "enum": ["ascii", "vertical", "html", "plain", "markdown", "json", "csv", "table"], "default": "ascii"}
TOOLS = [
    {"name": "research_cve",
     "description": "Research one or more CVE IDs: description, affected products, CVSS, vector, auth, app type, "
                    "public exploit availability (GitHub/Reddit/X), chatter level, IoCs (GreyNoise/VirusTotal), "
                    "ITW exploitation (CISA KEV/SSVC).",
     "inputSchema": {"type": "object", "properties": {
         "cve_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
         "include_social": {"type": "boolean", "default": True}, "format": FMT},
         "required": ["cve_ids"]}},
    {"name": "research_product",
     "description": "Find CVEs affecting a product+version (NVD CPE ranges) and research each like research_cve.",
     "inputSchema": {"type": "object", "properties": {
         "product": {"type": "string"}, "version": {"type": "string", "default": ""},
         "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50},
         "include_social": {"type": "boolean", "default": True}, "format": FMT},
         "required": ["product"]}},
]


def call(name, args):
    argv = []
    if name == "research_cve":
        argv += list(args["cve_ids"])
    elif name == "research_product":
        argv += ["--product", args["product"], "--version", args.get("version", ""),
                 "--limit", str(args.get("limit", 10))]
    else:
        raise ValueError(f"unknown tool {name}")
    argv += ["--format", args.get("format", "ascii")]
    if not args.get("include_social", True):
        argv.append("--no-social")
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            vr.main(argv)
        except SystemExit as e:
            if e.code:
                raise ValueError(err.getvalue().strip() or "invalid arguments")
    return (err.getvalue().strip() + "\n" if err.getvalue().strip() else "") + out.getvalue()


def reply(i, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": i}
    msg["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(msg) + "\n"); sys.stdout.flush()


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        m, i = req.get("method"), req.get("id")
        if i is None:  # notification
            continue
        if m == "initialize":
            reply(i, {"protocolVersion": PROTO, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "vulnresearch", "version": "0.5.0"}})
        elif m == "tools/list":
            reply(i, {"tools": TOOLS})
        elif m == "tools/call":
            p = req.get("params", {})
            try:
                txt = call(p.get("name"), p.get("arguments", {}))
                reply(i, {"content": [{"type": "text", "text": txt}]})
            except Exception as e:
                reply(i, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
        elif m == "ping":
            reply(i, {})
        else:
            reply(i, error={"code": -32601, "message": f"method not found: {m}"})


if __name__ == "__main__":
    main()
