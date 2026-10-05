#!/usr/bin/env python3
"""Check vuln-research credential presence without printing secrets."""
import os, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"


def load_env(path):
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip("'\"")
        os.environ.setdefault(key.strip(), value)


load_env(ENV)
print(f"Repository .env: {'present' if ENV.is_file() else 'missing (copy .env.example to .env)'}")
for key in ("GITHUB_TOKEN", "NVD_API_KEY", "GREYNOISE_API_KEY", "VIRUSTOTAL_API_KEY", "THREATFOX_API_KEY"):
    value = os.environ.get(key, "")
    print(f"{key}: {'configured' if value else 'not configured'}")

if not shutil.which("xurl"):
    print("X/xurl: not installed (optional)")
    sys.exit(0)
try:
    allowed = ("HOME", "PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "TMPDIR",
               "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
    child_env = {name: os.environ[name] for name in allowed if name in os.environ}
    p = subprocess.run(["xurl", "auth", "status"], capture_output=True, text=True, timeout=15,
                       env=child_env)
    print("X/xurl: installed; auth status " + ("OK" if p.returncode == 0 else "needs configuration"))
except Exception as exc:
    print(f"X/xurl: check failed ({type(exc).__name__})")
