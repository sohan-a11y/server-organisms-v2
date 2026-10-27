#!/usr/bin/env python3
"""Adopt Server Organisms into ANY codebase.

Scans a repo, discovers its HTTP APIs (Flask, FastAPI, Express), and writes an
adoption kit next to this repo:

  adoption/apis.json            - route inventory (method, path, framework, file)
  adoption/replay.env           - REPLAY_NORMALS / UPSTREAM_URL for the gateway
  adoption/README-ADOPT.md      - exact steps to put the colony in front

Your app code is never modified. The gateway sits in front of it.

Usage:  python tools/adopt.py <path-to-your-repo> [--out adoption]
"""
import argparse
import json
import os
import re
import sys

PY_ROUTE = re.compile(r"""@\w+(?:\.\w+)*\.(get|post|put|patch|delete|route)\(\s*["']([^"']+)["']""")
PY_ROUTE_METHODS = re.compile(r"""methods\s*=\s*\[([^\]]+)\]""")
JS_ROUTE = re.compile(r"""(?:app|router)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]""")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}


def scan(root):
    apis = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith((".py", ".js", ".ts", ".mjs")):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            try:
                if os.path.islink(path) or os.path.getsize(path) > 512 * 1024:
                    continue  # never follow symlinks or slurp large files
                text = open(path, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            if name.endswith(".py"):
                for m in PY_ROUTE.finditer(text):
                    verb, route = m.group(1), m.group(2)
                    methods = [verb.upper()] if verb != "route" else ["GET"]
                    if verb == "route":
                        mm = PY_ROUTE_METHODS.search(text[m.end():m.end() + 200])
                        if mm:
                            methods = re.findall(r"""["'](\w+)["']""", mm.group(1))
                    framework = "fastapi" if "fastapi" in text.lower() else "flask"
                    for method in methods:
                        apis.append({"method": method.upper(), "path": route,
                                     "framework": framework, "file": rel})
            elif name.endswith((".js", ".ts", ".mjs")):
                for m in JS_ROUTE.finditer(text):
                    apis.append({"method": m.group(1).upper(), "path": m.group(2),
                                 "framework": "express", "file": rel})
    seen, out = set(), []
    for a in apis:
        key = (a["method"], a["path"], a["file"])
        if key not in seen:
            seen.add(key)
            out.append(a)
    return sorted(out, key=lambda a: (a["path"], a["method"]))


def main():
    ap = argparse.ArgumentParser(description="Make any codebase's APIs living organisms.")
    ap.add_argument("repo", help="path to the codebase to scan")
    ap.add_argument("--out", default="adoption", help="output directory (default: adoption/)")
    ap.add_argument("--upstream", default="http://host.docker.internal:8000",
                    help="where your app listens (default: http://host.docker.internal:8000)")
    args = ap.parse_args()

    apis = scan(args.repo)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "apis.json"), "w", encoding="utf-8") as f:
        json.dump({"source": os.path.abspath(args.repo), "apis": apis}, f, indent=1)
    unsafe_tokens = {"delete", "remove", "reset", "drop", "logout", "signout", "sign", "pay",
                     "charge", "transfer", "send", "cancel", "destroy", "purge", "webhook",
                     "callback", "execute", "run", "trigger", "activate", "flush", "update",
                     "create", "edit", "approve", "kill", "stop", "start", "sync", "import",
                     "process", "action", "do", "set", "clear", "empty", "wipe"}

    def _safe_get(path):
        tokens = set(re.split(r"[^a-z]+", path.lower()))
        return not (tokens & unsafe_tokens)

    normals = [a["path"] for a in apis
               if a["method"] == "GET" and "<" not in a["path"] and ":" not in a["path"] and "{" not in a["path"]
               and _safe_get(a["path"])]
    # Replay issues REAL GETs upstream: only side-effect-free-looking routes are
    # auto-listed. Review adoption/replay.env before use (see README-ADOPT.md).
    with open(os.path.join(args.out, "replay.env"), "w", encoding="utf-8") as f:
        f.write(f"UPSTREAM_URL={args.upstream}\n")
        f.write("REPLAY_NORMALS=" + ",".join(normals[:12]) + "\n")
        f.write("REPLAY_USER_ID=1\n")
    with open(os.path.join(args.out, "README-ADOPT.md"), "w", encoding="utf-8") as f:
        f.write(f"""# Your APIs are now living — adoption kit

Discovered **{len(apis)} API routes** in `{args.repo}` (see apis.json).

## Put the colony in front (no code changes in your app)

1. Start your app so it listens on {args.upstream} (host) or its container URL.
2. In the server-organisms repo, add to `.env` (values from replay.env):
   `UPSTREAM_URL=...`, `REPLAY_NORMALS=...`, `REPLAY_USER_ID=1`
3. `docker compose up --build -d`
4. Route your traffic to the gateway: http://127.0.0.1:18010/<your-path>
5. Open the dashboard: every discovered API appears as a living node in 3D,
   with live requests / blocks / attacks / immunity per route.

The colony senses exploits on each route, proposes immunity, proves it by
replaying YOUR normal routes, and only then blocks. Supervisor kill switch
stays outside the organisms. See ../TRUST.md before production use.
""")
    print(f"Discovered {len(apis)} API routes in {args.repo}:")
    for a in apis[:40]:
        print(f"  {a['method']:6} {a['path']:40} [{a['framework']}] {a['file']}")
    if len(apis) > 40:
        print(f"  ... and {len(apis) - 40} more")
    print(f"Adoption kit written to {args.out}/ (apis.json, replay.env, README-ADOPT.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
