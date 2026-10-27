"""Route discovery: find the HTTP APIs inside any codebase.

Pure stdlib so it runs anywhere (no Docker needed for `organisms init`).
"""
import os
import re

PY_ROUTE = re.compile(r"""@\w+(?:\.\w+)*\.(get|post|put|patch|delete|route)\(\s*["']([^"']+)["']""")
PY_ROUTE_METHODS = re.compile(r"""methods\s*=\s*\[([^\]]+)\]""")
JS_ROUTE = re.compile(r"""(?:app|router)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]""")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}
MAX_SCAN_BYTES = 512 * 1024

SAFE_TOKENS = {"api", "v1", "v2", "v3", "health", "healthz", "ready", "status", "ping",
               "version", "info", "users", "user", "items", "item", "products", "product",
               "posts", "post", "comments", "comment", "profile", "profiles", "list",
               "search", "query", "find", "all", "data", "orders", "order", "articles",
               "article", "news", "feed", "catalog", "categories", "category", "tags",
               "tag", "pages", "page", "home", "index", "public", "open", "view", "read",
               "get", "fetch", "detail", "details", "summary", "stats", "metrics"}


def scan(root):
    """Return [{method, path, framework, file}] for a codebase root."""
    apis = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith((".py", ".js", ".ts", ".mjs")):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            try:
                if os.path.islink(path) or os.path.getsize(path) > MAX_SCAN_BYTES:
                    continue
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
            else:
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


def path_tokens(path):
    camel = re.sub(r"(?<=[a-z])(?=[A-Z])", "/", path)
    return {tok for tok in re.split(r"[^a-z]+", camel.lower()) if tok}


def safe_replay_normals(apis, limit=12):
    """Fail-closed: only purely read-only static GET routes become replay normals."""
    ok, excluded = [], []
    for a in apis:
        if a["method"] != "GET" or any(c in a["path"] for c in "<:{"):
            continue
        (ok if (path_tokens(a["path"]) and path_tokens(a["path"]) <= SAFE_TOKENS) else excluded).append(a["path"])
    return ok[:limit], excluded
