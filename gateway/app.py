"""Gateway colony: living immune layer in front of any API.
Sense attack -> wound tissue -> swarm decides -> block/allow ->
immunity rule proposed -> canary replay gate -> promoted or rejected.
Supervisor (separate process) owns the lease; withdrawn lease halts enforcement.
"""
import hashlib
import hmac
import html
import json
import os
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from flask import Flask, Response, jsonify, request

import muse_client
from brain import Brain
from chemistry import Chemistry
from life import Population
from nca import NCAGrid

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_BODY_BYTES", str(2 * 1024 * 1024)))
UPSTREAM = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:18011")
SUPERVISOR = os.environ.get("SUPERVISOR_URL", "http://127.0.0.1:18012")
TOKEN = os.environ.get("GATEWAY_TOKEN", "")
AUDIT_TOKEN = os.environ.get("AUDIT_TOKEN", "")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "http://127.0.0.1:18000")
_inflight = set()  # classes with a proposal already in flight (LLM race guard)
_propose_hits = []  # proposal timestamps (rate limit)
MODE = os.environ.get("ORGANISM_MODE", "suggest")
_ask_hits = []  # timestamps for /organism/ask rate limiting
_audit_stats = {"dropped": 0}
_save_lock = threading.Lock()
_proposers = ThreadPoolExecutor(max_workers=2, thread_name_prefix="propose")
_propose_slots = threading.Semaphore(4)  # bounded proposal backlog
STATE_FILE = os.environ.get("STATE_FILE", "/tmp/colony_state.json")

grid = NCAGrid()
pop = Population()
chem = Chemistry()
brain = Brain("colony-leader", llm_ask=muse_client.ask_llm)
peers = [Brain(f"peer-{i}") for i in range(3)]
_lock = threading.RLock()
state = {"blocked": 0, "allowed": 0, "pending_rules": [], "active_rules": [], "last_verdict": None,
         "routes": {}, "save_ok": True}


def _route_key(method, path):
    clean = re.split(r"[\s?]", path)[0]  # payloads after the id are not new APIs
    seg = [("{id}" if (s.isdigit() or (s and not re.fullmatch(r"[a-z0-9_-]+", s))) else s) for s in clean.split("/")]
    return f"{method} {'/'.join(seg)}"


MAX_ROUTES = 200


def _route_stat(method, path, kind, cls=None):
    key = _route_key(method, path)
    with _lock:
        if key not in state["routes"] and len(state["routes"]) >= MAX_ROUTES:
            key = "OTHER /{overflow}"  # bounded cardinality: floods fold into one bucket
        r = state["routes"].setdefault(key, {"allowed": 0, "blocked": 0, "sensed": 0, "attacks": {}, "last": ""})
        r[kind] = r.get(kind, 0) + 1
        if cls:
            r["attacks"][cls] = r["attacks"].get(cls, 0) + 1
        r["last"] = time.strftime("%H:%M:%S")


_inv_cache = {"mtime": None, "apis": []}


def _inventory():
    path = os.environ.get("INVENTORY_FILE", "/adoption/apis.json")
    try:
        mtime = os.path.getmtime(path)
        if _inv_cache["mtime"] != mtime:
            with open(path) as f:
                _inv_cache.update(mtime=mtime, apis=json.load(f).get("apis", []))
    except Exception:
        return []
    return _inv_cache["apis"]

SQLI = [r"or\s+\d+\s*=\s*\d+", r"union\s+(all\s+)?select", r"'\s*or\s*'", r"--", r";\s*drop",
        r"select\s+.+\s+from\s+", r"insert\s+into", r"drop\s+table", r"\b1\s*=\s*1\b",
        r"\b(or|and)\b\s+\S+\s*(=|>|<|>=|<=)\s*\S+", r"\bor\b\s+\S+\s+like\s+",
        r"\b(or|and)\s+(true|1|not\s+0)\b", r"\b(or|and)\s+not\s+\d+", r"'\s*(or|and)\s+'",
        r"\b(or|and)\s+\d+\b", r"\b(or|and)\s+'[^']*'", r"\b(or|and)\s+\"[^\"]*\"",
        r"\b(or|and)\s+[a-z_]\w*\s+(glob|like|is|in)\b", r"\bglob\b", r"/api/user/\(",
        r"/api/user/(id|name|email|secret)\b"]
XSS = [r"<\s*script", r"on\w+\s*=", r"javascript\s*:", r"<\s*iframe", r"<\s*svg", r"<\s*img[^>]+on"]


def verified_identity(headers):
    """Identity the gateway will act on. With IDENTITY_HMAC_KEY set, only an
    X-User-Id carrying a valid X-User-Id-Sig HMAC counts; anything else is no
    identity. Without the key, the header is trusted as set by the ingress."""
    claimed = headers.get("x-user-id", "")
    idkey = os.environ.get("IDENTITY_HMAC_KEY", "")
    if claimed and idkey:
        expect = hmac.new(idkey.encode(), claimed.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, headers.get("x-user-id-sig", "")):
            return ""
    return claimed


def classify(path, query, headers, body=""):
    from urllib.parse import parse_qs, unquote

    raw = path + "?" + query + " " + (body or "")
    q = html.unescape(unquote(unquote(raw))).replace("+", " ").lower()
    q = re.sub(r"/\*.*?\*/", " ", q)
    q = re.sub(r"\s+", " ", q)
    if re.search(r"\b([a-z_]\w*)\s*=\s*\1\b", q):  # column=self tautology, e.g. id=id
        return "sql-injection"
    if any(re.search(p, q) for p in SQLI):
        return "sql-injection"
    if any(re.search(p, q) for p in XSS):
        return "xss"
    m = re.search(r"/api/profile/(\d+)", unquote(path))
    if m:
        params = parse_qs(query)
        # Identity source of truth is the authenticated X-User-Id header set (after
        # stripping any client-supplied value) by your authenticating ingress.
        # ?as_user is honoured ONLY under DEMO_IDENTITY=1 (bundled demo, see TRUST.md).
        claimed = verified_identity(headers)
        if not claimed and os.environ.get("DEMO_IDENTITY") == "1":
            claimed = headers.get("as_user", "") or params.get("as_user", [""])[0]
        # Ownership must be proven: missing or mismatched identity on a profile is the attack class.
        if claimed != m.group(1):
            return "broken-auth"
    return None


_idkey = os.environ.get("IDENTITY_HMAC_KEY", "")
if _idkey and len(_idkey) < 32:
    raise SystemExit("IDENTITY_HMAC_KEY must be >= 32 characters (fail closed)")

_lease_cache = {"value": False, "at": 0.0}


def lease_active():
    now = time.time()
    if now - _lease_cache["at"] < 2.0:
        return _lease_cache["value"]
    try:
        value = bool(requests.get(f"{SUPERVISOR}/lease", timeout=2).json().get("lease_active"))
    except Exception:
        value = False
    _lease_cache.update(value=value, at=now)
    return value


_audit_q = queue.Queue(maxsize=100)


def _audit_worker():
    while True:
        event, detail = _audit_q.get()
        delivered = False
        for attempt in range(3):  # retry with backoff; security events matter
            try:
                r = requests.post(f"{SUPERVISOR}/audit", headers={"X-Audit-Token": AUDIT_TOKEN},
                                  json={"event": event, "detail": detail}, timeout=2)
                delivered = r.status_code == 200
                if delivered:
                    break
            except Exception:
                pass
            time.sleep(1.0 * (attempt + 1))
        if not delivered:
            _audit_stats["dropped"] += 1


threading.Thread(target=_audit_worker, daemon=True).start()


def audit(event, detail=""):
    # Async, bounded: audit must never block or exhaust the proxy path.
    # Scoped token can ONLY append audit entries (cannot kill/revive).
    try:
        _audit_q.put_nowait((event, detail))
    except queue.Full:
        _audit_stats["dropped"] += 1


def decide_with_candidate(full_path, candidate_cls, headers=None):
    """Simulate ONLY the candidate rule: BLOCK iff this request classifies as candidate_cls."""
    path, _, query = full_path.partition("?")
    return "BLOCK" if classify(path, query, headers or {}) == candidate_cls else "ALLOW"


def replay_gate(cls):
    """Candidate-only simulation + REAL upstream replay of normal traffic.
    Attack must be blocked by the candidate alone; normals must (a) not be
    blocked by the candidate and (b) actually return 200 from upstream."""
    _defaults = "/api/users,/api/user/1,/api/profile/1?as_user=1,/api/comment?name=asha"
    normals = [n.strip() for n in (os.environ.get("REPLAY_NORMALS") or _defaults).split(",") if n.strip()]
    if not normals:  # separator-only config must not vacate the gate
        normals = [n.strip() for n in _defaults.split(",") if n.strip()]
    variants = {"sql-injection": ["/api/user/1%20OR%201=1", "/api/user/1%2520OR%25201=1",
                                  "/api/user/1 UNION/**/SELECT name FROM users", "/api/user/0 OR 2>1",
                                  "/api/user/1 OR TRUE", "/api/user/1 OR 1",
                                  "/api/user/1 OR 2", "/api/user/1 OR '1'",
                                  "/api/user/id", "/api/user/(id)", "/api/user/1 OR id GLOB *"],
                "xss": ["/api/comment?name=<script>alert(1)</script>", "/api/comment?name=%3Csvg%20onload%3Dalert(1)%3E",
                        "/api/comment?name=j&#x61;vascript:alert(1)"],
                "broken-auth": ["/api/profile/2?as_user=1", "/api/profile/2"]}[cls]
    # EVERY obfuscation variant of the class must be blocked by the candidate.
    blocked = all(decide_with_candidate(v, cls) == "BLOCK" for v in variants)
    sim_headers = {"x-user-id": os.environ.get("REPLAY_USER_ID", "1")}
    idkey = os.environ.get("IDENTITY_HMAC_KEY", "")
    if idkey:
        sim_headers["x-user-id-sig"] = hmac.new(idkey.encode(), sim_headers["x-user-id"].encode(), hashlib.sha256).hexdigest()
    sim_ok = all(decide_with_candidate(n, cls, sim_headers) != "BLOCK" for n in normals)
    replay_headers = {}
    idkey = os.environ.get("IDENTITY_HMAC_KEY", "")
    replay_user = os.environ.get("REPLAY_USER_ID", "1")
    if idkey:
        replay_headers["X-User-Id"] = replay_user
        replay_headers["X-User-Id-Sig"] = hmac.new(idkey.encode(), replay_user.encode(), hashlib.sha256).hexdigest()
    upstream_ok = True
    for n in normals:
        try:
            if requests.get(UPSTREAM + n, headers=replay_headers, timeout=3).status_code != 200:
                upstream_ok = False
        except Exception:
            upstream_ok = False
    return {"attack_blocked": blocked, "normal_ok": bool(sim_ok and upstream_ok and normals),
            "candidate_simulated": True, "upstream_replayed": bool(normals), "normals_replayed": len(normals)}


def _propose_task(cls):
    try:
        propose_immunity(cls, claimed=True)
    except Exception:
        import traceback

        traceback.print_exc()  # proposal failures must be visible in logs
    finally:
        _propose_slots.release()


def propose_immunity(cls, claimed=False):
    with _lock:
        known = (any(r["class"] == cls for r in state["active_rules"])
                 or any(r["class"] == cls for r in state["pending_rules"])
                 or (cls in _inflight and not claimed))
        now = time.time()
        _propose_hits[:] = [t for t in _propose_hits if now - t < 3600]
        if known or len(_propose_hits) >= 20:
            if claimed:
                _inflight.discard(cls)  # never leak the submit-time claim
            return None  # known/in-flight/rate-limited: never re-ask the teacher
        _inflight.add(cls)
        _propose_hits.append(now)
    try:
        return _propose_inner(cls)
    finally:
        with _lock:
            _inflight.discard(cls)


def _propose_inner(cls):
    summaries = {"sql-injection": "parameterize query; bind input, never interpolate",
                 "broken-auth": "check ownership on server for every record access",
                 "xss": "escape output; render input as text, never HTML"}
    rule = muse_client.propose_rule(cls, summaries[cls])
    verdict_replay = replay_gate(cls)
    passed = verdict_replay["attack_blocked"] and verdict_replay["normal_ok"]
    entry = {"class": cls, "rule": rule["rule"], "source": rule["source"], "degraded": rule["degraded"],
             "replay": verdict_replay, "status": "pending"}
    with _lock:
        if not any(r["class"] == cls for r in state["active_rules"]):
            if not any(r["class"] == cls for r in state["pending_rules"]):
                state["pending_rules"].append(entry)
        state["last_verdict"] = {"verdict": "PASS" if passed else "FAIL", **verdict_replay}
    brain.learn({"sql-injection": "sql injection dumps all users when input is interpolated into query",
                 "broken-auth": "broken authorization lets user read another user record by changing id",
                 "xss": "reflected xss script executes in victim browser when name is rendered"}[cls],
                summaries[cls], source="gateway-heal", confidence=0.6)
    _save()  # pending immunity + learning must survive a restart in suggest mode
    if MODE == "auto" and passed:
        promote(cls)
    return entry


def promote(cls):
    # Promotion is gated: re-run the replay gate at promotion time, never trust a stale PASS.
    gate = replay_gate(cls)
    if not (gate["attack_blocked"] and gate["normal_ok"]):
        audit("PROMOTE-REJECTED", cls)
        return False
    with _lock:
        pend = [r for r in state["pending_rules"] if r["class"] == cls]
        if not pend:
            return False
        state["pending_rules"] = [r for r in state["pending_rules"] if r["class"] != cls]
        entry = pend[0]
        entry["status"] = "active"
        state["active_rules"].append(entry)
    pop.record_outcome(True)
    brain.reward(cls.split("-")[0], True)
    pkt = brain.teach_packet()
    for p in peers:
        p.receive_teaching(pkt)
    chem.emit("heal_success")
    audit("PROMOTE", cls)
    _save()
    return True


def _save():
    with _save_lock:
        _save_inner()


def _save_inner():
    try:
        with _lock:  # consistent snapshot: no mutation during export
            payload = json.dumps({"brain": brain.export_state(), "life": pop.export_state(),
                                  "active": state["active_rules"], "pending": state["pending_rules"],
                                  "blocked": state["blocked"], "allowed": state["allowed"], "routes": state["routes"]})
        d = os.path.dirname(STATE_FILE)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = f"{STATE_FILE}.{threading.get_ident()}.tmp"
        with open(tmp, "w") as f:
            f.write(payload)
        os.replace(tmp, STATE_FILE)
        state["save_ok"] = True
    except Exception as e:  # persistence failure must be visible, never silent
        state["save_ok"] = False
        print(f"STATE SAVE FAILED: {e}", flush=True)


def _load():
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        brain.import_state(data.get("brain"))
        pop.import_state(data.get("life"))
        state["active_rules"], state["pending_rules"] = data.get("active", []), data.get("pending", [])
        state["blocked"], state["allowed"] = data.get("blocked", 0), data.get("allowed", 0)
        state["routes"] = data.get("routes", {})
        pkt = brain.teach_packet()
        for p in peers:
            p.receive_teaching(pkt)
    except Exception:
        pass


_load()
if not os.environ.get("IDENTITY_HMAC_KEY"):
    print("WARNING: IDENTITY_HMAC_KEY unset - header-trust mode (ingress must strip X-User-Id)", flush=True)


def tick():
    while True:
        time.sleep(0.8)
        with _lock:
            if lease_active():
                grid.step()
                pop.tick()
                chem.tick(1.0)
                chem.emit("idle")


threading.Thread(target=tick, daemon=True).start()


@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"] = CORS_ORIGIN
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Broker-Token"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return r


def _authed():
    return bool(TOKEN) and len(TOKEN) >= 16 and hmac.compare_digest(
        request.headers.get("X-Broker-Token", ""), TOKEN)


@app.get("/health")
def health():
    return jsonify(status="ok", lease_active=lease_active(), mode=MODE, audit_dropped=_audit_stats["dropped"], save_ok=state.get("save_ok", True))


@app.get("/organism/state")
def organism_state():
    if not _authed():
        return jsonify(error="forbidden"), 403
    with _lock:
        return jsonify(mode=MODE, lease_active=lease_active(), blocked=state["blocked"], allowed=state["allowed"],
                       active_rules=state["active_rules"], pending_rules=state["pending_rules"],
                       last_verdict=state["last_verdict"], grid=grid.snapshot(), life=pop.snapshot(),
                       brain=brain.snapshot(), peers=[p.snapshot() for p in peers], chemistry=chem.snapshot(),
                       routes=state["routes"], inventory=_inventory())


@app.post("/organism/approve")
def approve():
    if not _authed():
        return jsonify(error="forbidden"), 403
    if not lease_active():
        return jsonify(error="organisms halted by supervisor (lease withdrawn)"), 403
    cls = (request.get_json(silent=True) or {}).get("class", "")
    return jsonify(promoted=promote(cls))


@app.post("/organism/ask")
def ask():
    if not _authed():
        return jsonify(error="forbidden"), 403
    if not lease_active():
        return jsonify(error="organisms halted by supervisor (lease withdrawn)"), 403
    now = time.time()
    _ask_hits[:] = [t for t in _ask_hits if now - t < 60]
    if len(_ask_hits) >= 10:
        return jsonify(error="rate limited: 10 asks/minute"), 429
    _ask_hits.append(now)
    q = ((request.get_json(silent=True) or {}).get("question", "") or "").strip()
    if not q:
        return jsonify(error="question required"), 400
    ans = brain.ask(q)
    if ans.get("known"):
        pkt = brain.teach_packet()
        for p in peers:
            p.receive_teaching(pkt)
        chem.emit("teach")
        _save()
    return jsonify(answer=ans, brain=brain.snapshot())


@app.post("/organism/reset")
def reset():
    if not _authed():
        return jsonify(error="forbidden"), 403
    if not lease_active():
        return jsonify(error="organisms halted by supervisor (lease withdrawn)"), 403
    with _lock:
        grid.reset()
        state.update(blocked=0, allowed=0, pending_rules=[], active_rules=[], last_verdict=None, routes={})
    audit("RESET", "")
    _save()
    return jsonify(ok=True)


ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@app.route("/", defaults={"path": ""}, methods=ALL_METHODS)
@app.route("/<path:path>", methods=ALL_METHODS)
def proxy(path):
    full = "/" + path
    if full.startswith("/organism") or full == "/health":
        return jsonify(error="not found"), 404
    query = request.query_string.decode()
    body_text = request.get_data(as_text=True) if request.method not in ("GET", "HEAD") else ""
    hdrs = {k.lower(): v for k, v in request.headers.items()}
    header_blob = " ".join(v for k, v in hdrs.items() if k.startswith("x-custom") or k == "cookie")
    cls = classify(full, query, hdrs, body_text + " " + header_blob)
    active = lease_active()
    if cls and active:
        # Proposal (incl. teacher call) runs off the request path on a
        # bounded executor; skip entirely when already known/in-flight.
        with _lock:
            needed = not (any(r["class"] == cls for r in state["active_rules"])
                          or any(r["class"] == cls for r in state["pending_rules"])
                          or cls in _inflight)
            if needed:
                _inflight.add(cls)  # claimed at submit time, not in the worker
        if needed and _propose_slots.acquire(blocking=False):
            _proposers.submit(_propose_task, cls)
        elif needed:
            with _lock:
                _inflight.discard(cls)
        is_active = any(r["class"] == cls for r in state["active_rules"])
        if is_active:
            _route_stat(request.method, full, "blocked", cls)
            with _lock:
                state["blocked"] += 1
                grid.wound(1.0)
            chem.emit("attack")
            audit("BLOCK", cls)
            return jsonify(blocked=True, by="server-organisms colony", **{"class": cls},
                           reason="immunity rule active for this attack class"), 403
        _route_stat(request.method, full, "sensed", cls)
        with _lock:
            grid.wound(0.7)
        chem.emit("attack")
        audit("SENSED-PENDING", cls)
    # forward to upstream
    try:
        url = UPSTREAM + full + (("?" + query) if query else "")
        fwd = {k: v for k, v in request.headers.items()
               if k.lower() in ("authorization", "cookie", "content-type") or k.lower().startswith("x-custom")}
        vid = verified_identity(hdrs)
        if vid:
            fwd["X-User-Id"] = vid  # only the verified identity travels upstream
        r = requests.request(request.method, url, timeout=5, data=request.get_data(), headers=fwd, stream=True)
        cap = int(os.environ.get("MAX_RESPONSE_BYTES", str(5 * 1024 * 1024)))
        chunks, total = [], 0
        for chunk in r.iter_content(65536):
            total += len(chunk)
            if total > cap:
                return jsonify(error="upstream response exceeds size cap"), 502
            chunks.append(chunk)
        _route_stat(request.method, full, "allowed")
        with _lock:
            state["allowed"] += 1
        resp = Response(b"".join(chunks), status=r.status_code,
                        content_type=r.headers.get("Content-Type", "application/json"))
        hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailers", "transfer-encoding", "upgrade", "content-length", "content-type"}
        for k, v in r.headers.items():
            if k.lower() not in hop:
                resp.headers[k] = v
        return resp
    except Exception as e:
        return jsonify(error=f"upstream unreachable: {e}"), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18010)
