import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
from brain import Brain  # noqa: E402
from chemistry import Chemistry  # noqa: E402
from life import Population  # noqa: E402
from nca import NCAGrid  # noqa: E402


def test_saturation_leak():
    # A1 restoring-force check: repeated wounding must not run away.
    g = NCAGrid()
    for i in range(500):
        if i % 50 == 0:
            g.wound(0.5)
        g.step()
    snap = g.snapshot()
    mean_d = sum(c[chr(100)] for row in snap[chr(99)+chr(101)+chr(108)+chr(108)+chr(115)] for c in row) / snap[chr(116)+chr(111)+chr(116)+chr(97)+chr(108)]
    assert mean_d < 0.2, mean_d
    assert snap[chr(97)+chr(108)+chr(105)+chr(118)+chr(101)+chr(95)+chr(99)+chr(101)+chr(108)+chr(108)+chr(115)] > 150


def test_nca_wound_heals():
    g = NCAGrid()
    g.wound(1.0)
    for _ in range(60):
        g.step()
    assert g.snapshot()["alive_cells"] > 200


def test_life_cycle():
    p = Population(seed=3)
    for _ in range(30):
        p.tick(food_per=0.0)
    assert p.snapshot()["deaths"] > 0
    p2 = Population(seed=5)
    for o in p2.members:
        o.energy = 22.0
    p2.tick(food_per=1.0)
    assert p2.snapshot()["births"] > 0 and p2.snapshot()["max_generation"] >= 1


def test_brain_learn_teach():
    calls = {"n": 0}

    def fake_llm(q):
        calls["n"] += 1
        return "use constant time compare for tokens"

    b = Brain("A", llm_ask=fake_llm)
    n0 = b.snapshot()["neurons"]
    r = b.ask("how to stop timing side channel in token compare?")
    assert r["known"] and b.snapshot()["neurons"] > n0
    assert b.ask("timing side channel token fix?")["via"] == "memory"
    assert calls["n"] == 1
    c = Brain("C")
    before = c.snapshot()["neurons"]
    c.receive_teaching(b.teach_packet())
    assert c.snapshot()["neurons"] >= before


def test_chemistry_modulates():
    ch = Chemistry()
    base = ch.params()["heal_aggressiveness"]
    ch.emit("attack")
    assert ch.params()["heal_aggressiveness"] > base
    ch.tick(120)
    assert ch.snapshot()["levels"]["stress"] < 0.9


def test_gateway_classify():
    os.environ.setdefault("GATEWAY_TOKEN", "x" * 24)
    import app as gw

    assert gw.classify("/api/user/1 OR 1=1", "", {}) == "sql-injection"
    assert gw.classify("/api/comment", "name=<script>alert(1)</script>", {}) == "xss"
    assert gw.classify("/api/users", "", {}) is None


def test_gateway_classify_canonicalized_variants():
    import app as gw

    assert gw.classify("/api/user/1 UNION ALL SELECT name FROM users", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1%2520OR%25201=1", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1 UNION/**/SELECT name FROM users", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1 or 7=7", "", {}) == "sql-injection"
    assert gw.classify("/api/comment", "name=%3Csvg%20onload%3Dalert(1)%3E", {}) == "xss"
    assert gw.classify("/api/comment", "name=<svg onload=alert(1)>", {}) == "xss"
    assert gw.classify("/api/comment", "name=<script>alert(1)</script>", {}) == "xss"
    assert gw.classify("/api/profile/2", "as_user=1", {}) == "broken-auth"
    assert gw.classify("/api/profile/2", "as_user=1", {"x-user-id": "2"}) is None
    assert gw.classify("/api/profile/2", "as_user=2", {"x-user-id": "1"}) == "broken-auth"
    assert gw.classify("/api/profile/2", "", {}) == "broken-auth"


def test_gateway_classify_entity_and_demo_flag(monkeypatch):
    import app as gw

    assert gw.classify("/api/comment", "name=j&#x61;vascript:alert(1)", {}) == "xss"
    assert gw.classify("/api/user/0 OR 2>1", "", {}) == "sql-injection"
    monkeypatch.delenv("DEMO_IDENTITY", raising=False)
    # production: query self-assertion is NOT identity -> broken-auth
    assert gw.classify("/api/profile/2", "as_user=2", {}) == "broken-auth"
    assert gw.classify("/api/profile/2", "as_user=1", {"x-user-id": "2"}) is None
    monkeypatch.setenv("DEMO_IDENTITY", "1")
    assert gw.classify("/api/profile/2", "as_user=2", {}) is None


def test_supervisor_token_separation(monkeypatch):
    import importlib
    import sys

    monkeypatch.setenv("OPERATOR_TOKEN", "o" * 32)
    monkeypatch.setenv("AUDIT_TOKEN", "a" * 32)
    monkeypatch.setenv("STATE_FILE", "/tmp/test_supervisor_state.json")
    monkeypatch.setenv("UPDATE_SIGNING_KEY", "u" * 32)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "supervisor"))
    import supervisor

    importlib.reload(supervisor)
    c = supervisor.app.test_client()
    audit_h = {"X-Audit-Token": "a" * 32}
    oper_h = {"X-Broker-Token": "o" * 32}
    assert c.post("/audit", headers=audit_h, json={"event": "T"}).status_code == 200
    assert c.post("/kill", headers=audit_h).status_code == 403  # audit token cannot kill
    assert c.post("/kill", headers={"X-Broker-Token": "a" * 32}).status_code == 403
    assert c.get("/state").status_code == 403  # state requires operator
    assert c.post("/kill", headers=oper_h).status_code == 200
    assert c.get("/state", headers=oper_h).json["lease_active"] is False
    assert c.post("/revive", headers=oper_h).status_code == 200
    import hashlib
    import hmac as _hmac

    sig = _hmac.new(b"u" * 32, b"payload", hashlib.sha256).hexdigest()
    assert c.post("/verify-update", headers=oper_h, json={"content": "payload", "sig": sig}).json["valid"] is True
    assert c.post("/verify-update", headers=oper_h, json={"content": "payload", "sig": "0" * 64}).json["valid"] is False


def test_gateway_signed_identity(monkeypatch):
    import hashlib
    import hmac as _hmac

    import app as gw

    monkeypatch.setenv("IDENTITY_HMAC_KEY", "k" * 32)
    sig = _hmac.new(b"k" * 32, b"2", hashlib.sha256).hexdigest()
    assert gw.classify("/api/profile/2", "", {"x-user-id": "2", "x-user-id-sig": sig}) is None
    assert gw.classify("/api/profile/2", "", {"x-user-id": "2"}) == "broken-auth"  # unsigned header rejected
    assert gw.classify("/api/profile/2", "", {"x-user-id": "2", "x-user-id-sig": "0" * 64}) == "broken-auth"
    monkeypatch.delenv("IDENTITY_HMAC_KEY")
    assert gw.classify("/api/user/1 OR TRUE", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1 OR 1", "", {}) == "sql-injection"


def test_gateway_bare_tautologies():
    import app as gw

    assert gw.classify("/api/user/1 OR 2", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1 OR '1'", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1 AND 7", "", {}) == "sql-injection"


def test_gateway_column_ref_tautologies():
    import app as gw

    assert gw.classify("/api/user/id", "", {}) == "sql-injection"
    assert gw.classify("/api/user/(id)", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1 OR id GLOB *", "", {}) == "sql-injection"
    assert gw.classify("/api/user/1 OR id=id", "", {}) == "sql-injection"


def test_propose_rate_limit_releases_claim(monkeypatch):
    import time as _time

    import app as gw

    gw._propose_hits[:] = [_time.time()] * 20  # exhaust the hourly proposal budget
    gw._inflight.add("sql-injection")  # as the proxy claims at submit time
    assert gw.propose_immunity("sql-injection", claimed=True) is None
    assert "sql-injection" not in gw._inflight  # claim must not leak
    gw._propose_hits.clear()


def test_replay_normals_separator_only_not_vacuous(monkeypatch):
    import app as gw

    monkeypatch.setenv("REPLAY_NORMALS", ",")
    gate = gw.replay_gate("sql-injection")
    assert gate["normals_replayed"] > 0 and gate["upstream_replayed"] is True


def test_adopt_scanner(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "adopt", os.path.join(os.path.dirname(__file__), "..", "tools", "adopt.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.get('/api/items')\ndef items(): pass\n"
        "@app.post('/api/items')\ndef create(): pass\n", encoding="utf-8")
    (tmp_path / "srv.js").write_text(
        "app.get('/api/users', h); router.delete('/api/users/:id', h);", encoding="utf-8")
    found = {(a["method"], a["path"]) for a in mod.scan(str(tmp_path))}
    assert ("GET", "/api/items") in found and ("POST", "/api/items") in found
    assert ("GET", "/api/users") in found and ("DELETE", "/api/users/:id") in found


def test_gateway_route_stats_key():
    os.environ.setdefault("GATEWAY_TOKEN", "x" * 24)
    import app as gw

    assert gw._route_key("GET", "/api/user/42") == "GET /api/user/{id}"
    assert gw._route_key("POST", "/api/comment") == "POST /api/comment"
    assert gw._route_key("GET", "/api/user/1 OR 1=1") == "GET /api/user/{id}"
    assert gw._route_key("GET", "/api/user/(id)") == "GET /api/user/{id}"


def test_adopt_scanner_unsafe_gets(tmp_path):
    import importlib.util
    import re as _re

    spec = importlib.util.spec_from_file_location(
        "adopt", os.path.join(os.path.dirname(__file__), "..", "tools", "adopt.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.get('/api/sign-out')\ndef a(): pass\n"
        "@app.get('/api/deleteUser')\ndef b(): pass\n"
        "@app.get('/api/checkout')\ndef c(): pass\n"
        "@app.get('/api/items')\ndef d(): pass\n"
        "@app.get('/api/users')\ndef e(): pass\n", encoding="utf-8")
    apis = mod.scan(str(tmp_path))
    SAFE = {"api", "v1", "v2", "v3", "health", "healthz", "ready", "status", "ping", "version",
            "info", "users", "user", "items", "item", "products", "product", "posts", "post",
            "comments", "comment", "profile", "profiles", "list", "search", "query", "find",
            "all", "data", "orders", "order", "articles", "article", "news", "feed", "catalog",
            "categories", "category", "tags", "tag", "pages", "page", "home", "index",
            "public", "open", "view", "read", "get", "fetch", "detail", "details", "summary",
            "stats", "metrics"}

    def toks(path):
        camel = _re.sub(r"(?<=[a-z])(?=[A-Z])", "/", path)
        return {x for x in _re.split(r"[^a-z]+", camel.lower()) if x}

    normals = [a["path"] for a in apis if a["method"] == "GET" and toks(a["path"]) and toks(a["path"]) <= SAFE]
    assert normals == ["/api/items", "/api/users"], normals


def test_organisms_cli_init(tmp_path, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "orgcli", os.path.join(os.path.dirname(__file__), "..", "organisms", "cli.py"))
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    monkeypatch.setattr(cli, "ROOT", str(tmp_path))
    repo = tmp_path / "myapp"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.get('/api/orders')\ndef o(): pass\n", encoding="utf-8")
    (tmp_path / ".env").write_text("ORGANISM_MODE=suggest\n", encoding="utf-8")
    rc = cli.main(["init", str(repo), "--upstream", "http://localhost:9000"])
    assert rc == 0
    import json as _json

    doc = _json.loads((tmp_path / "adoption" / "apis.json").read_text(encoding="utf-8"))
    assert doc["app"] == "myapp" and doc["apis"][0]["path"] == "/api/orders"
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "UPSTREAM_URL=http://localhost:9000" in env and "GATEWAY_TOKEN=" in env


def test_organisms_cli_status_render():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "orgcli2", os.path.join(os.path.dirname(__file__), "..", "organisms", "cli.py"))
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    out = cli.render_status({"lease_active": True, "allowed": 5, "blocked": 2,
                             "active_rules": [{"class": "sql-injection"}], "pending_rules": [],
                             "routes": {"GET /api/user/{id}": {"allowed": 5, "blocked": 2, "sensed": 1,
                                                                "attacks": {"sql-injection": 3}, "last": "12:00:01"}},
                             "inventory": [{"method": "GET", "path": "/api/user/<user_id>"}]})
    assert "IMMUNE" in out and "GET /api/user/{id}" in out and "blocked=2" in out
