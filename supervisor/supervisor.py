"""Immune supervisor: SEPARATE process the organism cannot modify.
Owns lease/kill switch, audit log, budget, signed-update verification.
Organism asks; supervisor decides. Lease withdrawn = organisms halt.
"""
import hashlib
import hmac
import json
import os
import threading
import time

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
# Two credentials, least privilege:
#  OPERATOR_TOKEN (env BROKER_TOKEN for the operator/dashboard) — kill/revive/verify only.
#  AUDIT_TOKEN — append-only audit from the gateway; CANNOT kill or revive.
TOKEN = os.environ.get("OPERATOR_TOKEN", "") or os.environ.get("BROKER_TOKEN", "")
AUDIT_TOKEN = os.environ.get("AUDIT_TOKEN", "")
STATE_FILE = os.environ.get("STATE_FILE", "/shared/supervisor_state.json")
_lock = threading.RLock()
state = {"lease_active": True, "epoch": 0, "audit": [], "kills": 0}


_save_lock = threading.Lock()


def _save():
    with _save_lock:
        _save_inner()


def _save_inner():
    try:
        d = os.path.dirname(STATE_FILE)
        if d:
            os.makedirs(d, exist_ok=True)
        with _lock:
            payload = json.dumps(state)
        tmp = f"{STATE_FILE}.{threading.get_ident()}.tmp"
        with open(tmp, "w") as f:
            f.write(payload)
        os.replace(tmp, STATE_FILE)
        state["save_ok"] = True
    except Exception as e:  # persistence failure must be visible, never silent
        state["save_ok"] = False
        print(f"SUPERVISOR STATE SAVE FAILED: {e}", flush=True)


def _load():
    try:
        with open(STATE_FILE) as f:
            state.update(json.load(f))
    except Exception:
        pass


def audit(event, detail=""):
    with _lock:
        state["audit"].append({"ts": time.strftime("%H:%M:%S"), "event": event, "detail": str(detail)[:200]})
        del state["audit"][:-100]
        _save()


def authed():
    """Operator credential: required for kill/revive/verify-update."""
    return bool(TOKEN) and len(TOKEN) >= 16 and hmac.compare_digest(request.headers.get("X-Broker-Token", ""), TOKEN)


def audit_authed():
    """Scoped audit credential (or the operator credential) for /audit only."""
    tok = request.headers.get("X-Audit-Token", "")
    ok_audit = bool(AUDIT_TOKEN) and len(AUDIT_TOKEN) >= 16 and hmac.compare_digest(tok, AUDIT_TOKEN)
    return ok_audit or authed()


@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"] = os.environ.get("CORS_ORIGIN", "http://127.0.0.1:18000")
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Broker-Token, X-Audit-Token"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return r


@app.get("/health")
def health():
    return jsonify(status="ok", lease_active=state["lease_active"], epoch=state["epoch"], save_ok=state.get("save_ok", True))


@app.get("/lease")
def lease():
    return jsonify(lease_active=state["lease_active"], epoch=state["epoch"])


@app.post("/kill")
def kill():
    if not authed():
        return jsonify(error="forbidden"), 403
    with _lock:
        state["lease_active"] = False
        state["epoch"] += 1
        state["kills"] += 1
    audit("KILL", f"epoch {state['epoch']}")
    return jsonify(lease_active=False, epoch=state["epoch"])


@app.post("/revive")
def revive():
    if not authed():
        return jsonify(error="forbidden"), 403
    with _lock:
        state["lease_active"] = True
        state["epoch"] += 1
    audit("REVIVE", f"epoch {state['epoch']}")
    return jsonify(lease_active=True, epoch=state["epoch"])


@app.post("/audit")
def post_audit():
    if not audit_authed():
        return jsonify(error="forbidden"), 403
    body = request.get_json(silent=True) or {}
    audit(body.get("event", "note"), body.get("detail", ""))
    return jsonify(ok=True)


@app.get("/state")
def get_state():
    if not authed():
        return jsonify(error="forbidden"), 403
    with _lock:
        return jsonify(lease_active=state["lease_active"], epoch=state["epoch"], kills=state["kills"], audit=state["audit"][-20:])


@app.post("/verify-update")
def verify_update():
    if not authed():
        return jsonify(error="forbidden"), 403
    signing_key = os.environ.get("UPDATE_SIGNING_KEY", "")
    if not signing_key or len(signing_key) < 32:
        return jsonify(error="update signing not configured (UPDATE_SIGNING_KEY >= 32 chars required)"), 503
    body = request.get_json(silent=True) or {}
    payload = (body.get("content", "")).encode()
    expect = hmac.new(signing_key.encode(), payload, hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(expect, body.get("sig", ""))
    audit("UPDATE-VERIFY", "PASS" if ok else "REJECTED-BAD-SIGNATURE")
    return jsonify(valid=ok)


_load()
if __name__ == "__main__":
    audit("SUPERVISOR-START", "lease active")
    app.run(host="0.0.0.0", port=18012)
