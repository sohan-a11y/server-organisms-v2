"""Meta Model API (Muse Spark) client: teacher + patch proposer. Graceful degraded mode."""
import os

import requests

API_KEY = os.environ.get("META_API_KEY", "")
MODEL = os.environ.get("META_MODEL", "muse-spark-1.1")
BASE = os.environ.get("META_API_BASE", "https://api.meta.ai/v1")
LAST_DEGRADED = [False]
FIXED = 'rows = con.execute("SELECT id,name,email FROM users WHERE id=?", (user_id,)).fetchall()  # parameterized'
VULN = 'q = f"SELECT id,name,email FROM users WHERE id = {user_id}"  # string-formatted SQL'


def _call(system, user):
    if not API_KEY:
        LAST_DEGRADED[0] = True
        return None
    try:
        r = requests.post(f"{BASE}/chat/completions",
                          headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
                          json={"model": MODEL, "messages": [{"role": "system", "content": system},
                                                             {"role": "user", "content": user}]}, timeout=30)
        if r.ok:
            return r.json()["choices"][0]["message"]["content"]
        LAST_DEGRADED[0] = True
    except Exception:
        LAST_DEGRADED[0] = True
    return None


def ask_llm(question):
    return _call("You are a security teacher for a server organism. Answer in one concise sentence.", question)


def propose_rule(cls, summary):
    out = _call("You write one defensive rule in plain English for an API gateway. One sentence only.",
                f"Class: {cls}. Fix: {summary}")
    return {"class": cls, "rule": out or summary, "source": f"Meta Model API ({MODEL})" if out else "fallback template",
            "degraded": not bool(out)}
