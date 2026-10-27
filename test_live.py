import os
import time

import requests

os.environ["NO_PROXY"] = "127.0.0.1,localhost"
tok = gtok = ""
for line in open(".env", encoding="utf-8"):
    if line.startswith("BROKER_TOKEN="):
        tok = line.strip().split("=", 1)[1]
    if line.startswith("GATEWAY_TOKEN="):
        gtok = line.strip().split("=", 1)[1]
assert tok and gtok, "BROKER_TOKEN and GATEWAY_TOKEN required in .env"
H = {"X-Broker-Token": tok}
HG = {"X-Broker-Token": gtok}
GW, SUP = "http://127.0.0.1:18010", "http://127.0.0.1:18012"

def wait_pending(cls, tries=25):
    for _ in range(tries):
        time.sleep(1)
        s = requests.get(GW + "/organism/state", headers=HG, timeout=10).json()
        if any(r["class"] == cls for r in s.get("pending_rules", [])):
            return True
    return False



requests.post(SUP + "/revive", headers=H, timeout=10)  # self-recover from any prior killed state
time.sleep(3)
requests.post(GW + "/organism/reset", headers=HG, timeout=10)
assert requests.get(GW + "/organism/state", timeout=10).status_code == 403  # state requires gateway token
r1 = requests.get(GW + "/api/user/1%20OR%201=1", timeout=10)
assert r1.status_code == 200 and len(r1.json()) > 1, r1.text[:200]
print("1 first attack leaks (no immunity yet): OK")
s = {}
for _ in range(20):
    time.sleep(1)
    s = requests.get(GW + "/organism/state", headers=HG, timeout=10).json()
    if s.get("pending_rules"):
        break
assert s["pending_rules"], s
print("2 immunity proposed, pending approval:", s["pending_rules"][-1]["class"])
# pending immunity must survive a gateway restart (propose persists immediately)
import subprocess as _sp
_sp.run(["docker", "compose", "restart", "gateway"], check=True, timeout=120, stdout=_sp.DEVNULL)
for _ in range(30):
    time.sleep(2)
    try:
        s = requests.get(GW + "/organism/state", headers=HG, timeout=5).json()
        if s.get("pending_rules"):
            break
    except Exception:
        pass
assert s["pending_rules"], "pending rule lost across gateway restart"
print("2b pending immunity persists across gateway restart: OK")
assert requests.post(GW + "/organism/approve", headers=HG, json={"class": "sql-injection"}, timeout=30).json()["promoted"]
r2 = requests.get(GW + "/api/user/1%20OR%201=1", timeout=10)
assert r2.status_code == 403 and r2.json()["blocked"], r2.text[:200]
print("3 same attack BLOCKED after promotion: OK")
assert requests.get(GW + "/api/users", timeout=10).status_code == 200
print("4 normal traffic still passes: OK")
# 5 promoted rule blocks encoded/obfuscated variants, not just the exact payload
for variant in ["/api/user/1%2520OR%25201=1", "/api/user/1%20UNION%20ALL%20SELECT%20name%20FROM%20users",
                "/api/user/1 UNION/**/SELECT name FROM users"]:
    rv = requests.get(GW + variant, timeout=10)
    assert rv.status_code == 403 and rv.json().get("blocked"), (variant, rv.text[:200])
print("5 encoded/comment variants of promoted class BLOCKED: OK")
# 6 XSS lifecycle: leak -> propose -> approve -> blocked; normal passes
assert requests.get(GW + "/api/comment", params={"name": "<script>alert(1)</script>"}, timeout=10).status_code == 200
assert wait_pending("xss"), "xss proposal never became pending"
assert requests.post(GW + "/organism/approve", headers=HG, json={"class": "xss"}, timeout=30).json()["promoted"]
assert requests.get(GW + "/api/comment", params={"name": "<svg onload=alert(1)>"}, timeout=10).status_code == 403
assert requests.get(GW + "/api/comment", params={"name": "asha"}, timeout=10).status_code == 200
print("6 xss lifecycle (incl. svg/onload variant): OK")
# 7 broken-auth lifecycle
assert requests.get(GW + "/api/profile/2?as_user=1", timeout=10).status_code == 200
assert wait_pending("broken-auth"), "broken-auth proposal never became pending"
assert requests.post(GW + "/organism/approve", headers=HG, json={"class": "broken-auth"}, timeout=30).json()["promoted"]
assert requests.get(GW + "/api/profile/2?as_user=1", timeout=10).status_code == 403
import hashlib as _hl
import hmac as _hm
_ikey = ""
for _line in open(".env", encoding="utf-8"):
    if _line.startswith("IDENTITY_HMAC_KEY="):
        _ikey = _line.strip().split("=", 1)[1]
_sig = _hm.new(_ikey.encode(), b"1", _hl.sha256).hexdigest()
assert requests.get(GW + "/api/profile/1?as_user=1", headers={"X-User-Id": "1", "X-User-Id-Sig": _sig}, timeout=10).status_code == 200
print("7 broken-auth lifecycle: OK")
# 7d column-reference tautologies blocked too
for taut in ["/api/user/id", "/api/user/(id)", "/api/user/1 OR id GLOB *"]:
    assert requests.get(GW + taut, timeout=10).status_code == 403, taut
print("7d column-reference tautology variants BLOCKED: OK")
# 7b bare tautologies are blocked once sql-injection immunity is active
for taut in ["/api/user/1 OR TRUE", "/api/user/1 OR 1"]:
    assert requests.get(GW + taut, timeout=10).status_code == 403, taut
print("7b bare tautology variants BLOCKED: OK")
for taut in ["/api/user/1 OR 2", "/api/user/1 OR '1'"]:
    assert requests.get(GW + taut, timeout=10).status_code == 403, taut
print("7c bare-literal tautology variants BLOCKED: OK")
# 8 scoped tokens: audit token cannot kill; ask requires operator token
audit_tok = ""
for line in open(".env", encoding="utf-8"):
    if line.startswith("AUDIT_TOKEN="):
        audit_tok = line.strip().split("=", 1)[1]
assert audit_tok, "AUDIT_TOKEN missing in .env"
assert requests.post(SUP + "/kill", headers={"X-Broker-Token": audit_tok}, timeout=10).status_code == 403
assert requests.post(GW + "/organism/ask", json={"question": "what stops sql injection?"}, timeout=10).status_code == 403
assert requests.post(GW + "/organism/ask", headers=HG, json={"question": "what stops sql injection?"}, timeout=30).status_code == 200
print("8 audit token cannot kill; /organism/ask requires operator token: OK")
# 9 persistence: promoted immunity survives a gateway restart
import subprocess
subprocess.run(["docker", "compose", "restart", "gateway"], check=True, timeout=120,
               stdout=subprocess.DEVNULL)
for _ in range(30):
    time.sleep(2)
    try:
        s = requests.get(GW + "/organism/state", headers=HG, timeout=5).json()
        if len(s.get("active_rules", [])) >= 3:
            break
    except Exception:
        pass
classes = {r["class"] for r in s["active_rules"]}
assert {"sql-injection", "xss", "broken-auth"} <= classes, classes
assert requests.get(GW + "/api/user/1%20OR%201=1", timeout=10).status_code == 403
print("9 immunity persists across gateway restart:", sorted(classes))
assert requests.post(SUP + "/kill", headers=H, timeout=10).json()["lease_active"] is False
time.sleep(3)  # gateway lease cache TTL is 2s
assert requests.get(GW + "/health", timeout=10).json()["lease_active"] is False
print("10 kill switch halts colony (supervisor lease): OK")
requests.post(SUP + "/revive", headers=H, timeout=10)
requests.post(GW + "/organism/reset", headers=HG, timeout=10)
# 11 supervisor state (kills/audit) persists across supervisor restart
import subprocess as _sp2
_sp2.run(["docker", "compose", "restart", "supervisor"], check=True, timeout=120, stdout=_sp2.DEVNULL)
for _ in range(30):
    time.sleep(2)
    try:
        ss = requests.get(SUP + "/state", headers=H, timeout=5)
        if ss.status_code == 200:
            break
    except Exception:
        pass
assert ss.json()["kills"] >= 1 and ss.json()["lease_active"] is True, ss.text[:200]
print("11 supervisor kill/audit state persists across restart: OK")
print("LIVE TEST PASS")
