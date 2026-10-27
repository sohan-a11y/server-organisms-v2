# Server Organisms — Living Immune Layer for Your API

**Not the biggest immune system. The first one that's alive — and yours.**

Organisms live between the internet and your API on *your* server. They sense exploits, wound, propose immunity, prove it on replay, promote it, teach their children, and die when you withdraw their lease. No GPU. No data leaving your host. No code changes in your app — put the gateway in front of it.

Darktrace watches enterprises like an immune system. Cloudflare shields at global scale. This is the living defence for the rest of us: indie devs and small teams whose APIs get nothing from enterprise contracts today.

## Make YOUR APIs living (the actual product)

```bash
python tools/adopt.py <path-to-your-repo>   # Flask / FastAPI / Express
```

The scanner discovers every API route in your code (no changes to your app),
writes `adoption/` (route inventory, replay config, steps), and the gateway
colony then sits in front of your app. Open the dashboard: **every one of
your APIs is a living node in 3D** — traffic, attacks sensed, blocks and
immunity per route, live. Set `UPSTREAM_URL` to your app and route traffic
through the gateway.

## Install (bundled demo, one command)

```powershell
.\install.ps1   # Linux/macOS: ./install.sh
```

It generates three private tokens (operator / gateway / audit-only), builds, and prints your dashboard link. Open it.

## Demo (90 seconds)
1. **Attack through gateway** — SQL injection leaks through the demo API; tissue wounds red; immunity proposed.
2. **Approve immunity** — canary replay already proved: attack blocked, normal traffic passes. Rule promoted.
3. **Attack again** — BLOCKED at the gate (403, colony signature).
4. **Ask the organisms** in English — they answer from memory or learn once from Muse Spark and teach peers.
5. **Kill switch** — the *supervisor* (separate process the colony cannot modify) withdraws the lease; enforcement halts.

## How it works
`Internet -> Gateway Colony (:18010) -> Your API -> DB`. Supervisor (:18012) owns lease/audit/kill. Leaky NCA tissue (leak 0.3, from the NCA-Pet-0 A1 finding) expresses damage; endocrine chemistry modulates behaviour; population metabolizes, reproduces with mutated genomes, is selected by measured fitness; brain grows neurons/instincts, persists across restarts on the shared volume.

Modes: `ORGANISM_MODE=suggest` (human approves promotion, default) or `auto` (PASS promotes itself).

## Protect your own API
Set your app behind the gateway: route traffic to `http://127.0.0.1:18010/<your-path>` with `UPSTREAM_URL` pointing at your service (see `docker-compose.yml` gateway environment). Attack classes today: SQL injection, broken authorization, XSS. Replay gate is deterministic — LLM opinion never promotes a rule.

## Built during the hackathon vs prior art
Novel: living enforcement with birth/heredity/mortality, NCA tissue substrate, local verifier-gated learning, separate-process immune supervisor. Prior art cited honestly: Darktrace (immune branding/detection), Cloudflare WAF ML (centralized learning rules), Salt (API behaviour baselining), GenProg/DARPA CGC (automated repair), Mordvintsev NCA + CAX. Reused OSS licences preserved (Flask/requests MIT/BSD).

## Tests
`python -m pytest tests/ -q` (9 tests) and the live Docker loop in `test_live.py` (11 steps: leak->propose->approve->blocked for SQLi/XSS/broken-auth, encoded variants, token separation, persistence across gateway and supervisor restarts, kill switch).

## Safety
Demo upstream (`demo-api/`) is intentionally vulnerable — never deploy it. The gateway fails open to upstream when the lease is withdrawn (availability over enforcement), and says so in TRUST.md.

## Identity & production notes
Broken-auth detection trusts `X-User-Id` only as set by your authenticating ingress (strip client-supplied values first). The bundled demo runs with `DEMO_IDENTITY=1` so `?as_user=` works as demo identity; never enable that in production. See TRUST.md.

## Production replay configuration
The replay gate replays *your* normal traffic before any promotion. Set `REPLAY_NORMALS` (comma-separated safe GET paths, defaulting to the demo routes) and `REPLAY_USER_ID` for your API; when `IDENTITY_HMAC_KEY` is set the gateway signs that identity on replays. Point the gateway at your app with `UPSTREAM_URL` (compose `.env` or Helm `upstreamUrl`).
