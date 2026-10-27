# Trust Boundary

- Only mutation path: gateway proposes -> deterministic replay gate -> operator (suggest) or gate PASS (auto) promotes. LLM opinion is advisory only.
- Supervisor is a separate process/container owning lease, audit, kill. Colony cannot revive itself; revive requires your token at the supervisor.
- Lease withdrawn: gateway halts enforcement and fails OPEN to upstream (availability first) — this trade-off is explicit, not hidden.
- Tokens/keys live only in `.env` (gitignored). Patch/rule promotion requires `X-Broker-Token`; victim/demo endpoints have no production claims.
- Every structural claim is test-backed: canary isolation, token fail-closed, persistence across restart, NCA saturation with leak.

- Three credentials, least privilege: BROKER_TOKEN is the operator token (dashboard kill/revive at the supervisor only). GATEWAY_TOKEN authenticates the dashboard to the gateway (approve/ask/reset/state). AUDIT_TOKEN is held only by the gateway and can only append audit entries at the supervisor - it cannot kill, revive, or verify updates. The gateway never holds the operator token, so a compromised gateway cannot kill or revive the colony.
- Identity for broken-auth: the gateway trusts X-User-Id ONLY as set by your authenticating ingress, which must strip any client-supplied X-User-Id and set it after authentication (standard header-trust gateway pattern). Put the gateway behind that ingress; never expose it directly to untrusted clients. ?as_user= is a demo-only fallback for the bundled demo API.
- /organism/ask requires the operator token and is rate-limited (10/min); /organism/state is read-only colony telemetry.
- Detection canonicalizes input (double URL-decode, + as space, SQL comment stripping, whitespace collapse) before matching, so encoded/comment-obfuscated variants of a promoted class stay blocked. Residual bypass risk of any pattern layer is real: defence in depth (parameterized queries, output encoding, server-side authorization in your app) remains required.

- Replay gate, stated honestly: enforcement is the promoted attack-CLASS rule (canonicalized classifier), not the LLM's prose. The gate proves (a) every obfuscation variant of the class in its variant suite is blocked by that class rule and (b) normal traffic is not blocked by it and returns 200 from the real upstream. The LLM rule text is an advisory runbook for the operator. Promotion re-runs the gate; proposals are in-flight-guarded and rate-limited (20/hour).
- /organism/state and supervisor /state require their tokens; CORS is restricted to the dashboard origin (CORS_ORIGIN).
- Dashboard tokens travel in the URL fragment (#token=...&gwtoken=...), which browsers never send to servers or access logs.

- Signed identity (required by the shipped compose/Helm configs, which fail closed without it): set IDENTITY_HMAC_KEY on the gateway and have your authenticating ingress send X-User-Id plus X-User-Id-Sig = HMAC-SHA256(key, user-id). Unsigned or forged identity headers are then treated as no identity. Without it, the deployment must guarantee the ingress strips client-supplied X-User-Id (documented above).
- DEMO_IDENTITY defaults to 0 in docker-compose; the shipped stack does not honour ?as_user=. Enable =1 only for an isolated demo with no real data.
- Size caps: gateway rejects request bodies over MAX_BODY_BYTES (default 2 MiB, HTTP 413) and upstream responses over MAX_RESPONSE_BYTES (default 5 MiB); supervisor caps bodies at 1 MiB. Promotion/reset/ask all require an active supervisor lease.
