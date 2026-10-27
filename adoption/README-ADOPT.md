# Your APIs are now living — adoption kit

Discovered **5 API routes** in `server-organisms\demo-api` (see apis.json).

## Put the colony in front (no code changes in your app)

1. Start your app so it listens on http://demo-api:18011 (host) or its container URL.
2. In the server-organisms repo, add to `.env` (values from replay.env):
   `UPSTREAM_URL=...`, `REPLAY_NORMALS=...`, `REPLAY_USER_ID=1`
3. `docker compose up --build -d`
4. Route your traffic to the gateway: http://127.0.0.1:18010/<your-path>
5. Open the dashboard: every discovered API appears as a living node in 3D,
   with live requests / blocks / attacks / immunity per route.

The colony senses exploits on each route, proposes immunity, proves it by
replaying YOUR normal routes, and only then blocks. Supervisor kill switch
stays outside the organisms. See ../TRUST.md before production use.
