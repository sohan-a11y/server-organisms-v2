# Product review: what MiroFish (82k stars) teaches Server Organisms

Method: `/search-first` on MiroFish (open-source multi-agent swarm product,
Vue 3 + Vite + D3 frontend, Python backend, Docker Compose). Compared
against this repo, file by file. Each gap below is an ISSUE with a fix state.

## The one-line lesson

MiroFish's README says: **"You only need to: upload seed materials"** and
**"MiroFish will return: a report + an interactive world."** One input, two
outputs, zero-setup live demo, screenshots above the fold. Our README said
"clone, install, open dashboard" — three inputs, vague outputs, no pictures.
Every fix below serves that reframing.

## Issue list

| # | Issue (MiroFish comparison) | Fix |
|---|------------------------------|-----|
| 1 | No zero-setup demo. MiroFish has a live demo URL + prepared scenario. Ours required reading install docs + tokens. | `organisms demo`: one command starts the stack, runs attack→approve→blocked, prints the private link. |
| 2 | README was a manual, not a product page. MiroFish: badges, screenshots, demo video, vision, FAQ. | README rewritten: badges, screenshots, "you only need" framing, quickstart, architecture, FAQ. |
| 3 | No screenshots anywhere. MiroFish shows 6 above the fold. | `static/` holds real captures from the running product, embedded in README. |
| 4 | Dashboard's next action was ambiguous (critic rounds 1–4). MiroFish funnels to ONE primary action per screen. | Primary action highlighted per phase; "Attack again" hidden until immunity exists; pending rule in plain words. |
| 5 | Frontend is one hand-rolled HTML file; MiroFish ships Vue 3 + router + store + D3. | Accepted gap (documented): single-file dashboard keeps zero-build deploy (`python -m http.server`, no npm). Revisit with a Vue+D3 frontend only if adoption demands it. |
| 6 | Backend is loose scripts; MiroFish has `backend/app` package + `pyproject` + lockfile. | Accepted gap (documented): pinned requirements + Docker builds give reproducibility today; packaging is the next step. |
| 7 | No community surface (MiroFish: Discord/X/badges). | Badges added; Discord/X left to the maintainer (needs accounts). |
| 8 | No demo video (MiroFish embeds two). | Placeholder section in README; recording is a human step (3-min hackathon video doubles as this). |

## What we deliberately did NOT copy

- MiroFish is AGPL-3.0; we copied zero code, only product patterns (no license impact).
- No fake "live demo" link: our demo requires a local stack (it proxies real
  traffic), so `organisms demo` is honest automation, not a hosted pretence.
- No Node build chain: the dashboard stays dependency-free (vendored Three.js)
  so `docker compose up` is still the whole install.
