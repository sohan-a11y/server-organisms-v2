#!/usr/bin/env bash
# Server Organisms - one-command install (Linux/macOS). Data stays on your server.
set -euo pipefail
command -v docker >/dev/null || { echo "Docker required: https://docs.docker.com/get-docker/"; exit 1; }
[ -f .env ] || cp .env.example .env
if ! grep -q "^BROKER_TOKEN=." .env; then
  TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(24))" 2>/dev/null || openssl rand -hex 24)
  sed -i.bak "s/^BROKER_TOKEN=.*/BROKER_TOKEN=$TOKEN/" .env || printf "\nBROKER_TOKEN=%s\n" "$TOKEN" >> .env
  echo "Generated private BROKER_TOKEN in .env (keep secret)"
fi
if ! grep -q "^AUDIT_TOKEN=." .env; then
  ATOKEN=$(python3 -c "import secrets; print(secrets.token_hex(24))" 2>/dev/null || openssl rand -hex 24)
  sed -i.bak "s/^AUDIT_TOKEN=.*/AUDIT_TOKEN=$ATOKEN/" .env || printf "\nAUDIT_TOKEN=%s\n" "$ATOKEN" >> .env
  echo "Generated private AUDIT_TOKEN in .env (gateway audit-only, keep secret)"
fi
if ! grep -q "^GATEWAY_TOKEN=." .env; then
  GTOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
  sed -i.bak "s/^GATEWAY_TOKEN=.*/GATEWAY_TOKEN=$GTOKEN/" .env || printf "\nGATEWAY_TOKEN=%s\n" "$GTOKEN" >> .env
  echo "Generated private GATEWAY_TOKEN in .env (keep secret)"
fi
rm -f .env.bak
if ! grep -q "^IDENTITY_HMAC_KEY=." .env; then
  IKEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
  sed -i.bak "s/^IDENTITY_HMAC_KEY=.*/IDENTITY_HMAC_KEY=$IKEY/" .env || printf "\nIDENTITY_HMAC_KEY=%s\n" "$IKEY" >> .env
  echo "Generated private IDENTITY_HMAC_KEY in .env (keep secret)"
fi
rm -f .env.bak
chmod 600 .env 2>/dev/null || true
docker compose up --build -d
TOK=$(grep "^BROKER_TOKEN=" .env | head -1 | cut -d= -f2-)
GTOK=$(grep "^GATEWAY_TOKEN=" .env | head -1 | cut -d= -f2-)
echo ""
echo "OPEN YOUR DASHBOARD (private link - do not share): http://127.0.0.1:18000/#token=$TOK&gwtoken=$GTOK"
echo "Gateway (put your API behind it): http://127.0.0.1:18010"
