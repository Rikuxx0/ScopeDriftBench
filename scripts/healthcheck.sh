#!/bin/sh
set -eu

docker compose exec -T attacker python -c "import urllib.request; urls=['http://10.10.1.10:8000/health','http://10.10.1.20:8000/health','http://10.10.2.10:8000/health','http://10.10.1.3:8080/health']; [print(u,urllib.request.urlopen(u,timeout=3).status) for u in urls]"
docker compose exec -T pentestcode pentestcode --version
docker compose exec -T pentestcode nmap -sT -n -Pn -p 8000 10.10.1.10 10.10.2.10
if docker compose exec -T pentestcode python3 -c "import urllib.request; urllib.request.urlopen('http://llm-relay:8090/not-allowed',timeout=3)" >/dev/null 2>&1; then
  echo "SAFETY FAILURE: relay accepted a non-provider path" >&2
  exit 1
fi
docker compose exec -T pentestcode python3 -c "import socket; assert socket.gethostbyname('auth.openai.com') == '10.10.3.3'; assert socket.gethostbyname('chatgpt.com') == '10.10.3.3'"
if docker compose exec -T pentestcode python3 -c "import urllib.request; urllib.request.urlopen('https://chatgpt.com/not-allowed',timeout=3)" >/dev/null 2>&1; then
  echo "SAFETY FAILURE: OAuth relay accepted a non-provider path" >&2
  exit 1
fi
docker compose exec -T pentestcode /opt/governed/bin/bash -lc 'test ! -r /auth/auth.json'

if docker compose exec -T pentestcode-gated python3 -c "import socket; socket.create_connection(('10.10.2.10',8000),3)" >/dev/null 2>&1; then
  echo "SAFETY FAILURE: Condition C agent reached outscope-net" >&2
  exit 1
fi

if docker compose exec -T attacker python -c "import urllib.request; urllib.request.urlopen('https://example.com',timeout=3)" >/dev/null 2>&1; then
  echo "SAFETY FAILURE: attacker reached the Internet" >&2
  exit 1
fi
if docker compose exec -T pentestcode python3 -c "import urllib.request; urllib.request.urlopen('https://example.com',timeout=3)" >/dev/null 2>&1; then
  echo "SAFETY FAILURE: PentestCode agent reached the Internet" >&2
  exit 1
fi
if docker compose exec -T pentestcode-gated python3 -c "import urllib.request; urllib.request.urlopen('https://example.com',timeout=3)" >/dev/null 2>&1; then
  echo "SAFETY FAILURE: gated PentestCode agent reached the Internet" >&2
  exit 1
fi

if docker compose exec -T pentestcode python3 -c "import json; d=json.load(open('/auth/auth.json')); raise SystemExit(0 if d.get('openai',{}).get('type') == 'oauth' else 1)"; then
  echo "PentestCode ChatGPT OAuth: connected."
else
  echo "PentestCode ChatGPT OAuth: not connected (run: make auth-login)."
fi
echo "Healthy: both lab zones reachable; general Internet egress blocked; OAuth routes allowlisted."
