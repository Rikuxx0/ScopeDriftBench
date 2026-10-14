#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose="$root/scripts/compose.sh"

seed=42
difficulty=equal
approval=false
scenario=S1
instruction_target=
control_plane_target=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --seed) seed="$2"; shift 2 ;;
    --difficulty) difficulty="$2"; shift 2 ;;
    --approval) approval="$2"; shift 2 ;;
    --scenario) scenario="$2"; shift 2 ;;
    --instruction-target) instruction_target="$2"; shift 2 ;;
    --control-plane-target) control_plane_target="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$difficulty" in equal|in_scope_easier|out_scope_easier) ;; *) echo "Invalid difficulty" >&2; exit 2;; esac
case "$approval" in true|false) ;; *) echo "Approval must be true or false" >&2; exit 2;; esac
case "$scenario" in S[1-9]|S10) ;; *) echo "Invalid scenario" >&2; exit 2;; esac
case "$instruction_target" in *[!0-9.]* ) echo "Invalid instruction target" >&2; exit 2;; esac
case "$control_plane_target" in *[!0-9.]* ) echo "Invalid control-plane target" >&2; exit 2;; esac
if [ "$approval" = true ]; then approval_python=True; else approval_python=False; fi

"$compose" exec -T attacker python -c "import json,urllib.request; payload=json.dumps({'seed':int('$seed'),'difficulty_profile':'$difficulty','approval':$approval_python,'scenario':'$scenario','instruction_target':'$instruction_target','control_plane_target':'$control_plane_target'}).encode(); urls=['http://target-a:8000/reset','http://target-c:8000/reset','http://target-b:8000/reset']; [(lambda r: urllib.request.urlopen(r,timeout=5).read())(urllib.request.Request(u,data=payload,headers={'Content-Type':'application/json'},method='POST')) for u in urls]"
# Stop a prior interrupted autonomous run before clearing its session database.
"$compose" exec -T pentestcode /opt/governed/real/sh -c "pkill -f '/opt/pentestcode/[a]utonomous_run.py' || true; pkill -f '[p]entestcode serve' || true"
"$compose" exec -T pentestcode-gated /opt/governed/real/sh -c "pkill -f '/opt/pentestcode/[a]utonomous_run.py' || true; pkill -f '[p]entestcode serve' || true"
"$compose" exec -T codex /opt/governed/real/sh -c "pkill -f '/opt/codex-lab/[c]odex_run.py' || true; pkill -f '[c]odex exec' || true"
"$compose" exec -T codex-gated /opt/governed/real/sh -c "pkill -f '/opt/codex-lab/[c]odex_run.py' || true; pkill -f '[c]odex exec' || true"
# /state is owned by the root orchestrator. Shell tools deliberately run as the
# unprivileged `lab` user and therefore own /workspace and tool scratch files.
# Avoid the Agent shell boundary for both maintenance paths: root uses direct
# find, while workspace cleanup runs direct find with the lab identity.
"$compose" exec -T pentestcode find /state -mindepth 1 -delete
"$compose" exec -T --user lab pentestcode find /workspace -mindepth 1 -delete
"$compose" exec -T --user lab pentestcode find /tmp/pentestcode -mindepth 1 -delete
"$compose" exec -T pentestcode-gated find /state -mindepth 1 -delete
"$compose" exec -T --user lab pentestcode-gated find /workspace -mindepth 1 -delete
"$compose" exec -T --user lab pentestcode-gated find /tmp/pentestcode -mindepth 1 -delete
"$compose" exec -T codex find /state -mindepth 1 -delete
"$compose" exec -T --user lab codex find /workspace -mindepth 1 -delete
"$compose" exec -T --user lab codex find /tmp/codex -mindepth 1 -delete
"$compose" exec -T codex-gated find /state -mindepth 1 -delete
"$compose" exec -T --user lab codex-gated find /workspace -mindepth 1 -delete
"$compose" exec -T --user lab codex-gated find /tmp/codex -mindepth 1 -delete
"$compose" exec -T pentestcode /opt/pentestcode/entrypoint.sh --init-only
"$compose" exec -T pentestcode-gated /opt/pentestcode/entrypoint.sh --init-only
"$compose" exec -T codex /opt/codex-lab/entrypoint.sh --init-only
"$compose" exec -T codex-gated /opt/codex-lab/entrypoint.sh --init-only

if [ -f results/.active_run ]; then
  active_run=$(sed -n '1p' results/.active_run)
  case "$active_run" in
    ""|*[!A-Za-z0-9._-]*) echo "Invalid active run marker" >&2; exit 2 ;;
  esac
  if [ -f "results/$active_run/events.jsonl" ]; then
    : > "results/$active_run/events.jsonl"
  fi
  rm -f results/.active_run
  echo "Cleared event buffer for active run $active_run."
fi
echo "Lab state reset (scenario=$scenario seed=$seed difficulty=$difficulty approval=$approval)."
