#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${RESEARCH_PYTHON:-}" ]; then
    python_bin=$RESEARCH_PYTHON
elif [ -x "$root/.venv/bin/python" ]; then
    python_bin="$root/.venv/bin/python"
else
    python_bin=python3
fi
cd "$root"
exec "$python_bin" -m analysis.collect_runs "$@"
