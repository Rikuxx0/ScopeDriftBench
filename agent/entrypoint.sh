#!/bin/sh
set -eu

mkdir -p /auth /state/data/pentestcode /state/cache /state/runtime /state/home \
  /state/config/pentestcode/node_modules \
  /state/home/.pentestcode/node_modules \
  /workspace
# The container intentionally has no CAP_CHOWN. Create the tool scratch
# directory as the `lab` user using only the retained SETUID/SETGID caps.
python3 -c 'import os,pwd; u=pwd.getpwnam("lab"); os.setgroups([]); os.setgid(u.pw_gid); os.setuid(u.pw_uid); os.makedirs("/tmp/pentestcode", exist_ok=True)'
chmod 0700 /auth /state
if [ ! -f /auth/auth.json ]; then
  printf '{}\n' > /auth/auth.json
fi
chmod 0600 /auth/auth.json
ln -sfn /auth/auth.json /state/data/pentestcode/auth.json

# The standalone release embeds the runtime needed by this lab. PentestCode
# checks both the XDG config directory and ~/.pentestcode independently. Mark
# the plugin SDK dependency as satisfied in both locations so startup never
# attempts npm egress from the isolated agent.
for plugin_dir in /state/config/pentestcode /state/home/.pentestcode; do
  mkdir -p "$plugin_dir/node_modules"
  printf '%s\n' '{"dependencies":{"@pentestcode/plugin":"0.2.2"}}' \
    > "$plugin_dir/package.json"
  printf '%s\n' '{"lockfileVersion":3,"packages":{"":{"dependencies":{"@pentestcode/plugin":"0.2.2"}}}}' \
    > "$plugin_dir/package-lock.json"
done

if [ "${1:-}" = "--init-only" ]; then
  exit 0
fi

echo 'PentestCode isolated OAuth agent ready'
exec sleep infinity
