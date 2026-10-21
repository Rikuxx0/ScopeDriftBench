#!/bin/sh
set -eu
/usr/local/bin/reset-s14-host
exec /usr/sbin/sshd -D -e
