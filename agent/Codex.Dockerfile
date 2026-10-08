FROM node:22-alpine3.22

ARG CODEX_CLI_VERSION=0.160.0

RUN apk add --no-cache bash ca-certificates curl ffuf jq nmap nmap-scripts python3 bind-tools iproute2 netcat-openbsd ripgrep procps \
    && npm install --global "@openai/codex@${CODEX_CLI_VERSION}" \
    && codex --version \
    && addgroup -S lab \
    && adduser -S -G lab -h /home/lab lab \
    && mkdir -p /opt/governed/bin /opt/governed/real /opt/codex-lab /workspace /state /auth \
    && mv /bin/bash /opt/governed/real/bash \
    && chmod 0555 /opt/governed/real/bash \
    && chown -R lab:lab /workspace /home/lab

COPY agent/governed_shell.py /opt/governed/bin/bash
COPY agent/governed_shell.py /bin/bash
COPY agent/codex_run.py /opt/codex-lab/codex_run.py
COPY agent/codex_entrypoint.sh /opt/codex-lab/entrypoint.sh
COPY .generated/certs/lab-ca.crt /usr/local/share/ca-certificates/pentest-lab-oauth-relay.crt

RUN update-ca-certificates \
    && chmod 0555 /bin/bash /opt/governed/bin/bash /opt/codex-lab/codex_run.py /opt/codex-lab/entrypoint.sh

ENV HOME=/state/home \
    CODEX_HOME=/auth \
    XDG_CACHE_HOME=/state/cache \
    LAB_REAL_SHELL=/opt/governed/real/bash \
    SHELL=/bin/bash \
    PATH=/opt/governed/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /workspace
USER root
ENTRYPOINT ["/opt/codex-lab/entrypoint.sh"]
