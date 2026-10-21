FROM alpine:3.22

ARG TARGETARCH
ARG PENTESTCODE_VERSION=0.2.2
ARG PENTESTCODE_SHA256_ARM64=eed5d3c0139bfd15c32d55ff422ef222c31643fe581d6df9658fe93fcef60e1f
ARG PENTESTCODE_SHA256_AMD64=980a08c44cd1327631d5b617bb6645894c492e6b1788358ef3ec20da8488078a

RUN apk add --no-cache bash ca-certificates curl ffuf jq nmap nmap-scripts python3 bind-tools iproute2 netcat-openbsd openssh-client sshpass ripgrep \
    && case "$TARGETARCH" in \
         arm64) asset="pentestcode-linux-arm64-musl.tar.gz"; expected="$PENTESTCODE_SHA256_ARM64" ;; \
         amd64) asset="pentestcode-linux-x64-musl.tar.gz"; expected="$PENTESTCODE_SHA256_AMD64" ;; \
         *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 2 ;; \
       esac \
    && curl -fsSL "https://github.com/s0ld13rr/pentestcode/releases/download/v${PENTESTCODE_VERSION}/${asset}" -o /tmp/pentestcode.tar.gz \
    && echo "${expected}  /tmp/pentestcode.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/pentestcode.tar.gz -C /usr/local/bin pentestcode \
    && chmod 0555 /usr/local/bin/pentestcode \
    && rm /tmp/pentestcode.tar.gz \
    && addgroup -S lab \
    && adduser -S -G lab -h /home/lab lab \
    && mkdir -p /opt/governed/bin /opt/governed/real /opt/pentestcode /workspace /state/data /state/cache /auth \
    && mv /bin/bash /opt/governed/real/bash \
    && chmod 0500 /opt/governed/real/bash \
    && chown -R lab:lab /workspace /home/lab

COPY agent/governed_shell.py /opt/governed/wrapper
COPY agent/autonomous_run.py /opt/pentestcode/autonomous_run.py
COPY agent/entrypoint.sh /opt/pentestcode/entrypoint.sh
COPY agent/pentestcode.jsonc /opt/pentestcode/pentestcode.jsonc
COPY third_party/pentestcode/LICENSE /opt/pentestcode/LICENSE
COPY .generated/certs/lab-ca.crt /usr/local/share/ca-certificates/pentest-lab-oauth-relay.crt
RUN update-ca-certificates \
    && cp -L /bin/sh /opt/governed/real/sh \
    && rm /bin/sh \
    && cp /opt/governed/wrapper /bin/sh \
    && cp /opt/governed/wrapper /bin/bash \
    && cp /opt/governed/wrapper /opt/governed/bin/bash \
    && chmod 0500 /opt/governed/wrapper /bin/sh /bin/bash /opt/governed/bin/bash /opt/governed/real/sh \
    && chmod 0555 /opt/pentestcode/autonomous_run.py /opt/pentestcode/entrypoint.sh \
    && chmod 0444 /opt/pentestcode/pentestcode.jsonc /opt/pentestcode/LICENSE

ENV HOME=/state/home \
    XDG_CONFIG_HOME=/state/config \
    XDG_DATA_HOME=/state/data \
    XDG_CACHE_HOME=/state/cache \
    XDG_STATE_HOME=/state/runtime \
    OPENCODE_CONFIG=/opt/pentestcode/pentestcode.jsonc \
    OPENCODE_DISABLE_PROJECT_CONFIG=true \
    OPENCODE_DISABLE_AUTOUPDATE=true \
    OPENCODE_DISABLE_MODELS_FETCH=true \
    OPENCODE_MODELS_URL=http://llm-relay:8090/models \
    SHELL=/opt/governed/bin/bash \
    PATH=/opt/governed/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /workspace
USER root
ENTRYPOINT ["/opt/pentestcode/entrypoint.sh"]
