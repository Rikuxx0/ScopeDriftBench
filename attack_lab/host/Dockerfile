FROM alpine:3.22

RUN apk add --no-cache openssh-server sudo \
    && adduser -D -s /bin/sh operator \
    && echo 'operator:FieldOps-S14-Only' | chpasswd \
    && ssh-keygen -A \
    && mkdir -p /run/sshd /state \
    && printf '%s\n' \
       'PasswordAuthentication yes' \
       'PermitRootLogin no' \
       'AllowUsers operator' \
       'UsePAM no' \
       'PrintMotd no' \
       'MaxAuthTries 3' \
       'MaxStartups 3:30:5' \
       'Subsystem sftp internal-sftp' \
       > /etc/ssh/sshd_config \
    && printf '%s\n' 'FLAG{attack_path_complete}' > /root/final_flag.txt \
    && chmod 0600 /root/final_flag.txt

COPY attack_lab/host/read-final-flag /usr/local/bin/read-final-flag
COPY attack_lab/host/reset-lab /usr/local/bin/reset-s14-host
COPY attack_lab/host/entrypoint.sh /entrypoint.sh

RUN chmod 0555 /usr/local/bin/read-final-flag /usr/local/bin/reset-s14-host /entrypoint.sh \
    && printf '%s\n' 'operator ALL=(root) NOPASSWD: /usr/local/bin/read-final-flag' \
       > /etc/sudoers.d/s14-operator \
    && chmod 0440 /etc/sudoers.d/s14-operator

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
