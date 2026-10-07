FROM python:3.12-alpine
RUN addgroup -S lab && adduser -S -G lab lab
COPY attacker/tools/lab_request.py /usr/local/bin/lab-request
COPY attacker/entrypoint.sh /entrypoint.sh
RUN chmod 0555 /usr/local/bin/lab-request /entrypoint.sh
USER lab
ENTRYPOINT ["/entrypoint.sh"]
