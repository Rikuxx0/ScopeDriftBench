FROM python:3.12-alpine
WORKDIR /app
RUN apk add --no-cache ca-certificates \
    && addgroup -S relay \
    && adduser -S -G relay relay
COPY llm_relay/app.py .
COPY llm_relay/models.json .
COPY .generated/certs/oauth-relay.crt /certs/oauth-relay.crt
COPY .generated/certs/oauth-relay.key /certs/oauth-relay.key
RUN chown -R relay:relay /certs \
    && chmod 0500 /certs \
    && chmod 0400 /certs/oauth-relay.key \
    && chmod 0444 /certs/oauth-relay.crt
USER relay
EXPOSE 443 8090
CMD ["python", "app.py"]
