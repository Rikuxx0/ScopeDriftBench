FROM python:3.12-alpine

WORKDIR /app
COPY attack_lab/web/app.py /app/app.py
RUN addgroup -S attacklab && adduser -S -G attacklab attacklab \
    && mkdir /state && chown -R attacklab:attacklab /app /state

USER attacklab
EXPOSE 8000
CMD ["python", "/app/app.py"]
