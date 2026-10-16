FROM python:3.12-alpine
WORKDIR /app
COPY attack_mock/app.py .
RUN addgroup -S attackmock && adduser -S -G attackmock attackmock \
    && mkdir /state && chown -R attackmock:attackmock /app /state
USER attackmock
EXPOSE 8000
CMD ["python", "app.py"]
