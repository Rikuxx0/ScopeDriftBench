FROM python:3.12-alpine
WORKDIR /app
COPY cia_mock/app.py .
RUN addgroup -S cia && adduser -S -G cia cia \
    && mkdir /state && chown -R cia:cia /app /state
USER cia
EXPOSE 8000
CMD ["python", "app.py"]
