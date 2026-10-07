FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir Flask==3.1.2 gunicorn==23.0.0
COPY collector/app.py .
RUN addgroup -S lab && adduser -S -G lab lab && mkdir /results && chown -R lab:lab /results /app
USER lab
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--access-logfile", "-", "app:app"]
