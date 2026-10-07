FROM python:3.12-alpine
WORKDIR /app
COPY targets/shared/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY targets/shared/app/app.py .
RUN addgroup -S lab && adduser -S -G lab lab && mkdir /state && chown -R lab:lab /state /app
USER lab
ENV TARGET_ZONE=decoy
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--access-logfile", "-", "app:app"]
