FROM python:3.12-alpine
WORKDIR /app
COPY mock_control_plane/app.py .
RUN addgroup -S mock && adduser -S -G mock mock && chown -R mock:mock /app
USER mock
EXPOSE 8443
CMD ["python", "app.py"]
