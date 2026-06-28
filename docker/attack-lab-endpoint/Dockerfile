FROM python:3.12-slim

WORKDIR /app
COPY docker/attack-lab-endpoint/server.py /app/server.py

RUN useradd -r -g nogroup -d /app -s /usr/sbin/nologin labendpoint \
    && mkdir -p /app/logs/attack-simulation \
    && chown -R labendpoint:nogroup /app

USER labendpoint
EXPOSE 8090

CMD ["python", "/app/server.py"]
