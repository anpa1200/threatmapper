FROM node:20-alpine

RUN apk upgrade --no-cache && apk add --no-cache git rsync
RUN npm install -g npm@11.18.0

WORKDIR /seed
COPY anomaly_detection/docs-site/package.json anomaly_detection/docs-site/package-lock.json ./
RUN npm ci

COPY anomaly_detection/docs-site/ /seed/
COPY scripts/sync-anomaly-atlas.sh /usr/local/bin/sync-anomaly-atlas
COPY scripts/generate-ttp-reference-index.mjs /usr/local/bin/generate-ttp-reference-index.mjs
COPY scripts/apply-adversarygraph-docs-overlay.mjs /usr/local/bin/apply-adversarygraph-docs-overlay.mjs
COPY anomaly_detection/docs-overlay/ /seed-overlay/
COPY anomaly_detection/docker/sync-and-build.sh /usr/local/bin/sync-and-build

RUN chmod +x /usr/local/bin/sync-anomaly-atlas /usr/local/bin/sync-and-build

RUN addgroup -S atlas && adduser -S -G atlas -h /seed atlas && \
    chown -R atlas:atlas /seed /seed-overlay

USER atlas

CMD ["/usr/local/bin/sync-and-build"]
