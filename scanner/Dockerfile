FROM mcr.microsoft.com/playwright:v1.55.0-noble

WORKDIR /srv/scanner
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY server.mjs ./

ENV NODE_ENV=production \
    SCAN_PORT=8090 \
    SCAN_TIMEOUT_MS=12000 \
    SCAN_MAX_REQUESTS=100

USER pwuser
EXPOSE 8090
CMD ["node", "server.mjs"]
