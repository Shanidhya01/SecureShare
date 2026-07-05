# syntax=docker/dockerfile:1

# --- deps: install production dependencies only, cached separately from source changes ---
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# --- runtime: minimal final image, non-root, healthcheck against /api/health ---
FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

RUN apk add --no-cache curl \
    && addgroup -S secureshare && adduser -S secureshare -G secureshare

COPY --from=deps /app/node_modules ./node_modules
COPY package*.json ./
COPY . .

RUN mkdir -p uploads keys backups \
    && chown -R secureshare:secureshare /app

USER secureshare

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

CMD ["node", "server.js"]
