# Node + Babeltrace 2 image for the CTF trace validator.
# Debian Bookworm ships a "babeltrace2" package, so the tool the app shells out
# to is actually present at runtime (Render's stock environment has no bt2).
FROM node:20-bookworm-slim

# Install Babeltrace 2 (provides the "babeltrace2" CLI on PATH).
RUN apt-get update \
    && apt-get install -y --no-install-recommends babeltrace2 \
    && rm -rf /var/lib/apt/lists/* \
    && babeltrace2 --version

WORKDIR /app

# Install production dependencies first for better layer caching.
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Render sets PORT at runtime; default to 3000 for local `docker run`.
ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
