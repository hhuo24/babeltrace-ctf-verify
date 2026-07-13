# Node + Babeltrace 2.1 image for the CTF trace validator.
#
# Debian Bookworm only packages Babeltrace 2.0.x, which reads CTF 1.8 but not
# CTF 2. So we compile Babeltrace 2.1.2 from source (adds CTF2 support) in a
# builder stage, then copy just the build artifacts into a slim runtime image.

# ---- Stage 1: build babeltrace2 2.1.2 from source ----
FROM debian:bookworm-slim AS bt2-builder

ARG BT2_VERSION=2.1.2
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential \
        libglib2.0-dev flex bison pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The efficios dist tarball ships a pre-generated ./configure (no autotools/
# bootstrap needed). CLI build does not require Python.
RUN curl -fsSL -o bt2.tar.bz2 \
        "https://www.efficios.com/files/babeltrace/babeltrace2-${BT2_VERSION}.tar.bz2" \
    && tar -xjf bt2.tar.bz2 \
    && cd "babeltrace2-${BT2_VERSION}" \
    && ./configure --prefix=/usr/local --disable-man-pages --disable-debug-info \
    && make -j"$(nproc)" \
    && make install DESTDIR=/opt/bt2

# ---- Stage 2: runtime ----
FROM node:20-bookworm-slim

# Runtime shared-library dependency for babeltrace2 (GLib).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Bring in the compiled babeltrace2 (binary, libbabeltrace2, ctf plugin .so).
COPY --from=bt2-builder /opt/bt2/usr/local /usr/local
RUN ldconfig && babeltrace2 --version

WORKDIR /app

# Install production dependencies first for better layer caching.
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# Render sets PORT at runtime; default to 3000 for local `docker run`.
ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
