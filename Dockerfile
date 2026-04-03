# Stage 1: builder
FROM gcc:12-bookworm AS builder
ARG TARGET=x64
ARG EXTRA_OPTS=""
WORKDIR /usr/src/multics
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends make git && rm -rf /var/lib/apt/lists/*
RUN mkdir -p ${TARGET} && make target=${TARGET} EXTRA_OPTS="${EXTRA_OPTS}" && cp ${TARGET}/multics /usr/local/bin/multics

# Stage 2: tester (extends builder)
FROM builder AS tester
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY tests/ /tests/
RUN pip3 install --no-cache-dir pytest
WORKDIR /tests
CMD ["pytest", "-v", "--tb=short"]

# Stage 3: runtime (minimal image)
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libgcc-s1 netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/multics /usr/local/bin/multics
WORKDIR /etc/multics
VOLUME ["/etc/multics"]
EXPOSE 15000-15010/tcp 15000-15010/udp
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD nc -z localhost ${MULTICS_PORT:-15000} || exit 1
CMD ["multics", "-c", "/etc/multics/multics.cfg"]