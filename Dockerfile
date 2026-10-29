# One small image: the server and the TLS library it links, nothing else.
FROM rust:1.99-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked && cp target/release/ilo-server /ilo-server

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data ilo \
    && mkdir /data && chown ilo /data
COPY --from=build /ilo-server /usr/local/bin/ilo-server
USER ilo
# SQLite in the volume unless DATABASE_URL names a Postgres.
ENV DATABASE_URL=sqlite:/data/ilo-server.db?mode=rwc PORT=8080
VOLUME /data
EXPOSE 8080
CMD ["ilo-server"]
