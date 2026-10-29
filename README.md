# ilo-server

Accounts, end-to-end encrypted sync, and a relay between devices for [ilo](https://github.com/MartinPTielemans/browser), the open-source browser. ilo will use the hosted copy by default, and Settings › Account will take the address of your own.

- **Accounts.** Sign in with a code sent by email, then with a passkey. The server is an OpenID Connect provider, so ilo signs in through a page in a tab.
- **Sync.** `/command/` speaks Chromium's own sync protocol, so ilo's unmodified sync engine syncs bookmarks, passwords, history, tabs, extensions and settings here. ilo encrypts them with a passphrase the server never sees; the server stores ciphertext.
- **Relay.** Each device keeps one WebSocket. When one device commits, the others hear within a second instead of polling, and devices pass each other encrypted messages, such as approving a new device.

One binary, configured by environment variables, on SQLite or Postgres.

## Self-hosting

You need a domain with HTTPS in front of the server, which passkeys require, and an SMTP account to send sign-in codes.

**With Docker Compose** (the server and Postgres):

1. `git clone https://github.com/MartinPTielemans/ilo-server && cd ilo-server`
2. `cp .env.example .env`. Set `POSTGRES_PASSWORD` to a long random string, `PUBLIC_URL` to your address, such as `https://sync.example.org`, and `SMTP_URL` and `MAIL_FROM` to your mail account. Remove `DEV_MODE=1`.
3. `docker compose up -d`
4. Point your HTTPS proxy at port 8080, and check that `https://sync.example.org/health` says `ok`.
5. In ilo, set the account server to your address, and sign in.

**With one container** (SQLite in a volume):

```sh
docker build -t ilo-server .
docker run -d --name ilo-server -p 8080:8080 -v ilo-data:/data \
  -e PUBLIC_URL=https://sync.example.org \
  -e SMTP_URL=smtps://user:password@smtp.example.org:465 \
  -e MAIL_FROM='ilo <sync@example.org>' \
  ilo-server
```

**To try it** on your own machine, with codes in the log instead of mail: `docker run --rm -p 8080:8080 -e DEV_MODE=1 ilo-server`, or `DEV_MODE=1 cargo run`.

Back up the database: it holds accounts, the key that signs ID tokens, and the encrypted sync data.

### Proxies

The relay is a WebSocket on `/relay`. A proxy in front has to pass `Upgrade` through, and its idle timeout must be longer than 45 seconds, the server's ping interval. nginx needs `proxy_http_version 1.1`, `proxy_set_header Upgrade $http_upgrade` and `proxy_set_header Connection "upgrade"`; Caddy passes WebSockets as they are.

Run one instance. The relay keeps connections in its process.

## Configuration

| Variable | Default | |
|---|---|---|
| `PUBLIC_URL` | `https://$RAILWAY_PUBLIC_DOMAIN`, else `http://localhost:$PORT` | The address clients use: the OIDC issuer and the passkeys' origin. Must be https unless it's localhost or `DEV_MODE` is on. |
| `DATABASE_URL` | `sqlite:ilo-server.db?mode=rwc` (the image: `/data/ilo-server.db`) | `sqlite:…` or `postgres://…`. Migrations run at start. |
| `SMTP_URL` | | Where codes are mailed from, as `smtps://user:password@host:465` or `smtp://user:password@host:587?tls=required`. Required unless `DEV_MODE`. |
| `MAIL_FROM` | | The codes' sender, such as `ilo <sync@example.org>`. |
| `DEV_MODE` | off | `1` logs sign-in codes instead of mailing them and allows plain http. Never for real users. |
| `OIDC_REDIRECT_URIS` | | More redirect URIs to allow, comma-separated, besides loopback addresses and `$PUBLIC_URL/signed-in`. |
| `PORT`, `HOST` | `8080`, `0.0.0.0` | Where it listens. |
| `LOG` | `info` | Log filter, such as `debug` or `ilo_server=debug`. |

## Endpoints

| | |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery. The client id is `ilo`, a public client using the code flow with PKCE (S256). |
| `GET /authorize` | The sign-in pages. They redirect to the client with `code`, `state` and `iss`. |
| `POST /token` | `authorization_code` (takes an optional `device_name`) and `refresh_token`. Each code exchange makes a device. Refresh tokens rotate. |
| `GET /userinfo`, `GET /jwks`, `POST /revoke` | Revoking a refresh token signs its device out. |
| `POST /command/` | Chromium sync: GetUpdates, Commit, ClearServerData. Bearer access token. |
| `GET /relay` | The device's WebSocket. Bearer access token. Frames are described in [`src/relay.rs`](src/relay.rs). |
| `GET /api/devices`, `DELETE /api/devices/{id}`, `DELETE /api/account` | The account's devices, removing one, and deleting the account with all its data. |
| `GET /health` | `ok` while the database answers. |

## Developing

```sh
DEV_MODE=1 cargo run       # serves on localhost:8080
cargo test                 # on SQLite; ILO_TEST_DATABASE_URL=postgres://… for Postgres
```

[AGENTS.md](AGENTS.md) holds the project's rules and traps, and [CONTRIBUTING.md](CONTRIBUTING.md) how to send a change.

## Licence

AGPL-3.0: if you run a changed copy for others, offer them its source. `proto/` is Chromium's sync protocol, under its BSD licence.
