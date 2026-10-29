# ilo-server

Accounts, end-to-end encrypted sync, and a relay between devices for [ilo](https://github.com/MartinPTielemans/browser), the open-source browser. ilo will use the hosted copy by default, and Settings › Account will take the address of your own.

- **Accounts.** Sign in with a code sent by email, then with a passkey. The server is an OpenID Connect provider, so ilo signs in through a page in a tab.
- **Sync.** `/command/` speaks Chromium's own sync protocol, so ilo's unmodified sync engine syncs bookmarks, passwords, history, tabs, extensions and settings here. ilo encrypts them with a passphrase the server never sees; the server stores ciphertext.
- **Relay.** Each device keeps one WebSocket. When one device commits, the others hear within a second instead of polling, and devices pass each other encrypted messages. A new device gets the passphrase from another through it, once the user sees the same match code on both.

One binary, configured by environment variables, on SQLite or Postgres.

## What the server can see

ilo turns on a custom passphrase before it first syncs, so Chromium encrypts each item's contents with a key made from it, which never leaves the devices. Under a passphrase, Chromium doesn't sync history, journeys, history deletions, user events or addresses at all. What any server, this one included, still sees:

- **The account:** its email address, and when it was made.
- **Devices:** the name each sends at sign-in, and when it signed in and was last seen. Chromium also keeps its device records unencrypted: each device's name, operating system and form factor, browser version, and when it was last active.
- **A few settings:** Chromium's priority preferences, a small set it keeps unencrypted.
- **Everything else, in outline:** which data types an account syncs, how many items each has, their sizes, when they're created and changed, and how bookmarks nest and are ordered. Not their names, addresses or contents.
- **The relay:** which of an account's devices message each other, when, and how large the messages are. Not what they say. Adding a device also shows the name and operating system it gives, and keys and a sealed passphrase that the server can't open.
- **The network:** like any web server, the addresses requests come from and when. This server doesn't log them, but a proxy in front of it may.

The server refuses an item that arrives unencrypted, for every type Chromium encrypts under a passphrase, so a client that hasn't set one, an unmodified Chromium included, can't sync those types here.

Sign-in codes and tokens are stored only as hashes.

## Self-hosting

You need a domain with HTTPS in front of the server, which passkeys require, and a way to send sign-in codes: an SMTP account, or Cloudflare Email Service's send API where the host blocks outbound SMTP, as Railway does below its Pro plan.

**With Docker Compose** (the server and Postgres):

1. `git clone https://github.com/MartinPTielemans/ilo-server && cd ilo-server`
2. `cp .env.example .env`. Set `POSTGRES_PASSWORD` to a long random string, `PUBLIC_URL` to your address, such as `https://sync.example.org`, and `SMTP_URL` and `MAIL_FROM` to your mail account, or `MAIL_API=cloudflare` and its two settings in place of `SMTP_URL`.
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

**On Railway**, a service made from this repo builds its Dockerfile, and Railway gives it `PORT` and `RAILWAY_PUBLIC_DOMAIN`, which `PUBLIC_URL` defaults to. Add a Postgres database and set the service's `DATABASE_URL` to the database's, set `MAIL_API=cloudflare`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` and `MAIL_FROM`, since Railway blocks outbound SMTP on its Free, Trial and Hobby plans, and Railway reads the `/health` health check and the one replica from [`railway.json`](railway.json). [`.railway/railway.ts`](.railway/railway.ts) describes the same for `railway config apply`; it hasn't been tried yet.

### Proxies

The relay is a WebSocket on `/relay`. A proxy in front has to pass `Upgrade` through, and its idle timeout must be longer than 45 seconds, the server's ping interval. nginx needs `proxy_http_version 1.1`, `proxy_set_header Upgrade $http_upgrade` and `proxy_set_header Connection "upgrade"`; Caddy passes WebSockets as they are.

Sign-in counts the codes each client asks for by its address, so a proxy has to name it: set `CLIENT_IP_HEADER` to the header the proxy puts it in, such as `X-Real-IP` with nginx's `proxy_set_header X-Real-IP $remote_addr`, or `X-Forwarded-For`, whose last address counts. Name only a header the proxy sets itself, or a client can claim any address. Without a proxy, leave it unset, and the connection's address counts.

Run one instance. The relay keeps connections in its process.

## Configuration

| Variable | Default | |
|---|---|---|
| `PUBLIC_URL` | `https://$RAILWAY_PUBLIC_DOMAIN`, else `http://localhost:$PORT` | The address clients use: the OIDC issuer and the passkeys' origin. Must be https unless it's localhost or `DEV_MODE` is on. |
| `DATABASE_URL` | `sqlite:ilo-server.db?mode=rwc` (the image: `/data/ilo-server.db`) | `sqlite:…` or `postgres://…`. Migrations run at start. |
| `SMTP_URL` | | Where codes are mailed from, as `smtps://user:password@host:465` or `smtp://user:password@host:587?tls=required`. This or `MAIL_API` is required unless `DEV_MODE`, and not both. |
| `MAIL_API` | | `cloudflare` sends codes through [Cloudflare Email Service's send API](https://developers.cloudflare.com/email-service/api/send-emails/rest-api/) over HTTPS instead of SMTP, for hosts that block outbound SMTP. |
| `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` | | With `MAIL_API=cloudflare`: the account that sends, and an API token with Email Sending: Edit. |
| `MAIL_FROM` | | The codes' sender, such as `ilo <sync@example.org>`, on a domain the mail account or Email Service sends for. Required with either. |
| `DEV_MODE` | off | `1` logs sign-in codes instead of mailing them and allows plain http. Never for real users. |
| `CLIENT_IP_HEADER` | `X-Real-IP` on Railway, else none | The header the proxy in front puts the client's address in, which the code limits count by; none counts the connection's address. |
| `CODES_PER_CLIENT_PER_HOUR` | `10` | Sign-in codes mailed in an hour to sign-ins from one client (an IPv6 client by its /64), across every address it asks for. Each address also gets at most 5 an hour. |
| `CODES_PER_DAY` | `800` | Codes the server mails in a day, all clients together: keep it under your mail account's daily quota, with room for new-sign-in notices. |
| `OIDC_REDIRECT_URIS` | | More redirect URIs to allow, comma-separated, besides loopback addresses and `$PUBLIC_URL/signed-in`. |
| `PORT`, `HOST` | `8080`, `0.0.0.0` | Where it listens. |
| `LOG` | `info` | Log filter, such as `debug` or `ilo_server=debug`. |

## Endpoints

| | |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery. The client id is `ilo`, a public client using the code flow with PKCE (S256). |
| `GET /authorize` | The sign-in pages: email or a passkey, the mailed code, a passkey offered once after an account's first sign-in, and a done page that sends the tab back to the client with `code`, `state` and `iss`. |
| `POST /token` | `authorization_code` (takes an optional `device_name`) and `refresh_token`. Each code exchange makes a device, and mails the account when it already had one. Refresh tokens rotate. |
| `GET /userinfo`, `GET /jwks`, `POST /revoke` | Revoking a refresh token signs its device out. |
| `POST /command/` | Chromium sync: GetUpdates, Commit, ClearServerData. Bearer access token. |
| `GET /relay` | The device's WebSocket, which also carries pairing. Bearer access token. |
| `GET /api/devices`, `DELETE /api/devices/{id}`, `DELETE /api/account` | The account's devices, removing one, and deleting the account with all its data. |
| `GET /health` | `ok` while the database answers. |

## Developing

```sh
DEV_MODE=1 cargo run       # serves on localhost:8080
cargo test                 # on SQLite; ILO_TEST_DATABASE_URL=postgres://… for Postgres
```

[docs/protocol.md](docs/protocol.md) is the contract with clients: sign-in, sync, the relay's frames and pairing. [AGENTS.md](AGENTS.md) holds the project's rules and traps, and [CONTRIBUTING.md](CONTRIBUTING.md) how to send a change.

## Licence

AGPL-3.0: if you run a changed copy for others, offer them its source. `proto/` is Chromium's sync protocol, under its BSD licence.
