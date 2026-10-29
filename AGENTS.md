# ilo-server

The account, sync and relay server for [ilo](https://github.com/MartinPTielemans/browser), the open-source browser. ilo's Chromium sync engine talks to it instead of Google, and its devices keep a WebSocket to it. One Rust binary (axum, sqlx) on SQLite or Postgres, shipped as a container image. ilo's hosted copy runs on Railway, and anyone can run their own. AGPL-3.0.

## What we never compromise on

1. **The server can't read what it syncs.** With ilo's custom passphrase, specifics arrive encrypted, and the server stores and serves them byte for byte. It never decodes specifics past their field numbers, never logs them, and relay payloads stay opaque strings. This is broken by giving the server a reason to decrypt or by decoding specifics into proto types (which also drops newer clients' fields), and by logging a token, a code or a payload outside `DEV_MODE`.
2. **Anyone can run it.** Self-hosting is one container plus a database, configured only through environment variables, with no license checks, no phone-home and no paid features. The hosted copy differs only in its URL and mail settings. This is broken by a feature that works only on Railway, by a setting outside the environment, and by a secret the repo needs.
3. **An idle browser stays idle.** The relay replaces polling, so a device waits on one quiet socket. This is broken by anything that wakes clients on a timer more often than the heartbeat, or by server timers that sweep on a schedule; sweeps happen lazily, during requests that write the same tables.
4. **Chromium's protocol as Chromium speaks it.** `/command/` behaves as LoopbackServer does at the engine's pinned commit (`src/sync.rs` names it), so the unmodified sync engine works against it. A change to ids, progress tokens, birthdays or permanent folders is a change to what Chromium sees.

## A note on taste

Ambitious ideas, simple systems, software that feels obvious. Do not preserve complexity just because it already exists. Do not introduce machinery because it looks architecturally impressive. Understand the real constraint, then fight for the smallest model that makes the correct behavior unsurprising. Channel both "measure twice, cut once" and "yagni". Fight scope creep. These are good defaults, not hard rules; the owner's preferences override them.

## Glossary

- **Account**: one email address. **Device**: one sign-in of one ilo install, made when `/token` exchanges a code. Tokens, relay connections and the device list hang off devices; removing one signs that install out.
- **Store**: an account's sync data, with its **birthday**. A new birthday (after ClearServerData) makes every client start over.
- **Keystore key**: the per-account key Chromium asks for when it sets up Nigori. It encrypts nothing once the account has a custom passphrase, which is ilo's end-to-end encryption.
- **Agent** means an AI coding agent working on this repo. ilo's browser agents get no access to accounts, devices or synced data.

## The ways to hurt yourself

1. **Deploying, or touching the hosted copy.** The Railway service holds real users' accounts and data. Changes reach it only through a merged PR. Never run `railway` commands, apply `.railway/railway.ts`, or connect to its database without the owner's go-ahead.
2. **Mailing real people.** Without `DEV_MODE`, sign-in sends mail through `SMTP_URL` or `MAIL_API`. Run the server with `DEV_MODE=1` and neither, and the codes go to the log. Tests use a recording mailer and `@example.org` addresses.
3. **Running the tests against a real database.** `ILO_TEST_DATABASE_URL` points the tests at a Postgres they write accounts into and never clean. Use a throwaway container only.
4. **Editing the protos.** `proto/` is Chromium's, unmodified, from the engine's pin. To change what the server sees, change `build.rs`; to update them, follow `proto/README.md`.
5. **Editing a migration that has shipped.** Databases that ran it won't run it again. Add a new numbered file instead, in both `migrations/sqlite` and `migrations/postgres`.
6. **Running more than one instance.** The relay keeps each device's socket in its process, so a commit on one instance doesn't reach devices connected to another. Keep `replicas: 1` until the relay crosses instances, such as through Postgres `LISTEN`/`NOTIFY`.
7. **Committing a secret.** `.env` is gitignored, and `.env.example` holds only names. The ID-token signing key is generated into the database on first start, so the server needs no key in its environment.

## Hit every surface

The most common defect is a change that works on the path you tested and is missing everywhere else. Before calling work done, walk this list and say which entries applied.

- **Both databases.** Every query runs on SQLite and Postgres through sqlx's `Any` driver: `$1` parameters, `ON CONFLICT`, `RETURNING`; flags as integers, times as Unix seconds, and `BIGINT`/`BYTEA` in the Postgres migration where SQLite has `INTEGER`/`BLOB`. Run the tests on both.
- **Chromium's client.** A sync change keeps working for the unmodified engine: ids, the version order of GetUpdates, conflict answers, tombstones, birthdays.
- **ilo's client.** The OIDC endpoints, `/api/`, the relay's frames and pairing are what ilo's core builds on, and `docs/protocol.md` is their contract. A change to them rewrites it, and the PR says so. Pairing's cryptography changes only with its version label (`ilo pairing v1`) and the reference client in `tests/pairing/client.rs`.
- **Self-hosters.** A new setting is an environment variable, read in `src/config.rs`, with its default and its row in the README's table, and in `docker-compose.yml` and `.env.example` when a self-hoster sets it.
- **Railway.** `.railway/railway.ts` follows a change in how the service runs: healthcheck, replicas, database.
- **Sign-in pages.** They run in an ilo tab: light and dark, keyboard only, and screen readers (the alerts use `role="alert"`). Their look is the browser's tokens (`app/design/tokens.toml` there), and their CSP allows nothing inline, so style goes in `sign-in.css` and script in `sign-in.js`.
- **Reverse states.** If you added a way in, add the way out and the way to see it. A one-way door is a bug. A device is listed and removable, an account deletable, a token revocable, and synced data clearable.

## Dev

- `DEV_MODE=1 cargo run` serves on `localhost:8080` with SQLite in `ilo-server.db`; codes appear in the log. `LOG=debug` shows more.
- `docker compose up` runs it with Postgres; it needs `POSTGRES_PASSWORD` in `.env`.
- `build.rs` compiles the protos with `protox`, so no `protoc` is needed. The generated types are in `target/*/build/ilo-server-*/out/sync_pb.rs`.
- Stop what you started, by the PID or container name you tracked.

## Verifying

- `cargo test` runs the unit tests and the integration tests in `tests/`, each against a server on a free port with its own SQLite file. `ILO_TEST_DATABASE_URL=postgres://… cargo test` runs them on Postgres.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`, as CI does.
- Name the exact checks you ran.
- Test meaningful logic or observable behavior, not wiring that mirrors the implementation. The integration tests drive the server as clients do: the sign-in pages, `/token`, protobuf on `/command/`, frames on `/relay`.
- Tests await the event that marks the milestone; a test that needs a sleep to pass is wrong.

## Commits and pull requests

- Commit only when asked, with `git commit -s`. The `Signed-off-by` line is the DCO certification in [CONTRIBUTING.md](CONTRIBUTING.md#sign-off).
- Authorship is human only: no `Co-Authored-By` trailers and no "Generated with" lines in commits or PRs.
- Conventional commit titles in plain language, describing the outcome: `fix(sync): a deleted folder's bookmarks reach other devices as deleted`.
- Code copied from another project keeps its licence header and names its source and upstream commit.
- Never open a PR unless asked. One request is one PR. The PR body follows `.github/pull_request_template.md`.
- Sign-in page changes need before-and-after images, uploaded to GitHub. Never commit PR-only assets.

## Documentation

- Most changes need no doc change; agents can read the code.
- Docs hold decisions and their reasons, cross-cutting constraints, and traps the source doesn't reveal. When one changes, rewrite or remove the text; never append a second account.
- Plans, research notes and scratch files stay out of the repo. A merged PR is the implementation record.

## Where code lives

- `src/accounts/`: sign-in pages, passkeys, the OIDC provider, devices.
- `src/sync.rs`: `/command/`. `src/relay.rs`: `/relay`, and `src/pairing.rs` the pairing steps it carries. `src/tokens.rs`: the device tokens both accept.
- `docs/protocol.md`: the contract with clients.
- `proto/`: Chromium's sync protocol, vendored.

## Taste

- Comments say why, in a sentence. The code says what.
- Runtime `sqlx::query`, not the compile-time macros, so building needs no database.
- If a rule here fights the task in front of you, say so loudly and get a human sign-off before breaking it.
