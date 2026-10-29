# ilo-server's protocol

What ilo's clients and the server say to each other. This is the contract for clients, ilo's or anyone else's, and the account of what a self-hosted server holds. The server is never trusted with sync data: everything below keeps it able to store and pass on, and unable to read.

Binary values in JSON are base64url without padding. Times are Unix seconds.

## Sign-in

The server is an OpenID Connect provider (`/.well-known/openid-configuration`). ilo is a public client, `client_id=ilo`, using the authorization code flow with PKCE (`S256` only). It may redirect to a loopback address (RFC 8252), to the server's own `/signed-in` page, or to an address in the server's `OIDC_REDIRECT_URIS`.

ilo opens `/authorize` in a tab. The user enters their email and then the 6-digit code mailed to it. A code works for 10 minutes and for 5 tries, a sign-in may ask for one new code, and an address gets at most 5 codes in an hour from its first, however many sign-ins ask. A passkey signs in from the email page instead, without an address: passkeys are made discoverable, and the server asks the authenticator which account it holds, so no address's credential ids are sent. Every address gets the same answer, a code, so the pages don't say which have accounts. After an account's first sign-in, the pages offer a passkey once. Each way ends on `/authorize/done`, which sends the tab on after a second to the redirect URI with `code`, `state` and `iss`.

`POST /token` exchanges the code (`grant_type=authorization_code`, `code_verifier`, and `device_name`, which the device list shows). Each exchange makes a **device** and gives it:

- an access token, valid for an hour, sent as `Authorization: Bearer` to `/command/`, `/relay`, `/userinfo` and `/api/`. An expired or revoked one gets `401` with `WWW-Authenticate: Bearer`, never `403`;
- a refresh token, valid for 90 days, which `grant_type=refresh_token` exchanges for a new pair. Each refresh token works once;
- an ID token, ES256-signed with the key at `/jwks`, with `sub` the account and `sid` the device.

`POST /revoke` with a refresh token signs its device out. `GET /api/devices` lists the account's devices, with `current` and `online`. `DELETE /api/devices/{id}` signs one out, and `DELETE /api/account` deletes the account and everything it holds. A signed-out device's relay connection closes with code 4001.

## Sync: `/command/`

Chromium's sync protocol, unchanged: `POST /command/` with a `ClientToServerMessage` and the access token, answered with a `ClientToServerResponse`. The server behaves as Chromium's LoopbackServer at the commit `src/sync.rs` names, so Chromium's own engine is the client.

- A body may be gzipped (`Content-Encoding: gzip`), as Chromium's engine always sends it. The answer is gzipped when `Accept-Encoding` offers it. A body over 32 MiB, after inflating, gets `413`.
- `ClearServerData` gives the account a new store birthday, and a client with the old one gets `NOT_MY_BIRTHDAY` and starts over.
- The server reads only an entity's data type, the top-level field number of its specifics. It stores the specifics as they come.

A client turns on a custom passphrase, the account secret below, before its first commit. Chromium then encrypts every item's specifics with keys derived from it, and stops syncing the types it won't sync under a passphrase.

## Relay: `/relay`

One WebSocket per device, opened with the access token. A device's new connection replaces its old one. Frames are JSON text with a `type`.

Server to device:

| Frame | When |
|---|---|
| `{"type":"hello","device":ID}` | On connect. Pairing requests waiting for this device follow it. |
| `{"type":"changed","types":[32904]}` | Another device committed these data types (field numbers); an empty list means any. Fetch with GetUpdates. |
| `{"type":"message","from":ID,"payload":P}` | Another of the account's devices sent `P`. |
| `{"type":"undelivered","to":ID,"id":X}` | A `send` didn't reach its device, which isn't connected or isn't the account's. |
| `{"type":"error","message":M}` | A frame was refused. Pairing errors carry `pairing`. |

Device to server: `{"type":"send","to":ID,"payload":P,"id":X}`, where `P` is a string the server doesn't read, up to 64 KiB, and `X` is optional and comes back in `undelivered`. Pairing's frames are below.

The server pings every 45 seconds and drops a device silent for 100. Close code 4001 means the device was signed out: get new tokens before reconnecting.

## The account secret

Each account has a secret: 256 random bits, made by the first device that turns on sync. Its sync passphrase, the one Chromium is given, is the secret as 24 words: BIP-39's English encoding (the 256 bits and the first 8 bits of their SHA-256, 11 bits a word), lowercase, separated by single spaces.

The first device shows the words once, for the user to write down. They are the recovery code: typed into a new device, they let it sync with no other device present. A device gets the secret from the words or from another device by pairing, never from the server, which never sees it. Losing the words and every device means clearing the account's sync data and starting again.

## Pairing

A device that has signed in has tokens, but not the secret, so it can't read what's synced. Pairing has a device that holds the secret seal it to the new one, through the relay.

The relay is the server, and the server is the party the secret is kept from. In the middle, it could hand each device a key of its own and read what they send. So both devices show a **match code** made from both their keys, and the user approves only when the codes are the same. A code of 6 digits is enough only if neither key can be chosen after the other is seen: otherwise the server waits for the approver's key and tries a million keys of its own until one gives the same code, which takes it about a second. So the new device first sends only a **commitment** to its key, and reveals the key after the approver has sent its own. The server has to pick its keys before it learns the keys they must match, and it gets the code right one time in a million.

### Steps

The new device is the **requester**; the device that holds the secret and answers is the **approver**. Each makes a fresh X25519 key pair for the pairing and drops it after.

| | Requester sends | The others get |
|---|---|---|
| 1 | `{"type":"pair_request","commitment":C,"name":N,"os":O}` | Every other device of the account: `{"type":"pair_request","pairing":P,"from":ID,"name":N,"os":O,"commitment":C,"expires_at":T}`. The requester gets `{"type":"pair_requested","pairing":P,"expires_at":T}`. |
| 2 | (Approver) `{"type":"pair_accept","pairing":P,"public_key":KA}` | The requester: `{"type":"pair_accept","pairing":P,"from":ID,"public_key":KA}`. The account's other devices: `pair_closed` with `"reason":"taken"`. |
| 3 | `{"type":"pair_reveal","pairing":P,"public_key":KR}` | The approver: `{"type":"pair_reveal","pairing":P,"public_key":KR}`. |
| 4 | (Approver) `{"type":"pair_seal","pairing":P,"sealed":S}` | The requester: `{"type":"pair_sealed","pairing":P,"from":ID,"sealed":S}`. The approver gets `pair_closed` with `"reason":"done"`. |

After step 3, the approver checks that `KR` is the key `C` committed to, and both show the match code. The user approves on the approver only if the two codes are the same; otherwise the approver cancels.

Either device sends `{"type":"pair_cancel","pairing":P}` to stop. Before a device accepts, any of the account's devices may, such as one whose user didn't start the request. The other side gets `{"type":"pair_closed","pairing":P,"reason":R}`, where `R` is `cancelled`, `taken`, `expired`, `unreachable` or `done`.

### The server's rules

- A pairing stays within its account: other accounts' devices never get its frames, and a pairing id from another account is `no such pairing`.
- Steps come in order, each from its own device: only another device accepts, only the requester reveals, and only the approver seals. A step out of order is refused with an `error` frame.
- A pairing lasts 5 minutes from the request. No timer ends it: the next step after that closes it as `expired`, so clients also give up at `expires_at` on their own.
- A device has one request open at a time, and a new one cancels the last. An account makes at most 10 requests an hour.
- A device that connects while a request is open gets it after `hello`. Every later step needs the other side connected: a step that can't be delivered ends the pairing as `unreachable`.

### Cryptography

With `KR` and `KA` the requester's and approver's 32-byte X25519 public keys, and `||` concatenation:

- **Commitment:** `C = SHA-256("ilo pairing v1 commitment" || KR)`.
- **Match code:** the first 8 bytes of `SHA-256("ilo pairing v1 code" || KR || KA)`, as a big-endian integer, mod 1,000,000, written as 6 digits with leading zeros.
- **Seal key:** HKDF-SHA256 of the X25519 shared secret between the two keys, with salt `SHA-256("ilo pairing v1 keys" || KR || KA)` and info `"ilo pairing v1 seal"`, 32 bytes. An all-zero shared secret means a low-order key; refuse it.
- **Sealed secret:** ChaCha20-Poly1305 with the seal key, a nonce of 12 zero bytes (each key seals once), the pairing id's UTF-8 as associated data, and the 32-byte secret as plaintext. `S` is the ciphertext followed by the 16-byte tag.

The labels are ASCII, without a terminator. The requester opens `S` with the same key and checks it as Chromium checks any passphrase: it decrypts the account's Nigori.

`tests/pairing/client.rs` is a reference implementation, and `tests/pairing.rs` runs it through the relay. An example, worked out separately with Python's `cryptography`:

| | |
|---|---|
| Requester's private key | 32 bytes of `0x11` |
| Approver's private key | 32 bytes of `0x22` |
| `KR` | `e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM` |
| `KA` | `D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyA` |
| `C` | `iQWWm0uPaU4SyelWA0dwWNlsMHC39SNJ4PjHEuJhCMo` |
| Match code | `312568` |
| Secret, pairing id | 32 bytes of `0x33`, `example` |
| `S` | `MIbD9AQ11WmirOWxkJoDGTitoTFomGYAyLFIQ20_tWtXiV2OFNqWo46897wVJd9I` |

## What the server sees

The README's [What the server can see](../README.md#what-the-server-can-see) lists it. Pairing adds the names and operating systems devices give in their requests, which devices pair and when, and the commitment, public keys and sealed secret, which are of no use without the devices' private keys. A request's details are dropped when it ends. The emptied row is kept for an hour, so the limit on requests can count it.
