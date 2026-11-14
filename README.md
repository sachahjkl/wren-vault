# wren-vault

`wren-vault` is a small program that gives the Wren browser access to a Bitwarden® account. Wren starts it as a child
process and talks to it through its standard input and output. The program holds the account's keys; Wren never does.

wren-vault is not made, endorsed or supported by Bitwarden Inc. Bitwarden is a trademark of Bitwarden Inc.

## Licence

GPL-3.0-only (the file `LICENSE`). wren-vault links the Bitwarden SDK (`bitwarden/sdk-internal`), which is licensed
`GPL-3.0-only OR LicenseRef-Bitwarden-SDK`; this program selects GPL-3.0-only. It contains no code of Wren. Wren and
wren-vault are separate programs that exchange the messages of the protocol below.

## SDK revision

| Item | Value |
|---|---|
| Repository | https://github.com/bitwarden/sdk-internal |
| Revision | `300aea5933ef3bc139e430575b6868b9a9b1d4a7` (2026-11-12, workspace version 4.0.0) |
| Crates | `bitwarden-core` (feature `internal`), `bitwarden-auth`, `bitwarden-vault`, `bitwarden-sync`, `bitwarden-crypto-sync-handler`, `bitwarden-api-api`, `bitwarden-crypto`, `bitwarden-generators`, `bitwarden-state` |
| Features | Default only. Never `wasm`, `uniffi`, `bitwarden-license`, `no-memory-hardening`, `dangerous-crypto-debug`, `debug-capabilities`. |
| Minimum Rust | 1.89 (edition 2024) |

An SDK update is a planned task: change the `rev` of every SDK crate in `Cargo.toml` at once, update `Cargo.lock`, run
the tests, and do the manual check of "Tests". All SDK calls are in `src/sdk.rs`.

## Build

```
cargo build --release --locked
cargo test --locked
```

The program is `target/release/wren-vault` (`.exe` on Windows). In the Wren repository, `wrentool build vault` builds
this directory (`../wren-vault` by default) and copies the program to `build/vault/`. If `Cargo.lock` does not exist
yet, `wrentool build vault` makes it once; commit it.

On Linux the build links libdbus (the Secret Service store of the tokens): `pkg-config` and the `dbus` development
files must be present (the Nix flake provides them).

## Protocol

Version 5 (this helper 0.5.0). Changes from version 4: `hello` takes and answers `protocol` 5; new requests `save`
(create or update a login, on the server and at once in the helper's copy of the vault) and `generate` (a password or a
passphrase from the SDK's generator, also while locked); the rows of `search` list cards and identities too, and every
row carries `kind`; `search` pages (`offset`, `limit` up to 500, `kinds`) and answers `total`; `fill` gives the fields
of a card or an identity; the error `save_failed`; new requests `passkeys_for` and `passkey_assert` (the vault's
passkeys answer a page's `navigator.credentials.get`) and the error `assert_failed`.

Version 4 (helper 0.4.0). Changes from version 3: new requests `password_hint`, `device_request`, `device_poll`,
`passkey_options` and `login_passkey`; `login` takes `remember`; `unlock` takes `prf` and `credential_id`; `hello`
answers `passkey`; the errors `denied`, `expired`, `no_passkey` and `account_locked`. Every token request carries the
headers `Auth-Email` (a password login) and `Bitwarden-Client-Version`, without which the server refuses it.

Version 3 (this helper 0.3.0). Changes from version 2: new requests `search` and `totp`; `fill` takes the field
`"totp"`; `logins_for` applies the rules `StartsWith` and `Exact` and the account's equivalent domains, its rows carry
the match types `equivalent`, `starts_with` and `exact`, and its answer carries `equivalent`; the error `no_totp`.

Version 2 (helper 0.2.0) changed from version 1: `login` carries `code` and `provider` instead of `totp`, and answers
`need_device_code`; new requests `login_api_key`, `logout`, `pin_set`, `pin_clear`; `unlock` takes `pin`; `hello`
takes `idle_seconds` and answers `login` and `pin`; the event `locked`.

### Frames

Each message is one frame: a 4-byte unsigned length, little-endian, then that many bytes of UTF-8 JSON (one object).
The length is from 1 to 1 048 576 (1 MiB). A frame outside these bounds ends the connection.

Wren writes requests on the helper's standard input. The helper writes answers on its standard output, one for each
request, in the order of the requests. `keepalive` has no answer. The helper writes nothing else on standard output.
It writes no value of the vault on standard error.

The helper exits when its standard input closes, after it answers `lock` or `logout`, and at its idle deadline.

### Requests and answers

A request is `{"id": <integer from 1>, "op": "<name>", ...fields}`. An answer repeats the id:

- success: `{"id": n, "ok": true, ...fields}`
- failure: `{"id": n, "ok": false, "error": "<code>", "message": "<sentence>"}`

An event answers no request: `{"id": 0, "ok": true, "event": "<name>"}`. The only event is `locked` (see "Idle
deadline").

An unknown `op` or a malformed request gets the error `bad_request` (with id 0 when the id cannot be read). Every
request but `hello` needs a `hello` before it (`no_hello`).

| op | Request fields | Answer fields |
|---|---|---|
| `hello` | `protocol` (5), `state_dir` (string), `identity_url`, `api_url`, `persist` (bool), `device_name`, `client_version`, `idle_seconds` | `protocol`, `helper_version`, `account` (`"none"` or `"locked"`), `email`, `login` (`"password"` or `"api_key"`), `pin` (bool), `passkey` (bool: a passkey of the account unlocks) |
| `login` | first step: `email`, `password`; second step: `email`, `code`, `provider`; a new code: `email`, `provider`, `resend` (true); `remember` (true): the server lets this device skip the second step next time | `result`: `"ok"` (unlocked) with `pin` (bool: the account's PIN was kept, see "PIN"); or `"need_two_factor"` with `providers` and `email_sent`; or `"need_device_code"` |
| `login_api_key` | `client_id` (`user.<uuid>`), `client_secret`, `password` (the master password) | `result` (`"ok"`), `email`, `pin` |
| `unlock` | `password`, `pin`, or `prf` and `credential_id` (a passkey) | none; a `bad_pin` error carries `tries_left` |
| `lock` | none | none; the helper then exits |
| `logout` | `keep_pin` (bool, default false: the session ended without the person asking) | none; the helper forgets the account (state, tokens, PIN; with `keep_pin`, all but the PIN and the account's names), then exits |
| `sync` | none | `items` (count), `last_sync` (Unix seconds) |
| `pin_set` | `pin` (4 characters or more) | none |
| `pin_clear` | none | none |
| `logins_for` | `url` (the document's address), `host`, `domain` (registrable domain, `""` if none) | `rows`: a list of `{id, name, username, uri, match, has_totp, kind}` (logins only: `kind` is `"login"`); `equivalent`: the domains that the account makes equivalent to `domain` |
| `search` | `query` (words; `""`: every item), `offset` (the first match to return, 0 by default), `limit` (0: 100; never more than 500), `kinds` (`"login"`, `"card"`, `"identity"`; empty: all three) | `rows`: `{id, name, username, uri, has_totp, kind}`, the page from `offset`, sorted by name; `uri` is a login's first `http` or `https` address (`""` if none); `total`: how many items match in all; see "Item kinds" |
| `fill` | `item` (a row id), `fields` (a list of field names, see "Fill") | one field per asked name that the item has, named the same; `totp` is the current code |
| `save` | `item` (`""`: create a login; else the id of the login to update), `name` (on create: the site's host), `uri` (the page's address, `""` = none), `username`, `password` | `item` (the id of the created or updated login) |
| `generate` | `kind` (`"password"` or `"passphrase"`); password: `length`, `uppercase`, `lowercase`, `numbers`, `special`, `min_numbers`, `min_special`; passphrase: `words`, `separator`, `capitalize`, `include_number` (see "Generate") | `value` (zeroed by the helper once written) |
| `totp` | `item` | `totp` (the current code), `period` and `remaining` (seconds) |
| `password_hint` | `email` | none; the server mails the hint to the account's address |
| `device_request` | `email` | `fingerprint` (the phrase the other device shows) |
| `device_poll` | none | `result`: `"pending"`, or `"ok"` (unlocked) with `email` |
| `passkey_options` | `purpose` (`"login"` or `"unlock"`), `rp_id` (the web vault's domain) | `options` (the WebAuthn request's options, JSON text) |
| `login_passkey` | `credential_id`, `authenticator_data`, `client_data_json`, `signature`, `user_handle` (each base64url), `prf` (the PRF output, base64url) | `result` (`"ok"`), `email` |
| `passkeys_for` | `rp_id`, `allow` (credential ids, base64url; empty or absent: any passkey of `rp_id`) | `rows`: `{item, name, username, credential_id, user_handle}` (see "Passkeys of sites") |
| `passkey_assert` | `item`, `credential_id`, `rp_id`, `client_data_hash` (base64url of the SHA-256 of the clientDataJSON) | `authenticator_data`, `signature`, `user_handle`, `credential_id` (each base64url) |
| `keepalive` | none | no answer; the idle deadline starts again |

### Login steps

- `provider` is `"authenticator"` (the code of an authenticator app; the default), `"email"` (a code by email) or
  `"device"` (the code of the server's new-device mail). `providers` lists the second steps of the account that the
  helper supports (`"authenticator"`, `"email"`). An account with none of them (Duo, a security key, YubiKey OTP only)
  gets `unsupported_two_factor`: its API key logs in instead.
- A login with a second step is two requests or more. The first `login` (email and password) answers
  `need_two_factor` or `need_device_code`, and the helper keeps the email, the password and the device identifier of
  that login. The browser asks the person for the code and sends `login` again with the same email, `code` and
  `provider`: the master password crosses the pipe once. A failed second step forgets the kept password; a new
  `login` with a password replaces it. (A `login` may also carry `password`, `code` and `provider` together.)
- `resend` asks for a code again. With `provider` `"email"`, the helper asks the server to mail the two-step code and
  answers `need_two_factor` with `email_sent` true. With `"device"`, it sends the first step again, and the server
  mails a new code. `email_sent` is also true when the email code is the account's only second step: the server mailed
  it with its answer.

### Item kinds

`search` lists logins, cards and identities (`kind` `"login"`, `"card"`, `"identity"`); secure notes and SSH keys are
not listed. `logins_for` lists logins only.

- A card row: `name` the item's name, `username` the brand and the last 4 digits (`"Visa *1234"`; `""` when the card
  has no number), `uri` `""`. No other digit of the number is in a row.
- An identity row: `name` the item's name, `username` the full name, else the email; `uri` `""`.
- `has_totp` is false for cards and identities.

### Fill

`fields` names what the browser asks:

- login: `"username"`, `"password"`, `"totp"` (the current code; `no_totp` when the login has no readable key);
- card: `"cardholder"`, `"number"`, `"exp_month"` (as stored, `"1"` to `"12"`), `"exp_year"` (as stored), `"code"`,
  `"brand"`;
- identity: `"title"`, `"first_name"`, `"middle_name"`, `"last_name"`, `"full_name"` (first, middle and last, with
  single spaces), `"address1"`, `"address2"`, `"address3"`, `"city"`, `"state"`, `"postal_code"`, `"country"`,
  `"company"`, `"email"`, `"phone"`, `"username"`, `"ssn"`, `"passport"`, `"license"`.

The answer has one field per asked name that the item has (a card's and an identity's empty fields are left out). A
name of another kind of item gives nothing, without an error.

### Save

`save` needs an unlocked vault (`locked`).

- Create (`item` `""`): a login in the account's own vault (no organization, no folder), with `name` (the host of `uri`
  when `name` is empty), the `uri` (with the account's default match rule), `username` and `password`.
- Update (`item` an id): only the non-empty `username` and `password` change; the SDK keeps the former password in the
  item's password history. `uri` joins the item's addresses when none of them covers it (the rules of "Matching"; a
  `Domain` address covers the subdomains of its host). An id that is not a login of the vault: `no_item`.
- The SDK encrypts the item and sends it: `POST {api}/ciphers` (create), `PUT {api}/ciphers/{id}` (update). The
  server's answer goes into the helper's items and its state: `logins_for`, `search` and `fill` see it before the next
  sync.
- The server refused it, or cannot be reached: `save_failed`, with the server's sentence when it gave one.

### Passkeys of sites

- `passkeys_for` lists the vault's passkeys (the passkeys of login items) whose relying party is `rp_id` (ASCII case
  aside). With a non-empty `allow` (the credential ids of the page's `allowCredentials`, base64url), it lists only the
  passkeys in it. A passkey without a user handle is not listed. `username` is the passkey's user name, else its
  display name, else the login's username, else the item's name. `credential_id` and `user_handle` are base64url. The
  rows are sorted by item name.
- `passkey_assert` signs with the SDK's authenticator (`bitwarden-fido`). The authenticator data holds the SHA-256 of
  `rp_id`, the flags UP and UV (an unlocked vault is a verified user) and the sign count. The signature (ES256, DER) is
  over the authenticator data and `client_data_hash`. Wren makes the clientDataJSON and its hash: the helper sees
  only the hash.
- A passkey with a sign counter (not 0) gets its new count saved in its item, as `save` does (`PUT
  {api}/ciphers/{id}`). A failed save does not fail the assertion.
- Errors: `locked`; `bad_request` (an empty `rp_id`, a `client_data_hash` that is not 32 bytes); `no_item` (the item
  or the passkey is not in the vault, or not of `rp_id`); `assert_failed` (the authenticator refused to sign).

### Generate

The SDK's generator (`bitwarden-generators`) makes the value; no account and no server are needed, only `hello`.

| Field | Default (0, `""`, all false) | Range |
|---|---|---|
| `length` | 20 | 5 to 128 |
| `uppercase`, `lowercase`, `numbers`, `special` | all four on when none is | |
| `min_numbers`, `min_special` | 1 when the class is on | 0 to 9; their sum fits in `length` |
| `words` | 5 | 3 to 20 |
| `separator` | `"-"` | |
| `capitalize`, `include_number` | false | |

A value out of range, or another `kind`: `bad_request`.

### Idle deadline

`hello`'s `idle_seconds` (0: none) is the helper's own guard. When no request (`keepalive` included) comes for that
long, the helper writes the event `locked` and exits: lock is the exit of the process. The browser locks first, on
its own timer, and sends `keepalive` while the person is active.

### Errors

| Code | Meaning |
|---|---|
| `bad_request` | The frame is not a request of this protocol, or a field is missing (a code without a waiting login, an unlock without a password or a PIN, a PIN shorter than 4). |
| `bad_protocol` | `hello` asked for another protocol version. |
| `no_hello` | A request came before `hello`. |
| `bad_server` | A server URL is not `https` (or `http` to `127.0.0.1`, `[::1]`, `localhost`). |
| `bad_credentials` | The server refused the email, the password, the code or the API key. The message is the server's. |
| `unsupported_two_factor` | The account's second steps are none that the helper supports. |
| `unsupported_account` | The account does not unlock with a master password (SSO, key connector), or its key settings are not supported. |
| `network` | The server cannot be reached or refused the request. |
| `login_failed` | Another login failure, or an answer of the server that the helper does not understand. |
| `no_account` | `unlock` or a PIN request without a remembered account. |
| `bad_password` | `unlock` with a wrong master password, or a master password that does not open the account's keys. |
| `bad_pin` | `unlock` with a wrong PIN. `tries_left` says how many wrong PINs remain. |
| `pin_reset` | The fifth wrong PIN in a row: the PIN was removed. Only the master password unlocks now. |
| `no_pin` | `unlock` with a PIN, and none is set. |
| `no_state` | `pin_set` with `persist` false: the PIN's envelope would not survive the exit of the helper. |
| `locked` | The request needs an unlocked vault. |
| `sync_failed` | The sync failed. The vault stays unlocked with the items of the last sync. |
| `session_expired` | The server refuses the session and its token cannot be renewed (401): only a new login opens one. The browser logs the account out. |
| `no_item` | `fill` names an item that is not a login, a card or an identity of the vault; `totp` or a `save` update names one that is not a login; `passkey_assert` names a passkey that is not in the vault for that relying party. |
| `no_totp` | `fill` with `"totp"`, or `totp`, for a login without a TOTP key, or with a key that cannot be read. |
| `save_failed` | `save`: the server refused the item, or cannot be reached. The message says why. |
| `assert_failed` | `passkey_assert`: the SDK's authenticator did not sign (a passkey whose key cannot be read, or without a user handle). |
| `denied` | The other device refused the login (`device_poll`). |
| `expired` | The login with a device was not approved in time: ask again. |
| `no_passkey` | No passkey of the account opens its keys (a passkey without PRF, or none for this vault). |
| `account_locked` | The server locked the account for now (too many attempts). The message is the server's. |
| `decrypt` | The item cannot be decrypted, or the PIN cannot be set. |
| `state_write`, `state_format` | The state directory (or the token store) cannot be written, or the saved state cannot be read. |

### Matching

`logins_for` returns the logins with a saved URI that matches the page:

- `Domain` (the default): the URI's host is the page's registrable domain, or a subdomain of it (match `domain`); or
  the URI's host is one of the domains that the account makes equivalent to it, or a subdomain of one (match
  `equivalent`). If the page has no registrable domain (an IP address, `localhost`, a public suffix), the `Host` rule
  applies.
- `Host`: the same host and the same port.
- `StartsWith`: the page's address starts with the saved URI. `Exact`: the page's address is the saved URI. Both
  addresses are compared as the URL standard serializes them.
- `RegularExpression`, `Never`: no match.
- An item saved for `https` never matches an `http` page. A URI without a scheme is read as `https`.

Equivalent domains: the account's own groups, then the server's global groups that the account did not exclude, as the
last sync gave them (kept in the state as `equivalent_domains`). The helper has no Public Suffix List. The browser
sends the registrable domain, and it checks every row again with its own list before it shows it; for an `equivalent`
row it checks that the saved host's registrable domain is in the answer's `equivalent`.

`search` matches each word of the query, case aside, in the item's name, the text of its row's `username` (a card's
brand and last digits, an identity's name or email) or one of a login's URIs. It returns no password, no code and no
card number: a palette shows its rows.

TOTP codes are the SDK's (`generate_totp`): an `otpauth://` URI, a `steam://` URI or a base32 secret; SHA-1, SHA-256 or
SHA-512; the key's digits and period.

## Device

The helper sends its own token request, `POST {identity}/connect/token` (`src/identity.rs`): the SDK's
`login_password` at the pinned revision sends device type `ChromeBrowser`, one device identifier that every SDK user
shares, and no field for the new-device code. The helper sends:

| Field | Value |
|---|---|
| `client_id` | `web`: the client of browsers. The SDK renews the access token with the same client id. |
| `deviceType` | 14, `UnknownBrowser`: a browser that the server does not know by name. The SDK's `Device-Type` header is the same. |
| `deviceIdentifier` | A random UUID made at the first login of the account, kept in the state. |
| `deviceName` | `device_name` of `hello` (`Wren`). |

Everything else is the SDK's: the prelogin, the hash of the master password, the sync, the keys, the PIN, the items. A
renewal with an API key goes through the SDK and names the SDK's fixed device; no new-device check applies to API
keys.

## Security

- The keys stay in this process. Lock is the exit of the process: the operating system frees every page.
- The Bitwarden SDK installs a zeroizing global allocator: freed memory is cleared. Passwords, PINs, codes and client
  secrets received on the pipe are also zeroed after use.
- Linux: no core dump (`RLIMIT_CORE` 0) and `PR_SET_DUMPABLE` 0 (no debugger attach from the same user). Windows: no
  error dialog or error-reporting prompt on a crash. A panic writes a fixed line on standard error.
- The SDK's `tracing` output goes nowhere: the program installs no subscriber.
- The helper connects only to the two configured URLs. TLS uses the system's certificate store: a self-hosted server
  with a certificate of a private authority needs that authority in the system's store.

### State on disk

`<state_dir>/state.json`, mode 0600, in a directory of mode 0700, written by a rename. With `persist` false nothing is
written: the account is forgotten when the helper exits. Version 2 of the file; a file of another version is not read
(the account logs in again).

| Field | Content |
|---|---|
| `email`, `identity_url`, `api_url`, `device_id`, `user_id` | Public. |
| `login`, `api_client_id` | How the account logged in (`password` or `api_key`), and the API key's client id. |
| `master_password_unlock` | KDF parameters, salt, and the user key wrapped by the master key. |
| `account_crypto` | The account's private keys, wrapped by the user key. |
| `org_keys` | Organization keys, encrypted for the account. |
| `ciphers` | The items as the server sends them, encrypted. |
| `pin_envelope`, `pin_failures` | The user key sealed by the PIN (the SDK's PIN envelope), and the wrong PINs since the last good one. |
| `pin_check` | HMAC-SHA-256 of a fixed text under the user key the PIN seals: a later login of the account keeps the PIN when its key gives the same check. It says nothing of the key. |
| `logged_out` | The session ended without the person asking: only the account's names and the PIN remain, no account unlocks. |
| `last_sync` | Time of the last sync. |
| `equivalent_domains` | The groups of equivalent domains of the last sync (public). |

Nothing in the file opens the vault without the master password or the PIN.

### Tokens

The secrets that open the account on the server stay out of `state.json` (`src/tokens.rs`): the refresh token, and the
API key's client secret.

- They go to the system store when one answers: the Secret Service on Linux (GNOME Keyring, KWallet; service
  `wren-vault`, account the device identifier), the Credential Manager on Windows (DPAPI, bound to the user's
  account).
- If none answers, they go to `<state_dir>/tokens.json`, mode 0600: the level of a browser without a keyring. A later
  write that the system store takes deletes the file.
- The access token is never stored: the SDK renews it at the first request after an unlock.
- `logout` deletes both.

A stolen refresh token gives access to the encrypted items on the server, not to their content.

### PIN

`pin_set` seals the user key with the PIN (the SDK's PIN envelope, a password-based key derivation) and keeps the
envelope in the state. A PIN is weaker than the master password: the helper counts wrong PINs in the state, and the
fifth one in a row deletes the envelope (`pin_reset`).

The PIN is never stored, nor put in the system store: anyone with the session would then open the vault, and the PIN
would protect nothing. A new login keeps the PIN when it is the same account on the same server, and its user key gives
the same `pin_check` as when the PIN was set: the envelope still opens with that PIN. These remove the PIN:

- a `logout` the person asks for (`keep_pin` false);
- a login of another account, or on another server;
- a user key changed in the web vault (a key rotation): the check differs.

A session the server refuses (`session_expired`) is no logout the person asked for: the browser sends `logout` with
`keep_pin`, and the next login of the account has its PIN again.

## Tests

- `cargo test`: the frame codec, the protocol, the idle deadline (on tokio's paused clock), the matching rules (the
  equivalent domains and the search included), the TOTP codes (RFC 6238's vectors), the state file, the token store and its file fallback (with a fake system store), the PIN try counter, the form of the
  token request, the generator's options, the rows and fill fields of cards and identities, and the login against a
  wiremock server on loopback (wrong password, the authenticator and email second steps, the new-device code, the API
  key, no server). `save` runs against wiremock with a session unlocked by keys that the test makes (create, update,
  the password history, a refusal). No test contacts a real server.
- A successful login needs fixtures made once from a test account (prelogin, token and sync answers). They are not in
  the repository yet.
- Manual check before a release that changes the SDK revision: log in with a real account (US and EU), sync, fill.
