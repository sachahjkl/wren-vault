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
| Crates | `bitwarden-core` (feature `internal`), `bitwarden-auth`, `bitwarden-vault`, `bitwarden-sync`, `bitwarden-crypto-sync-handler`, `bitwarden-api-api`, `bitwarden-crypto` |
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

## Protocol

Version 1.

### Frames

Each message is one frame: a 4-byte unsigned length, little-endian, then that many bytes of UTF-8 JSON (one object).
The length is from 1 to 1 048 576 (1 MiB). A frame outside these bounds ends the connection.

Wren writes requests on the helper's standard input. The helper writes answers on its standard output, one for each
request, in the order of the requests. `keepalive` has no answer. The helper writes nothing else on standard output.
It writes no value of the vault on standard error.

The helper exits when its standard input closes, and after it answers `lock`.

### Requests and answers

A request is `{"id": <integer from 1>, "op": "<name>", ...fields}`. An answer repeats the id:

- success: `{"id": n, "ok": true, ...fields}`
- failure: `{"id": n, "ok": false, "error": "<code>", "message": "<sentence>"}`

An unknown `op` or a malformed request gets the error `bad_request` (with id 0 when the id cannot be read). Every
request but `hello` needs a `hello` before it (`no_hello`).

| op | Request fields | Answer fields |
|---|---|---|
| `hello` | `protocol` (1), `state_dir` (string), `identity_url`, `api_url`, `persist` (bool), `device_name`, `client_version` | `protocol`, `helper_version`, `account` (`"none"` or `"locked"`), `email` |
| `login` | `email` and `password`; or, for the second step, `email` and `totp` (the code of the authenticator app) | `result`: `"ok"` (unlocked), or `"need_two_factor"` with `providers` (`["authenticator"]`) |
| `unlock` | `password` | none |
| `lock` | none | none; the helper then exits |
| `sync` | none | `items` (count), `last_sync` (Unix seconds) |
| `logins_for` | `url` (the document's address), `host`, `domain` (registrable domain, `""` if none) | `rows`: a list of `{id, name, username, uri, match, has_totp}` |
| `fill` | `item` (a row id), `fields` (a list of `"username"`, `"password"`) | `username`, `password` (only the asked fields that the item has) |
| `keepalive` | none | no answer |

A login with a second factor is two requests. The first `login` (email and password) answers `need_two_factor`, and
the helper keeps that email and password. The browser asks the person for the code and sends `login` again with the
same email and `totp` only: the master password crosses the pipe once. A failed second step forgets the kept password;
a new `login` with a password replaces it. (A `login` may also carry `password` and `totp` together.)

### Errors

| Code | Meaning |
|---|---|
| `bad_request` | The frame is not a request of this protocol. |
| `bad_protocol` | `hello` asked for another protocol version. |
| `no_hello` | A request came before `hello`. |
| `bad_server` | A server URL is not `https` (or `http` to `127.0.0.1`, `[::1]`, `localhost`). |
| `bad_credentials` | The server refused the email, the password or the code. The message is the server's. |
| `unsupported_two_factor` | The account asks for a second factor other than an authenticator app. |
| `unsupported_account` | The account does not unlock with a master password (SSO, key connector). |
| `network` | The server cannot be reached or refused the request. |
| `login_failed` | Another login failure. |
| `no_account` | `unlock` without a remembered account. |
| `bad_password` | `unlock` with a wrong master password. |
| `locked` | The request needs an unlocked vault. |
| `sync_failed` | The sync failed. The vault stays unlocked with the items of the last sync. |
| `no_item` | `fill` names an item that is not a login of the vault. |
| `decrypt` | The item cannot be decrypted. |
| `state_write`, `state_format` | The state directory cannot be written, or the saved state cannot be read. |

### Matching

`logins_for` returns the logins with a saved URI that matches the page:

- `Domain` (the default): the URI's host is the page's registrable domain, or a subdomain of it. If the page has no
  registrable domain (an IP address, `localhost`, a public suffix), the `Host` rule applies.
- `Host`: the same host and the same port.
- `StartsWith`, `Exact`, `RegularExpression`, `Never`: no match in this version.
- An item saved for `https` never matches an `http` page. A URI without a scheme is read as `https`.

The helper has no Public Suffix List. The browser sends the registrable domain, and it checks every row again with its
own list before it shows it.

## Security

- The keys stay in this process. Lock is the exit of the process: the operating system frees every page.
- The Bitwarden SDK installs a zeroizing global allocator: freed memory is cleared. Passwords received on the pipe are
  also zeroed after use.
- Linux: no core dump (`RLIMIT_CORE` 0) and `PR_SET_DUMPABLE` 0 (no debugger attach from the same user). Windows: no
  error dialog or error-reporting prompt on a crash. A panic writes a fixed line on standard error.
- The SDK's `tracing` output goes nowhere: the program installs no subscriber.
- The helper connects only to the two configured URLs.

### State on disk

`<state_dir>/state.json`, mode 0600, in a directory of mode 0700, written by a rename. With `persist` false nothing is
written: the account is forgotten when the helper exits.

| Field | Content |
|---|---|
| `email`, `identity_url`, `api_url`, `device_id` | Public. |
| `master_password_unlock` | KDF parameters, salt, and the user key wrapped by the master key. |
| `account_crypto` | The account's private keys, wrapped by the user key. |
| `org_keys` | Organization keys, encrypted for the account. |
| `ciphers` | The items as the server sends them, encrypted. |
| `tokens`, `login_method` | The access and refresh tokens, and the login method that the SDK renews them with. |
| `last_sync` | Time of the last sync. |

Nothing in the file opens the vault without the master password. A stolen refresh token gives access to the encrypted
items on the server.

## Tests

- `cargo test`: the frame codec, the protocol, the matching rules, the state file, and the login against a wiremock
  server on loopback (wrong password, second factor, no server). No test contacts a real server.
- A successful login needs fixtures made once from a test account (prelogin, token and sync answers). They are not in
  the repository yet.
- Manual check before a release that changes the SDK revision: log in with a real account (US and EU), sync, fill.
