# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each change is a fragment in `changelog.d/` until a release
moves the fragments here.

## [Unreleased]

## [0.5.1] - 2026-11-25

### Fixed
- **Sessions stay open after unlocking with a PIN**: unlocking restores the login method after `initialize_user_crypto` (which clears `client_id`), so the sync that follows renews the access token instead of failing with `session_expired` and asking for the master password. Login and sync answers also report `passkey` so the browser keeps the passkey unlock option.

## [0.5.0] - 2026-11-17

### Added
- **Signed releases for Windows and Linux**: each release publishes the program for Windows x64 and Linux x64, a signed manifest of each (its size and SHA-256), and `SHA256SUMS.txt`; its source is the release's tag. The Linux program runs on glibc 2.36 and later. Wren downloads or ships the release it names, and checks it.
- **The vault's passkeys sign in to sites**: `passkeys_for` lists the vault's passkeys of a site (and of the page's allow list), and `passkey_assert` signs the page's request with the one the person picked, by the Bitwarden SDK's authenticator. A passkey with a sign counter keeps its count on the server. A refused signature is the error `assert_failed`.
- **Remembered unlock**: `remember_unlock` keeps the open vault's user key in the system's keyring only (`session`: until the computer restarts, `always`, `never`), and `unlock` with `remembered` opens the vault from it. A key of another boot, or one that no longer opens, is deleted (`not_remembered`); without a keyring, `no_keyring`. A logout deletes it.
- **Protocol 5: save logins, generate passwords, cards and identities**: `save` creates a login or updates one on the server, and the browser sees it at once without a sync; `generate` makes a password or a passphrase, also while the vault is locked; `search` lists cards (brand and last 4 digits) and identities (name or email) besides logins, every row says its kind, and `fill` gives the fields of a card or an identity. `search` pages through a long list (`offset`, `limit` up to 500, `kinds`) and says how many items match in all: a vault of any size can be listed. A refused save is the error `save_failed`. Protocol 4 browsers are refused.
- **Protocol 3: search, TOTP codes, more match rules**: `search` lists the logins whose name, user name or address hold the words typed (no password); `totp` and `fill` with `"totp"` give the current code of a login's TOTP key, computed by the SDK; `logins_for` applies the `StartsWith` and `Exact` rules and the account's equivalent domains, which the sync now keeps. Protocol 2 browsers are refused.
- **Protocol 2: the rest of a session's life**: EU and self-hosted servers work as the US server does; the login takes an email code (sent on request) as well as an authenticator code, and the new-device code that the server mails; a personal API key logs in for accounts whose second step is not supported; a PIN unlocks the account (5 wrong PINs remove it); `logout` forgets the account, its tokens and its PIN; the helper locks itself (it exits) at the idle deadline that the browser gives, unless a `keepalive` comes. Protocol 1 browsers are refused.
- **The first helper**: wren-vault serves the pipe protocol version 1 to the Wren browser: log in to a Bitwarden® account with the master password and an authenticator code, unlock the remembered account, sync, list the logins of a page, and give one login's user name and password for a fill. Lock is the exit of the program.
- **Protocol 4: more ways to log in**: a login approved from another device of the account (`device_request`, `device_poll`), a login or an unlock with a passkey and its PRF output (`passkey_options`, `login_passkey`, `unlock` with `prf`), the master password hint by mail (`password_hint`), and "remember this device" for the second step (`login` with `remember`).

### Changed
- **A login keeps the account's PIN**: a new login of the same account on the same server keeps its PIN while its user key is the one the PIN seals (`pin_check`); the login answers say `pin`. `logout` takes `keep_pin` for a session the server ended. A logout asked for, another account or a rotated key removes it.
- **A truthful device**: the helper sends its own token request, with device type 14 (a browser unknown to the server by name), client id `web`, the device name of `hello` and the account's own random device identifier, instead of the SDK's `ChromeBrowser` and its shared identifier.
- **Tokens in the system store**: the refresh token and an API key's client secret go to the Secret Service on Linux or the Credential Manager on Windows, or to `tokens.json` (mode 0600) when no store answers; the access token is no longer stored. The state file moves to version 2: a state of version 1 is not read, and the account logs in again.

### Fixed
- **The session survives a renewal**: the refresh token the server gives at each renewal of the access token is kept after every request, not only after a sync that succeeded; a session the server refuses (401) is the error `session_expired`.
- **Logins refused for a missing client version**: every token request now carries the `Bitwarden-Client-Version` header, without which the server answers "No client version header found".
- **Logging in with a password works**: the token request now carries the account's email in the `Auth-Email` header, which the Bitwarden server requires; without it, every password login was refused.

[Unreleased]: https://github.com/sachahjkl/wren-vault/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/sachahjkl/wren-vault/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/sachahjkl/wren-vault/releases/tag/v0.5.0
