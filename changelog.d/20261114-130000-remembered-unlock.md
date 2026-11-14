type: Added

**Remembered unlock**: `remember_unlock` keeps the open vault's user key in the system's keyring only (`session`: until the computer restarts, `always`, `never`), and `unlock` with `remembered` opens the vault from it. A key of another boot, or one that no longer opens, is deleted (`not_remembered`); without a keyring, `no_keyring`. A logout deletes it.
