type: Fixed

**Sessions stay open after unlocking with a PIN**: unlocking restores the login method after `initialize_user_crypto` (which clears `client_id`), so the sync that follows renews the access token instead of failing with `session_expired` and asking for the master password. Login and sync answers also report `passkey` so the browser keeps the passkey unlock option.
