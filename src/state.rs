//! The account state on disk: `<state_dir>/state.json`, mode 0600, in a directory of mode 0700.
//!
//! Every value in it is either public (email, server URLs, device id, user id, KDF parameters) or encrypted as the
//! server sends it (wrapped user key, private keys, organization keys, items), or encrypted by the PIN (the PIN's
//! envelope of the user key). The secrets that open the server are not here: `tokens` keeps them. Nothing in it opens
//! the vault without the master password or the PIN.
//!
//! The SDK values are kept as JSON values here: `sdk` gives them their types. This module only stores bytes.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const STATE_FILE: &str = "state.json";
/// Version 2: the tokens left the file for the system store; the PIN's envelope and its try counter came.
pub const STATE_VERSION: u32 = 2;

/// How the account logged in: how the SDK renews its access token.
pub const LOGIN_PASSWORD: &str = "password";
pub const LOGIN_API_KEY: &str = "api_key";

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Saved {
    pub version: u32,
    pub email: String,
    pub identity_url: String,
    pub api_url: String,
    /// The random device identifier made at the first login. Also the account name in the system store.
    pub device_id: String,
    /// The account's id on the server ("" when unknown).
    #[serde(default)]
    pub user_id: String,
    /// `LOGIN_PASSWORD` or `LOGIN_API_KEY`.
    #[serde(default)]
    pub login: String,
    /// The API key's client id (`user.<uuid>`), with `LOGIN_API_KEY`. Its secret is in the system store.
    #[serde(default)]
    pub api_client_id: String,
    /// The SDK's values, opaque here: master password unlock data, account cryptographic state.
    pub master_password_unlock: Value,
    pub account_crypto: Value,
    /// Organization id and its encrypted key, as the sync gives them.
    pub org_keys: Vec<(String, String)>,
    /// The encrypted items of the last sync.
    pub ciphers: Vec<Value>,
    /// Unix time of the last sync, in seconds.
    pub last_sync: i64,
    /// The account's groups of equivalent domains (its own and the server's global ones that it did not exclude), as
    /// the last sync gave them. Public: the server's list is the same for every account.
    #[serde(default)]
    pub equivalent_domains: Vec<Vec<String>>,
    /// The user key sealed by the PIN (the SDK's PIN envelope); null when no PIN is set.
    #[serde(default)]
    pub pin_envelope: Value,
    /// Wrong PINs since the last good one. At `PIN_TRIES` the envelope is deleted.
    #[serde(default)]
    pub pin_failures: u32,
}

/// Wrong PINs that delete the PIN's envelope (README.md, "PIN").
pub const PIN_TRIES: u32 = 5;

impl Saved {
    pub fn has_pin(&self) -> bool {
        !self.pin_envelope.is_null()
    }
}

/// Where the state lives. `None`: in memory only (the browser keeps no profile data).
#[derive(Clone)]
pub struct Store {
    dir: Option<PathBuf>,
}

impl Store {
    pub fn new(dir: &str, persist: bool) -> Store {
        Store {
            dir: (persist && !dir.is_empty()).then(|| PathBuf::from(dir)),
        }
    }

    pub fn persistent(&self) -> bool {
        self.dir.is_some()
    }

    pub fn dir(&self) -> Option<PathBuf> {
        self.dir.clone()
    }

    /// The saved state, if a readable one of this version exists.
    pub fn load(&self) -> Option<Saved> {
        let path = self.dir.as_ref()?.join(STATE_FILE);
        let bytes = zeroize::Zeroizing::new(fs::read(path).ok()?);
        let saved: Saved = serde_json::from_slice(&bytes).ok()?;
        (saved.version == STATE_VERSION).then_some(saved)
    }

    /// Writes the state: a temporary file, then a rename, so a crash leaves the old state or the new one.
    pub fn save(&self, saved: &Saved) -> std::io::Result<()> {
        let Some(dir) = &self.dir else { return Ok(()) };
        make_private_dir(dir)?;
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(saved).map_err(std::io::Error::other)?);
        let tmp = dir.join(format!("{STATE_FILE}.tmp"));
        {
            let mut f = private_file(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, dir.join(STATE_FILE))
    }

    /// Deletes the state (logout), and a state of an older version.
    pub fn wipe(&self) {
        if let Some(dir) = &self.dir {
            let _ = fs::remove_file(dir.join(STATE_FILE));
        }
    }
}

#[cfg(unix)]
pub(crate) fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub(crate) fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    // (Windows: the profile directory's ACL, the user's own, applies)
    fs::create_dir_all(dir)
}

#[cfg(unix)]
pub(crate) fn private_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_and_a_wipe_forgets_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("vault").to_str().unwrap(), true);
        assert!(store.load().is_none());
        let saved = Saved {
            version: STATE_VERSION,
            email: "a@b.c".into(),
            last_sync: 5,
            ..Default::default()
        };
        store.save(&saved).unwrap();
        let back = store.load().unwrap();
        assert_eq!(back.email, "a@b.c");
        assert_eq!(back.last_sync, 5);
        assert!(!back.has_pin());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("vault").join(STATE_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.wipe();
        assert!(store.load().is_none());
    }

    #[test]
    fn a_state_of_another_version_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_str().unwrap(), true);
        store
            .save(&Saved {
                version: 1,
                email: "a@b.c".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(store.load().is_none());
    }

    #[test]
    fn a_store_without_persistence_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_str().unwrap(), false);
        store
            .save(&Saved {
                version: STATE_VERSION,
                ..Default::default()
            })
            .unwrap();
        assert!(!dir.path().join(STATE_FILE).exists());
    }
}
