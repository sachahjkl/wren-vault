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
    /// The check of the user key the PIN's envelope seals (sdk.rs, `pin_check_of`): a new login of the account keeps
    /// the PIN when its user key gives the same check (the key was not rotated). "" when no PIN is set.
    #[serde(default)]
    pub pin_check: String,
    /// The session ended without the person logging out (the server refused it): only the account's names and its PIN
    /// are kept, for the next login of the same account. Not an account that unlocks: `hello` says none.
    #[serde(default)]
    pub logged_out: bool,
    /// The account's passkeys that can unlock it, as the last sync gave them (the SDK's PRF unlock options: the
    /// credential's id and transports, its private key wrapped by its PRF key, the user key encapsulated to it); null
    /// or empty when none. Nothing in them opens the vault without the authenticator.
    #[serde(default)]
    pub prf_options: Value,
    /// The relying party of the account's passkeys (the web vault's domain), from a passkey login; "" when the account
    /// never logged in with one here (the browser then names it).
    #[serde(default)]
    pub rp_id: String,
}

/// The file of this profile's device identifier (`Store::device`).
pub const DEVICE_FILE: &str = "device.json";

#[derive(Serialize, Deserialize, Default)]
struct DeviceFile {
    device_id: String,
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

    /// This profile's device identifier, from `device.json`; `None` when there is none yet or nothing persists. It
    /// outlives a logout: the account's list of devices keeps one entry for this browser, and the server's "remember
    /// me" of two-step login stays valid for it.
    pub fn device(&self) -> Option<String> {
        let path = self.dir.as_ref()?.join(DEVICE_FILE);
        let bytes = fs::read(path).ok()?;
        let d: DeviceFile = serde_json::from_slice(&bytes).ok()?;
        (!d.device_id.is_empty()).then_some(d.device_id)
    }

    /// Keeps the device identifier (a public value: the server shows it in the account's device list).
    pub fn save_device(&self, id: &str) -> std::io::Result<()> {
        let Some(dir) = &self.dir else { return Ok(()) };
        make_private_dir(dir)?;
        let bytes = serde_json::to_vec(&DeviceFile {
            device_id: id.to_string(),
        })
        .map_err(std::io::Error::other)?;
        let tmp = dir.join(format!("{DEVICE_FILE}.tmp"));
        {
            let mut f = private_file(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, dir.join(DEVICE_FILE))
    }

    /// Deletes the state (logout), and a state of an older version. The device file stays.
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
    fn the_device_outlives_a_wipe() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_str().unwrap(), true);
        assert!(store.device().is_none());
        store.save_device("11111111-2222-3333-4444-555555555555").unwrap();
        store.wipe();
        assert_eq!(store.device().as_deref(), Some("11111111-2222-3333-4444-555555555555"));
        let memory = Store::new("", false);
        memory.save_device("x").unwrap();
        assert!(memory.device().is_none());
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
