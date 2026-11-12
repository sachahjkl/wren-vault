//! The secrets that open the account on the server: the refresh token, and the client secret of a personal API key.
//! They stay out of `state.json` (README.md, "State on disk"):
//!
//! - in the system store when one answers: the Secret Service on Linux (GNOME Keyring, KWallet), the Credential Manager
//!   on Windows (DPAPI, bound to the user's account);
//! - else in `tokens.json` beside the state, mode 0600: the level of a browser without a keyring;
//! - in memory only when the state does not persist (then nothing is written).
//!
//! The access token is never stored: it lives an hour, and the SDK renews it with the refresh token (or the API key)
//! at the first request after an unlock.
//!
//! The system store blocks (D-Bus, Win32): every call of this module runs on a blocking thread of the runtime.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The service name of the entries in the system store. The account name is the device identifier of the login.
pub const SERVICE: &str = "wren-vault";
/// The file of the secrets when no system store answers.
pub const TOKENS_FILE: &str = "tokens.json";

/// The secrets of one account. Zeroed when dropped.
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct Secrets {
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        if let Some(t) = &mut self.refresh_token {
            t.zeroize();
        }
        if let Some(s) = &mut self.client_secret {
            s.zeroize();
        }
    }
}

/// The file of the remembered two-step tokens when no system store answers.
pub const REMEMBER_FILE: &str = "remember.json";

/// The account name of the remembered two-step tokens in the system store: they are this device's, not one login's,
/// and a logout keeps them (the server's "remember me" is for the device, as in Bitwarden's own clients).
pub fn remember_account(device: &str) -> String {
    format!("{device}.remember")
}

/// The two-step tokens that the server gave this device, one per account (the email in lower case). Zeroed when
/// dropped.
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct Remembered {
    #[serde(default)]
    pub tokens: Vec<(String, String)>,
}

impl Remembered {
    pub fn token_of(&self, email: &str) -> Option<&str> {
        let key = email.to_lowercase();
        self.tokens.iter().find(|(e, _)| *e == key).map(|(_, t)| t.as_str())
    }

    /// Sets (`Some`) or forgets (`None`) the token of `email`.
    pub fn set(&mut self, email: &str, token: Option<&str>) {
        let key = email.to_lowercase();
        self.tokens.retain(|(e, _)| *e != key);
        if let Some(t) = token {
            self.tokens.push((key, t.to_string()));
        }
    }
}

impl Drop for Remembered {
    fn drop(&mut self) {
        for (_, t) in &mut self.tokens {
            t.zeroize();
        }
    }
}

/// A store of the system that keeps one text per account. `Err` means it did not answer or refused.
pub trait SystemStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<String>, ()>;
    fn set(&self, account: &str, value: &str) -> Result<(), ()>;
    fn delete(&self, account: &str) -> Result<(), ()>;
}

/// Where `save` put the secrets.
#[derive(Debug, PartialEq, Eq)]
pub enum Place {
    System,
    File,
    Memory,
}

/// The secrets' store of one state directory. Cheap to clone: the blocking calls take a clone.
#[derive(Clone, Default)]
pub struct TokenStore {
    /// The state directory; `None`: nothing persists.
    dir: Option<PathBuf>,
    /// The system store, looked for at the first use (connecting to it blocks).
    system: Arc<OnceLock<Option<Arc<dyn SystemStore>>>>,
}

impl TokenStore {
    pub fn new(dir: Option<PathBuf>) -> TokenStore {
        TokenStore {
            dir,
            system: Arc::new(OnceLock::new()),
        }
    }

    /// A store with a given system store (`None`: none answers). For tests.
    pub fn with_system(dir: Option<PathBuf>, system: Option<Arc<dyn SystemStore>>) -> TokenStore {
        let cell = OnceLock::new();
        let _ = cell.set(system);
        TokenStore {
            dir,
            system: Arc::new(cell),
        }
    }

    fn system(&self) -> Option<Arc<dyn SystemStore>> {
        self.system.get_or_init(platform_store).clone()
    }

    /// The secrets of `account`: the system store's first, else the file's. Blocks.
    pub fn load(&self, account: &str) -> Option<Secrets> {
        self.load_as(account, TOKENS_FILE)
    }

    /// Keeps the secrets of `account`: in the system store when it takes them (and the file goes), else in the file.
    /// Blocks.
    pub fn save(&self, account: &str, secrets: &Secrets) -> std::io::Result<Place> {
        self.save_as(account, TOKENS_FILE, secrets)
    }

    /// Forgets the secrets of `account` in both places (logout). Blocks.
    pub fn wipe(&self, account: &str) {
        self.wipe_as(account, TOKENS_FILE)
    }

    /// The tokens of two-step logins that the server remembers for this device (`remember_account`). Blocks.
    pub fn load_remembered(&self, device: &str) -> Remembered {
        self.load_as(&remember_account(device), REMEMBER_FILE)
            .unwrap_or_default()
    }

    /// Keeps them (an empty list: they go). Blocks.
    pub fn save_remembered(&self, device: &str, r: &Remembered) -> std::io::Result<Place> {
        if r.tokens.is_empty() {
            self.wipe_as(&remember_account(device), REMEMBER_FILE);
            return Ok(Place::Memory);
        }
        self.save_as(&remember_account(device), REMEMBER_FILE, r)
    }

    fn load_as<T: serde::de::DeserializeOwned>(&self, account: &str, file_name: &str) -> Option<T> {
        let dir = self.dir.as_ref()?;
        if let Some(system) = self.system()
            && let Ok(Some(text)) = system.get(account)
        {
            let text = Zeroizing::new(text);
            if let Ok(s) = serde_json::from_str::<T>(&text) {
                return Some(s);
            }
        }
        let bytes = Zeroizing::new(fs::read(dir.join(file_name)).ok()?);
        serde_json::from_slice::<T>(&bytes).ok()
    }

    fn save_as<T: Serialize>(&self, account: &str, file_name: &str, value: &T) -> std::io::Result<Place> {
        let Some(dir) = self.dir.as_ref() else {
            return Ok(Place::Memory);
        };
        let file = dir.join(file_name);
        let text = Zeroizing::new(serde_json::to_string(value).map_err(std::io::Error::other)?);
        if let Some(system) = self.system()
            && system.set(account, &text).is_ok()
        {
            let _ = fs::remove_file(&file);
            return Ok(Place::System);
        }
        crate::state::make_private_dir(dir)?;
        let tmp = dir.join(format!("{file_name}.tmp"));
        {
            let mut f = crate::state::private_file(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &file)?;
        Ok(Place::File)
    }

    fn wipe_as(&self, account: &str, file_name: &str) {
        let Some(dir) = self.dir.as_ref() else { return };
        if let Some(system) = self.system() {
            let _ = system.delete(account);
        }
        let _ = fs::remove_file(dir.join(file_name));
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
}

/// A store of keyring-core (the platform's).
struct Keyring {
    inner: Arc<keyring_core::CredentialStore>,
}

impl Keyring {
    fn entry(&self, account: &str) -> Result<keyring_core::Entry, ()> {
        self.inner.build(SERVICE, account, None).map_err(|_| ())
    }
}

impl SystemStore for Keyring {
    fn get(&self, account: &str) -> Result<Option<String>, ()> {
        match self.entry(account)?.get_password() {
            Ok(text) => Ok(Some(text)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(_) => Err(()),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<(), ()> {
        self.entry(account)?.set_password(value).map_err(|_| ())
    }

    fn delete(&self, account: &str) -> Result<(), ()> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_store() -> Option<Arc<dyn SystemStore>> {
    // (no session bus, or no Secret Service on it: None, and the file takes the secrets)
    let store = dbus_secret_service_keyring_store::Store::new().ok()?;
    let inner: Arc<keyring_core::CredentialStore> = store;
    Some(Arc::new(Keyring { inner }))
}

#[cfg(windows)]
fn platform_store() -> Option<Arc<dyn SystemStore>> {
    let store = windows_native_keyring_store::Store::new().ok()?;
    let inner: Arc<keyring_core::CredentialStore> = store;
    Some(Arc::new(Keyring { inner }))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn platform_store() -> Option<Arc<dyn SystemStore>> {
    None
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    /// A system store in memory, or one that refuses everything (`down`).
    #[derive(Default)]
    struct Fake {
        down: bool,
        entries: Mutex<HashMap<String, String>>,
    }

    impl SystemStore for Fake {
        fn get(&self, account: &str) -> Result<Option<String>, ()> {
            if self.down {
                return Err(());
            }
            Ok(self.entries.lock().unwrap().get(account).cloned())
        }
        fn set(&self, account: &str, value: &str) -> Result<(), ()> {
            if self.down {
                return Err(());
            }
            self.entries.lock().unwrap().insert(account.into(), value.into());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<(), ()> {
            if self.down {
                return Err(());
            }
            self.entries.lock().unwrap().remove(account);
            Ok(())
        }
    }

    fn secrets() -> Secrets {
        Secrets {
            refresh_token: Some("refresh".into()),
            client_secret: None,
        }
    }

    #[test]
    fn the_system_store_takes_the_secrets_and_no_file_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::default());
        let store = TokenStore::with_system(Some(dir.path().to_path_buf()), Some(fake.clone()));
        assert_eq!(store.save("device", &secrets()).unwrap(), Place::System);
        assert!(!dir.path().join(TOKENS_FILE).exists());
        assert!(store.load("device") == Some(secrets()));
        store.wipe("device");
        assert!(store.load("device").is_none());
        assert!(fake.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn without_a_system_store_the_secrets_go_to_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("vault");
        for system in [
            None,
            Some(Arc::new(Fake {
                down: true,
                ..Default::default()
            }) as Arc<dyn SystemStore>),
        ] {
            let store = TokenStore::with_system(Some(state.clone()), system);
            assert_eq!(store.save("device", &secrets()).unwrap(), Place::File);
            assert!(store.load("device") == Some(secrets()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(state.join(TOKENS_FILE)).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            store.wipe("device");
            assert!(!state.join(TOKENS_FILE).exists());
            assert!(store.load("device").is_none());
        }
    }

    #[test]
    fn a_system_store_that_comes_back_replaces_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let down = TokenStore::with_system(Some(path.clone()), None);
        down.save("device", &secrets()).unwrap();
        assert!(path.join(TOKENS_FILE).exists());
        let up = TokenStore::with_system(Some(path.clone()), Some(Arc::new(Fake::default())));
        assert_eq!(up.save("device", &secrets()).unwrap(), Place::System);
        assert!(!path.join(TOKENS_FILE).exists());
    }

    #[test]
    fn remembered_two_step_tokens_outlive_a_logout() {
        let dir = tempfile::tempdir().unwrap();
        for system in [None, Some(Arc::new(Fake::default()) as Arc<dyn SystemStore>)] {
            let store = TokenStore::with_system(Some(dir.path().to_path_buf()), system);
            let mut r = store.load_remembered("device");
            assert!(r.token_of("a@b.c").is_none());
            r.set("A@B.c", Some("tok"));
            store.save_remembered("device", &r).unwrap();
            store.save("device", &secrets()).unwrap();
            store.wipe("device");
            assert_eq!(store.load_remembered("device").token_of("a@b.C"), Some("tok"));
            r.set("a@b.c", None);
            store.save_remembered("device", &r).unwrap();
            assert!(store.load_remembered("device").token_of("a@b.c").is_none());
            assert!(!dir.path().join(REMEMBER_FILE).exists());
        }
    }

    #[test]
    fn nothing_is_written_without_persistence() {
        let fake = Arc::new(Fake::default());
        let store = TokenStore::with_system(None, Some(fake.clone()));
        assert_eq!(store.save("device", &secrets()).unwrap(), Place::Memory);
        assert!(fake.entries.lock().unwrap().is_empty());
        assert!(store.load("device").is_none());
    }
}
