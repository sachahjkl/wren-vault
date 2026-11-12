//! Every call to the Bitwarden SDK (sdk-internal at the revision of Cargo.toml). No other module names an SDK type: a
//! new SDK revision changes this file only.
//!
//! A session is one account. Logging in or unlocking makes an SDK client that holds the keys; locking is the exit of
//! the process (README.md, "Lock is process exit").
//!
//! The token request is the helper's own (`identity`): the SDK's sends another device type, a shared device identifier
//! and no new-device code. The rest (prelogin, the master password hash, sync, keys, PIN, items) is the SDK's.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_core::{
    Client, ClientBuilder, ClientSettings, DeviceType, OrganizationId,
    auth::{JwtToken, login::TwoFactorEmailRequest},
    client::{
        login_method::UserLoginMethod,
        persisted_state::{AUTHENTICATION_TOKENS, AuthenticationTokens, USER_LOGIN_METHOD},
    },
    key_management::{
        MasterPasswordAuthenticationData, MasterPasswordUnlockData,
        account_cryptographic_state::WrappedAccountCryptographicState,
        crypto::{InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest},
    },
};
use bitwarden_crypto::{Kdf, UnsignedSharedKey, safe::PasswordProtectedKeyEnvelope};
use bitwarden_crypto_sync_handler::CryptoSyncData;
use bitwarden_sync::{SyncClientExt, SyncHandler, SyncHandlerError, SyncRequest};
use bitwarden_vault::{Cipher, CipherType, CipherView, UriMatchType, VaultClientExt, generate_totp};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    HELPER_VERSION,
    identity::{self, CLIENT_ID, Device, Second, TokenAnswer},
    matching::{self, Page, Rule},
    protocol::Row,
    state::{LOGIN_API_KEY, LOGIN_PASSWORD, PIN_TRIES, STATE_VERSION, Saved, Store},
    tokens::{Secrets, TokenStore},
};

/// A failed request: a stable code (README.md, "Errors") and a sentence for the person. Never a secret.
#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
    /// `bad_pin`: the wrong PINs that remain before the PIN is removed.
    pub tries_left: Option<u32>,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Failure {
        Failure {
            code,
            message: message.into(),
            tries_left: None,
        }
    }
}

fn no_hello() -> Failure {
    Failure::new("no_hello", "hello first")
}

fn locked() -> Failure {
    Failure::new("locked", "The vault is locked.")
}

fn no_account() -> Failure {
    Failure::new("no_account", "No account is remembered: log in.")
}

/// The server and the client identity that `hello` gave.
#[derive(Clone)]
pub struct Config {
    pub identity_url: String,
    pub api_url: String,
    pub client_version: String,
    /// The device name that the account's device list shows ("Wren" when the browser gave none).
    pub device_name: String,
}

/// What `hello` says about the remembered account.
pub struct Account {
    /// "none" or "locked".
    pub state: &'static str,
    pub email: String,
    /// "password" or "api_key": how the account logged in.
    pub login: &'static str,
    /// A PIN can unlock it.
    pub pin: bool,
}

/// One `login` request: a first step (a password), a second step (a code and its provider), or a code sent again.
#[derive(Clone, Copy, Default)]
pub struct LoginRequest<'a> {
    pub email: &'a str,
    pub password: Option<&'a str>,
    pub code: Option<&'a str>,
    /// "authenticator" (the default), "email" or "device".
    pub provider: Option<&'a str>,
    pub resend: bool,
}

/// What a login gave.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    Done,
    /// The account asks for a second step: the providers that the helper can use ("authenticator", "email").
    /// `email_sent`: the server mailed a code already (email is the account's only provider).
    NeedTwoFactor {
        providers: Vec<&'static str>,
        email_sent: bool,
    },
    /// The account must confirm this new device with the code that the server mailed.
    NeedDeviceCode,
}

/// How `unlock` opens the keys.
#[derive(Clone, Copy)]
pub enum Unlock<'a> {
    Password(&'a str),
    Pin(&'a str),
}

/// The values of one login for a fill or a copy. Zeroed when dropped.
#[derive(Default)]
pub struct Values {
    pub username: Option<String>,
    pub password: Option<String>,
    /// The current code of the login's TOTP key.
    pub totp: Option<String>,
}

impl Drop for Values {
    fn drop(&mut self) {
        for v in [&mut self.username, &mut self.password, &mut self.totp]
            .into_iter()
            .flatten()
        {
            v.zeroize();
        }
    }
}

/// A TOTP code and how long it stays valid.
pub struct Code {
    pub code: Zeroizing<String>,
    /// The key's period, in seconds.
    pub period: u32,
    /// The seconds left in the current period (1 to `period`).
    pub remaining: u32,
}

/// The most rows that `search` returns when the browser names no bound, and the most it ever returns: the browser
/// shows them in its palette, which needs a short list.
pub const SEARCH_LIMIT: usize = 50;

/// A password login that waits for its second step: what the next `login` needs.
struct Waiting {
    email: String,
    password: String,
    device_id: String,
    providers: Vec<&'static str>,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.email.zeroize();
        self.password.zeroize();
    }
}

/// How a login renews its access token.
enum Login {
    Password,
    ApiKey {
        client_id: String,
        client_secret: Zeroizing<String>,
    },
}

/// The account of this helper.
pub struct Session {
    store: Store,
    tokens: TokenStore,
    config: Option<Config>,
    /// The remembered account (also kept in memory when the store does not persist).
    saved: Option<Saved>,
    /// The SDK client while the vault is unlocked.
    client: Option<Client>,
    /// The encrypted items of the last sync.
    ciphers: Vec<Cipher>,
    /// The account's groups of equivalent domains, from the last sync.
    domains: Vec<Vec<String>>,
    /// A login that waits for its second step.
    waiting: Option<Waiting>,
    /// The secrets last written to the token store (they are written again only when they change).
    secrets: Option<Secrets>,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            store: Store::new("", false),
            tokens: TokenStore::new(None),
            config: None,
            saved: None,
            client: None,
            ciphers: Vec::new(),
            domains: Vec::new(),
            waiting: None,
            secrets: None,
        }
    }
}

/// `https`, or `http` to a loopback host (tests and a server on this machine).
pub fn server_url_allowed(u: &str) -> bool {
    let Ok(p) = url::Url::parse(u) else { return false };
    match p.scheme() {
        "https" => p.host_str().is_some(),
        "http" => matches!(p.host_str(), Some("127.0.0.1") | Some("[::1]") | Some("localhost")),
        _ => false,
    }
}

/// Runs a call that blocks (the system store, a file) on a blocking thread of the runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

impl Session {
    pub fn configured(&self) -> bool {
        self.config.is_some()
    }

    pub fn unlocked(&self) -> bool {
        self.client.is_some()
    }

    /// `hello`: the server and the state directory.
    pub fn hello(&mut self, mut config: Config, state_dir: &str, persist: bool) -> Result<Account, Failure> {
        if !server_url_allowed(&config.identity_url) || !server_url_allowed(&config.api_url) {
            return Err(Failure::new(
                "bad_server",
                "The server address must use https (or http to this machine).",
            ));
        }
        if config.device_name.trim().is_empty() {
            config.device_name = "Wren".into();
        }
        self.store = Store::new(state_dir, persist);
        self.tokens = TokenStore::new(self.store.dir());
        let saved = self
            .store
            .load()
            .filter(|s| s.identity_url == config.identity_url && s.api_url == config.api_url);
        self.config = Some(config);
        self.saved = saved;
        Ok(match &self.saved {
            Some(s) => Account {
                state: "locked",
                email: s.email.clone(),
                login: if s.login == LOGIN_API_KEY {
                    LOGIN_API_KEY
                } else {
                    LOGIN_PASSWORD
                },
                pin: s.has_pin(),
            },
            None => Account {
                state: "none",
                email: String::new(),
                login: LOGIN_PASSWORD,
                pin: false,
            },
        })
    }

    fn forget_waiting(&mut self) {
        self.waiting = None; // (zeroed by its drop)
    }

    /// The device identifier for a login of `email`: the remembered one of that account, else a new one.
    fn device_for(&self, email: &str) -> String {
        self.saved
            .as_ref()
            .filter(|s| s.email.eq_ignore_ascii_case(email))
            .map(|s| s.device_id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }

    /// `login`. A first step carries the password; a second step the code and its provider (the password is the one
    /// the helper kept); `resend` asks for a new code.
    pub async fn login(&mut self, req: LoginRequest<'_>) -> Result<LoginOutcome, Failure> {
        let config = self.config.clone().ok_or_else(no_hello)?;
        let (password, device_id, providers) = match req.password {
            Some(p) => {
                self.forget_waiting();
                (Zeroizing::new(p.to_string()), self.device_for(req.email), Vec::new())
            }
            None => match self.waiting.take() {
                Some(mut w) if w.email.eq_ignore_ascii_case(req.email) && (req.code.is_some() || req.resend) => (
                    Zeroizing::new(std::mem::take(&mut w.password)),
                    std::mem::take(&mut w.device_id),
                    std::mem::take(&mut w.providers),
                ),
                other => {
                    self.waiting = other;
                    return Err(Failure::new("bad_request", "A login needs the master password."));
                }
            },
        };
        if req.resend && req.provider == Some("email") {
            let client = new_client(&config, &device_id);
            let request = TwoFactorEmailRequest {
                password: password.to_string(),
                email: req.email.to_string(),
            };
            let sent = client.auth().send_two_factor_email(&request).await;
            drop(request); // (the zeroizing allocator clears the password's memory)
            if sent.is_err() {
                return Err(Failure::new("network", "The server did not send the code."));
            }
            self.waiting = Some(Waiting {
                email: req.email.to_string(),
                password: password.to_string(),
                device_id,
                providers: providers.clone(),
            });
            return Ok(LoginOutcome::NeedTwoFactor {
                providers,
                email_sent: true,
            });
        }
        let code = req.code.map(str::trim);
        let second = match (code, req.provider) {
            (Some(c), Some("device")) => Some(Second::DeviceCode(c)),
            (Some(c), p) => Some(Second::TwoFactor {
                provider: p.and_then(identity::provider_id).unwrap_or(0),
                code: c,
            }),
            (None, _) => None,
        };
        let result = self
            .password_step(&config, req.email, &password, second.as_ref(), device_id.clone())
            .await;
        match &result {
            Ok(LoginOutcome::NeedTwoFactor { providers, .. }) => {
                self.waiting = Some(Waiting {
                    email: req.email.to_string(),
                    password: password.to_string(),
                    device_id,
                    providers: providers.clone(),
                })
            }
            Ok(LoginOutcome::NeedDeviceCode) => {
                self.waiting = Some(Waiting {
                    email: req.email.to_string(),
                    password: password.to_string(),
                    device_id,
                    providers: Vec::new(),
                })
            }
            _ => {}
        }
        result
    }

    /// One token request with the master password, then on success the sync and the keys.
    async fn password_step(
        &mut self,
        config: &Config,
        email: &str,
        password: &str,
        second: Option<&Second<'_>>,
        device_id: String,
    ) -> Result<LoginOutcome, Failure> {
        let client = new_client(config, &device_id);
        let kdf = client.auth().prelogin(email.to_string()).await.map_err(|_| {
            Failure::new(
                "network",
                "The server cannot be reached, or it does not know this account.",
            )
        })?;
        let hash = {
            let auth = MasterPasswordAuthenticationData::derive(password, &kdf, email)
                .map_err(|_| Failure::new("unsupported_account", "The account's key settings are not supported."))?;
            Zeroizing::new(auth.master_password_authentication_hash.to_string())
        };
        let form = identity::password_form(
            email,
            &hash,
            &Device {
                identifier: &device_id,
                name: &config.device_name,
            },
            second,
        );
        match token_request(&client, &form).await? {
            TokenAnswer::Tokens {
                access_token,
                refresh_token,
                expires_in,
            } => {
                set_tokens(&client, access_token, refresh_token, expires_in).await;
                self.finish_login(config, client, device_id, Some(email), password, Login::Password)
                    .await?;
                Ok(LoginOutcome::Done)
            }
            TokenAnswer::TwoFactor { providers } if providers.is_empty() => Err(Failure::new(
                "unsupported_two_factor",
                "This account asks for a second step that the Vault does not support (Duo, a security key, YubiKey). Add an authenticator app or the email code to the account, or log in with its API key.",
            )),
            TokenAnswer::TwoFactor { providers } => {
                let email_sent = providers == ["email"];
                Ok(LoginOutcome::NeedTwoFactor { providers, email_sent })
            }
            TokenAnswer::DeviceCode => Ok(LoginOutcome::NeedDeviceCode),
            TokenAnswer::Refused(message) => Err(Failure::new("bad_credentials", message)),
            TokenAnswer::Unexpected => Err(Failure::new(
                "login_failed",
                "The server's answer to the login is not understood.",
            )),
        }
    }

    /// `login_api_key`: the account's personal API key, then the master password for the keys. Returns the email.
    pub async fn login_api_key(
        &mut self,
        client_id: &str,
        client_secret: &str,
        password: &str,
    ) -> Result<String, Failure> {
        let config = self.config.clone().ok_or_else(no_hello)?;
        self.forget_waiting();
        let client_id = client_id.trim();
        let device_id = self
            .saved
            .as_ref()
            .filter(|s| s.login == LOGIN_API_KEY && s.api_client_id == client_id)
            .map(|s| s.device_id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let client = new_client(&config, &device_id);
        let form = identity::api_key_form(
            client_id,
            client_secret.trim(),
            &Device {
                identifier: &device_id,
                name: &config.device_name,
            },
        );
        match token_request(&client, &form).await? {
            TokenAnswer::Tokens {
                access_token,
                refresh_token,
                expires_in,
            } => {
                set_tokens(&client, access_token, refresh_token, expires_in).await;
                let login = Login::ApiKey {
                    client_id: client_id.to_string(),
                    client_secret: Zeroizing::new(client_secret.trim().to_string()),
                };
                self.finish_login(&config, client, device_id, None, password, login)
                    .await
            }
            TokenAnswer::Refused(message) => Err(Failure::new("bad_credentials", message)),
            TokenAnswer::TwoFactor { .. } | TokenAnswer::DeviceCode | TokenAnswer::Unexpected => Err(Failure::new(
                "login_failed",
                "The server's answer to the API key login is not understood.",
            )),
        }
    }

    /// After the tokens: the sync, the keys with the master password, the state. Returns the account's email.
    async fn finish_login(
        &mut self,
        config: &Config,
        client: Client,
        device_id: String,
        email: Option<&str>,
        password: &str,
        login: Login,
    ) -> Result<String, Failure> {
        let captured = sync_capture(&client).await?;
        let unlock = captured
            .crypto
            .user_decryption
            .as_ref()
            .and_then(|d| d.master_password_unlock.clone())
            .ok_or_else(|| {
                Failure::new(
                    "unsupported_account",
                    "This account does not unlock with a master password.",
                )
            })?;
        let account_crypto = captured
            .crypto
            .account_cryptographic_state
            .clone()
            .ok_or_else(|| Failure::new("unsupported_account", "The server sent no account keys."))?;
        let email = match email {
            Some(e) => e.to_string(),
            None => captured
                .email
                .clone()
                .ok_or_else(|| Failure::new("login_failed", "The server sent no email for this account."))?,
        };
        let state = client.platform().state();
        let user_id = state
            .value::<AUTHENTICATION_TOKENS>()
            .try_get()
            .await
            .ok()
            .flatten()
            .and_then(|t| t.access_token.parse::<JwtToken>().ok())
            .map(|j| j.sub)
            .unwrap_or_default();
        let request = InitUserCryptoRequest {
            user_id: user_id.parse().ok(),
            kdf_params: unlock.kdf.clone(),
            email: email.clone(),
            account_cryptographic_state: account_crypto.clone(),
            method: InitUserCryptoMethod::MasterPasswordUnlock {
                password: password.to_string(),
                master_password_unlock: unlock.clone(),
            },
            upgrade_token: None,
        };
        client
            .crypto()
            .initialize_user_crypto(request)
            .await
            .map_err(|_| Failure::new("bad_password", "The master password does not open this account's keys."))?;
        let (kind, api_client_id, method) = match login {
            Login::Password => (
                LOGIN_PASSWORD,
                String::new(),
                UserLoginMethod::Username {
                    client_id: CLIENT_ID.to_string(),
                    email: email.clone(),
                    kdf: unlock.kdf.clone(),
                },
            ),
            Login::ApiKey {
                client_id,
                client_secret,
            } => (
                LOGIN_API_KEY,
                client_id.clone(),
                UserLoginMethod::ApiKey {
                    client_id,
                    client_secret: client_secret.to_string(),
                    email: email.clone(),
                    kdf: unlock.kdf.clone(),
                },
            ),
        };
        let _ = state.value::<USER_LOGIN_METHOD>().set(method).await;
        init_organizations(&client, &captured.org_keys).await;
        // a former account of this state (another server, another login) leaves its secrets behind it
        if let Some(old) = self.store.load().or_else(|| self.saved.clone())
            && old.device_id != device_id
        {
            let tokens = self.tokens.clone();
            blocking(move || tokens.wipe(&old.device_id)).await;
        }
        let mut saved = Saved {
            version: STATE_VERSION,
            email: email.clone(),
            identity_url: config.identity_url.clone(),
            api_url: config.api_url.clone(),
            device_id,
            user_id,
            login: kind.to_string(),
            api_client_id,
            master_password_unlock: to_value(&unlock)?,
            account_crypto: to_value(&account_crypto)?,
            ..Default::default()
        };
        self.secrets = None;
        self.ciphers = captured.ciphers;
        self.domains = captured.domains;
        self.client = Some(client);
        self.remember(&mut saved, captured.org_keys).await?;
        Ok(email)
    }

    /// `unlock`: the master password or the PIN of the remembered account.
    pub async fn unlock(&mut self, with: Unlock<'_>) -> Result<(), Failure> {
        if self.client.is_some() {
            return Ok(());
        }
        let config = self.config.clone().ok_or_else(no_hello)?;
        let mut saved = self.saved.clone().ok_or_else(no_account)?;
        let unlock: MasterPasswordUnlockData = from_value(&saved.master_password_unlock)?;
        let account_crypto: WrappedAccountCryptographicState = from_value(&saved.account_crypto)?;
        let method = match with {
            Unlock::Password(password) => InitUserCryptoMethod::MasterPasswordUnlock {
                password: password.to_string(),
                master_password_unlock: unlock.clone(),
            },
            Unlock::Pin(pin) => {
                if !saved.has_pin() {
                    return Err(Failure::new(
                        "no_pin",
                        "No PIN is set: unlock with the master password.",
                    ));
                }
                let envelope: PasswordProtectedKeyEnvelope = from_value(&saved.pin_envelope)?;
                InitUserCryptoMethod::PinEnvelope {
                    pin: pin.to_string(),
                    pin_protected_user_key_envelope: envelope,
                }
            }
        };
        let tokens = self.tokens.clone();
        let account = saved.device_id.clone();
        let secrets = blocking(move || tokens.load(&account))
            .await
            .flatten()
            .unwrap_or_default();
        let client = new_client(&config, &saved.device_id);
        let state = client.platform().state();
        // (no access token: the SDK renews it with the refresh token, or the API key, at the first request)
        let _ = state
            .value::<AUTHENTICATION_TOKENS>()
            .set(AuthenticationTokens {
                access_token: String::new(),
                refresh_token: secrets.refresh_token.clone(),
                expires_on: 0,
            })
            .await;
        if let Some(method) = login_method(&saved, &unlock.kdf, &secrets) {
            let _ = state.value::<USER_LOGIN_METHOD>().set(method).await;
        }
        let request = InitUserCryptoRequest {
            user_id: saved.user_id.parse().ok(),
            kdf_params: unlock.kdf.clone(),
            email: saved.email.clone(),
            account_cryptographic_state: account_crypto,
            method,
            upgrade_token: None,
        };
        let opened = client.crypto().initialize_user_crypto(request).await.is_ok();
        if let Unlock::Pin(_) = with {
            if !opened {
                let failure = count_wrong_pin(&mut saved);
                let _ = self.store.save(&saved);
                self.saved = Some(saved);
                return Err(failure);
            }
            if saved.pin_failures > 0 {
                saved.pin_failures = 0;
                let _ = self.store.save(&saved);
            }
        } else if !opened {
            return Err(Failure::new("bad_password", "The master password is wrong."));
        }
        init_organizations(&client, &saved.org_keys).await;
        self.ciphers = saved
            .ciphers
            .iter()
            .filter_map(|c| serde_json::from_value(c.clone()).ok())
            .collect();
        self.domains = saved.equivalent_domains.clone();
        self.client = Some(client);
        self.secrets = Some(secrets);
        self.saved = Some(saved);
        Ok(())
    }

    /// `pin_set`: a PIN that unlocks this account on this machine. The SDK seals the user key with it.
    pub fn pin_set(&mut self, pin: &str) -> Result<(), Failure> {
        let client = self.client.as_ref().ok_or_else(locked)?;
        if !self.store.persistent() {
            return Err(Failure::new(
                "no_state",
                "A PIN needs a profile that keeps its data between runs.",
            ));
        }
        if pin.chars().count() < 4 {
            return Err(Failure::new("bad_request", "A PIN has at least 4 characters."));
        }
        let mut saved = self.saved.clone().ok_or_else(no_account)?;
        let enrolled = client
            .crypto()
            .enroll_pin(pin.to_string())
            .map_err(|_| Failure::new("decrypt", "The PIN cannot be set."))?;
        saved.pin_envelope = to_value(&enrolled.pin_protected_user_key_envelope)?;
        saved.pin_failures = 0;
        self.store
            .save(&saved)
            .map_err(|_| Failure::new("state_write", "The Vault cannot write its state in the profile."))?;
        self.saved = Some(saved);
        Ok(())
    }

    /// `pin_clear`: the PIN's envelope goes.
    pub fn pin_clear(&mut self) -> Result<(), Failure> {
        let mut saved = self.saved.clone().ok_or_else(no_account)?;
        saved.pin_envelope = Value::Null;
        saved.pin_failures = 0;
        self.store
            .save(&saved)
            .map_err(|_| Failure::new("state_write", "The Vault cannot write its state in the profile."))?;
        self.saved = Some(saved);
        Ok(())
    }

    /// `logout`: the state, the secrets in the system store and the PIN go. The caller exits after.
    pub async fn logout(&mut self) {
        self.forget_waiting();
        self.client = None;
        self.ciphers.clear();
        self.domains.clear();
        self.secrets = None;
        if let Some(old) = self.saved.take().or_else(|| self.store.load()) {
            let tokens = self.tokens.clone();
            blocking(move || tokens.wipe(&old.device_id)).await;
        }
        self.store.wipe();
    }

    /// `sync`: the vault from the server. Returns the item count and the time of the sync (Unix seconds).
    pub async fn sync(&mut self) -> Result<(usize, i64), Failure> {
        let client = self.client.clone().ok_or_else(locked)?;
        let captured = sync_capture(&client).await?;
        init_organizations(&client, &captured.org_keys).await;
        let mut saved = self.saved.clone().ok_or_else(no_account)?;
        if let Some(unlock) = captured
            .crypto
            .user_decryption
            .as_ref()
            .and_then(|d| d.master_password_unlock.clone())
        {
            saved.master_password_unlock = to_value(&unlock)?;
        }
        if let Some(account_crypto) = &captured.crypto.account_cryptographic_state {
            saved.account_crypto = to_value(account_crypto)?;
        }
        self.ciphers = captured.ciphers;
        self.domains = captured.domains;
        self.remember(&mut saved, captured.org_keys).await?;
        Ok((self.ciphers.len(), saved.last_sync))
    }

    /// Keeps the account: the encrypted items and the organization keys in the state, the refresh token (and the API
    /// key's secret) in the token store when they changed.
    async fn remember(&mut self, saved: &mut Saved, org_keys: Vec<(String, String)>) -> Result<(), Failure> {
        let client = self.client.as_ref().ok_or_else(locked)?;
        let state = client.platform().state();
        let refresh_token = state
            .value::<AUTHENTICATION_TOKENS>()
            .try_get()
            .await
            .ok()
            .flatten()
            .and_then(|t| t.refresh_token);
        let client_secret = match state.value::<USER_LOGIN_METHOD>().try_get().await.ok().flatten() {
            Some(UserLoginMethod::ApiKey { client_secret, .. }) => Some(client_secret),
            _ => None,
        };
        let secrets = Secrets {
            refresh_token,
            client_secret,
        };
        saved.org_keys = org_keys;
        saved.equivalent_domains = self.domains.clone();
        saved.ciphers = self
            .ciphers
            .iter()
            .filter_map(|c| serde_json::to_value(c).ok())
            .collect();
        saved.last_sync = chrono::Utc::now().timestamp();
        self.store
            .save(saved)
            .map_err(|_| Failure::new("state_write", "The Vault cannot write its state in the profile."))?;
        if self.secrets.as_ref() != Some(&secrets) {
            let tokens = self.tokens.clone();
            let account = saved.device_id.clone();
            let copy = secrets.clone();
            let written = blocking(move || tokens.save(&account, &copy).is_ok())
                .await
                .unwrap_or(false);
            if !written {
                return Err(Failure::new(
                    "state_write",
                    "The Vault cannot keep its tokens: no system store answered and the profile cannot be written.",
                ));
            }
            self.secrets = Some(secrets);
        }
        self.saved = Some(saved.clone());
        Ok(())
    }

    /// The decrypted login items, then dropped by the caller.
    async fn views(&self) -> Result<Vec<CipherView>, Failure> {
        let client = self.client.as_ref().ok_or_else(locked)?;
        let result = client
            .vault()
            .ciphers()
            .decrypt_list_full_with_failures(self.ciphers.clone())
            .await;
        Ok(result
            .successes
            .into_iter()
            .filter(|v| v.deleted_date.is_none() && matches!(v.r#type, CipherType::Login) && v.login.is_some())
            .collect())
    }

    /// The domains equivalent to a page's registrable domain (`matching::equivalent_of` over the account's groups).
    pub fn equivalent_of(&self, domain: &str) -> Vec<String> {
        matching::equivalent_of(&self.domains, domain)
    }

    /// `logins_for`: the rows of the logins whose URIs match the page. No password. `page.equivalent` comes from
    /// `equivalent_of`.
    pub async fn logins_for(&self, page: &Page<'_>) -> Result<Vec<Row>, Failure> {
        let mut rows = Vec::new();
        for view in self.views().await? {
            let Some(id) = view.id.map(|i| i.to_string()) else {
                continue;
            };
            let Some(login) = &view.login else { continue };
            let mut matched = None;
            for u in login.uris.iter().flatten() {
                let Some(uri) = &u.uri else { continue };
                if let Some(how) = matching::matches(page, uri, rule_of(&u.r#match)) {
                    matched = Some((uri.clone(), how));
                    break;
                }
            }
            if let Some((uri, how)) = matched {
                rows.push(Row {
                    id,
                    name: view.name.clone(),
                    username: login.username.clone().unwrap_or_default(),
                    uri,
                    matched: how,
                    has_totp: login.totp.is_some(),
                });
            }
        }
        rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(rows)
    }

    /// `search`: the logins whose name, user name or addresses hold every word of `query`, sorted by name, at most
    /// `limit` (0 or more than `SEARCH_LIMIT`: `SEARCH_LIMIT`). No password.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<Row>, Failure> {
        let limit = if limit == 0 {
            SEARCH_LIMIT
        } else {
            limit.min(SEARCH_LIMIT)
        };
        let mut rows = Vec::new();
        for view in self.views().await? {
            let Some(id) = view.id.map(|i| i.to_string()) else {
                continue;
            };
            let Some(login) = &view.login else { continue };
            let uris: Vec<&str> = login.uris.iter().flatten().filter_map(|u| u.uri.as_deref()).collect();
            let username = login.username.clone().unwrap_or_default();
            let mut texts = vec![view.name.as_str(), username.as_str()];
            texts.extend(uris.iter().copied());
            if !matching::search_matches(query, &texts) {
                continue;
            }
            let web = uris
                .iter()
                .find(|u| {
                    matches!(
                        url::Url::parse(u).map(|p| p.scheme().to_string()).as_deref(),
                        Ok("https") | Ok("http")
                    )
                })
                .map(|u| u.to_string())
                .unwrap_or_default();
            rows.push(Row {
                id,
                name: view.name.clone(),
                username,
                uri: web,
                matched: "",
                has_totp: login.totp.is_some(),
            });
        }
        rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        rows.truncate(limit);
        Ok(rows)
    }

    /// The decrypted login of one item.
    async fn login_view(&self, item: &str) -> Result<CipherView, Failure> {
        let client = self.client.as_ref().ok_or_else(locked)?;
        let cipher = self
            .ciphers
            .iter()
            .find(|c| c.id.map(|i| i.to_string()).as_deref() == Some(item))
            .cloned()
            .ok_or_else(|| Failure::new("no_item", "The item is not in the vault any more."))?;
        let view = client
            .vault()
            .ciphers()
            .decrypt(cipher)
            .await
            .map_err(|_| Failure::new("decrypt", "The item cannot be decrypted."))?;
        if view.deleted_date.is_some() || view.login.is_none() {
            return Err(Failure::new("no_item", "The item is not a login."));
        }
        Ok(view)
    }

    /// `fill`: the values of one item that the user picked. A wanted TOTP code that the item cannot give is an error
    /// (`no_totp`): the browser asked for it because the row said the item has one.
    pub async fn fill(
        &self,
        item: &str,
        want_username: bool,
        want_password: bool,
        want_totp: bool,
    ) -> Result<Values, Failure> {
        let view = self.login_view(item).await?;
        let Some(login) = view.login.as_ref() else {
            return Err(Failure::new("no_item", "The item is not a login."));
        };
        let mut values = Values::default();
        if want_username {
            values.username = login.username.clone();
        }
        if want_password {
            values.password = login.password.clone();
        }
        if want_totp {
            let code = totp_now(login.totp.as_deref())?;
            values.totp = Some(code.code.to_string());
        }
        Ok(values)
    }

    /// `totp`: the current code of one item's TOTP key, computed by the SDK.
    pub async fn totp(&self, item: &str) -> Result<Code, Failure> {
        let view = self.login_view(item).await?;
        totp_now(view.login.as_ref().and_then(|l| l.totp.as_deref()))
    }
}

/// The code of a TOTP key now (an otpauth:// URI, a steam:// URI or a base32 secret; the SDK reads all three).
fn totp_now(key: Option<&str>) -> Result<Code, Failure> {
    let key = key
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| Failure::new("no_totp", "This login has no TOTP key."))?;
    let now = chrono::Utc::now();
    totp_at(key, now)
}

/// The code of `key` at `at`, and the seconds left in its period.
pub fn totp_at(key: &str, at: chrono::DateTime<chrono::Utc>) -> Result<Code, Failure> {
    let answer = generate_totp(key.to_string(), Some(at))
        .map_err(|_| Failure::new("no_totp", "The login's TOTP key cannot be read."))?;
    let period = answer.period.max(1);
    let remaining = period - (at.timestamp().rem_euclid(i64::from(period)) as u32);
    Ok(Code {
        code: Zeroizing::new(answer.code),
        period,
        remaining,
    })
}

/// A wrong PIN: counted in the state; at `PIN_TRIES` the envelope goes and only the master password unlocks.
pub fn count_wrong_pin(saved: &mut Saved) -> Failure {
    saved.pin_failures += 1;
    if saved.pin_failures >= PIN_TRIES {
        saved.pin_envelope = Value::Null;
        saved.pin_failures = 0;
        return Failure::new(
            "pin_reset",
            "Too many wrong PINs: the PIN was removed. Unlock with the master password.",
        );
    }
    let left = PIN_TRIES - saved.pin_failures;
    Failure {
        code: "bad_pin",
        message: if left == 1 {
            "The PIN is wrong. 1 try left.".to_string()
        } else {
            format!("The PIN is wrong. {left} tries left.")
        },
        tries_left: Some(left),
    }
}

/// The login method that renews the access token of the remembered account. `None`: an API key login whose secret is
/// lost (the vault opens; the sync asks for a new login).
fn login_method(saved: &Saved, kdf: &Kdf, secrets: &Secrets) -> Option<UserLoginMethod> {
    if saved.login == LOGIN_API_KEY {
        return Some(UserLoginMethod::ApiKey {
            client_id: saved.api_client_id.clone(),
            client_secret: secrets.client_secret.clone()?,
            email: saved.email.clone(),
            kdf: kdf.clone(),
        });
    }
    Some(UserLoginMethod::Username {
        client_id: CLIENT_ID.to_string(),
        email: saved.email.clone(),
        kdf: kdf.clone(),
    })
}

/// An SDK client for the configured server, with the SDK's own token handler (renewal with the refresh token). The
/// device type is the one of the helper's token request (`identity::DEVICE_TYPE`).
fn new_client(config: &Config, device_id: &str) -> Client {
    let settings = ClientSettings {
        identity_url: config.identity_url.clone(),
        api_url: config.api_url.clone(),
        user_agent: format!("Wren/{} wren-vault/{}", config.client_version, HELPER_VERSION),
        device_type: DeviceType::UnknownBrowser,
        device_identifier: Some(device_id.to_string()),
        bitwarden_client_version: None,
        bitwarden_package_type: None,
    };
    ClientBuilder::new()
        .with_settings(settings)
        .with_token_handler(Arc::new(PasswordManagerTokenHandler::default()))
        .build()
}

/// Sends a token request with the SDK's HTTP client of the identity server (its TLS roots, its user agent and its
/// `Device-Type` header) and reads the answer.
async fn token_request(client: &Client, form: &str) -> Result<TokenAnswer, Failure> {
    let network = || Failure::new("network", "The server cannot be reached, or it refused the request.");
    let configurations = client.internal.get_api_configurations();
    let id_config = &configurations.identity_config;
    let response = id_config
        .client
        .post(format!("{}/connect/token", id_config.base_path))
        .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
        .header("accept", "application/json")
        .body(form.to_string())
        .send()
        .await
        .map_err(|_| network())?;
    let status = response.status().as_u16();
    let text = Zeroizing::new(response.text().await.map_err(|_| network())?);
    Ok(identity::parse_token_answer(status, &text))
}

/// The tokens of a login into the client's state, where the SDK's token handler reads and renews them.
async fn set_tokens(client: &Client, access_token: String, refresh_token: Option<String>, expires_in: u64) {
    let tokens = AuthenticationTokens {
        access_token,
        refresh_token,
        expires_on: chrono::Utc::now().timestamp() + expires_in as i64,
    };
    let _ = client
        .platform()
        .state()
        .value::<AUTHENTICATION_TOKENS>()
        .set(tokens)
        .await;
}

fn rule_of(m: &Option<UriMatchType>) -> Rule {
    match m {
        None | Some(UriMatchType::Domain) => Rule::Domain,
        Some(UriMatchType::Host) => Rule::Host,
        Some(UriMatchType::StartsWith) => Rule::StartsWith,
        Some(UriMatchType::Exact) => Rule::Exact,
        Some(UriMatchType::RegularExpression) => Rule::RegularExpression,
        Some(UriMatchType::Never) => Rule::Never,
    }
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value, Failure> {
    serde_json::to_value(v).map_err(|_| Failure::new("state_format", "The Vault cannot store the account state."))
}

fn from_value<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, Failure> {
    serde_json::from_value(v.clone())
        .map_err(|_| Failure::new("state_format", "The saved account state cannot be read: log in again."))
}

/// Organization keys as the SDK wants them; a malformed entry is left out.
async fn init_organizations(client: &Client, keys: &[(String, String)]) {
    let mut organization_keys = HashMap::new();
    for (id, key) in keys {
        if let (Ok(id), Ok(key)) = (id.parse::<OrganizationId>(), key.parse::<UnsignedSharedKey>()) {
            organization_keys.insert(id, key);
        }
    }
    if !organization_keys.is_empty() {
        let _ = client
            .crypto()
            .initialize_org_crypto(InitOrgCryptoRequest { organization_keys })
            .await;
    }
}

/// What a sync gives the helper: the encrypted items, the account's key data, the organization keys, the email, the
/// groups of equivalent domains.
#[derive(Default)]
struct Captured {
    ciphers: Vec<Cipher>,
    crypto: CryptoSyncData,
    org_keys: Vec<(String, String)>,
    email: Option<String>,
    domains: Vec<Vec<String>>,
}

/// A sync handler that keeps the response's parts that the helper stores.
#[derive(Default)]
struct Capture {
    got: Mutex<Option<Captured>>,
}

#[async_trait::async_trait]
impl SyncHandler for Capture {
    async fn on_sync(&self, response: &SyncResponseModel) -> Result<(), SyncHandlerError> {
        let crypto = CryptoSyncData::try_from(response).map_err(|e| SyncHandlerError::from(e.to_string()))?;
        let ciphers = response
            .ciphers
            .iter()
            .flatten()
            .filter_map(|c| Cipher::try_from(c.clone()).ok())
            .collect();
        let mut org_keys = Vec::new();
        if let Some(orgs) = response.profile.as_deref().and_then(|p| p.organizations.as_ref()) {
            for o in orgs {
                if let (Some(id), Some(key)) = (o.id, &o.key) {
                    org_keys.push((id.to_string(), key.clone()));
                }
            }
        }
        let email = response.profile.as_deref().and_then(|p| p.email.clone());
        let domains = response.domains.as_deref().map(domain_groups).unwrap_or_default();
        *self
            .got
            .lock()
            .map_err(|_| SyncHandlerError::from("lock".to_string()))? = Some(Captured {
            ciphers,
            crypto,
            org_keys,
            email,
            domains,
        });
        Ok(())
    }
}

/// The account's own groups of equivalent domains, then the server's global groups that the account did not exclude.
fn domain_groups(d: &bitwarden_api_api::models::DomainsResponseModel) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = d.equivalent_domains.clone().unwrap_or_default();
    for g in d.global_equivalent_domains.iter().flatten() {
        if g.excluded != Some(true)
            && let Some(list) = &g.domains
        {
            out.push(list.clone());
        }
    }
    out.retain(|g| g.len() > 1);
    out
}

/// A full sync through the SDK, with the capture handler (the SDK makes a new sync client, with no handler, per call).
async fn sync_capture(client: &Client) -> Result<Captured, Failure> {
    let capture = Arc::new(Capture::default());
    let sync = client.sync();
    sync.register_sync_handler(capture.clone());
    // (`exclude_subdomains` is the API's `excludeDomains`: false, the answer carries the equivalent domains)
    sync.sync(SyncRequest {
        force: true,
        exclude_subdomains: Some(false),
    })
    .await
    .map_err(|_| Failure::new("sync_failed", "The vault could not be synced with the server."))?;
    let got = capture.got.lock().ok().and_then(|mut g| g.take());
    got.ok_or_else(|| Failure::new("sync_failed", "The server sent no vault."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_http_servers() {
        assert!(server_url_allowed("https://vault.bitwarden.com"));
        assert!(server_url_allowed("http://127.0.0.1:8000"));
        assert!(server_url_allowed("http://localhost:8000/identity"));
        assert!(!server_url_allowed("http://example.com"));
        assert!(!server_url_allowed("ftp://example.com"));
        assert!(!server_url_allowed("not a url"));
    }

    // RFC 6238's SHA-1 vector (the secret "12345678901234567890" in base32), cut to the SDK's 6 digits
    #[test]
    fn totp_codes_come_from_the_sdk_with_the_time_left() {
        let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let at = chrono::DateTime::from_timestamp(59, 0).unwrap();
        let c = totp_at(key, at).unwrap();
        assert_eq!(c.code.as_str(), "287082");
        assert_eq!(c.period, 30);
        assert_eq!(c.remaining, 1);
        let at = chrono::DateTime::from_timestamp(1_111_111_109, 0).unwrap();
        let c = totp_at(&format!("otpauth://totp/x?secret={key}"), at).unwrap();
        assert_eq!(c.code.as_str(), "081804");
        assert_eq!(c.remaining, 1);
        assert_eq!(totp_now(None).err().map(|f| f.code), Some("no_totp"));
        assert_eq!(totp_now(Some("  ")).err().map(|f| f.code), Some("no_totp"));
    }

    #[test]
    fn equivalent_domains_come_from_the_account_and_the_unexcluded_global_groups() {
        use bitwarden_api_api::models::{DomainsResponseModel, GlobalDomains};
        let mut d = DomainsResponseModel::new();
        d.equivalent_domains = Some(vec![
            vec!["a.example".into(), "b.example".into()],
            vec!["alone.example".into()],
        ]);
        let mut kept = GlobalDomains::new();
        kept.domains = Some(vec!["google.com".into(), "youtube.com".into()]);
        kept.excluded = Some(false);
        let mut excluded = GlobalDomains::new();
        excluded.domains = Some(vec!["apple.com".into(), "icloud.com".into()]);
        excluded.excluded = Some(true);
        d.global_equivalent_domains = Some(vec![kept, excluded]);
        let groups = domain_groups(&d);
        assert_eq!(
            groups.len(),
            2,
            "a group of one domain and an excluded group are left out"
        );
        assert_eq!(groups[1], vec!["google.com".to_string(), "youtube.com".to_string()]);
    }

    #[test]
    fn five_wrong_pins_remove_the_pin() {
        let mut saved = Saved {
            pin_envelope: Value::String("sealed".into()),
            ..Default::default()
        };
        for left in (1..PIN_TRIES).rev() {
            let f = count_wrong_pin(&mut saved);
            assert_eq!(f.code, "bad_pin");
            assert_eq!(f.tries_left, Some(left));
            assert!(saved.has_pin());
        }
        let f = count_wrong_pin(&mut saved);
        assert_eq!(f.code, "pin_reset");
        assert!(!saved.has_pin());
        assert_eq!(saved.pin_failures, 0);
    }

    #[test]
    fn the_login_method_follows_the_saved_login() {
        let kdf = Kdf::default_pbkdf2();
        let mut saved = Saved {
            email: "a@b.c".into(),
            login: LOGIN_PASSWORD.into(),
            ..Default::default()
        };
        assert!(matches!(
            login_method(&saved, &kdf, &Secrets::default()),
            Some(UserLoginMethod::Username { .. })
        ));
        saved.login = LOGIN_API_KEY.into();
        saved.api_client_id = "user.x".into();
        assert!(login_method(&saved, &kdf, &Secrets::default()).is_none());
        let secrets = Secrets {
            refresh_token: None,
            client_secret: Some("s".into()),
        };
        assert!(matches!(
            login_method(&saved, &kdf, &secrets),
            Some(UserLoginMethod::ApiKey { .. })
        ));
    }
}
