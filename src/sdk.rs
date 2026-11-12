//! Every call to the Bitwarden SDK (sdk-internal at the revision of Cargo.toml). No other module names an SDK type: a
//! new SDK revision changes this file only.
//!
//! A session is one account. Logging in or unlocking makes an SDK client that holds the keys; locking is the exit of
//! the process (README.md, "Lock is process exit").

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_core::{
    Client, ClientBuilder, ClientSettings, DeviceType, OrganizationId, UserId,
    auth::{
        JwtToken,
        login::{LoginError, PasswordLoginRequest, TwoFactorProvider, TwoFactorRequest},
    },
    client::persisted_state::{AUTHENTICATION_TOKENS, AuthenticationTokens, USER_LOGIN_METHOD},
    key_management::{
        MasterPasswordUnlockData,
        account_cryptographic_state::WrappedAccountCryptographicState,
        crypto::{InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest},
    },
};
use bitwarden_crypto::UnsignedSharedKey;
use bitwarden_crypto_sync_handler::CryptoSyncData;
use bitwarden_sync::{SyncClientExt, SyncHandler, SyncHandlerError, SyncRequest};
use bitwarden_vault::{Cipher, CipherType, CipherView, UriMatchType, VaultClientExt};
use serde_json::Value;
use zeroize::Zeroize;

use crate::{
    HELPER_VERSION,
    matching::{self, Page, Rule},
    protocol::Row,
    state::{STATE_VERSION, Saved, Store},
};

/// A failed request: a stable code (README.md, "Errors") and a sentence for the person. Never a secret.
#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Failure {
        Failure {
            code,
            message: message.into(),
        }
    }
}

/// The server and the client identity that `hello` gave.
#[derive(Clone)]
pub struct Config {
    pub identity_url: String,
    pub api_url: String,
    pub client_version: String,
}

/// What a login gave.
pub enum LoginOutcome {
    Done,
    /// The account asks for a second factor: the providers that the helper can use ("authenticator").
    NeedTwoFactor(Vec<&'static str>),
}

/// The values of one login for a fill. Zeroed when dropped.
#[derive(Default)]
pub struct Values {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Drop for Values {
    fn drop(&mut self) {
        if let Some(u) = &mut self.username {
            u.zeroize();
        }
        if let Some(p) = &mut self.password {
            p.zeroize();
        }
    }
}

/// The account of this helper.
pub struct Session {
    store: Store,
    config: Option<Config>,
    /// The remembered account (also kept in memory when the store does not persist).
    saved: Option<Saved>,
    /// The SDK client while the vault is unlocked.
    client: Option<Client>,
    /// The encrypted items of the last sync.
    ciphers: Vec<Cipher>,
    /// A login that waits for its second factor: the email and the password, until the code comes or another login.
    waiting: Option<(String, String)>,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            store: Store::new("", false),
            config: None,
            saved: None,
            client: None,
            ciphers: Vec::new(),
            waiting: None,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.forget_waiting();
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

impl Session {
    pub fn configured(&self) -> bool {
        self.config.is_some()
    }

    pub fn unlocked(&self) -> bool {
        self.client.is_some()
    }

    /// `hello`: the server and the state directory. Returns the account state ("none" or "locked") and its email.
    pub fn hello(&mut self, config: Config, state_dir: &str, persist: bool) -> Result<(&'static str, String), Failure> {
        if !server_url_allowed(&config.identity_url) || !server_url_allowed(&config.api_url) {
            return Err(Failure::new(
                "bad_server",
                "The server address must use https (or http to this machine).",
            ));
        }
        self.store = Store::new(state_dir, persist);
        let saved = self
            .store
            .load()
            .filter(|s| s.identity_url == config.identity_url && s.api_url == config.api_url);
        self.config = Some(config);
        self.saved = saved;
        Ok(match &self.saved {
            Some(s) => ("locked", s.email.clone()),
            None => ("none", String::new()),
        })
    }

    fn forget_waiting(&mut self) {
        if let Some((mut e, mut p)) = self.waiting.take() {
            e.zeroize();
            p.zeroize();
        }
    }

    /// `login`: email and master password; on the second try, the same email and the TOTP code without the password.
    pub async fn login(
        &mut self,
        email: &str,
        password: Option<&str>,
        totp: Option<&str>,
    ) -> Result<LoginOutcome, Failure> {
        let config = self
            .config
            .clone()
            .ok_or_else(|| Failure::new("no_hello", "hello first"))?;
        let mut password = match password {
            Some(p) => {
                self.forget_waiting();
                p.to_string()
            }
            None => match self.waiting.take() {
                Some((e, p)) if e.eq_ignore_ascii_case(email) && totp.is_some() => p,
                other => {
                    self.waiting = other;
                    return Err(Failure::new("bad_request", "A login needs the master password."));
                }
            },
        };
        let result = self.login_with(&config, email, &password, totp).await;
        match &result {
            Ok(LoginOutcome::NeedTwoFactor(_)) => {
                self.waiting = Some((email.to_string(), std::mem::take(&mut password)))
            }
            _ => password.zeroize(),
        }
        result
    }

    async fn login_with(
        &mut self,
        config: &Config,
        email: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<LoginOutcome, Failure> {
        let device_id = self
            .saved
            .as_ref()
            .filter(|s| s.email.eq_ignore_ascii_case(email))
            .map(|s| s.device_id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let client = new_client(config, &device_id);
        let request = PasswordLoginRequest {
            email: email.to_string(),
            password: password.to_string(),
            two_factor: totp.map(|t| TwoFactorRequest {
                token: t.trim().to_string(),
                provider: TwoFactorProvider::Authenticator,
                remember: false,
            }),
        };
        let result = client.auth().login_password(&request).await;
        drop(request); // (the zeroizing allocator clears the password's memory)
        let response = result.map_err(login_failure)?;
        if let Some(two_factor) = response.two_factor {
            if two_factor.authenticator.is_some() {
                return Ok(LoginOutcome::NeedTwoFactor(vec!["authenticator"]));
            }
            return Err(Failure::new(
                "unsupported_two_factor",
                "This account asks for a second factor that the Vault does not support yet. Add an authenticator app to the account.",
            ));
        }
        if !response.authenticated {
            return Err(Failure::new("login_failed", "The server refused the login."));
        }
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
        init_organizations(&client, &captured.org_keys).await;
        let mut saved = Saved {
            version: STATE_VERSION,
            email: email.to_string(),
            identity_url: config.identity_url.clone(),
            api_url: config.api_url.clone(),
            device_id,
            master_password_unlock: to_value(&unlock)?,
            account_crypto: to_value(&account_crypto)?,
            ..Default::default()
        };
        self.ciphers = captured.ciphers;
        self.client = Some(client);
        self.remember(&mut saved, captured.org_keys).await?;
        Ok(LoginOutcome::Done)
    }

    /// `unlock`: the master password of the remembered account.
    pub async fn unlock(&mut self, password: &str) -> Result<(), Failure> {
        if self.client.is_some() {
            return Ok(());
        }
        let config = self
            .config
            .clone()
            .ok_or_else(|| Failure::new("no_hello", "hello first"))?;
        let saved = self
            .saved
            .clone()
            .ok_or_else(|| Failure::new("no_account", "No account is remembered: log in."))?;
        let unlock: MasterPasswordUnlockData = from_value(&saved.master_password_unlock)?;
        let account_crypto: WrappedAccountCryptographicState = from_value(&saved.account_crypto)?;
        let tokens: Option<AuthenticationTokens> = serde_json::from_value(saved.tokens.clone()).ok();
        let client = new_client(&config, &saved.device_id);
        let state = client.platform().state();
        if let Some(t) = &tokens {
            let _ = state.value::<AUTHENTICATION_TOKENS>().set(t.clone()).await;
        }
        if let Ok(method) = serde_json::from_value(saved.login_method.clone()) {
            let _ = state.value::<USER_LOGIN_METHOD>().set(method).await;
        }
        let user_id: Option<UserId> = tokens
            .as_ref()
            .and_then(|t| t.access_token.parse::<JwtToken>().ok())
            .and_then(|j| j.sub.parse().ok());
        let request = InitUserCryptoRequest {
            user_id,
            kdf_params: unlock.kdf.clone(),
            email: saved.email.clone(),
            account_cryptographic_state: account_crypto,
            method: InitUserCryptoMethod::MasterPasswordUnlock {
                password: password.to_string(),
                master_password_unlock: unlock,
            },
            upgrade_token: None,
        };
        client
            .crypto()
            .initialize_user_crypto(request)
            .await
            .map_err(|_| Failure::new("bad_password", "The master password is wrong."))?;
        init_organizations(&client, &saved.org_keys).await;
        self.ciphers = saved
            .ciphers
            .iter()
            .filter_map(|c| serde_json::from_value(c.clone()).ok())
            .collect();
        self.client = Some(client);
        Ok(())
    }

    /// `sync`: the vault from the server. Returns the item count and the time of the sync (Unix seconds).
    pub async fn sync(&mut self) -> Result<(usize, i64), Failure> {
        let client = self
            .client
            .clone()
            .ok_or_else(|| Failure::new("locked", "The vault is locked."))?;
        let captured = sync_capture(&client).await?;
        init_organizations(&client, &captured.org_keys).await;
        let mut saved = self
            .saved
            .clone()
            .ok_or_else(|| Failure::new("no_account", "No account is remembered."))?;
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
        self.remember(&mut saved, captured.org_keys).await?;
        Ok((self.ciphers.len(), saved.last_sync))
    }

    /// Keeps the account: the encrypted items, the organization keys, the tokens and the login method of the client.
    async fn remember(&mut self, saved: &mut Saved, org_keys: Vec<(String, String)>) -> Result<(), Failure> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| Failure::new("locked", "The vault is locked."))?;
        let state = client.platform().state();
        if let Ok(Some(tokens)) = state.value::<AUTHENTICATION_TOKENS>().try_get().await {
            saved.tokens = to_value(&tokens)?;
        }
        if let Ok(Some(method)) = state.value::<USER_LOGIN_METHOD>().try_get().await {
            saved.login_method = to_value(&method)?;
        }
        saved.org_keys = org_keys;
        saved.ciphers = self
            .ciphers
            .iter()
            .filter_map(|c| serde_json::to_value(c).ok())
            .collect();
        saved.last_sync = chrono::Utc::now().timestamp();
        self.store
            .save(saved)
            .map_err(|_| Failure::new("state_write", "The Vault cannot write its state in the profile."))?;
        self.saved = Some(saved.clone());
        Ok(())
    }

    /// The decrypted login items, then dropped by the caller.
    async fn views(&self) -> Result<Vec<CipherView>, Failure> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| Failure::new("locked", "The vault is locked."))?;
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

    /// `logins_for`: the rows of the logins whose URIs match the page. No password.
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

    /// `fill`: the values of one item that the user picked.
    pub async fn fill(&self, item: &str, want_username: bool, want_password: bool) -> Result<Values, Failure> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| Failure::new("locked", "The vault is locked."))?;
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
        let login = view
            .login
            .as_ref()
            .filter(|_| view.deleted_date.is_none())
            .ok_or_else(|| Failure::new("no_item", "The item is not a login."))?;
        let mut values = Values::default();
        if want_username {
            values.username = login.username.clone();
        }
        if want_password {
            values.password = login.password.clone();
        }
        Ok(values)
    }
}

/// An SDK client for the configured server, with the SDK's own token handler (renewal with the refresh token).
fn new_client(config: &Config, device_id: &str) -> Client {
    let settings = ClientSettings {
        identity_url: config.identity_url.clone(),
        api_url: config.api_url.clone(),
        user_agent: format!("Wren/{} wren-vault/{}", config.client_version, HELPER_VERSION),
        device_type: DeviceType::SDK,
        device_identifier: Some(device_id.to_string()),
        bitwarden_client_version: None,
        bitwarden_package_type: None,
    };
    ClientBuilder::new()
        .with_settings(settings)
        .with_token_handler(Arc::new(PasswordManagerTokenHandler::default()))
        .build()
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

/// A login error as a stable code. The server's sentence is kept: it names no secret.
fn login_failure(e: LoginError) -> Failure {
    match e {
        LoginError::IdentityFail(r) => Failure::new("bad_credentials", r.to_string()),
        LoginError::Api(_) => Failure::new("network", "The server cannot be reached, or it refused the request."),
        LoginError::Prelogin(_) => Failure::new(
            "network",
            "The server cannot be reached, or it does not know this account.",
        ),
        _ => Failure::new("login_failed", "The login failed."),
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

/// What a sync gives the helper: the encrypted items, the account's key data, the organization keys.
#[derive(Default)]
struct Captured {
    ciphers: Vec<Cipher>,
    crypto: CryptoSyncData,
    org_keys: Vec<(String, String)>,
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
        *self
            .got
            .lock()
            .map_err(|_| SyncHandlerError::from("lock".to_string()))? = Some(Captured {
            ciphers,
            crypto,
            org_keys,
        });
        Ok(())
    }
}

/// A full sync through the SDK, with the capture handler.
async fn sync_capture(client: &Client) -> Result<Captured, Failure> {
    let capture = Arc::new(Capture::default());
    let sync = client.sync();
    sync.register_sync_handler(capture.clone());
    sync.sync(SyncRequest {
        force: true,
        exclude_subdomains: Some(true),
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
}
