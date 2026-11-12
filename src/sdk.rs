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
    ApiError, Client, ClientBuilder, ClientSettings, DeviceType, OrganizationId,
    auth::{AuthRequestResponse, JwtToken, login::TwoFactorEmailRequest},
    client::{
        login_method::UserLoginMethod,
        persisted_state::{AUTHENTICATION_TOKENS, AuthenticationTokens, USER_LOGIN_METHOD},
    },
    key_management::{
        MasterPasswordAuthenticationData, MasterPasswordUnlockData, WebAuthnPrfUnlockOption,
        account_cryptographic_state::WrappedAccountCryptographicState,
        crypto::{AuthRequestMethod, InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest},
    },
};
use bitwarden_crypto::{
    EncString, Kdf, KeyDecryptable, Pkcs8PrivateKeyBytes, PrivateKey, SymmetricCryptoKey, UnsignedSharedKey,
    derive_symmetric_key_from_prf, safe::PasswordProtectedKeyEnvelope,
};
use bitwarden_crypto_sync_handler::CryptoSyncData;
use bitwarden_generators::{
    GeneratorClientsExt, MAXIMUM_MIN_CHAR_COUNT, MAXIMUM_PASSPHRASE_NUM_WORDS, MAXIMUM_PASSWORD_LENGTH,
    MINIMUM_PASSPHRASE_NUM_WORDS, MINIMUM_PASSWORD_LENGTH, PassphraseGeneratorRequest, PasswordGeneratorRequest,
};
use bitwarden_sync::{SyncClientExt, SyncHandler, SyncHandlerError, SyncRequest};
use bitwarden_vault::{
    CardView, Cipher, CipherCreateRequest, CipherEditRequest, CipherId, CipherRepromptType, CipherType, CipherView,
    CipherViewType, CreateCipherError, EditCipherError, IdentityView, LoginUriView, LoginView, UriMatchType,
    VaultClientExt, generate_totp,
};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    HELPER_VERSION,
    identity::{self, Approval, Assertion, CLIENT_ID, Device, PrfOption, Second, TokenAnswer},
    matching::{self, Page, Rule},
    protocol::Row,
    state::{LOGIN_API_KEY, LOGIN_PASSWORD, PIN_TRIES, STATE_VERSION, Saved, Store},
    tokens::{Remembered, Secrets, TokenStore},
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

fn cannot_reach() -> Failure {
    Failure::new(
        "network",
        "The server cannot be reached. Check its address and the network connection.",
    )
}

fn expired() -> Failure {
    Failure::new(
        "expired",
        "The login with a device expired without an approval. Ask again.",
    )
}

fn unsupported_two_factor() -> Failure {
    Failure::new(
        "unsupported_two_factor",
        "This account asks for a second step that the Vault does not support (Duo, a security key, YubiKey). Add an authenticator app or the email code to the account, or log in with a device, a passkey or the account's API key.",
    )
}

/// The failure of a token answer that is no login and no next step.
fn refusal(answer: TokenAnswer) -> Failure {
    match answer {
        TokenAnswer::Captcha => Failure::new(
            "captcha_required",
            "The server asks to solve a captcha first. Log in once on the web vault, then try again here.",
        ),
        TokenAnswer::BadAuthEmail => Failure::new(
            "bad_auth_email",
            "The server refused the account's email (its Auth-Email header). Check the email and log in again.",
        ),
        TokenAnswer::Locked(message) => Failure::new("account_locked", message),
        TokenAnswer::Refused(message) => Failure::new("bad_credentials", message),
        TokenAnswer::Tokens { .. }
        | TokenAnswer::TwoFactor { .. }
        | TokenAnswer::DeviceCode
        | TokenAnswer::Unexpected => {
            Failure::new("login_failed", "The server's answer to the login is not understood.")
        }
    }
}

/// The server's sentence in an error answer of the API (`message`, or the first of the model's errors).
fn error_message(body: &str) -> Option<String> {
    let v = serde_json::from_str::<Value>(body).ok()?;
    let text = v
        .get("message")
        .or_else(|| v.get("Message"))
        .and_then(Value::as_str)?
        .trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// The sync's passkeys that unlock the account, for the state (null when none).
fn prf_options_value(crypto: &CryptoSyncData) -> Result<Value, Failure> {
    match crypto
        .user_decryption
        .as_ref()
        .and_then(|d| d.web_authn_prf_options.as_ref())
        .filter(|o| !o.is_empty())
    {
        Some(options) => to_value(options),
        None => Ok(Value::Null),
    }
}

/// The account's passkeys that unlock it, from the state.
fn prf_options_of(saved: &Saved) -> Vec<WebAuthnPrfUnlockOption> {
    serde_json::from_value(saved.prf_options.clone()).unwrap_or_default()
}

/// The user key from a passkey's PRF output (base64url) and its keys: the PRF key (the SDK's
/// `derive_symmetric_key_from_prf`) unwraps the private key, which decapsulates the user key. Returns the user key in
/// base64, for `InitUserCryptoMethod::DecryptedKey`.
fn prf_open(prf: &str, option: &PrfOption) -> Result<Zeroizing<String>, Failure> {
    let private: EncString = option.encrypted_private_key.parse().map_err(|_| prf_wrong())?;
    let user: UnsignedSharedKey = option.encrypted_user_key.parse().map_err(|_| prf_wrong())?;
    prf_user_key(prf, &private, &user)
}

fn prf_wrong() -> Failure {
    Failure::new(
        "passkey_failed",
        "The passkey's answer does not open the vault. Use the passkey that was registered for this account, or the master password.",
    )
}

fn prf_user_key(prf: &str, private: &EncString, user: &UnsignedSharedKey) -> Result<Zeroizing<String>, Failure> {
    let bytes = Zeroizing::new(identity::base64url_decode(prf).ok_or_else(prf_wrong)?);
    let prf_key: SymmetricCryptoKey = derive_symmetric_key_from_prf(&bytes).map_err(|_| prf_wrong())?;
    let der: Vec<u8> = private.decrypt_with_key(&prf_key).map_err(|_| prf_wrong())?;
    let private_key = PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(der)).map_err(|_| prf_wrong())?;
    // (the SDK's own login with a passkey and its auth requests decapsulate the same way, unsigned)
    #[allow(deprecated)]
    let user_key = user.decapsulate_key_unsigned(&private_key).map_err(|_| prf_wrong())?;
    Ok(Zeroizing::new(user_key.to_base64().to_string()))
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
    /// One of its passkeys can unlock it (the PRF extension).
    pub passkey: bool,
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
    /// With a two-step code: the server remembers this device for two-step login.
    pub remember: bool,
}

/// What a poll of a login with another device gave.
#[derive(Debug, PartialEq, Eq)]
pub enum DevicePoll {
    /// The other device has not answered yet.
    Pending,
    /// Approved: logged in and unlocked. The account's email.
    Done(String),
}

/// How long the server keeps an auth request (Bitwarden's 15 minutes): past it, a poll is `expired` without asking.
pub const AUTH_REQUEST_LIFE: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// A login with another device that waits for its approval.
struct DeviceWait {
    email: String,
    id: String,
    device_id: String,
    started: std::time::Instant,
    /// The key pair and the access code (the SDK's `new_auth_request`): its private key opens the approval's key.
    auth: AuthRequestResponse,
}

/// What opens the account's keys at the end of a login.
enum Opener<'a> {
    Password(&'a str),
    /// Another device's approval: the request's private key and the key it encapsulated (the user key, or the master
    /// key with `master_key`).
    AuthRequest {
        auth: AuthRequestResponse,
        key: String,
        master_key: bool,
    },
    /// The user key itself, in base64 (a passkey's PRF output opened it).
    UserKey(Zeroizing<String>),
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
    /// A passkey of the account: its PRF output (base64url) and its credential id (base64url; "" when unknown).
    Passkey {
        prf: &'a str,
        credential_id: &'a str,
    },
}

/// The values of one item for a fill or a copy: each asked field that the item has, by its protocol name ("totp" is
/// the current code of a login's TOTP key). Zeroed when dropped.
#[derive(Default)]
pub struct Values(pub Vec<(String, String)>);

impl Drop for Values {
    fn drop(&mut self) {
        for (_, v) in &mut self.0 {
            v.zeroize();
        }
    }
}

/// One `save`: a new login (`item` "") or the changes to an existing one ("" leaves a field as it is).
#[derive(Clone, Copy, Default)]
pub struct SaveRequest<'a> {
    pub item: &'a str,
    pub name: &'a str,
    /// The page's address ("" = none).
    pub uri: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

/// One `generate`: a password or a passphrase. A field at 0, "" or false takes its default; a password with no
/// character class asks for all four.
#[derive(Clone, Default)]
pub struct Generate {
    /// "password" or "passphrase".
    pub kind: String,
    pub length: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub min_numbers: u32,
    pub min_special: u32,
    pub words: u32,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

/// The length of a password when the browser names none: longer than the SDK's 16, because nobody types it.
pub const PASSWORD_LENGTH: u32 = 20;
/// The words of a passphrase when the browser names none.
pub const PASSPHRASE_WORDS: u32 = 5;
pub const PASSPHRASE_SEPARATOR: &str = "-";

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
    /// A login with another device that waits for its approval.
    device_wait: Option<DeviceWait>,
    /// A passkey login between its options and its assertion: the options' token, and their relying party.
    passkey: Option<(Zeroizing<String>, String)>,
    /// This profile's device identifier (`Store::device`), once read or made.
    device: Option<String>,
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
            device_wait: None,
            passkey: None,
            device: None,
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
                passkey: !prf_options_of(s).is_empty(),
            },
            None => Account {
                state: "none",
                email: String::new(),
                login: LOGIN_PASSWORD,
                pin: false,
                passkey: false,
            },
        })
    }

    fn forget_waiting(&mut self) {
        self.waiting = None; // (zeroed by its drop)
        self.device_wait = None;
        self.passkey = None;
    }

    /// The device identifier for a login of `email`: the remembered one of that account, else this profile's.
    fn device_for(&mut self, email: &str) -> String {
        if let Some(s) = self.saved.as_ref().filter(|s| s.email.eq_ignore_ascii_case(email)) {
            return s.device_id.clone();
        }
        self.profile_device()
    }

    /// This profile's device identifier: kept in `device.json` (it outlives a logout), made at its first use.
    fn profile_device(&mut self) -> String {
        if let Some(d) = &self.device {
            return d.clone();
        }
        let id = self.store.device().unwrap_or_else(|| {
            let id = uuid::Uuid::new_v4().to_string();
            // (not kept: the next login makes another one, as before this file existed)
            let _ = self.store.save_device(&id);
            id
        });
        self.device = Some(id.clone());
        id
    }

    /// The token of a two-step login that the server remembers for `device` and `email`.
    async fn remembered_token(&self, device: &str, email: &str) -> Option<Zeroizing<String>> {
        let tokens = self.tokens.clone();
        let device = device.to_string();
        let email = email.to_string();
        blocking(move || {
            tokens
                .load_remembered(&device)
                .token_of(&email)
                .map(|t| Zeroizing::new(t.to_string()))
        })
        .await
        .flatten()
    }

    /// Keeps (`Some`) or forgets (`None`) that token.
    async fn remember_token(&self, device: &str, email: &str, token: Option<String>) {
        let tokens = self.tokens.clone();
        let device = device.to_string();
        let email = email.to_string();
        let token = token.map(Zeroizing::new);
        blocking(move || {
            let mut r: Remembered = tokens.load_remembered(&device);
            r.set(&email, token.as_deref().map(String::as_str));
            let _ = tokens.save_remembered(&device, &r);
        })
        .await;
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
        if req.resend {
            // (a resend that fails keeps the login waiting: the person can ask again or type a code already mailed)
            let sent = match req.provider {
                Some("email") => {
                    let client = new_client(&config, &device_id);
                    let request = TwoFactorEmailRequest {
                        password: password.to_string(),
                        email: req.email.to_string(),
                    };
                    let sent = client.auth().send_two_factor_email(&request).await.is_ok();
                    drop(request); // (the zeroizing allocator clears the password's memory)
                    sent
                }
                _ => resend_device_code(&config, &device_id, req.email, &password).await,
            };
            self.waiting = Some(Waiting {
                email: req.email.to_string(),
                password: password.to_string(),
                device_id,
                providers: providers.clone(),
            });
            if !sent {
                return Err(Failure::new(
                    "network",
                    "The server did not send a new code. Ask again, or type the code already mailed.",
                ));
            }
            return Ok(if req.provider == Some("email") {
                LoginOutcome::NeedTwoFactor {
                    providers,
                    email_sent: true,
                }
            } else {
                LoginOutcome::NeedDeviceCode
            });
        }
        let code = req.code.map(str::trim);
        // (a first step goes with the token of an earlier "remember me", when this device has one for the account)
        let remembered = match code {
            None => self.remembered_token(&device_id, req.email).await,
            Some(_) => None,
        };
        let second = match (code, req.provider) {
            (Some(c), Some("device")) => Some(Second::DeviceCode(c)),
            (Some(c), p) => Some(Second::TwoFactor {
                provider: p.and_then(identity::provider_id).unwrap_or(0),
                code: c,
                remember: req.remember,
            }),
            (None, _) => remembered.as_deref().map(|t| Second::Remembered(t.as_str())),
        };
        let result = self
            .password_step(&config, req.email, &password, second.as_ref(), device_id.clone())
            .await;
        if remembered.is_some() && matches!(result, Ok(LoginOutcome::NeedTwoFactor { .. })) {
            // (the server forgot this device: its token is of no use any more)
            self.remember_token(&device_id, req.email, None).await;
        }
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
        let kdf = client
            .auth()
            .prelogin(email.to_string())
            .await
            .map_err(|_| cannot_reach())?;
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
        match token_request(&client, &form, Some(email)).await? {
            TokenAnswer::Tokens {
                access_token,
                refresh_token,
                expires_in,
                two_factor_token,
                prf: _,
            } => {
                set_tokens(&client, access_token, refresh_token, expires_in).await;
                if let Some(t) = two_factor_token {
                    self.remember_token(&device_id, email, Some(t)).await;
                }
                self.finish_login(
                    config,
                    client,
                    device_id,
                    Some(email),
                    Opener::Password(password),
                    Login::Password,
                )
                .await?;
                Ok(LoginOutcome::Done)
            }
            TokenAnswer::TwoFactor { providers } if providers.is_empty() => Err(unsupported_two_factor()),
            TokenAnswer::TwoFactor { providers } => {
                let email_sent = providers == ["email"];
                Ok(LoginOutcome::NeedTwoFactor { providers, email_sent })
            }
            TokenAnswer::DeviceCode => Ok(LoginOutcome::NeedDeviceCode),
            other => Err(refusal(other)),
        }
    }

    /// `password_hint`: the server mails the account's master password hint (it answers the same for an unknown
    /// email: nobody learns which emails have an account).
    pub async fn password_hint(&mut self, email: &str) -> Result<(), Failure> {
        let config = self.config.clone().ok_or_else(no_hello)?;
        let email = email.trim();
        if email.is_empty() {
            return Err(Failure::new("bad_request", "The hint needs the account's email."));
        }
        let client = new_client(&config, &self.profile_device());
        let body = serde_json::json!({ "email": email }).to_string();
        match http(&client, Server::Api, "/accounts/password-hint", Some(body.as_str())).await {
            Some((status, _)) if (200..300).contains(&status) => Ok(()),
            Some((status, text)) if status == 400 => Err(Failure::new(
                "bad_request",
                error_message(&text).unwrap_or_else(|| "The server refused to send the hint.".into()),
            )),
            Some(_) => Err(Failure::new("network", "The server refused to send the hint.")),
            None => Err(cannot_reach()),
        }
    }

    /// `device_request`: a login that another device of the account approves (Bitwarden's "log in with device"). The
    /// helper makes a key pair and an access code (the SDK's `new_auth_request`), sends the public key to the server,
    /// and returns the fingerprint phrase that the other device shows too.
    pub async fn device_request(&mut self, email: &str) -> Result<String, Failure> {
        let config = self.config.clone().ok_or_else(no_hello)?;
        self.forget_waiting();
        let email = email.trim().to_string();
        if email.is_empty() {
            return Err(Failure::new(
                "bad_request",
                "A login with a device needs the account's email.",
            ));
        }
        let device_id = self.device_for(&email);
        let client = new_client(&config, &device_id);
        let auth = client
            .auth()
            .new_auth_request(&email)
            .map_err(|_| Failure::new("decrypt", "The keys of the request cannot be made."))?;
        // (type 0: AuthenticateAndUnlock; the server takes the device type from the Device-Type header)
        let body = serde_json::json!({
            "email": email, "publicKey": auth.public_key.to_string(), "deviceIdentifier": device_id,
            "accessCode": auth.access_code, "type": 0,
        })
        .to_string();
        let Some((status, text)) = http(&client, Server::Api, "/auth-requests", Some(body.as_str())).await else {
            return Err(cannot_reach());
        };
        if !(200..300).contains(&status) {
            return Err(Failure::new(
                "login_failed",
                error_message(&text)
                    .unwrap_or_else(|| "The server refused the login with a device. Is the email right?".into()),
            ));
        }
        let id = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("id")
                    .or_else(|| v.get("Id"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .ok_or_else(|| Failure::new("login_failed", "The server's answer to the request is not understood."))?;
        let fingerprint = auth.fingerprint.clone();
        self.device_wait = Some(DeviceWait {
            email,
            id,
            device_id,
            started: std::time::Instant::now(),
            auth,
        });
        Ok(fingerprint)
    }

    /// `device_poll`: one look at the request (the browser asks again on its own timer). Approved: the token request
    /// with the access code, the sync, the keys from the approval.
    pub async fn device_poll(&mut self) -> Result<DevicePoll, Failure> {
        let config = self.config.clone().ok_or_else(no_hello)?;
        let Some(wait) = self.device_wait.take() else {
            return Err(Failure::new("bad_request", "No login with a device waits."));
        };
        if wait.started.elapsed() > AUTH_REQUEST_LIFE {
            return Err(expired());
        }
        let client = new_client(&config, &wait.device_id);
        let path = format!(
            "/auth-requests/{}/response?code={}",
            wait.id,
            url::form_urlencoded::byte_serialize(wait.auth.access_code.as_bytes()).collect::<String>()
        );
        let Some((status, text)) = http(&client, Server::Api, &path, None).await else {
            // (a network that comes back: the next poll may succeed)
            self.device_wait = Some(wait);
            return Err(cannot_reach());
        };
        if status == 404 {
            return Err(expired());
        }
        let approval = if (200..300).contains(&status) {
            identity::parse_approval(&text)
        } else {
            None
        };
        let (key, master_key) = match approval {
            Some(Approval::Pending) => {
                self.device_wait = Some(wait);
                return Ok(DevicePoll::Pending);
            }
            Some(Approval::Denied) => {
                return Err(Failure::new("denied", "The other device refused the login."));
            }
            Some(Approval::Approved { key, master_key }) => (key, master_key),
            None => {
                self.device_wait = Some(wait);
                return Err(Failure::new(
                    "login_failed",
                    "The server's answer to the request is not understood.",
                ));
            }
        };
        let form = identity::auth_request_form(
            &wait.email,
            &wait.auth.access_code,
            &wait.id,
            &Device {
                identifier: &wait.device_id,
                name: &config.device_name,
            },
            None,
        );
        match token_request(&client, &form, Some(&wait.email)).await? {
            TokenAnswer::Tokens {
                access_token,
                refresh_token,
                expires_in,
                ..
            } => {
                set_tokens(&client, access_token, refresh_token, expires_in).await;
                let DeviceWait {
                    email, device_id, auth, ..
                } = wait;
                let opener = Opener::AuthRequest { auth, key, master_key };
                let email = self
                    .finish_login(&config, client, device_id, Some(&email), opener, Login::Password)
                    .await?;
                Ok(DevicePoll::Done(email))
            }
            TokenAnswer::TwoFactor { .. } => Err(Failure::new(
                "unsupported_two_factor",
                "The server asks for a second step after the approval: log in with the master password.",
            )),
            other => Err(refusal(other)),
        }
    }

    /// `passkey_options`: the options of a passkey ceremony, as JSON text. `login`: the server's assertion options
    /// (their token is kept for `login_passkey`). `unlock`: the account's passkeys that unlock it, with a random
    /// challenge, for the relying party `rp_id` (the saved one of a passkey login first).
    pub async fn passkey_options(&mut self, purpose: &str, rp_id: &str) -> Result<String, Failure> {
        let config = self.config.clone().ok_or_else(no_hello)?;
        match purpose {
            "login" => {
                self.forget_waiting();
                let client = new_client(&config, &self.profile_device());
                let Some((status, text)) =
                    http(&client, Server::Identity, "/accounts/webauthn/assertion-options", None).await
                else {
                    return Err(cannot_reach());
                };
                let v = serde_json::from_str::<Value>(&text)
                    .ok()
                    .filter(|_| (200..300).contains(&status));
                let token = v
                    .as_ref()
                    .and_then(|v| v.get("token").or_else(|| v.get("Token")))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let options = v
                    .as_ref()
                    .and_then(|v| v.get("options").or_else(|| v.get("Options")))
                    .and_then(identity::passkey_request_options);
                let (Some(token), Some(options)) = (token, options) else {
                    return Err(Failure::new(
                        "login_failed",
                        "The server does not offer a login with a passkey (or its answer is not understood).",
                    ));
                };
                let rp = options.get("rpId").and_then(Value::as_str).unwrap_or(rp_id).to_string();
                self.passkey = Some((Zeroizing::new(token), rp));
                Ok(options.to_string())
            }
            "unlock" => {
                let saved = self.saved.as_ref().ok_or_else(no_account)?;
                let credentials: Vec<(String, Vec<String>)> = prf_options_of(saved)
                    .into_iter()
                    .filter_map(|o| o.credential_id.map(|id| (id, o.transports.unwrap_or_default())))
                    .collect();
                if credentials.is_empty() {
                    return Err(Failure::new(
                        "no_passkey",
                        "No passkey of this account unlocks the vault.",
                    ));
                }
                let rp = if saved.rp_id.is_empty() {
                    rp_id
                } else {
                    saved.rp_id.as_str()
                };
                if rp.is_empty() {
                    return Err(Failure::new(
                        "bad_request",
                        "An unlock with a passkey needs its relying party.",
                    ));
                }
                let mut challenge = Vec::with_capacity(32);
                challenge.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
                challenge.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
                let options = identity::passkey_unlock_options(rp, &identity::base64url(&challenge), &credentials);
                Ok(options.to_string())
            }
            _ => Err(Failure::new(
                "bad_request",
                "A passkey's options are for a login or an unlock.",
            )),
        }
    }

    /// `login_passkey`: the assertion of the ceremony whose options `passkey_options` gave, and its PRF output
    /// (base64url). The server checks the assertion; the PRF output opens the passkey's keys here, never there.
    pub async fn login_passkey(&mut self, assertion: &Assertion<'_>, prf: &str) -> Result<String, Failure> {
        let config = self.config.clone().ok_or_else(no_hello)?;
        let Some((token, rp)) = self.passkey.take() else {
            return Err(Failure::new("bad_request", "Ask for the passkey's options first."));
        };
        let device_id = self.profile_device();
        let client = new_client(&config, &device_id);
        let response = identity::passkey_response(assertion);
        let form = identity::webauthn_form(
            &token,
            &response,
            &Device {
                identifier: &device_id,
                name: &config.device_name,
            },
        );
        match token_request(&client, &form, None).await? {
            TokenAnswer::Tokens {
                access_token,
                refresh_token,
                expires_in,
                prf: option,
                ..
            } => {
                let Some(option) = option else {
                    return Err(Failure::new(
                        "passkey_no_unlock",
                        "This passkey logs in but does not open the vault: turn on its use for encryption in the web vault, or log in with the master password.",
                    ));
                };
                let user_key = prf_open(prf, &option)?;
                set_tokens(&client, access_token, refresh_token, expires_in).await;
                let email = self
                    .finish_login(
                        &config,
                        client,
                        device_id,
                        None,
                        Opener::UserKey(user_key),
                        Login::Password,
                    )
                    .await?;
                if let Some(saved) = self.saved.as_mut() {
                    saved.rp_id = rp;
                    let _ = self.store.save(saved);
                }
                Ok(email)
            }
            TokenAnswer::TwoFactor { .. } => Err(Failure::new(
                "unsupported_two_factor",
                "The server asks for a second step after the passkey: log in with the master password.",
            )),
            other => Err(refusal(other)),
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
        match token_request(&client, &form, None).await? {
            // (an API key login has no second step, and its answer carries no passkey material)
            TokenAnswer::Tokens {
                access_token,
                refresh_token,
                expires_in,
                ..
            } => {
                set_tokens(&client, access_token, refresh_token, expires_in).await;
                let login = Login::ApiKey {
                    client_id: client_id.to_string(),
                    client_secret: Zeroizing::new(client_secret.trim().to_string()),
                };
                self.finish_login(&config, client, device_id, None, Opener::Password(password), login)
                    .await
            }
            TokenAnswer::TwoFactor { .. } | TokenAnswer::DeviceCode => Err(Failure::new(
                "login_failed",
                "The server's answer to the API key login is not understood.",
            )),
            other => Err(refusal(other)),
        }
    }

    /// After the tokens: the sync, the keys (`opener`), the state. Returns the account's email.
    async fn finish_login(
        &mut self,
        config: &Config,
        client: Client,
        device_id: String,
        email: Option<&str>,
        opener: Opener<'_>,
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
        let (method, wrong) = match opener {
            Opener::Password(password) => (
                InitUserCryptoMethod::MasterPasswordUnlock {
                    password: password.to_string(),
                    master_password_unlock: unlock.clone(),
                },
                Failure::new("bad_password", "The master password does not open this account's keys."),
            ),
            Opener::AuthRequest { auth, key, master_key } => {
                let bad = || {
                    Failure::new(
                        "decrypt",
                        "The other device's approval does not open this account's keys.",
                    )
                };
                let method = if master_key {
                    AuthRequestMethod::MasterKey {
                        protected_master_key: key.parse().map_err(|_| bad())?,
                        auth_request_key: unlock.master_key_wrapped_user_key.clone(),
                    }
                } else {
                    AuthRequestMethod::UserKey {
                        protected_user_key: key.parse().map_err(|_| bad())?,
                    }
                };
                (
                    InitUserCryptoMethod::AuthRequest {
                        request_private_key: auth.private_key,
                        method,
                    },
                    bad(),
                )
            }
            Opener::UserKey(key) => (
                InitUserCryptoMethod::DecryptedKey {
                    decrypted_user_key: key.to_string(),
                },
                prf_wrong(),
            ),
        };
        let request = InitUserCryptoRequest {
            user_id: user_id.parse().ok(),
            kdf_params: unlock.kdf.clone(),
            email: email.clone(),
            account_cryptographic_state: account_crypto.clone(),
            method,
            upgrade_token: None,
        };
        client
            .crypto()
            .initialize_user_crypto(request)
            .await
            .map_err(|_| wrong)?;
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
            prf_options: prf_options_value(&captured.crypto)?,
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
            Unlock::Passkey { prf, credential_id } => {
                let options = prf_options_of(&saved);
                if options.is_empty() {
                    return Err(Failure::new(
                        "no_passkey",
                        "No passkey of this account unlocks the vault.",
                    ));
                }
                // (the passkey the authenticator used; all of them when its id is not known)
                let key = options
                    .iter()
                    .filter(|o| credential_id.is_empty() || o.credential_id.as_deref() == Some(credential_id))
                    .find_map(|o| prf_user_key(prf, &o.encrypted_private_key, &o.encrypted_user_key).ok())
                    .ok_or_else(prf_wrong)?;
                InitUserCryptoMethod::DecryptedKey {
                    decrypted_user_key: key.to_string(),
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
            return Err(match with {
                Unlock::Passkey { .. } => prf_wrong(),
                _ => Failure::new("bad_password", "The master password is wrong."),
            });
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
        // (a passkey added or removed in the web vault since: the unlock dialog offers it, or not, from now on)
        saved.prf_options = prf_options_value(&captured.crypto)?;
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

    /// The decrypted items that the browser lists (logins, cards, identities), then dropped by the caller.
    async fn views(&self) -> Result<Vec<CipherView>, Failure> {
        let client = self.client.as_ref().ok_or_else(locked)?;
        let result = client
            .vault()
            .ciphers()
            .decrypt_list_full_with_failures(self.ciphers.clone())
            .await;
        Ok(result.successes.into_iter().filter(listed).collect())
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
            if !matches!(view.r#type, CipherType::Login) {
                continue;
            }
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
                    kind: "login",
                });
            }
        }
        rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(rows)
    }

    /// `search`: the logins, cards and identities whose name, user name (a card's brand and last digits, an identity's
    /// name or email) or addresses hold every word of `query`, sorted by name, at most `limit` (0 or more than
    /// `SEARCH_LIMIT`: `SEARCH_LIMIT`). No password, no card number.
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
            let Some((kind, username)) = summary(&view) else {
                continue;
            };
            let login = view.login.as_ref().filter(|_| kind == "login");
            let uris: Vec<&str> = login
                .and_then(|l| l.uris.as_ref())
                .into_iter()
                .flatten()
                .filter_map(|u| u.uri.as_deref())
                .collect();
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
                has_totp: login.is_some_and(|l| l.totp.is_some()),
                kind,
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

    /// The decrypted item that a row named: a login, a card or an identity.
    async fn item_view(&self, item: &str) -> Result<CipherView, Failure> {
        let client = self.client.as_ref().ok_or_else(locked)?;
        let cipher = self
            .ciphers
            .iter()
            .find(|c| id_is(c, item))
            .cloned()
            .ok_or_else(|| Failure::new("no_item", "The item is not in the vault any more."))?;
        let view = client
            .vault()
            .ciphers()
            .decrypt(cipher)
            .await
            .map_err(|_| Failure::new("decrypt", "The item cannot be decrypted."))?;
        if !listed(&view) {
            return Err(Failure::new(
                "no_item",
                "The item is not a login, a card or an identity.",
            ));
        }
        Ok(view)
    }

    /// `fill`: the values of one item that the user picked, one per asked field that the item has. A field of another
    /// kind of item gives nothing. A wanted TOTP code that a login cannot give is an error (`no_totp`): the browser
    /// asked for it because the row said the item has one.
    pub async fn fill(&self, item: &str, fields: &[String]) -> Result<Values, Failure> {
        let view = self.item_view(item).await?;
        let mut values = Values::default();
        for name in fields {
            if values.0.iter().any(|(n, _)| n == name) {
                continue;
            }
            let value = match (&view.r#type, &view.login, &view.card, &view.identity) {
                (CipherType::Login, Some(login), _, _) => match name.as_str() {
                    "username" => login.username.clone(),
                    "password" => login.password.clone(),
                    "totp" => Some(totp_now(login.totp.as_deref())?.code.to_string()),
                    _ => None,
                },
                (CipherType::Card, _, Some(card), _) => card_field(card, name),
                (CipherType::Identity, _, _, Some(identity)) => identity_field(identity, name),
                _ => None,
            };
            if let Some(v) = value {
                values.0.push((name.clone(), v));
            }
        }
        Ok(values)
    }

    /// `save`: creates a login (`item` "") or updates one, through the SDK's vault client: it encrypts the item, sends
    /// it to the server (POST /ciphers, PUT /ciphers/{id}) and keeps the password history. The server's copy then
    /// goes into the helper's items and its state, so that `logins_for`, `search` and `fill` see it before a sync.
    /// Returns the item's id.
    pub async fn save(&mut self, req: SaveRequest<'_>) -> Result<String, Failure> {
        let client = self.client.clone().ok_or_else(locked)?;
        let uri = req.uri.trim();
        let id = if req.item.is_empty() {
            create_login(&client, &req, uri).await?
        } else {
            self.update_login(&client, &req, uri).await?
        };
        let cipher = stored_cipher(&client, id).await?;
        let id = id.to_string();
        self.keep_cipher(&id, cipher);
        Ok(id)
    }

    /// The edit of an existing login: the non-empty username and password, and the page's address when none of the
    /// item's addresses covers it. Returns its id.
    async fn update_login(&self, client: &Client, req: &SaveRequest<'_>, uri: &str) -> Result<CipherId, Failure> {
        let no_login = || Failure::new("no_item", "The item is not a login of the vault.");
        let cipher = self
            .ciphers
            .iter()
            .find(|c| id_is(c, req.item))
            .cloned()
            .ok_or_else(no_login)?;
        let id = cipher.id.ok_or_else(no_login)?;
        let view = client
            .vault()
            .ciphers()
            .decrypt(cipher.clone())
            .await
            .map_err(|_| Failure::new("decrypt", "The item cannot be decrypted."))?;
        if view.deleted_date.is_some() || !matches!(view.r#type, CipherType::Login) || view.login.is_none() {
            return Err(no_login());
        }
        // the SDK's edit reads the item from the client's own store (its password history is kept against that copy);
        // the helper keeps the items itself, so it puts this one there first
        let repository = client.platform().state().get::<Cipher>().map_err(|_| not_saved())?;
        repository.set(id, cipher).await.map_err(|_| not_saved())?;
        let mut request = CipherEditRequest::try_from(view).map_err(|_| not_saved())?;
        if let CipherViewType::Login(login) = &mut request.r#type {
            if !req.username.is_empty() {
                login.username = Some(req.username.to_string());
            }
            if !req.password.is_empty() {
                login.password = Some(req.password.to_string());
            }
            if !uri.is_empty() {
                let covered = {
                    let saved: Vec<(&str, Rule)> = login
                        .uris
                        .iter()
                        .flatten()
                        .filter_map(|u| u.uri.as_deref().map(|s| (s, rule_of(&u.r#match))))
                        .collect();
                    matching::covered(uri, &saved)
                };
                if !covered {
                    login.uris.get_or_insert_with(Vec::new).push(new_uri(uri));
                }
            }
        }
        client.vault().ciphers().edit(request).await.map_err(|e| match e {
            EditCipherError::Api(a) => api_failure(&a),
            _ => not_saved(),
        })?;
        Ok(id)
    }

    /// Puts the server's copy of a saved item into the helper's items and its state.
    fn keep_cipher(&mut self, id: &str, cipher: Cipher) {
        match self.ciphers.iter_mut().find(|c| id_is(c, id)) {
            Some(c) => *c = cipher,
            None => self.ciphers.push(cipher),
        }
        if let Some(saved) = self.saved.as_mut() {
            saved.ciphers = self
                .ciphers
                .iter()
                .filter_map(|c| serde_json::to_value(c).ok())
                .collect();
            // (the server has the item already: a failure here is no failure of the save, and the next sync writes it)
            let _ = self.store.save(saved);
        }
    }

    /// `totp`: the current code of one item's TOTP key, computed by the SDK.
    pub async fn totp(&self, item: &str) -> Result<Code, Failure> {
        let view = self.login_view(item).await?;
        totp_now(view.login.as_ref().and_then(|l| l.totp.as_deref()))
    }
}

/// Whether the browser lists this item: a login, a card or an identity, not in the trash.
fn listed(view: &CipherView) -> bool {
    view.deleted_date.is_none()
        && match view.r#type {
            CipherType::Login => view.login.is_some(),
            CipherType::Card => view.card.is_some(),
            CipherType::Identity => view.identity.is_some(),
            _ => false,
        }
}

fn id_is(cipher: &Cipher, id: &str) -> bool {
    cipher.id.map(|i| i.to_string()).as_deref() == Some(id)
}

/// A row's kind and the text it shows under the name: a login's username, a card's brand and last digits, an
/// identity's name or email. `None` for the items that the browser does not list.
fn summary(view: &CipherView) -> Option<(&'static str, String)> {
    match (&view.r#type, &view.login, &view.card, &view.identity) {
        (CipherType::Login, Some(l), _, _) => Some(("login", l.username.clone().unwrap_or_default())),
        (CipherType::Card, _, Some(c), _) => Some(("card", card_label(c.brand.as_deref(), c.number.as_deref()))),
        (CipherType::Identity, _, _, Some(i)) => Some(("identity", identity_label(i))),
        _ => None,
    }
}

/// "Visa *1234": the card's brand and the last 4 digits of its number; "" when it has no number. The rest of the
/// number never leaves the helper in a row.
pub fn card_label(brand: Option<&str>, number: Option<&str>) -> String {
    let digits: Vec<char> = number.unwrap_or("").chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return String::new();
    }
    let last: String = digits[digits.len().saturating_sub(4)..].iter().collect();
    match brand.map(str::trim).filter(|b| !b.is_empty()) {
        Some(b) => format!("{b} *{last}"),
        None => format!("*{last}"),
    }
}

/// An identity's full name, else its email, else "".
pub fn identity_label(i: &IdentityView) -> String {
    let name = full_name(i);
    if name.is_empty() {
        i.email.as_deref().map(str::trim).unwrap_or("").to_string()
    } else {
        name
    }
}

/// First, middle and last names, with single spaces.
fn full_name(i: &IdentityView) -> String {
    [&i.first_name, &i.middle_name, &i.last_name]
        .into_iter()
        .flatten()
        .flat_map(|p| p.split_whitespace())
        .collect::<Vec<_>>()
        .join(" ")
}

fn text(v: &Option<String>) -> Option<String> {
    v.clone().filter(|s| !s.is_empty())
}

/// A card's field by its protocol name; `None` when the card does not have it or the name is no card field.
pub fn card_field(c: &CardView, name: &str) -> Option<String> {
    text(match name {
        "cardholder" => &c.cardholder_name,
        "number" => &c.number,
        "exp_month" => &c.exp_month,
        "exp_year" => &c.exp_year,
        "code" => &c.code,
        "brand" => &c.brand,
        _ => return None,
    })
}

/// An identity's field by its protocol name; `None` when the identity does not have it or the name is no identity
/// field.
pub fn identity_field(i: &IdentityView, name: &str) -> Option<String> {
    if name == "full_name" {
        return Some(full_name(i)).filter(|n| !n.is_empty());
    }
    text(match name {
        "title" => &i.title,
        "first_name" => &i.first_name,
        "middle_name" => &i.middle_name,
        "last_name" => &i.last_name,
        "address1" => &i.address1,
        "address2" => &i.address2,
        "address3" => &i.address3,
        "city" => &i.city,
        "state" => &i.state,
        "postal_code" => &i.postal_code,
        "country" => &i.country,
        "company" => &i.company,
        "email" => &i.email,
        "phone" => &i.phone,
        "username" => &i.username,
        "ssn" => &i.ssn,
        "passport" => &i.passport_number,
        "license" => &i.license_number,
        _ => return None,
    })
}

fn not_saved() -> Failure {
    Failure::new("save_failed", "The item could not be saved.")
}

/// A refused or failed request of the vault's API: the server's sentence when it gave one.
fn api_failure(e: &ApiError) -> Failure {
    match e {
        ApiError::Response(r) => Failure::new(
            "save_failed",
            error_message(&r.message)
                .unwrap_or_else(|| format!("The server refused the item (status {}).", r.status.as_u16())),
        ),
        _ => Failure::new("save_failed", "The server cannot be reached: the item was not saved."),
    }
}

fn new_uri(uri: &str) -> LoginUriView {
    // (no match type: the account's default, as a login saved in Bitwarden's own clients)
    LoginUriView {
        uri: Some(uri.to_string()),
        r#match: None,
        uri_checksum: None,
    }
}

fn some_text(v: &str) -> Option<String> {
    (!v.is_empty()).then(|| v.to_string())
}

/// A new login in the account's own vault (no organization, no folder), sent by the SDK. Returns its id. Its name is
/// the browser's (the site's host), else the host of `uri`.
async fn create_login(client: &Client, req: &SaveRequest<'_>, uri: &str) -> Result<CipherId, Failure> {
    let name = match req.name.trim() {
        "" => url::Url::parse(uri)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .ok_or_else(|| Failure::new("bad_request", "A new login needs a name."))?,
        n => n.to_string(),
    };
    let login = LoginView {
        username: some_text(req.username),
        password: some_text(req.password),
        password_revision_date: None,
        uris: (!uri.is_empty()).then(|| vec![new_uri(uri)]),
        totp: None,
        autofill_on_page_load: None,
        http_authentication_enabled: None,
        fido2_credentials: None,
    };
    let request = CipherCreateRequest {
        organization_id: None,
        collection_ids: Vec::new(),
        folder_id: None,
        name,
        notes: None,
        favorite: false,
        reprompt: CipherRepromptType::None,
        r#type: CipherViewType::Login(login),
        fields: Vec::new(),
        archived_date: None,
    };
    let view = client.vault().ciphers().create(request).await.map_err(|e| match e {
        CreateCipherError::Api(a) => api_failure(&a),
        _ => not_saved(),
    })?;
    view.id.ok_or_else(not_saved)
}

/// The encrypted item as the server answered it: the SDK's create and edit keep it in the client's store.
async fn stored_cipher(client: &Client, id: CipherId) -> Result<Cipher, Failure> {
    let repository = client.platform().state().get::<Cipher>().map_err(|_| not_saved())?;
    repository.get(id).await.ok().flatten().ok_or_else(not_saved)
}

/// A generator request, checked: the defaults filled in, the values out of range refused (`bad_request`).
enum Recipe {
    Password(PasswordGeneratorRequest),
    Passphrase(PassphraseGeneratorRequest),
}

fn out_of_range(message: &str) -> Failure {
    Failure::new("bad_request", message)
}

fn recipe(g: &Generate) -> Result<Recipe, Failure> {
    match g.kind.as_str() {
        "password" => {
            let length = if g.length == 0 { PASSWORD_LENGTH } else { g.length };
            if !(u32::from(MINIMUM_PASSWORD_LENGTH)..=u32::from(MAXIMUM_PASSWORD_LENGTH)).contains(&length) {
                return Err(out_of_range(&format!(
                    "A password has {MINIMUM_PASSWORD_LENGTH} to {MAXIMUM_PASSWORD_LENGTH} characters."
                )));
            }
            if g.min_numbers > u32::from(MAXIMUM_MIN_CHAR_COUNT) || g.min_special > u32::from(MAXIMUM_MIN_CHAR_COUNT) {
                return Err(out_of_range(&format!(
                    "A minimum count of numbers or special characters is at most {MAXIMUM_MIN_CHAR_COUNT}."
                )));
            }
            let all = !(g.uppercase || g.lowercase || g.numbers || g.special);
            let numbers = all || g.numbers;
            let special = all || g.special;
            // (0: one of the class when it is on; the SDK ignores the minimum of a class that is off)
            let minimum = |n: u32, on: bool| on.then(|| n.max(1) as u8);
            Ok(Recipe::Password(PasswordGeneratorRequest {
                lowercase: all || g.lowercase,
                uppercase: all || g.uppercase,
                numbers,
                special,
                length: length as u8,
                min_number: minimum(g.min_numbers, numbers),
                min_special: minimum(g.min_special, special),
                ..Default::default()
            }))
        }
        "passphrase" => {
            let words = if g.words == 0 { PASSPHRASE_WORDS } else { g.words };
            if !(u32::from(MINIMUM_PASSPHRASE_NUM_WORDS)..=u32::from(MAXIMUM_PASSPHRASE_NUM_WORDS)).contains(&words) {
                return Err(out_of_range(&format!(
                    "A passphrase has {MINIMUM_PASSPHRASE_NUM_WORDS} to {MAXIMUM_PASSPHRASE_NUM_WORDS} words."
                )));
            }
            Ok(Recipe::Passphrase(PassphraseGeneratorRequest {
                num_words: words as u8,
                word_separator: if g.separator.is_empty() {
                    PASSPHRASE_SEPARATOR.to_string()
                } else {
                    g.separator.clone()
                },
                capitalize: g.capitalize,
                include_number: g.include_number,
            }))
        }
        _ => Err(out_of_range("A generated value is a password or a passphrase.")),
    }
}

/// `generate`: a password or a passphrase from the SDK's generator. It needs no account: a client without settings
/// runs it, and nothing goes to a server.
pub fn generate(g: &Generate) -> Result<Zeroizing<String>, Failure> {
    let request = recipe(g)?;
    let generator = ClientBuilder::new().build().generator();
    match request {
        Recipe::Password(r) => generator.password(r).map(Zeroizing::new).map_err(|_| {
            out_of_range("The minimum counts of numbers and special characters do not fit in the length.")
        }),
        Recipe::Passphrase(r) => generator
            .passphrase(r)
            .map(Zeroizing::new)
            .map_err(|_| out_of_range("The passphrase's options are out of range.")),
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
        bitwarden_client_version: Some(BITWARDEN_CLIENT_VERSION.to_string()),
        bitwarden_package_type: None,
    };
    ClientBuilder::new()
        .with_settings(settings)
        .with_token_handler(Arc::new(PasswordManagerTokenHandler::default()))
        .build()
}

/// The Bitwarden client version this helper speaks for (the `Bitwarden-Client-Version` header). The identity server
/// refuses a token without it, and refuses an account with V2 encryption below 2026.10.1 (its ClientVersionValidator).
/// It names the clients of the pinned SDK's release: raise it with the SDK pin.
pub const BITWARDEN_CLIENT_VERSION: &str = "2026.11.0";

/// Sends a token request with the SDK's HTTP client of the identity server (its TLS roots, its user agent and its
/// `Device-Type` header) and reads the answer.
async fn token_request(client: &Client, form: &str, auth_email: Option<&str>) -> Result<TokenAnswer, Failure> {
    let network = || Failure::new("network", "The server cannot be reached, or it refused the request.");
    let configurations = client.internal.get_api_configurations();
    let id_config = &configurations.identity_config;
    let mut request = id_config
        .client
        .post(format!("{}/connect/token", id_config.base_path))
        .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
        .header("accept", "application/json");
    if let Some(email) = auth_email {
        request = request.header("auth-email", identity::auth_email_header(email));
    }
    let response = request.body(form.to_string()).send().await.map_err(|_| network())?;
    let status = response.status().as_u16();
    let text = Zeroizing::new(response.text().await.map_err(|_| network())?);
    Ok(identity::parse_token_answer(status, &text))
}

/// Which of the configured servers a request goes to.
#[derive(Clone, Copy)]
enum Server {
    Identity,
    Api,
}

/// One request without a session to the identity server or the API, with the SDK's HTTP client (its TLS roots, its
/// user agent, its `Device-Type` header): a POST of `body` (JSON), else a GET. The status and the body, zeroed when
/// dropped; `None` when the server did not answer.
async fn http(client: &Client, server: Server, path: &str, body: Option<&str>) -> Option<(u16, Zeroizing<String>)> {
    let configurations = client.internal.get_api_configurations();
    let (base, http) = match server {
        Server::Identity => (
            &configurations.identity_config.base_path,
            &configurations.identity_config.client,
        ),
        Server::Api => (&configurations.api_config.base_path, &configurations.api_config.client),
    };
    let url = format!("{base}{path}");
    let request = match body {
        Some(b) => http
            .post(url)
            .header("content-type", "application/json; charset=utf-8")
            .body(b.to_string()),
        None => http.get(url),
    };
    let response = request.header("accept", "application/json").send().await.ok()?;
    let status = response.status().as_u16();
    let text = Zeroizing::new(response.text().await.ok()?);
    Some((status, text))
}

/// Asks the server to mail a new code of the new-device verification (`POST {api}/accounts/resend-new-device-otp`,
/// with the master password hash: what Bitwarden's clients send). True when it says it did.
async fn resend_device_code(config: &Config, device_id: &str, email: &str, password: &str) -> bool {
    let client = new_client(config, device_id);
    let Ok(kdf) = client.auth().prelogin(email.to_string()).await else {
        return false;
    };
    let Ok(auth) = MasterPasswordAuthenticationData::derive(password, &kdf, email) else {
        return false;
    };
    let hash = Zeroizing::new(auth.master_password_authentication_hash.to_string());
    let body = Zeroizing::new(serde_json::json!({ "email": email, "masterPasswordHash": hash.as_str() }).to_string());
    matches!(
        http(&client, Server::Api, "/accounts/resend-new-device-otp", Some(body.as_str())).await,
        Some((status, _)) if (200..300).contains(&status)
    )
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

    fn password(g: Generate) -> PasswordGeneratorRequest {
        match recipe(&Generate {
            kind: "password".into(),
            ..g
        }) {
            Ok(Recipe::Password(r)) => r,
            _ => panic!("not a password request"),
        }
    }

    fn refused(g: Generate) -> &'static str {
        match recipe(&g) {
            Err(f) => f.code,
            Ok(_) => "accepted",
        }
    }

    #[test]
    fn a_password_request_takes_its_defaults() {
        let r = password(Generate::default());
        assert_eq!(r.length, 20);
        assert!(
            r.lowercase && r.uppercase && r.numbers && r.special,
            "no class: all four"
        );
        assert_eq!((r.min_number, r.min_special), (Some(1), Some(1)));
        let r = password(Generate {
            length: 32,
            lowercase: true,
            numbers: true,
            min_numbers: 3,
            ..Default::default()
        });
        assert_eq!(r.length, 32);
        assert!(r.lowercase && r.numbers && !r.uppercase && !r.special);
        assert_eq!((r.min_number, r.min_special), (Some(3), None));
    }

    #[test]
    fn a_generate_request_out_of_range_is_refused() {
        let pw = |length, min_numbers| Generate {
            kind: "password".into(),
            length,
            min_numbers,
            ..Default::default()
        };
        assert_eq!(refused(pw(4, 0)), "bad_request");
        assert_eq!(refused(pw(129, 0)), "bad_request");
        assert_eq!(refused(pw(5, 0)), "accepted");
        assert_eq!(refused(pw(128, 0)), "accepted");
        assert_eq!(refused(pw(20, 10)), "bad_request");
        let words = |words| Generate {
            kind: "passphrase".into(),
            words,
            ..Default::default()
        };
        assert_eq!(refused(words(2)), "bad_request");
        assert_eq!(refused(words(21)), "bad_request");
        assert_eq!(refused(words(3)), "accepted");
        assert_eq!(refused(Generate::default()), "bad_request", "no kind");
        // the minimums are in range but do not fit in the length: the SDK refuses them
        let tight = Generate {
            kind: "password".into(),
            length: 5,
            numbers: true,
            special: true,
            min_numbers: 3,
            min_special: 3,
            ..Default::default()
        };
        assert_eq!(generate(&tight).err().map(|f| f.code), Some("bad_request"));
    }

    #[test]
    fn a_passphrase_request_takes_its_defaults() {
        let Ok(Recipe::Passphrase(r)) = recipe(&Generate {
            kind: "passphrase".into(),
            ..Default::default()
        }) else {
            panic!("not a passphrase request");
        };
        assert_eq!(r.num_words, 5);
        assert_eq!(r.word_separator, "-");
        assert!(!r.capitalize && !r.include_number);
        let value = generate(&Generate {
            kind: "passphrase".into(),
            words: 3,
            separator: "_".into(),
            capitalize: true,
            ..Default::default()
        })
        .unwrap();
        let words: Vec<&str> = value.split('_').collect();
        assert_eq!(words.len(), 3);
        assert!(words.iter().all(|w| w.chars().next().is_some_and(char::is_uppercase)));
        let value = generate(&Generate {
            kind: "password".into(),
            length: 12,
            numbers: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(value.len(), 12);
        assert!(value.chars().all(|c| c.is_ascii_digit()));
    }

    fn card() -> CardView {
        CardView {
            cardholder_name: Some("Ada Lovelace".into()),
            exp_month: Some("7".into()),
            exp_year: Some("2031".into()),
            code: Some("123".into()),
            brand: Some("Visa".into()),
            number: Some("4111 1111 1111 1234".into()),
        }
    }

    fn identity() -> IdentityView {
        IdentityView {
            title: Some("Dr".into()),
            first_name: Some("Ada".into()),
            middle_name: Some(" ".into()),
            last_name: Some("King  Lovelace".into()),
            address1: Some("1 Main St".into()),
            address2: None,
            address3: Some(String::new()),
            city: Some("London".into()),
            state: None,
            postal_code: Some("W1".into()),
            country: Some("GB".into()),
            company: None,
            email: Some("ada@example.com".into()),
            phone: Some("+44 20".into()),
            ssn: None,
            username: Some("ada".into()),
            passport_number: Some("P1".into()),
            license_number: Some("L1".into()),
        }
    }

    #[test]
    fn a_card_row_shows_its_brand_and_last_digits() {
        let c = card();
        assert_eq!(card_label(c.brand.as_deref(), c.number.as_deref()), "Visa *1234");
        assert_eq!(card_label(None, Some("5500-0000-0000-0004")), "*0004");
        assert_eq!(card_label(Some("Amex"), Some("12")), "Amex *12");
        assert_eq!(card_label(Some("Visa"), None), "");
        assert_eq!(card_label(Some("Visa"), Some("")), "");
    }

    #[test]
    fn an_identity_row_shows_its_name_or_its_email() {
        let mut i = identity();
        assert_eq!(identity_label(&i), "Ada King Lovelace");
        i.first_name = None;
        i.middle_name = None;
        i.last_name = None;
        assert_eq!(identity_label(&i), "ada@example.com");
        i.email = None;
        assert_eq!(identity_label(&i), "");
    }

    #[test]
    fn a_fill_names_the_fields_of_cards_and_identities() {
        let c = card();
        let field = |n| card_field(&c, n);
        assert_eq!(field("cardholder").as_deref(), Some("Ada Lovelace"));
        assert_eq!(field("number").as_deref(), Some("4111 1111 1111 1234"));
        assert_eq!(field("exp_month").as_deref(), Some("7"));
        assert_eq!(field("exp_year").as_deref(), Some("2031"));
        assert_eq!(field("code").as_deref(), Some("123"));
        assert_eq!(field("brand").as_deref(), Some("Visa"));
        // a login's field, or an identity's, gives nothing for a card
        for name in ["username", "password", "totp", "first_name", "email"] {
            assert_eq!(field(name), None, "{name}");
        }
        let i = identity();
        let field = |n| identity_field(&i, n);
        assert_eq!(field("full_name").as_deref(), Some("Ada King Lovelace"));
        assert_eq!(field("title").as_deref(), Some("Dr"));
        assert_eq!(field("first_name").as_deref(), Some("Ada"));
        assert_eq!(field("last_name").as_deref(), Some("King  Lovelace"));
        assert_eq!(field("address1").as_deref(), Some("1 Main St"));
        assert_eq!(field("city").as_deref(), Some("London"));
        assert_eq!(field("postal_code").as_deref(), Some("W1"));
        assert_eq!(field("country").as_deref(), Some("GB"));
        assert_eq!(field("email").as_deref(), Some("ada@example.com"));
        assert_eq!(field("phone").as_deref(), Some("+44 20"));
        assert_eq!(field("username").as_deref(), Some("ada"));
        assert_eq!(field("passport").as_deref(), Some("P1"));
        assert_eq!(field("license").as_deref(), Some("L1"));
        // what the identity does not have (none, or empty) is not in the answer
        for name in [
            "address2", "address3", "state", "company", "ssn", "password", "number", "totp",
        ] {
            assert_eq!(field(name), None, "{name}");
        }
    }

    const USER: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ITEM: &str = "5faa9684-c793-4a2d-8a12-b33900187097";

    /// The server's answer to a POST or a PUT of an item: the item that it received, with its id and its dates.
    struct Echo;

    impl wiremock::Respond for Echo {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let mut v: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            if let Some(o) = v.as_object_mut() {
                for (k, x) in [
                    ("object", serde_json::json!("cipher")),
                    ("id", serde_json::json!(ITEM)),
                    ("edit", serde_json::json!(true)),
                    ("viewPassword", serde_json::json!(true)),
                    ("creationDate", serde_json::json!("2026-11-12T10:00:00Z")),
                    ("revisionDate", serde_json::json!("2026-11-12T10:00:00Z")),
                ] {
                    o.insert(k.into(), x);
                }
            }
            wiremock::ResponseTemplate::new(200).set_body_json(v)
        }
    }

    /// A session unlocked with keys made here (a V1 account: a user key and a private key that it wraps), with an
    /// access token: what a login leaves, without the fixtures of a real account.
    async fn unlocked(server: &wiremock::MockServer) -> Session {
        use bitwarden_crypto::{KeyEncryptable, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm};
        let config = Config {
            identity_url: format!("{}/identity", server.uri()),
            api_url: format!("{}/api", server.uri()),
            client_version: "test".into(),
            device_name: String::new(),
        };
        let mut s = Session::default();
        s.hello(config.clone(), "", false)
            .ok()
            .expect("a loopback server is allowed");
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let der = PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1)
            .to_der()
            .expect("a private key has a DER form");
        let private_key: EncString = (&der).encrypt_with_key(&user_key).expect("the user key wraps it");
        let client = new_client(&config, "device");
        let request = InitUserCryptoRequest {
            user_id: USER.parse().ok(),
            kdf_params: Kdf::default_pbkdf2(),
            email: "user@example.com".into(),
            account_cryptographic_state: WrappedAccountCryptographicState::V1 { private_key },
            method: InitUserCryptoMethod::DecryptedKey {
                decrypted_user_key: user_key.to_base64().to_string(),
            },
            upgrade_token: None,
        };
        assert!(
            client.crypto().initialize_user_crypto(request).await.is_ok(),
            "the made keys open"
        );
        set_tokens(&client, "access".into(), None, 3600).await;
        s.client = Some(client);
        s.saved = Some(Saved::default());
        s
    }

    fn saved_ok(r: Result<String, Failure>) -> String {
        r.unwrap_or_else(|f| panic!("{}: {}", f.code, f.message))
    }

    #[tokio::test]
    async fn save_creates_then_updates_a_login_that_the_vault_sees_at_once() {
        use wiremock::{
            Mock, MockServer,
            matchers::{header, method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/ciphers"))
            .and(header("authorization", "Bearer access"))
            .respond_with(Echo)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/api/ciphers/{ITEM}")))
            .respond_with(Echo)
            .expect(2)
            .mount(&server)
            .await;
        let mut s = unlocked(&server).await;
        let created = s
            .save(SaveRequest {
                name: "a.example",
                uri: "https://a.example/login",
                username: "me",
                password: "first secret",
                ..Default::default()
            })
            .await;
        assert_eq!(saved_ok(created), ITEM);
        let requests = server.received_requests().await.unwrap();
        let posted = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(
            !posted.contains("first secret") && !posted.contains("a.example"),
            "the item goes encrypted"
        );
        // (no sync: the server's answer is in the helper's items and its state)
        let rows = s.search("a.example", 0).await.unwrap_or_default();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].kind, rows[0].username.as_str()), ("login", "me"));
        let page = Page {
            url: "https://www.a.example/",
            host: "www.a.example",
            domain: "a.example",
            equivalent: &[],
        };
        assert_eq!(s.logins_for(&page).await.unwrap_or_default().len(), 1);
        assert_eq!(s.saved.as_ref().map(|v| v.ciphers.len()), Some(1));
        let fields = ["username".to_string(), "password".to_string()];
        let values = s.fill(ITEM, &fields).await.unwrap_or_default();
        assert_eq!(
            values.0,
            vec![
                ("username".to_string(), "me".to_string()),
                ("password".to_string(), "first secret".to_string())
            ]
        );
        drop(values);

        // an update of the password, from a page that the saved address covers: no new address
        let updated = s
            .save(SaveRequest {
                item: ITEM,
                uri: "https://www.a.example/other",
                password: "second secret",
                ..Default::default()
            })
            .await;
        assert_eq!(saved_ok(updated), ITEM);
        let requests = server.received_requests().await.unwrap();
        let put: Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(
            put["passwordHistory"].as_array().map(Vec::len),
            Some(1),
            "the SDK keeps the former password in the history"
        );
        let values = s.fill(ITEM, &fields).await.unwrap_or_default();
        assert_eq!(values.0[0].1, "me", "an empty username leaves it as it is");
        assert_eq!(values.0[1].1, "second secret");
        drop(values);
        let page = Page {
            url: "https://b.example/",
            host: "b.example",
            domain: "b.example",
            equivalent: &[],
        };
        assert!(s.logins_for(&page).await.unwrap_or_default().is_empty());

        // a page of another site: its address joins the item's
        let updated = s
            .save(SaveRequest {
                item: ITEM,
                uri: "https://b.example/",
                ..Default::default()
            })
            .await;
        assert_eq!(saved_ok(updated), ITEM);
        assert_eq!(s.logins_for(&page).await.unwrap_or_default().len(), 1);
        assert_eq!(s.ciphers.len(), 1, "an update replaces the item");

        let missing = s
            .save(SaveRequest {
                item: "6faa9684-c793-4a2d-8a12-b33900187097",
                password: "x",
                ..Default::default()
            })
            .await;
        assert_eq!(missing.err().map(|f| f.code), Some("no_item"));
    }

    #[tokio::test]
    async fn a_refused_save_says_why() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/ciphers"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "message": "The field Name must be a string with a maximum length of 1000.",
                "object": "error"
            })))
            .mount(&server)
            .await;
        let mut s = unlocked(&server).await;
        let failure = s
            .save(SaveRequest {
                name: "a.example",
                password: "pw",
                ..Default::default()
            })
            .await
            .err()
            .expect("the server refused it");
        assert_eq!(failure.code, "save_failed");
        assert!(failure.message.contains("maximum length"), "{}", failure.message);
        assert!(s.ciphers.is_empty());
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
