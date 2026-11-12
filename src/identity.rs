//! The token request of the identity server (`POST {identity}/connect/token`), written by the helper itself.
//!
//! Why not the SDK's `login_password`: at the pinned revision it sends device type `ChromeBrowser`, one device identifier
//! that every SDK user shares, and it has no field for the new-device code (README.md, "Device"). The helper sends its
//! own device identifier, device type 14 (`UnknownBrowser`: a browser that the server does not know by name), client id
//! `web` (the client of browsers), and `newDeviceOtp` when the server asks for it. Everything else (prelogin, the hash
//! of the master password, the keys, the sync) stays the SDK's.
//!
//! This module only writes the form and reads the answer: no SDK type, no network. `sdk` sends it.

use serde_json::Value;
use zeroize::Zeroizing;

/// The client id of the token request, and of the renewal with the refresh token.
pub const CLIENT_ID: &str = "web";

/// The server's `DeviceType.UnknownBrowser`. The SDK's `ClientSettings` gets the same value (the `Device-Type` header).
pub const DEVICE_TYPE: u8 = 14;

/// The server's message when an account must confirm a new device with a code that it mails.
const NEW_DEVICE_MESSAGE: &str = "new device verification required";

/// The server's `TwoFactorProviderType.Remember`: the token that the server gave when the person asked it to remember
/// this device for two-step login.
pub const REMEMBER_PROVIDER: u8 = 5;

/// The PRF salt of a login or an unlock with a passkey: SHA-256 of the text "passwordless-login", in base64url without
/// padding. Bitwarden's clients use this salt when they register a passkey for the vault's encryption: the account's
/// PRF key set opens only with the authenticator's output for it.
pub const PRF_SALT: &str = "l7AG39jbWXuJLJpQNDtSSLpsMoBZ74Es7DR84Nd0OQs";

/// The device that logs in.
pub struct Device<'a> {
    /// A random UUID, made at the first login and kept in the state.
    pub identifier: &'a str,
    /// The name that the account's device list shows.
    pub name: &'a str,
}

/// The second step of a password login.
pub enum Second<'a> {
    /// A two-step login code. `provider`: the server's `TwoFactorProviderType` (0 authenticator app, 1 email).
    /// `remember`: the server gives a token that replaces the code on this device for its own time (30 days).
    TwoFactor {
        provider: u8,
        code: &'a str,
        remember: bool,
    },
    /// The code of the new-device verification mail.
    DeviceCode(&'a str),
    /// The token of an earlier `remember`.
    Remembered(&'a str),
}

/// The server's id of a two-step provider that the helper supports, by the protocol's name.
pub fn provider_id(name: &str) -> Option<u8> {
    match name {
        "authenticator" => Some(0),
        "email" => Some(1),
        _ => None,
    }
}

/// The `Auth-Email` header of a password login: the account's email in base64url without padding. The server refuses
/// the password grant without it ("Auth-Email header invalid").
pub fn auth_email_header(email: &str) -> String {
    base64url(email.as_bytes())
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 4648 section 5): the encoding of WebAuthn's binary values.
pub fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// Decodes base64url, with or without padding (a standard `+` and `/` are read too). `None` when it is not base64.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // (one character alone cannot end a group: it carries 6 bits of no byte)
    if bits >= 6 {
        return None;
    }
    Some(out)
}

/// The form of a password login. `hash`: the master password hash (the SDK's server authorization hash), never the
/// password. The form is zeroed when it is dropped.
pub fn password_form(email: &str, hash: &str, device: &Device, second: Option<&Second>) -> Zeroizing<String> {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    user_fields(&mut f, device);
    f.append_pair("grant_type", "password");
    f.append_pair("username", email);
    f.append_pair("password", hash);
    second_fields(&mut f, second);
    Zeroizing::new(f.finish())
}

/// The fields of every login of a person (not of an API key): the scope with the refresh token, and the device.
fn user_fields(f: &mut url::form_urlencoded::Serializer<String>, device: &Device) {
    f.append_pair("scope", "api offline_access");
    f.append_pair("client_id", CLIENT_ID);
    f.append_pair("deviceType", &DEVICE_TYPE.to_string());
    f.append_pair("deviceIdentifier", device.identifier);
    f.append_pair("deviceName", device.name);
}

fn second_fields(f: &mut url::form_urlencoded::Serializer<String>, second: Option<&Second>) {
    match second {
        Some(Second::TwoFactor {
            provider,
            code,
            remember,
        }) => {
            f.append_pair("twoFactorToken", code);
            f.append_pair("twoFactorProvider", &provider.to_string());
            f.append_pair("twoFactorRemember", if *remember { "1" } else { "0" });
        }
        Some(Second::Remembered(token)) => {
            f.append_pair("twoFactorToken", token);
            f.append_pair("twoFactorProvider", &REMEMBER_PROVIDER.to_string());
            f.append_pair("twoFactorRemember", "0");
        }
        Some(Second::DeviceCode(code)) => {
            f.append_pair("newDeviceOtp", code);
        }
        None => {}
    }
}

/// The form of a login that another device of the account approved (an auth request): the password grant with the
/// request's access code in place of the hash, and the request's id. The device that approved it vouches for this
/// one: no new-device code applies.
pub fn auth_request_form(
    email: &str,
    access_code: &str,
    request_id: &str,
    device: &Device,
    second: Option<&Second>,
) -> Zeroizing<String> {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    user_fields(&mut f, device);
    f.append_pair("grant_type", "password");
    f.append_pair("username", email);
    f.append_pair("password", access_code);
    f.append_pair("authRequest", request_id);
    second_fields(&mut f, second);
    Zeroizing::new(f.finish())
}

/// The form of a login with a passkey: the token of the server's assertion options and the authenticator's answer
/// (`device_response`, from `passkey_response`).
pub fn webauthn_form(token: &str, device_response: &str, device: &Device) -> Zeroizing<String> {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    user_fields(&mut f, device);
    f.append_pair("grant_type", "webauthn");
    f.append_pair("token", token);
    f.append_pair("deviceResponse", device_response);
    Zeroizing::new(f.finish())
}

/// The parts of a WebAuthn assertion, each in base64url without padding, as the browser read them from the
/// authenticator.
#[derive(Default, Clone)]
pub struct Assertion<'a> {
    pub id: &'a str,
    pub authenticator_data: &'a str,
    pub client_data_json: &'a str,
    pub signature: &'a str,
    pub user_handle: &'a str,
}

/// The `deviceResponse` of a passkey login: the assertion as Bitwarden's web vault sends it. Its `extensions` stay
/// empty: the PRF output opens the vault and must never reach the server.
pub fn passkey_response(a: &Assertion) -> String {
    serde_json::json!({
        "id": a.id,
        "rawId": a.id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "authenticatorData": a.authenticator_data,
            "clientDataJSON": a.client_data_json,
            "signature": a.signature,
            "userHandle": a.user_handle,
        },
    })
    .to_string()
}

/// The request options of a passkey ceremony (WebAuthn's `PublicKeyCredentialRequestOptionsJSON`) from the server's
/// assertion options: only the members the ceremony needs, and the PRF extension with `PRF_SALT`. `None` when the
/// server's options have no challenge.
pub fn passkey_request_options(server: &Value) -> Option<Value> {
    let challenge = server.get("challenge").and_then(Value::as_str)?;
    let mut o = serde_json::Map::new();
    o.insert("challenge".into(), Value::String(challenge.to_string()));
    for key in ["timeout", "rpId", "allowCredentials", "userVerification"] {
        if let Some(v) = server.get(key).filter(|v| !v.is_null()) {
            o.insert(key.into(), v.clone());
        }
    }
    o.insert(
        "extensions".into(),
        serde_json::json!({ "prf": { "eval": { "first": PRF_SALT } } }),
    );
    Some(Value::Object(o))
}

/// The request options of an unlock with a passkey: the account's PRF credentials (`(id, transports)`), a random
/// challenge (no server checks this assertion: only its PRF output counts) and the relying party of the web vault.
pub fn passkey_unlock_options(rp_id: &str, challenge: &str, credentials: &[(String, Vec<String>)]) -> Value {
    let allow: Vec<Value> = credentials
        .iter()
        .map(|(id, transports)| {
            let mut c = serde_json::json!({ "type": "public-key", "id": id });
            if !transports.is_empty()
                && let Some(o) = c.as_object_mut()
            {
                o.insert("transports".into(), serde_json::json!(transports));
            }
            c
        })
        .collect();
    serde_json::json!({
        "challenge": challenge,
        "rpId": rp_id,
        "allowCredentials": allow,
        "userVerification": "required",
        "timeout": 120000,
        "extensions": { "prf": { "eval": { "first": PRF_SALT } } },
    })
}

/// The encrypted keys of a passkey that the server can open the vault with (`UserDecryptionOptions.WebAuthnPrfOption`
/// of a passkey login): the private key wrapped by the PRF key, and the user key encapsulated to its public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrfOption {
    pub encrypted_private_key: String,
    pub encrypted_user_key: String,
}

/// The form of a login with the account's personal API key (`client_id` is `user.<uuid>`).
pub fn api_key_form(client_id: &str, client_secret: &str, device: &Device) -> Zeroizing<String> {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    f.append_pair("scope", "api");
    f.append_pair("client_id", client_id);
    f.append_pair("client_secret", client_secret);
    f.append_pair("deviceType", &DEVICE_TYPE.to_string());
    f.append_pair("deviceIdentifier", device.identifier);
    f.append_pair("deviceName", device.name);
    f.append_pair("grant_type", "client_credentials");
    Zeroizing::new(f.finish())
}

/// What the identity server answered.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenAnswer {
    /// Logged in. `two_factor_token`: the server remembers this device for two-step login (the login asked it to).
    /// `prf`: the keys a passkey login opens the vault with (none for another login, or for a passkey that is not
    /// used for the vault's encryption).
    Tokens {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: u64,
        two_factor_token: Option<String>,
        prf: Option<PrfOption>,
    },
    /// The account asks for a second step. `providers`: those that the helper supports, by their protocol names
    /// (empty when the account has none of them).
    TwoFactor { providers: Vec<&'static str> },
    /// The account must confirm this new device with the code that the server mailed.
    DeviceCode,
    /// The server asks to solve a captcha first: the helper cannot show one (the web vault can).
    Captcha,
    /// The server refused the `Auth-Email` header (an email that is not the account's, or a malformed one).
    BadAuthEmail,
    /// The server says the account is locked or disabled. The sentence is the server's.
    Locked(String),
    /// The server refused the login. The sentence is the server's: it names no secret.
    Refused(String),
    /// Not an answer of the identity server.
    Unexpected,
}

/// A member of an object by one of its names: the identity server writes some in PascalCase, some in camelCase.
fn member<'a>(v: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|n| v.get(*n)).filter(|x| !x.is_null())
}

fn member_str<'a>(v: &'a Value, names: &[&str]) -> Option<&'a str> {
    member(v, names).and_then(Value::as_str)
}

/// The passkey's keys in a token answer.
fn prf_option(v: &Value) -> Option<PrfOption> {
    let options = member(v, &["UserDecryptionOptions", "userDecryptionOptions"])?;
    let prf = member(options, &["WebAuthnPrfOption", "webAuthnPrfOption"])?;
    Some(PrfOption {
        encrypted_private_key: member_str(prf, &["EncryptedPrivateKey", "encryptedPrivateKey"])?.to_string(),
        encrypted_user_key: member_str(prf, &["EncryptedUserKey", "encryptedUserKey"])?.to_string(),
    })
}

/// Reads the answer of a token request.
pub fn parse_token_answer(status: u16, body: &str) -> TokenAnswer {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return TokenAnswer::Unexpected;
    };
    if status == 200 {
        return match v.get("access_token").and_then(Value::as_str) {
            Some(access_token) => TokenAnswer::Tokens {
                access_token: access_token.to_string(),
                refresh_token: v.get("refresh_token").and_then(Value::as_str).map(str::to_string),
                expires_in: v.get("expires_in").and_then(Value::as_u64).unwrap_or(3600),
                two_factor_token: member_str(&v, &["TwoFactorToken", "twoFactorToken"]).map(str::to_string),
                prf: prf_option(&v),
            },
            None => TokenAnswer::Unexpected,
        };
    }
    // (a server with captchas names its site key; the helper has no page to show the captcha in)
    if let Some(o) = v.as_object()
        && o.keys().any(|k| k.to_ascii_lowercase().contains("captcha_sitekey"))
    {
        return TokenAnswer::Captcha;
    }
    // (the server sends the providers' ids as the keys of TwoFactorProviders2, each with its data or null)
    if let Some(p) = v
        .get("TwoFactorProviders2")
        .and_then(Value::as_object)
        .filter(|p| !p.is_empty())
    {
        let mut providers = Vec::new();
        if p.contains_key("0") {
            providers.push("authenticator");
        }
        if p.contains_key("1") {
            providers.push("email");
        }
        return TokenAnswer::TwoFactor { providers };
    }
    let model = v.get("ErrorModel").or_else(|| v.get("errorModel"));
    let message = model
        .and_then(|m| m.get("Message").or_else(|| m.get("message")))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if message.eq_ignore_ascii_case(NEW_DEVICE_MESSAGE) {
        return TokenAnswer::DeviceCode;
    }
    let description = v.get("error_description").and_then(Value::as_str).unwrap_or("");
    if description.to_ascii_lowercase().contains("auth-email") || message.to_ascii_lowercase().contains("auth-email") {
        return TokenAnswer::BadAuthEmail;
    }
    if status == 400 {
        let text = if message.is_empty() {
            if description.is_empty() {
                "The server refused the login."
            } else {
                description
            }
        } else {
            message
        };
        let lower = text.to_ascii_lowercase();
        if lower.contains("locked") || lower.contains("disabled") {
            return TokenAnswer::Locked(text.to_string());
        }
        return TokenAnswer::Refused(text.to_string());
    }
    TokenAnswer::Unexpected
}

/// What an auth request's state says (`GET /auth-requests/{id}/response`).
#[derive(Debug, PartialEq, Eq)]
pub enum Approval {
    /// The other device has not answered yet.
    Pending,
    /// Approved. `key`: the user key (or the master key with `master_key`), encapsulated to the request's public key.
    Approved { key: String, master_key: bool },
    /// The other device refused.
    Denied,
}

/// Reads an auth request's state. `None`: not an answer of the API.
pub fn parse_approval(body: &str) -> Option<Approval> {
    let v = serde_json::from_str::<Value>(body).ok()?;
    match member(&v, &["requestApproved", "RequestApproved"]).and_then(Value::as_bool) {
        None => Some(Approval::Pending),
        Some(false) => Some(Approval::Denied),
        Some(true) => Some(Approval::Approved {
            key: member_str(&v, &["key", "Key"])?.to_string(),
            master_key: member_str(&v, &["masterPasswordHash", "MasterPasswordHash"]).is_some(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(form: &str) -> Vec<(String, String)> {
        url::form_urlencoded::parse(form.as_bytes()).into_owned().collect()
    }

    fn get<'a>(p: &'a [(String, String)], key: &str) -> Option<&'a str> {
        p.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_password_form_names_this_device_truthfully() {
        let device = Device {
            identifier: "11111111-2222-3333-4444-555555555555",
            name: "Wren",
        };
        let p = pairs(&password_form("a+b@example.com", "h/a=sh", &device, None));
        assert_eq!(get(&p, "grant_type"), Some("password"));
        assert_eq!(get(&p, "username"), Some("a+b@example.com"));
        assert_eq!(get(&p, "password"), Some("h/a=sh"));
        assert_eq!(get(&p, "deviceType"), Some("14"));
        assert_eq!(get(&p, "deviceIdentifier"), Some(device.identifier));
        assert_eq!(get(&p, "deviceName"), Some("Wren"));
        assert_eq!(get(&p, "client_id"), Some("web"));
        assert_eq!(get(&p, "newDeviceOtp"), None);
        assert_eq!(get(&p, "twoFactorToken"), None);
    }

    #[test]
    fn second_steps_add_their_fields() {
        let device = Device {
            identifier: "d",
            name: "Wren",
        };
        let email = Second::TwoFactor {
            provider: 1,
            code: "123456",
            remember: false,
        };
        let p = pairs(&password_form("a@b.c", "h", &device, Some(&email)));
        assert_eq!(get(&p, "twoFactorToken"), Some("123456"));
        assert_eq!(get(&p, "twoFactorProvider"), Some("1"));
        assert_eq!(get(&p, "twoFactorRemember"), Some("0"));
        let remember = Second::TwoFactor {
            provider: 0,
            code: "111111",
            remember: true,
        };
        let p = pairs(&password_form("a@b.c", "h", &device, Some(&remember)));
        assert_eq!(get(&p, "twoFactorRemember"), Some("1"));
        let p = pairs(&password_form("a@b.c", "h", &device, Some(&Second::Remembered("tok"))));
        assert_eq!(get(&p, "twoFactorToken"), Some("tok"));
        assert_eq!(get(&p, "twoFactorProvider"), Some("5"));
        assert_eq!(get(&p, "twoFactorRemember"), Some("0"));
        let p = pairs(&password_form(
            "a@b.c",
            "h",
            &device,
            Some(&Second::DeviceCode("654321")),
        ));
        assert_eq!(get(&p, "newDeviceOtp"), Some("654321"));
        assert_eq!(get(&p, "twoFactorToken"), None);
    }

    #[test]
    fn an_api_key_form_is_client_credentials() {
        let device = Device {
            identifier: "d",
            name: "Wren",
        };
        let p = pairs(&api_key_form("user.abc", "s3cret", &device));
        assert_eq!(get(&p, "grant_type"), Some("client_credentials"));
        assert_eq!(get(&p, "scope"), Some("api"));
        assert_eq!(get(&p, "client_id"), Some("user.abc"));
        assert_eq!(get(&p, "client_secret"), Some("s3cret"));
    }

    #[test]
    fn answers_are_read() {
        assert_eq!(
            parse_token_answer(200, r#"{"access_token":"a","refresh_token":"r","expires_in":60}"#),
            TokenAnswer::Tokens {
                access_token: "a".into(),
                refresh_token: Some("r".into()),
                expires_in: 60,
                two_factor_token: None,
                prf: None,
            }
        );
        assert_eq!(
            parse_token_answer(
                200,
                r#"{"access_token":"a","expires_in":60,"TwoFactorToken":"remember-me","UserDecryptionOptions":{"WebAuthnPrfOption":{"EncryptedPrivateKey":"2.x","EncryptedUserKey":"4.y"}}}"#
            ),
            TokenAnswer::Tokens {
                access_token: "a".into(),
                refresh_token: None,
                expires_in: 60,
                two_factor_token: Some("remember-me".into()),
                prf: Some(PrfOption {
                    encrypted_private_key: "2.x".into(),
                    encrypted_user_key: "4.y".into()
                }),
            }
        );
        assert_eq!(
            parse_token_answer(400, r#"{"error":"invalid_grant","HCaptcha_SiteKey":"site"}"#),
            TokenAnswer::Captcha
        );
        assert_eq!(
            parse_token_answer(
                400,
                r#"{"error":"invalid_grant","error_description":"Auth-Email header invalid."}"#
            ),
            TokenAnswer::BadAuthEmail
        );
        assert_eq!(
            parse_token_answer(
                400,
                r#"{"error":"invalid_grant","ErrorModel":{"Message":"This account is locked."}}"#
            ),
            TokenAnswer::Locked("This account is locked.".into())
        );
        assert_eq!(
            parse_token_answer(
                400,
                r#"{"error":"invalid_grant","TwoFactorProviders2":{"1":{"Email":"m***@x"},"7":null}}"#
            ),
            TokenAnswer::TwoFactor {
                providers: vec!["email"]
            }
        );
        assert_eq!(
            parse_token_answer(400, r#"{"TwoFactorProviders2":{"2":{"Host":"duo"}}}"#),
            TokenAnswer::TwoFactor { providers: vec![] }
        );
        assert_eq!(
            parse_token_answer(
                400,
                r#"{"error":"device_error","error_description":"New device verification required","ErrorModel":{"Message":"new device verification required","Object":"error"}}"#
            ),
            TokenAnswer::DeviceCode
        );
        assert_eq!(
            parse_token_answer(
                400,
                r#"{"error":"invalid_grant","ErrorModel":{"Message":"Username or password is incorrect. Try again."}}"#
            ),
            TokenAnswer::Refused("Username or password is incorrect. Try again.".into())
        );
        assert_eq!(parse_token_answer(500, "<html>"), TokenAnswer::Unexpected);
        assert_eq!(parse_token_answer(200, "{}"), TokenAnswer::Unexpected);
    }

    #[test]
    fn the_auth_email_header_is_base64url_without_padding() {
        assert_eq!(auth_email_header("user@example.com"), "dXNlckBleGFtcGxlLmNvbQ");
        assert_eq!(auth_email_header("a+b@c.d"), "YStiQGMuZA");
        assert_eq!(auth_email_header("ab"), "YWI");
        assert_eq!(auth_email_header("abc"), "YWJj");
        assert_eq!(auth_email_header("\u{ff}\u{fe}"), "w7_Dvg");
    }

    #[test]
    fn base64url_round_trips() {
        let cases: [&[u8]; 6] = [b"", b"a", b"ab", b"abc", b"\xff\xfe\xfd\xfc", &[0u8; 32]];
        for bytes in cases {
            assert_eq!(base64url_decode(&base64url(bytes)).as_deref(), Some(bytes));
        }
        assert_eq!(base64url_decode("YWI=").as_deref(), Some(&b"ab"[..]));
        assert_eq!(base64url_decode("w7/Dvg").as_deref(), Some(&b"\xc3\xbf\xc3\xbe"[..]));
        assert!(base64url_decode("a").is_none());
        assert!(base64url_decode("a b").is_none());
        assert_eq!(base64url_decode(PRF_SALT).map(|b| b.len()), Some(32));
    }

    #[test]
    fn an_auth_request_form_carries_the_access_code_and_the_request() {
        let device = Device {
            identifier: "d",
            name: "Wren",
        };
        let p = pairs(&auth_request_form("a@b.c", "code25", "req-1", &device, None));
        assert_eq!(get(&p, "grant_type"), Some("password"));
        assert_eq!(get(&p, "password"), Some("code25"));
        assert_eq!(get(&p, "authRequest"), Some("req-1"));
        assert_eq!(get(&p, "scope"), Some("api offline_access"));
    }

    #[test]
    fn a_passkey_login_sends_no_prf_output() {
        let a = Assertion {
            id: "cred",
            authenticator_data: "ad",
            client_data_json: "cd",
            signature: "sig",
            user_handle: "uh",
        };
        let response = passkey_response(&a);
        let v: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["rawId"], "cred");
        assert_eq!(v["response"]["clientDataJSON"], "cd");
        assert_eq!(v["extensions"], serde_json::json!({}));
        let device = Device {
            identifier: "d",
            name: "Wren",
        };
        let p = pairs(&webauthn_form("opt-token", &response, &device));
        assert_eq!(get(&p, "grant_type"), Some("webauthn"));
        assert_eq!(get(&p, "token"), Some("opt-token"));
        assert_eq!(get(&p, "deviceResponse"), Some(response.as_str()));
    }

    #[test]
    fn passkey_options_ask_for_the_prf_of_the_vaults_salt() {
        let server = serde_json::json!({"challenge": "Y2hhbA", "timeout": 60000, "rpId": "bitwarden.com",
            "allowCredentials": [], "userVerification": "required", "status": "ok", "errorMessage": ""});
        let o = passkey_request_options(&server).unwrap();
        assert_eq!(o["rpId"], "bitwarden.com");
        assert_eq!(o["extensions"]["prf"]["eval"]["first"], PRF_SALT);
        assert!(o.get("status").is_none(), "only the members of WebAuthn's options");
        assert!(passkey_request_options(&serde_json::json!({})).is_none());
        let u = passkey_unlock_options("vault.example", "Y2g", &[("aWQ".into(), vec!["usb".into()])]);
        assert_eq!(u["allowCredentials"][0]["id"], "aWQ");
        assert_eq!(u["allowCredentials"][0]["transports"][0], "usb");
        assert_eq!(u["userVerification"], "required");
        // (SHA-256 is 32 bytes: 43 characters of base64url without padding)
        assert_eq!(PRF_SALT.len(), 43);
    }

    #[test]
    fn approvals_are_read() {
        assert_eq!(
            parse_approval(r#"{"id":"x","requestApproved":null}"#),
            Some(Approval::Pending)
        );
        assert_eq!(parse_approval(r#"{"id":"x"}"#), Some(Approval::Pending));
        assert_eq!(parse_approval(r#"{"requestApproved":false}"#), Some(Approval::Denied));
        assert_eq!(
            parse_approval(r#"{"requestApproved":true,"key":"4.k","masterPasswordHash":null}"#),
            Some(Approval::Approved {
                key: "4.k".into(),
                master_key: false
            })
        );
        assert_eq!(
            parse_approval(r#"{"requestApproved":true,"key":"4.k","masterPasswordHash":"h"}"#),
            Some(Approval::Approved {
                key: "4.k".into(),
                master_key: true
            })
        );
        assert_eq!(parse_approval("<html>"), None);
    }

    #[test]
    fn provider_names_are_the_protocols() {
        assert_eq!(provider_id("authenticator"), Some(0));
        assert_eq!(provider_id("email"), Some(1));
        assert_eq!(provider_id("duo"), None);
    }
}
