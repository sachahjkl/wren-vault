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
    TwoFactor { provider: u8, code: &'a str },
    /// The code of the new-device verification mail.
    DeviceCode(&'a str),
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
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = email.as_bytes();
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

/// The form of a password login. `hash`: the master password hash (the SDK's server authorization hash), never the
/// password. The form is zeroed when it is dropped.
pub fn password_form(email: &str, hash: &str, device: &Device, second: Option<&Second>) -> Zeroizing<String> {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    f.append_pair("scope", "api offline_access");
    f.append_pair("client_id", CLIENT_ID);
    f.append_pair("deviceType", &DEVICE_TYPE.to_string());
    f.append_pair("deviceIdentifier", device.identifier);
    f.append_pair("deviceName", device.name);
    f.append_pair("grant_type", "password");
    f.append_pair("username", email);
    f.append_pair("password", hash);
    match second {
        Some(Second::TwoFactor { provider, code }) => {
            f.append_pair("twoFactorToken", code);
            f.append_pair("twoFactorProvider", &provider.to_string());
            f.append_pair("twoFactorRemember", "0");
        }
        Some(Second::DeviceCode(code)) => {
            f.append_pair("newDeviceOtp", code);
        }
        None => {}
    }
    Zeroizing::new(f.finish())
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
    /// Logged in.
    Tokens {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: u64,
    },
    /// The account asks for a second step. `providers`: those that the helper supports, by their protocol names
    /// (empty when the account has none of them).
    TwoFactor { providers: Vec<&'static str> },
    /// The account must confirm this new device with the code that the server mailed.
    DeviceCode,
    /// The server refused the login. The sentence is the server's: it names no secret.
    Refused(String),
    /// Not an answer of the identity server.
    Unexpected,
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
            },
            None => TokenAnswer::Unexpected,
        };
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
    if status == 400 {
        let text = if message.is_empty() {
            v.get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("The server refused the login.")
        } else {
            message
        };
        return TokenAnswer::Refused(text.to_string());
    }
    TokenAnswer::Unexpected
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
        };
        let p = pairs(&password_form("a@b.c", "h", &device, Some(&email)));
        assert_eq!(get(&p, "twoFactorToken"), Some("123456"));
        assert_eq!(get(&p, "twoFactorProvider"), Some("1"));
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
                expires_in: 60
            }
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
    fn provider_names_are_the_protocols() {
        assert_eq!(provider_id("authenticator"), Some(0));
        assert_eq!(provider_id("email"), Some(1));
        assert_eq!(provider_id("duo"), None);
    }
}
