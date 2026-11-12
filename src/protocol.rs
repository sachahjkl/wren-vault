//! The requests and answers of the pipe protocol (README.md). Plain types: no SDK type crosses the pipe.

use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

/// One request of the browser. `id` is a number that the answer repeats; 0 is not a valid id (it marks events).
#[derive(Deserialize)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub op: Op,
}

/// What a request asks. The `op` field names it.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// The first request. Says where the state is, which server to use, and the idle deadline.
    Hello {
        protocol: u32,
        /// The directory of the helper's state ("" with `persist` false: nothing is written).
        state_dir: String,
        identity_url: String,
        api_url: String,
        #[serde(default)]
        device_name: String,
        #[serde(default)]
        client_version: String,
        #[serde(default)]
        persist: bool,
        /// Seconds without a request after which the helper locks itself (exits). 0: never.
        #[serde(default)]
        idle_seconds: u64,
    },
    /// Log in with the master password. A second step carries the same email, the code and its provider; the helper
    /// kept the password of the first step. `resend` asks for the code again (a new mail).
    Login {
        email: String,
        #[serde(default)]
        password: Option<Secret>,
        #[serde(default)]
        code: Option<Secret>,
        /// "authenticator", "email" or "device".
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        resend: bool,
        /// With a two-step code: the server remembers this device for two-step login.
        #[serde(default)]
        remember: bool,
    },
    /// Ask the server to mail the account's master password hint.
    PasswordHint { email: String },
    /// Start a login that another device of the account approves; the answer is the fingerprint phrase.
    DeviceRequest { email: String },
    /// One look at that login's approval.
    DevicePoll,
    /// The options of a passkey ceremony: `purpose` "login" or "unlock"; `rp_id` the web vault's domain (an unlock's
    /// relying party when no passkey login named one).
    PasskeyOptions {
        purpose: String,
        #[serde(default)]
        rp_id: String,
    },
    /// Log in with the passkey ceremony's assertion (each value base64url) and its PRF output. (`credential_id`: the
    /// request's own `id` is the frame's.)
    LoginPasskey {
        credential_id: String,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
        #[serde(default)]
        user_handle: String,
        prf: Secret,
    },
    /// Log in with the account's personal API key, then unlock with the master password.
    LoginApiKey {
        client_id: String,
        client_secret: Secret,
        password: Secret,
    },
    /// Unlock the remembered account with the master password, the PIN, or a passkey's PRF output (`prf`, with the
    /// `credential_id` the authenticator used).
    Unlock {
        #[serde(default)]
        password: Option<Secret>,
        #[serde(default)]
        pin: Option<Secret>,
        #[serde(default)]
        prf: Option<Secret>,
        #[serde(default)]
        credential_id: String,
    },
    /// Lock: the helper answers, then exits.
    Lock,
    /// Forget the account here (state, tokens, PIN): the helper answers, then exits.
    Logout,
    /// Get the vault from the server again.
    Sync,
    /// Set the PIN that unlocks this account on this machine.
    PinSet { pin: Secret },
    /// Remove the PIN.
    PinClear,
    /// The logins that match a page.
    LoginsFor {
        /// The address of the document that holds the form.
        url: String,
        /// Its host (as the URL parser serializes it).
        host: String,
        /// Its registrable domain by the browser's Public Suffix List ("" when the host has none).
        #[serde(default)]
        domain: String,
    },
    /// The logins whose name, user name or address hold every word of `query` (the browser's command palette). No
    /// password, no code.
    Search {
        query: String,
        /// The first match to return (a page of a long list: the browser asks for the next one as it scrolls).
        #[serde(default)]
        offset: usize,
        /// The most rows to return (0: `SEARCH_PAGE`; never more than `SEARCH_PAGE_MAX`).
        #[serde(default)]
        limit: usize,
        /// The kinds of items to list ("login", "card", "identity"); empty: all three.
        #[serde(default)]
        kinds: Vec<String>,
    },
    /// The values of one item, for a fill or a copy that the user asked for: `fields` lists a login's "username",
    /// "password", "totp" (the current code), a card's or an identity's fields (README.md, "Fill").
    Fill { item: String, fields: Vec<String> },
    /// The current code of one login's TOTP key, and the seconds it stays valid.
    Totp { item: String },
    /// Create a login (`item` "") or update one (`item` its id). On update, only the non-empty `username` and
    /// `password` change, and `uri` is added when none of the item's addresses covers it.
    Save {
        #[serde(default)]
        item: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        uri: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: Secret,
    },
    /// A new password or passphrase from the SDK's generator. Needs no unlocked vault. A field left out (or 0, "",
    /// false) takes its default (`sdk::Generate`).
    Generate {
        /// "password" or "passphrase".
        kind: String,
        #[serde(default)]
        length: u32,
        #[serde(default)]
        uppercase: bool,
        #[serde(default)]
        lowercase: bool,
        #[serde(default)]
        numbers: bool,
        #[serde(default)]
        special: bool,
        #[serde(default)]
        min_numbers: u32,
        #[serde(default)]
        min_special: u32,
        #[serde(default)]
        words: u32,
        #[serde(default)]
        separator: String,
        #[serde(default)]
        capitalize: bool,
        #[serde(default)]
        include_number: bool,
    },
    /// The vault's passkeys of a site, for a page's `navigator.credentials.get`: `allow` lists the credential ids that
    /// the page accepts (base64url; empty: any passkey of `rp_id`).
    PasskeysFor {
        rp_id: String,
        #[serde(default)]
        allow: Vec<String>,
    },
    /// Sign a page's assertion with one passkey of the vault (`item` and `credential_id`, from a `passkeys_for` row).
    /// `client_data_hash`: the SHA-256 of the clientDataJSON that the browser made, base64url.
    PasskeyAssert {
        item: String,
        credential_id: String,
        rp_id: String,
        client_data_hash: String,
    },
    /// The user is active: the idle deadline starts again. No answer.
    Keepalive,
}

/// A value that is zeroed when it is dropped: a password, a PIN, a code, a client secret.
#[derive(Deserialize, Default)]
#[serde(transparent)]
pub struct Secret(pub String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An error answer. `code` is one of the stable codes of README.md; `message` is for the person, never a secret.
pub fn error(id: u64, code: &str, message: &str) -> Value {
    json!({ "id": id, "ok": false, "error": code, "message": message })
}

/// A success answer with the fields of `body` (an object).
pub fn ok(id: u64, body: Value) -> Value {
    let mut out = json!({ "id": id, "ok": true });
    if let (Some(o), Value::Object(b)) = (out.as_object_mut(), body) {
        for (k, v) in b {
            o.insert(k, v);
        }
    }
    out
}

/// An event: a message that answers no request (id 0).
pub fn event(name: &str) -> Value {
    json!({ "id": 0, "ok": true, "event": name })
}

/// One row of `logins_for` or `search`: what the browser shows. No password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub name: String,
    pub username: String,
    /// The saved URI that matched (`logins_for`), or the item's first web address (`search`; "" when it has none).
    pub uri: String,
    /// How it matched: "domain", "host", "equivalent", "starts_with" or "exact"; "" for a `search` row.
    pub matched: &'static str,
    pub has_totp: bool,
    /// "login", "card" or "identity".
    pub kind: &'static str,
}

impl Row {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "id": self.id, "name": self.name, "username": self.username, "uri": self.uri, "has_totp": self.has_totp,
            "kind": self.kind,
        });
        if let (false, Some(o)) = (self.matched.is_empty(), v.as_object_mut()) {
            o.insert("match".into(), json!(self.matched));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_by_their_op() {
        let r: Request = serde_json::from_str(r#"{"id":3,"op":"login","email":"a@b.c","password":"pw"}"#).unwrap();
        assert_eq!(r.id, 3);
        match r.op {
            Op::Login {
                email,
                password,
                code,
                provider,
                resend,
                remember,
            } => {
                assert_eq!(email, "a@b.c");
                assert_eq!(password.map(|p| p.0.clone()).as_deref(), Some("pw"));
                assert!(code.is_none() && provider.is_none() && !resend && !remember);
            }
            _ => panic!("not a login"),
        }
        let r: Request = serde_json::from_str(r#"{"id":4,"op":"lock"}"#).unwrap();
        assert!(matches!(r.op, Op::Lock));
        let r: Request =
            serde_json::from_str(r#"{"id":5,"op":"logins_for","url":"https://a.b/","host":"a.b","domain":"a.b"}"#)
                .unwrap();
        assert!(matches!(r.op, Op::LoginsFor { .. }));
        let r: Request = serde_json::from_str(
            r#"{"id":6,"op":"login_api_key","client_id":"user.x","client_secret":"s","password":"p"}"#,
        )
        .unwrap();
        assert!(matches!(r.op, Op::LoginApiKey { .. }));
        let r: Request = serde_json::from_str(r#"{"id":7,"op":"unlock","pin":"1234"}"#).unwrap();
        assert!(matches!(
            r.op,
            Op::Unlock {
                password: None,
                pin: Some(_),
                prf: None,
                ..
            }
        ));
        let r: Request = serde_json::from_str(r#"{"id":12,"op":"unlock","prf":"cHJm","credential_id":"aWQ"}"#).unwrap();
        assert!(matches!(r.op, Op::Unlock { prf: Some(_), .. }));
        let r: Request = serde_json::from_str(r#"{"id":13,"op":"password_hint","email":"a@b.c"}"#).unwrap();
        assert!(matches!(r.op, Op::PasswordHint { .. }));
        let r: Request = serde_json::from_str(r#"{"id":14,"op":"device_request","email":"a@b.c"}"#).unwrap();
        assert!(matches!(r.op, Op::DeviceRequest { .. }));
        let r: Request = serde_json::from_str(r#"{"id":15,"op":"passkey_options","purpose":"login"}"#).unwrap();
        assert!(matches!(r.op, Op::PasskeyOptions { .. }));
        let r: Request = serde_json::from_str(
            r#"{"id":16,"op":"login_passkey","credential_id":"i","authenticator_data":"a","client_data_json":"c","signature":"s","prf":"p"}"#,
        )
        .unwrap();
        assert!(matches!(r.op, Op::LoginPasskey { .. }));
        let r: Request = serde_json::from_str(r#"{"id":8,"op":"pin_set","pin":"1234"}"#).unwrap();
        assert!(matches!(r.op, Op::PinSet { .. }));
        let r: Request = serde_json::from_str(r#"{"id":10,"op":"search","query":"git"}"#).unwrap();
        assert!(matches!(r.op, Op::Search { limit: 0, offset: 0, ref kinds, .. } if kinds.is_empty()));
        let r: Request =
            serde_json::from_str(r#"{"id":17,"op":"search","query":"","offset":100,"limit":100,"kinds":["card"]}"#)
                .unwrap();
        assert!(
            matches!(r.op, Op::Search { offset: 100, limit: 100, ref kinds, .. } if kinds == &["card".to_string()])
        );
        let r: Request = serde_json::from_str(r#"{"id":11,"op":"totp","item":"x"}"#).unwrap();
        assert!(matches!(r.op, Op::Totp { .. }));
        for op in ["pin_clear", "logout", "keepalive", "sync", "device_poll"] {
            let text = format!(r#"{{"id":9,"op":"{op}"}}"#);
            assert!(serde_json::from_str::<Request>(&text).is_ok(), "{op}");
        }
    }

    #[test]
    fn save_and_generate_parse_with_their_defaults() {
        let r: Request = serde_json::from_str(
            r#"{"id":20,"op":"save","item":"","name":"a.example","uri":"https://a.example/login","username":"me","password":"pw"}"#,
        )
        .unwrap();
        match r.op {
            Op::Save {
                item,
                name,
                uri,
                username,
                password,
            } => {
                assert_eq!(item, "");
                assert_eq!(name, "a.example");
                assert_eq!(uri, "https://a.example/login");
                assert_eq!(username, "me");
                assert_eq!(password.as_str(), "pw");
            }
            _ => panic!("not a save"),
        }
        // an update of the password only: the other fields are empty
        let r: Request = serde_json::from_str(r#"{"id":21,"op":"save","item":"x","password":"new"}"#).unwrap();
        assert!(
            matches!(&r.op, Op::Save { item, username, uri, .. } if item == "x" && username.is_empty() && uri.is_empty())
        );
        let r: Request = serde_json::from_str(r#"{"id":22,"op":"generate","kind":"password"}"#).unwrap();
        match r.op {
            Op::Generate {
                kind,
                length,
                uppercase,
                special,
                words,
                separator,
                ..
            } => {
                assert_eq!(kind, "password");
                assert_eq!((length, words), (0, 0));
                assert!(!uppercase && !special);
                assert!(separator.is_empty());
            }
            _ => panic!("not a generate"),
        }
        let r: Request = serde_json::from_str(
            r#"{"id":23,"op":"generate","kind":"passphrase","words":6,"separator":".","capitalize":true,"include_number":true}"#,
        )
        .unwrap();
        assert!(matches!(
            r.op,
            Op::Generate {
                words: 6,
                capitalize: true,
                include_number: true,
                ..
            }
        ));
        assert!(
            serde_json::from_str::<Request>(r#"{"id":24,"op":"generate"}"#).is_err(),
            "a kind is needed"
        );
        assert!(
            serde_json::from_str::<Request>(r#"{"id":25,"op":"generate","kind":"password","length":-1}"#).is_err(),
            "a negative length is no request"
        );
    }

    #[test]
    fn passkey_requests_parse_with_their_defaults() {
        let r: Request = serde_json::from_str(r#"{"id":30,"op":"passkeys_for","rp_id":"a.example"}"#).unwrap();
        assert!(matches!(&r.op, Op::PasskeysFor { rp_id, allow } if rp_id == "a.example" && allow.is_empty()));
        let r: Request =
            serde_json::from_str(r#"{"id":31,"op":"passkeys_for","rp_id":"a.example","allow":["aWQ","aWQy"]}"#)
                .unwrap();
        assert!(matches!(&r.op, Op::PasskeysFor { allow, .. } if allow.len() == 2));
        let r: Request = serde_json::from_str(
            r#"{"id":32,"op":"passkey_assert","item":"x","credential_id":"aWQ","rp_id":"a.example","client_data_hash":"aGFzaA"}"#,
        )
        .unwrap();
        assert!(matches!(&r.op, Op::PasskeyAssert { item, credential_id, .. } if item == "x" && credential_id == "aWQ"));
        assert!(
            serde_json::from_str::<Request>(r#"{"id":33,"op":"passkey_assert","item":"x","rp_id":"a.example"}"#)
                .is_err(),
            "an assertion needs its credential and the client data's hash"
        );
    }

    #[test]
    fn an_unknown_op_is_refused() {
        assert!(serde_json::from_str::<Request>(r#"{"id":1,"op":"dump_keys"}"#).is_err());
    }

    #[test]
    fn answers_carry_the_id() {
        let v = ok(7, json!({ "account": "none" }));
        assert_eq!(v["id"], 7);
        assert_eq!(v["ok"], true);
        assert_eq!(v["account"], "none");
        let e = error(8, "bad_password", "The master password is wrong.");
        assert_eq!(e["ok"], false);
        assert_eq!(e["error"], "bad_password");
        let row = Row {
            id: "1".into(),
            name: "A".into(),
            username: "me".into(),
            uri: "https://a.example".into(),
            matched: "",
            has_totp: true,
            kind: "login",
        };
        assert!(row.to_json().get("match").is_none(), "a search row has no match type");
        assert_eq!(row.to_json()["kind"], "login");
        let ev = event("locked");
        assert_eq!(ev["id"], 0);
        assert_eq!(ev["event"], "locked");
    }
}
