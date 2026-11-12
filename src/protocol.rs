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
    },
    /// Log in with the account's personal API key, then unlock with the master password.
    LoginApiKey {
        client_id: String,
        client_secret: Secret,
        password: Secret,
    },
    /// Unlock the remembered account with the master password or the PIN.
    Unlock {
        #[serde(default)]
        password: Option<Secret>,
        #[serde(default)]
        pin: Option<Secret>,
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
        /// The most rows to return (0: the helper's own bound).
        #[serde(default)]
        limit: usize,
    },
    /// The values of one login, for a fill or a copy that the user asked for: `fields` lists "username", "password",
    /// "totp" (the current code).
    Fill { item: String, fields: Vec<String> },
    /// The current code of one login's TOTP key, and the seconds it stays valid.
    Totp { item: String },
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
}

impl Row {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "id": self.id, "name": self.name, "username": self.username, "uri": self.uri, "has_totp": self.has_totp,
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
            } => {
                assert_eq!(email, "a@b.c");
                assert_eq!(password.map(|p| p.0.clone()).as_deref(), Some("pw"));
                assert!(code.is_none() && provider.is_none() && !resend);
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
                pin: Some(_)
            }
        ));
        let r: Request = serde_json::from_str(r#"{"id":8,"op":"pin_set","pin":"1234"}"#).unwrap();
        assert!(matches!(r.op, Op::PinSet { .. }));
        let r: Request = serde_json::from_str(r#"{"id":10,"op":"search","query":"git"}"#).unwrap();
        assert!(matches!(r.op, Op::Search { limit: 0, .. }));
        let r: Request = serde_json::from_str(r#"{"id":11,"op":"totp","item":"x"}"#).unwrap();
        assert!(matches!(r.op, Op::Totp { .. }));
        for op in ["pin_clear", "logout", "keepalive", "sync"] {
            let text = format!(r#"{{"id":9,"op":"{op}"}}"#);
            assert!(serde_json::from_str::<Request>(&text).is_ok(), "{op}");
        }
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
        };
        assert!(row.to_json().get("match").is_none(), "a search row has no match type");
        let ev = event("locked");
        assert_eq!(ev["id"], 0);
        assert_eq!(ev["event"], "locked");
    }
}
