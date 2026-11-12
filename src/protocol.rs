//! The requests and answers of the pipe protocol (README.md). Plain types: no SDK type crosses the pipe.

use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

/// One request of the browser. `id` is a number that the answer repeats; 0 is not a valid id.
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
    /// The first request. Says where the state is and which server to use.
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
    },
    /// Log in with the master password. When the account asks for a second factor, the second `login` carries the
    /// same email and the code only: the helper kept the password of the first one.
    Login {
        email: String,
        #[serde(default)]
        password: Option<Secret>,
        #[serde(default)]
        totp: Option<Secret>,
    },
    /// Unlock the remembered account with the master password.
    Unlock { password: Secret },
    /// Lock: the helper answers, then exits.
    Lock,
    /// Get the vault from the server again.
    Sync,
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
    /// The values of one login, for a fill that the user asked for.
    Fill { item: String, fields: Vec<String> },
    /// The user is active. No answer.
    Keepalive,
}

/// A value that is zeroed when it is dropped: a password or a one-time code.
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

/// One row of `logins_for`: what the browser shows. No password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub name: String,
    pub username: String,
    /// The saved URI that matched.
    pub uri: String,
    /// How it matched: "domain" or "host".
    pub matched: &'static str,
    pub has_totp: bool,
}

impl Row {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id, "name": self.name, "username": self.username, "uri": self.uri,
            "match": self.matched, "has_totp": self.has_totp,
        })
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
            Op::Login { email, password, totp } => {
                assert_eq!(email, "a@b.c");
                assert_eq!(password.map(|p| p.0.clone()).as_deref(), Some("pw"));
                assert!(totp.is_none());
            }
            _ => panic!("not a login"),
        }
        let r: Request = serde_json::from_str(r#"{"id":4,"op":"lock"}"#).unwrap();
        assert!(matches!(r.op, Op::Lock));
        let r: Request =
            serde_json::from_str(r#"{"id":5,"op":"logins_for","url":"https://a.b/","host":"a.b","domain":"a.b"}"#)
                .unwrap();
        assert!(matches!(r.op, Op::LoginsFor { .. }));
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
    }
}
