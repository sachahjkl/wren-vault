//! The request loop: one frame in, one answer out, in order.
//!
//! Requests run one after the other. A login or an unlock takes the time of its key derivation; the browser has a
//! deadline per request and shows the wait. `keepalive` has no answer.

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::{
    PROTOCOL_VERSION,
    frame::{FrameError, read_frame, write_frame},
    matching::Page,
    protocol::{self, Op, Request},
    sdk::{Config, LoginOutcome, Session},
};

/// What the loop does after an answer.
enum Next {
    Continue,
    Exit,
}

/// Serves requests until the input closes or a `lock` arrives. The session (and every key) is dropped on return.
pub async fn serve<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut input: R, mut output: W) -> std::io::Result<()> {
    let mut session = Session::default();
    loop {
        let frame = match read_frame(&mut input).await {
            Ok(f) => f,
            Err(FrameError::Closed) => return Ok(()),
            // a broken peer: nothing more can be trusted on this pipe
            Err(_) => return Ok(()),
        };
        let (answer, next) = match serde_json::from_slice::<Value>(&frame) {
            Err(_) => (
                Some(protocol::error(0, "bad_request", "The request is not JSON.")),
                Next::Continue,
            ),
            Ok(v) => {
                let id = v.get("id").and_then(Value::as_u64).unwrap_or(0);
                match serde_json::from_value::<Request>(v) {
                    Ok(req) if req.id != 0 => handle(&mut session, req).await,
                    _ => (
                        Some(protocol::error(id, "bad_request", "The request is not understood.")),
                        Next::Continue,
                    ),
                }
            }
        };
        drop(frame);
        if let Some(a) = answer {
            let bytes = Zeroizing::new(serde_json::to_vec(&a).map_err(std::io::Error::other)?);
            drop(a);
            write_frame(&mut output, &bytes).await?;
        }
        if let Next::Exit = next {
            return Ok(());
        }
    }
}

async fn handle(session: &mut Session, req: Request) -> (Option<Value>, Next) {
    let id = req.id;
    let fail = |f: crate::sdk::Failure| Some(protocol::error(id, f.code, &f.message));
    match req.op {
        Op::Hello {
            protocol: version,
            state_dir,
            identity_url,
            api_url,
            device_name: _,
            client_version,
            persist,
        } => {
            if version != PROTOCOL_VERSION {
                let text = format!("This helper speaks protocol {PROTOCOL_VERSION}.");
                return (Some(protocol::error(id, "bad_protocol", &text)), Next::Continue);
            }
            let config = Config {
                identity_url,
                api_url,
                client_version,
            };
            match session.hello(config, &state_dir, persist) {
                Ok((account, email)) => (
                    Some(protocol::ok(
                        id,
                        json!({ "protocol": PROTOCOL_VERSION, "helper_version": crate::HELPER_VERSION, "account": account, "email": email }),
                    )),
                    Next::Continue,
                ),
                Err(f) => (fail(f), Next::Continue),
            }
        }
        _ if !session.configured() => (
            Some(protocol::error(id, "no_hello", "The first request must be hello.")),
            Next::Continue,
        ),
        Op::Login { email, password, totp } => {
            let result = session
                .login(
                    &email,
                    password.as_ref().map(|p| p.as_str()),
                    totp.as_ref().map(|t| t.as_str()),
                )
                .await;
            drop(password);
            drop(totp);
            match result {
                Ok(LoginOutcome::Done) => (Some(protocol::ok(id, json!({ "result": "ok" }))), Next::Continue),
                Ok(LoginOutcome::NeedTwoFactor(providers)) => (
                    Some(protocol::ok(
                        id,
                        json!({ "result": "need_two_factor", "providers": providers }),
                    )),
                    Next::Continue,
                ),
                Err(f) => (fail(f), Next::Continue),
            }
        }
        Op::Unlock { password } => {
            let result = session.unlock(password.as_str()).await;
            drop(password);
            match result {
                Ok(()) => (Some(protocol::ok(id, json!({}))), Next::Continue),
                Err(f) => (fail(f), Next::Continue),
            }
        }
        Op::Lock => (Some(protocol::ok(id, json!({}))), Next::Exit),
        Op::Sync => match session.sync().await {
            Ok((items, last_sync)) => (
                Some(protocol::ok(id, json!({ "items": items, "last_sync": last_sync }))),
                Next::Continue,
            ),
            Err(f) => (fail(f), Next::Continue),
        },
        Op::LoginsFor { url, host, domain } => {
            let page = Page {
                url: &url,
                host: &host,
                domain: &domain,
            };
            match session.logins_for(&page).await {
                Ok(rows) => {
                    let rows: Vec<Value> = rows.iter().map(|r| r.to_json()).collect();
                    (Some(protocol::ok(id, json!({ "rows": rows }))), Next::Continue)
                }
                Err(f) => (fail(f), Next::Continue),
            }
        }
        Op::Fill { item, fields } => {
            let want_username = fields.iter().any(|f| f == "username");
            let want_password = fields.iter().any(|f| f == "password");
            match session.fill(&item, want_username, want_password).await {
                Ok(values) => {
                    let mut body = serde_json::Map::new();
                    if let Some(u) = &values.username {
                        body.insert("username".into(), Value::String(u.clone()));
                    }
                    if let Some(p) = &values.password {
                        body.insert("password".into(), Value::String(p.clone()));
                    }
                    (Some(protocol::ok(id, Value::Object(body))), Next::Continue)
                }
                Err(f) => (fail(f), Next::Continue),
            }
        }
        Op::Keepalive => (None, Next::Continue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn exchange(requests: &[Value]) -> Vec<Value> {
        let mut input = Vec::new();
        for r in requests {
            write_frame(&mut input, &serde_json::to_vec(r).unwrap()).await.unwrap();
        }
        let mut output = Vec::new();
        serve(&input[..], &mut output).await.unwrap();
        let mut answers = Vec::new();
        let mut r = &output[..];
        while let Ok(f) = read_frame(&mut r).await {
            answers.push(serde_json::from_slice(&f).unwrap());
        }
        answers
    }

    #[tokio::test]
    async fn hello_first_then_lock_ends_the_loop() {
        let dir = tempfile::tempdir().unwrap();
        let answers = exchange(&[
            json!({"id": 1, "op": "sync"}),
            json!({"id": 2, "op": "hello", "protocol": 1, "state_dir": dir.path().to_str().unwrap(),
                   "identity_url": "http://127.0.0.1:9/identity", "api_url": "http://127.0.0.1:9/api", "persist": true}),
            json!({"id": 3, "op": "keepalive"}),
            json!({"id": 4, "op": "lock"}),
            json!({"id": 5, "op": "sync"}),
        ])
        .await;
        assert_eq!(answers.len(), 3, "keepalive has no answer and nothing runs after lock");
        assert_eq!(answers[0]["error"], "no_hello");
        assert_eq!(answers[1]["ok"], true);
        assert_eq!(answers[1]["account"], "none");
        assert_eq!(answers[2]["id"], 4);
    }

    #[tokio::test]
    async fn a_remote_http_server_is_refused() {
        let answers = exchange(&[json!({"id": 1, "op": "hello", "protocol": 1, "state_dir": "",
            "identity_url": "http://example.com/identity", "api_url": "https://example.com/api"})])
        .await;
        assert_eq!(answers[0]["error"], "bad_server");
    }

    #[tokio::test]
    async fn another_protocol_version_is_refused() {
        let answers = exchange(&[json!({"id": 9, "op": "hello", "protocol": 99, "state_dir": "",
            "identity_url": "https://a.example", "api_url": "https://a.example"})])
        .await;
        assert_eq!(answers[0]["error"], "bad_protocol");
        assert_eq!(answers[0]["id"], 9);
    }

    #[tokio::test]
    async fn requests_before_unlock_say_locked() {
        let answers = exchange(&[
            json!({"id": 1, "op": "hello", "protocol": 1, "state_dir": "", "identity_url": "https://a.example", "api_url": "https://a.example"}),
            json!({"id": 2, "op": "logins_for", "url": "https://a.example/", "host": "a.example", "domain": "a.example"}),
            json!({"id": 3, "op": "fill", "item": "x", "fields": ["password"]}),
            json!({"id": 4, "op": "unlock", "password": "pw"}),
        ])
        .await;
        assert_eq!(answers[1]["error"], "locked");
        assert_eq!(answers[2]["error"], "locked");
        assert_eq!(answers[3]["error"], "no_account");
    }
}
