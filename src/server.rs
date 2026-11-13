//! The request loop: one frame in, one answer out, in order.
//!
//! Requests run one after the other. A login or an unlock takes the time of its key derivation; the browser has a
//! deadline per request and shows the wait. `keepalive` has no answer.
//!
//! The idle deadline (`hello`'s `idle_seconds`) is the helper's own guard: the browser locks first, on its own timer;
//! if no request (a `keepalive` included) comes for that long, the helper writes the event `locked` and exits.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::{
    PROTOCOL_VERSION,
    frame::{FrameReader, write_frame},
    identity::Assertion,
    matching::Page,
    protocol::{self, Op, Request},
    sdk::{self, Config, DevicePoll, Failure, Generate, LoginOutcome, LoginRequest, SaveRequest, Session, Unlock},
};

/// What the loop does after an answer.
enum Next {
    Continue,
    Exit,
}

/// Serves requests until the input closes, a `lock` or a `logout` arrives, or the idle deadline passes. The session
/// (and every key) is dropped on return.
pub async fn serve<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut input: R, mut output: W) -> std::io::Result<()> {
    let mut session = Session::default();
    let mut reader = FrameReader::new();
    let mut idle: Option<Duration> = None;
    loop {
        let read = match idle {
            Some(after) => tokio::select! {
                f = reader.next(&mut input) => Some(f),
                _ = tokio::time::sleep(after) => None,
            },
            None => Some(reader.next(&mut input).await),
        };
        let Some(read) = read else {
            // idle: the browser is told, then the process exits (lock is the exit)
            let bytes = serde_json::to_vec(&protocol::event("locked")).map_err(std::io::Error::other)?;
            let _ = write_frame(&mut output, &bytes).await;
            return Ok(());
        };
        let frame = match read {
            Ok(f) => f,
            // closed, or a broken peer: nothing more can be trusted on this pipe
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
                    Ok(req) if req.id != 0 => {
                        if let Op::Hello { idle_seconds, .. } = &req.op {
                            idle = (*idle_seconds > 0).then(|| Duration::from_secs(*idle_seconds));
                        }
                        let answer = handle(&mut session, req).await;
                        // (a request may have renewed the access token: the new refresh token is kept at once)
                        let _ = session.keep_tokens().await;
                        answer
                    }
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

fn failed(id: u64, f: Failure) -> Option<Value> {
    let mut v = protocol::error(id, f.code, &f.message);
    if let (Some(n), Some(o)) = (f.tries_left, v.as_object_mut()) {
        o.insert("tries_left".into(), json!(n));
    }
    Some(v)
}

async fn handle(session: &mut Session, req: Request) -> (Option<Value>, Next) {
    let id = req.id;
    let done = |body: Value| (Some(protocol::ok(id, body)), Next::Continue);
    let fail = |f: Failure| (failed(id, f), Next::Continue);
    match req.op {
        Op::Hello {
            protocol: version,
            state_dir,
            identity_url,
            api_url,
            device_name,
            client_version,
            persist,
            idle_seconds: _,
        } => {
            if version != PROTOCOL_VERSION {
                let text = format!("This helper speaks protocol {PROTOCOL_VERSION}.");
                return (Some(protocol::error(id, "bad_protocol", &text)), Next::Continue);
            }
            let config = Config {
                identity_url,
                api_url,
                client_version,
                device_name,
            };
            match session.hello(config, &state_dir, persist) {
                Ok(a) => done(json!({
                    "protocol": PROTOCOL_VERSION, "helper_version": crate::HELPER_VERSION,
                    "account": a.state, "email": a.email, "login": a.login, "pin": a.pin, "passkey": a.passkey,
                })),
                Err(f) => fail(f),
            }
        }
        _ if !session.configured() => (
            Some(protocol::error(id, "no_hello", "The first request must be hello.")),
            Next::Continue,
        ),
        Op::Login {
            email,
            password,
            code,
            provider,
            resend,
            remember,
        } => {
            let request = LoginRequest {
                email: &email,
                password: password.as_ref().map(|p| p.as_str()),
                code: code.as_ref().map(|c| c.as_str()),
                provider: provider.as_deref(),
                resend,
                remember,
            };
            let result = session.login(request).await;
            drop(password);
            drop(code);
            match result {
                Ok(LoginOutcome::Done) => done(json!({ "result": "ok" })),
                Ok(LoginOutcome::NeedTwoFactor { providers, email_sent }) => done(json!({
                    "result": "need_two_factor", "providers": providers, "email_sent": email_sent,
                })),
                Ok(LoginOutcome::NeedDeviceCode) => done(json!({ "result": "need_device_code" })),
                Err(f) => fail(f),
            }
        }
        Op::LoginApiKey {
            client_id,
            client_secret,
            password,
        } => {
            let result = session
                .login_api_key(&client_id, client_secret.as_str(), password.as_str())
                .await;
            drop(client_secret);
            drop(password);
            match result {
                Ok(email) => done(json!({ "result": "ok", "email": email })),
                Err(f) => fail(f),
            }
        }
        Op::PasswordHint { email } => match session.password_hint(&email).await {
            Ok(()) => done(json!({})),
            Err(f) => fail(f),
        },
        Op::DeviceRequest { email } => match session.device_request(&email).await {
            Ok(fingerprint) => done(json!({ "fingerprint": fingerprint })),
            Err(f) => fail(f),
        },
        Op::DevicePoll => match session.device_poll().await {
            Ok(DevicePoll::Pending) => done(json!({ "result": "pending" })),
            Ok(DevicePoll::Done(email)) => done(json!({ "result": "ok", "email": email })),
            Err(f) => fail(f),
        },
        Op::PasskeyOptions { purpose, rp_id } => match session.passkey_options(&purpose, &rp_id).await {
            Ok(options) => done(json!({ "options": options })),
            Err(f) => fail(f),
        },
        Op::LoginPasskey {
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
            user_handle,
            prf,
        } => {
            let assertion = Assertion {
                id: &credential_id,
                authenticator_data: &authenticator_data,
                client_data_json: &client_data_json,
                signature: &signature,
                user_handle: &user_handle,
            };
            let result = session.login_passkey(&assertion, prf.as_str()).await;
            drop(prf);
            match result {
                Ok(email) => done(json!({ "result": "ok", "email": email })),
                Err(f) => fail(f),
            }
        }
        Op::Unlock {
            password,
            pin,
            prf,
            credential_id,
        } => {
            let result = match (&password, &pin, &prf) {
                (_, _, Some(p)) => {
                    session
                        .unlock(Unlock::Passkey {
                            prf: p.as_str(),
                            credential_id: &credential_id,
                        })
                        .await
                }
                (_, Some(p), None) => session.unlock(Unlock::Pin(p.as_str())).await,
                (Some(p), None, None) => session.unlock(Unlock::Password(p.as_str())).await,
                (None, None, None) => Err(Failure {
                    code: "bad_request",
                    message: "An unlock needs the master password, the PIN or a passkey.".into(),
                    tries_left: None,
                }),
            };
            drop(password);
            drop(pin);
            drop(prf);
            match result {
                Ok(()) => done(json!({})),
                Err(f) => fail(f),
            }
        }
        Op::Lock => (Some(protocol::ok(id, json!({}))), Next::Exit),
        Op::Logout => {
            session.logout().await;
            (Some(protocol::ok(id, json!({}))), Next::Exit)
        }
        Op::Sync => match session.sync().await {
            Ok((items, last_sync)) => done(json!({ "items": items, "last_sync": last_sync })),
            Err(f) => fail(f),
        },
        Op::PinSet { pin } => {
            let result = session.pin_set(pin.as_str());
            drop(pin);
            match result {
                Ok(()) => done(json!({})),
                Err(f) => fail(f),
            }
        }
        Op::PinClear => match session.pin_clear() {
            Ok(()) => done(json!({})),
            Err(f) => fail(f),
        },
        Op::LoginsFor { url, host, domain } => {
            let equivalent = session.equivalent_of(&domain);
            let page = Page {
                url: &url,
                host: &host,
                domain: &domain,
                equivalent: &equivalent,
            };
            match session.logins_for(&page).await {
                Ok(rows) => {
                    let rows: Vec<Value> = rows.iter().map(|r| r.to_json()).collect();
                    // (the browser checks an "equivalent" row against this list: it has no copy of the account's groups)
                    done(json!({ "rows": rows, "equivalent": equivalent }))
                }
                Err(f) => fail(f),
            }
        }
        Op::Search {
            query,
            offset,
            limit,
            kinds,
        } => match session.search(&query, offset, limit, &kinds).await {
            Ok((rows, total)) => {
                let rows: Vec<Value> = rows.iter().map(|r| r.to_json()).collect();
                done(json!({ "rows": rows, "total": total }))
            }
            Err(f) => fail(f),
        },
        Op::Fill { item, fields } => match session.fill(&item, &fields).await {
            Ok(values) => {
                let mut body = serde_json::Map::new();
                for (key, v) in &values.0 {
                    body.insert(key.clone(), Value::String(v.clone()));
                }
                done(Value::Object(body))
            }
            Err(f) => fail(f),
        },
        Op::Save {
            item,
            name,
            uri,
            username,
            password,
        } => {
            let request = SaveRequest {
                item: &item,
                name: &name,
                uri: &uri,
                username: &username,
                password: password.as_str(),
            };
            let result = session.save(request).await;
            drop(password);
            match result {
                Ok(id) => done(json!({ "item": id })),
                Err(f) => fail(f),
            }
        }
        Op::Generate {
            kind,
            length,
            uppercase,
            lowercase,
            numbers,
            special,
            min_numbers,
            min_special,
            words,
            separator,
            capitalize,
            include_number,
        } => {
            let request = Generate {
                kind,
                length,
                uppercase,
                lowercase,
                numbers,
                special,
                min_numbers,
                min_special,
                words,
                separator,
                capitalize,
                include_number,
            };
            match sdk::generate(&request) {
                // (the value is a secret: the loop writes the answer from zeroed bytes, as a fill's)
                Ok(value) => done(json!({ "value": value.as_str() })),
                Err(f) => fail(f),
            }
        }
        Op::Totp { item } => match session.totp(&item).await {
            Ok(c) => done(json!({ "totp": c.code.as_str(), "period": c.period, "remaining": c.remaining })),
            Err(f) => fail(f),
        },
        Op::PasskeysFor { rp_id, allow } => match session.passkeys_for(&rp_id, &allow).await {
            Ok(rows) => {
                let rows: Vec<Value> = rows
                    .iter()
                    .map(|r| {
                        json!({
                            "item": r.item, "name": r.name, "username": r.username,
                            "credential_id": r.credential_id, "user_handle": r.user_handle,
                        })
                    })
                    .collect();
                done(json!({ "rows": rows }))
            }
            Err(f) => fail(f),
        },
        Op::PasskeyAssert {
            item,
            credential_id,
            rp_id,
            client_data_hash,
        } => match session
            .passkey_assert(&item, &credential_id, &rp_id, &client_data_hash)
            .await
        {
            Ok(s) => done(json!({
                "authenticator_data": s.authenticator_data, "signature": s.signature,
                "user_handle": s.user_handle, "credential_id": s.credential_id,
            })),
            Err(f) => fail(f),
        },
        Op::Keepalive => (None, Next::Continue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::read_frame;
    use tokio::io::AsyncWriteExt;

    async fn exchange(requests: &[Value]) -> Vec<Value> {
        let mut input = Vec::new();
        for r in requests {
            write_frame(&mut input, &serde_json::to_vec(r).unwrap()).await.unwrap();
        }
        let mut output = Vec::new();
        serve(&input[..], &mut output).await.unwrap();
        answers_of(&output).await
    }

    async fn answers_of(output: &[u8]) -> Vec<Value> {
        let mut answers = Vec::new();
        let mut r = output;
        while let Ok(f) = read_frame(&mut r).await {
            answers.push(serde_json::from_slice(&f).unwrap());
        }
        answers
    }

    fn hello(id: u64, dir: &str, idle_seconds: u64) -> Value {
        json!({"id": id, "op": "hello", "protocol": 5, "state_dir": dir, "identity_url": "http://127.0.0.1:9/identity",
               "api_url": "http://127.0.0.1:9/api", "persist": !dir.is_empty(), "idle_seconds": idle_seconds})
    }

    #[tokio::test]
    async fn hello_first_then_lock_ends_the_loop() {
        let dir = tempfile::tempdir().unwrap();
        let answers = exchange(&[
            json!({"id": 1, "op": "sync"}),
            hello(2, dir.path().to_str().unwrap(), 0),
            json!({"id": 3, "op": "keepalive"}),
            json!({"id": 4, "op": "lock"}),
            json!({"id": 5, "op": "sync"}),
        ])
        .await;
        assert_eq!(answers.len(), 3, "keepalive has no answer and nothing runs after lock");
        assert_eq!(answers[0]["error"], "no_hello");
        assert_eq!(answers[1]["ok"], true);
        assert_eq!(answers[1]["account"], "none");
        assert_eq!(answers[1]["pin"], false);
        assert_eq!(answers[1]["login"], "password");
        assert_eq!(answers[2]["id"], 4);
    }

    #[tokio::test]
    async fn a_remote_http_server_is_refused() {
        let answers = exchange(&[json!({"id": 1, "op": "hello", "protocol": 5, "state_dir": "",
            "identity_url": "http://example.com/identity", "api_url": "https://example.com/api"})])
        .await;
        assert_eq!(answers[0]["error"], "bad_server");
    }

    #[tokio::test]
    async fn another_protocol_version_is_refused() {
        let answers = exchange(&[json!({"id": 9, "op": "hello", "protocol": 1, "state_dir": "",
            "identity_url": "https://a.example", "api_url": "https://a.example"})])
        .await;
        assert_eq!(answers[0]["error"], "bad_protocol");
        assert_eq!(answers[0]["id"], 9);
    }

    #[tokio::test]
    async fn requests_before_unlock_say_locked() {
        let answers = exchange(&[
            hello(1, "", 0),
            json!({"id": 2, "op": "logins_for", "url": "https://a.example/", "host": "a.example", "domain": "a.example"}),
            json!({"id": 3, "op": "fill", "item": "x", "fields": ["password"]}),
            json!({"id": 4, "op": "unlock", "password": "pw"}),
            json!({"id": 5, "op": "unlock", "pin": "1234"}),
            json!({"id": 6, "op": "pin_set", "pin": "1234"}),
            json!({"id": 7, "op": "unlock"}),
            json!({"id": 8, "op": "search", "query": "git"}),
            json!({"id": 9, "op": "totp", "item": "x"}),
            json!({"id": 10, "op": "fill", "item": "x", "fields": ["totp"]}),
            json!({"id": 11, "op": "save", "item": "", "name": "a.example", "uri": "https://a.example/",
                   "username": "me", "password": "pw"}),
            json!({"id": 12, "op": "save", "item": "x", "password": "pw"}),
            json!({"id": 13, "op": "passkeys_for", "rp_id": "a.example"}),
            json!({"id": 14, "op": "passkey_assert", "item": "x", "credential_id": "aWQ", "rp_id": "a.example",
                   "client_data_hash": "aGFzaA"}),
        ])
        .await;
        assert_eq!(answers[12]["error"], "locked");
        assert_eq!(answers[13]["error"], "locked");
        assert_eq!(answers[10]["error"], "locked");
        assert_eq!(answers[11]["error"], "locked");
        assert_eq!(answers[7]["error"], "locked");
        assert_eq!(answers[8]["error"], "locked");
        assert_eq!(answers[9]["error"], "locked");
        assert_eq!(answers[1]["error"], "locked");
        assert_eq!(answers[2]["error"], "locked");
        assert_eq!(answers[3]["error"], "no_account");
        assert_eq!(answers[4]["error"], "no_account");
        assert_eq!(answers[5]["error"], "locked");
        assert_eq!(answers[6]["error"], "bad_request");
    }

    #[tokio::test]
    async fn the_new_steps_need_their_first_step() {
        let answers = exchange(&[
            hello(1, "", 0),
            json!({"id": 2, "op": "device_poll"}),
            json!({"id": 3, "op": "login_passkey", "credential_id": "i", "authenticator_data": "a",
                   "client_data_json": "c", "signature": "s", "prf": "p"}),
            json!({"id": 4, "op": "passkey_options", "purpose": "unlock", "rp_id": "vault.example"}),
            json!({"id": 5, "op": "unlock", "prf": "cHJm", "credential_id": "aWQ"}),
            json!({"id": 6, "op": "passkey_options", "purpose": "other"}),
            json!({"id": 7, "op": "password_hint", "email": " "}),
        ])
        .await;
        assert_eq!(answers[1]["error"], "bad_request", "no login with a device waits");
        assert_eq!(answers[2]["error"], "bad_request", "no passkey options were asked");
        assert_eq!(answers[3]["error"], "no_account");
        assert_eq!(answers[4]["error"], "no_account");
        assert_eq!(answers[5]["error"], "bad_request");
        assert_eq!(answers[6]["error"], "bad_request");
        assert_eq!(answers[0]["passkey"], false);
    }

    #[tokio::test]
    async fn generate_needs_no_unlocked_vault() {
        let answers = exchange(&[
            json!({"id": 1, "op": "generate", "kind": "password"}),
            hello(2, "", 0),
            json!({"id": 3, "op": "generate", "kind": "password"}),
            json!({"id": 4, "op": "generate", "kind": "passphrase", "words": 4, "separator": "_"}),
            json!({"id": 5, "op": "generate", "kind": "password", "length": 4}),
            json!({"id": 6, "op": "generate", "kind": "passphrase", "words": 21}),
            json!({"id": 7, "op": "generate", "kind": "pin"}),
        ])
        .await;
        assert_eq!(answers[0]["error"], "no_hello");
        let password = answers[2]["value"].as_str().unwrap();
        assert_eq!(password.chars().count(), 20);
        let passphrase = answers[3]["value"].as_str().unwrap();
        assert_eq!(passphrase.split('_').count(), 4);
        for a in &answers[4..] {
            assert_eq!(a["error"], "bad_request", "{a}");
        }
    }

    #[tokio::test]
    async fn logout_answers_then_ends_the_loop() {
        let answers = exchange(&[
            hello(1, "", 0),
            json!({"id": 2, "op": "logout"}),
            json!({"id": 3, "op": "sync"}),
        ])
        .await;
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[1]["id"], 2);
        assert_eq!(answers[1]["ok"], true);
    }

    // (paused time: the runtime moves the clock when nothing can run; no test waits for real)
    #[tokio::test(start_paused = true)]
    async fn without_a_request_the_helper_locks_itself_at_its_deadline() {
        let (mut browser, helper) = tokio::io::duplex(4096);
        let (helper_in, mut helper_out) = tokio::io::split(helper);
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &serde_json::to_vec(&hello(1, "", 60)).unwrap())
            .await
            .unwrap();
        write_frame(
            &mut bytes,
            &serde_json::to_vec(&json!({"id": 2, "op": "keepalive"})).unwrap(),
        )
        .await
        .unwrap();
        browser.write_all(&bytes).await.unwrap();
        let started = tokio::time::Instant::now();
        // (the browser's end stays open: only the deadline ends the loop)
        serve(helper_in, &mut helper_out).await.unwrap();
        assert!(started.elapsed() >= Duration::from_secs(60));
        drop(helper_out); // (the browser's read then ends)
        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut browser, &mut out)
            .await
            .unwrap();
        let answers = answers_of(&out).await;
        assert_eq!(answers.len(), 2, "the answer of hello, then the event");
        assert_eq!(answers[1]["id"], 0);
        assert_eq!(answers[1]["event"], "locked");
    }
}
