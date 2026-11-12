//! The helper's login against a mock server on loopback (wiremock). No test contacts a real server.
//!
//! A login that succeeds needs the encrypted keys of a real account: those fixtures are made once from a test account
//! (README.md, "Tests") and are not in the repository yet. These tests cover what needs none: the KDF request, the
//! token request and its fields, a wrong password, the second steps (authenticator, email), the new-device code, the
//! API key, and a server that does not answer.

use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path},
};
use wren_vault::sdk::{Config, LoginOutcome, LoginRequest, Session};

/// The account's KDF: PBKDF2 with the smallest count the server allows, so the test derives fast.
async fn mount_prelogin(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin/password"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })))
        .mount(server)
        .await;
}

fn session_for(server: &MockServer) -> Session {
    session_at(&server.uri())
}

fn session_at(base: &str) -> Session {
    let mut s = Session::default();
    let config = Config {
        identity_url: format!("{base}/identity"),
        api_url: format!("{base}/api"),
        client_version: "test".into(),
        device_name: String::new(),
    };
    s.hello(config, "", false).expect("a loopback server is allowed");
    s
}

fn first<'a>(email: &'a str, password: &'a str) -> LoginRequest<'a> {
    LoginRequest {
        email,
        password: Some(password),
        ..Default::default()
    }
}

fn refused(message: &str) -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(json!({
        "error": "invalid_grant",
        "error_description": "invalid_username_or_password",
        "ErrorModel": { "Message": message, "Object": "error" }
    }))
}

#[tokio::test]
async fn a_wrong_password_is_bad_credentials() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=password"))
        // the device is Wren's own: type 14 (a browser the server does not know by name), the name "Wren"
        .and(body_string_contains("deviceType=14"))
        .and(body_string_contains("deviceName=Wren"))
        // the server refuses a password grant without the account's email in this header ("Auth-Email header invalid")
        .and(header("auth-email", "dXNlckBleGFtcGxlLmNvbQ"))
        .respond_with(refused("Username or password is incorrect. Try again."))
        .expect(1)
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    let err = match s.login(first("user@example.com", "wrong password")).await {
        Err(e) => e,
        Ok(_) => panic!("a wrong password must fail"),
    };
    assert_eq!(err.code, "bad_credentials");
    assert!(
        !err.message.contains("wrong password"),
        "the message never quotes the password"
    );
    assert!(!s.unlocked());
    let body = String::from_utf8(server.received_requests().await.unwrap().last().unwrap().body.clone()).unwrap();
    assert!(
        !body.contains("wrong"),
        "the password itself never goes to the server, only its hash"
    );
}

#[tokio::test]
async fn an_account_with_totp_asks_for_the_code() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": [0],
            "TwoFactorProviders2": { "0": null },
            "MasterPasswordPolicy": null
        })))
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    match s.login(first("user@example.com", "password")).await {
        Ok(LoginOutcome::NeedTwoFactor { providers, email_sent }) => {
            assert_eq!(providers, vec!["authenticator"]);
            assert!(!email_sent);
        }
        Ok(other) => panic!("the server asked for a second factor, not {other:?}"),
        Err(e) => panic!("unexpected failure {}", e.code),
    }
    assert!(!s.unlocked());
}

#[tokio::test]
async fn the_totp_code_goes_with_the_second_try() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=123456"))
        .and(body_string_contains("twoFactorProvider=0"))
        .respond_with(refused("Two-step token is invalid. Try again."))
        .expect(1)
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    let request = LoginRequest {
        code: Some("123456"),
        ..first("user@example.com", "password")
    };
    let err = match s.login(request).await {
        Err(e) => e,
        Ok(_) => panic!("the mock refuses the code"),
    };
    assert_eq!(err.code, "bad_credentials");
}

#[tokio::test]
async fn the_second_step_sends_the_code_with_the_kept_password() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    // the code is refused: the second request came, with a password the helper kept
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=654321"))
        .respond_with(refused("Two-step token is invalid. Try again."))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders2": { "0": null }
        })))
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    assert!(matches!(
        s.login(first("user@example.com", "password")).await,
        Ok(LoginOutcome::NeedTwoFactor { .. })
    ));
    let second = LoginRequest {
        email: "user@example.com",
        code: Some("654321"),
        provider: Some("authenticator"),
        ..Default::default()
    };
    let err = match s.login(second).await {
        Err(e) => e,
        Ok(_) => panic!("the mock refuses the code"),
    };
    assert_eq!(err.code, "bad_credentials");
    // the kept password went with the failed step: a code alone is not a login any more
    let again = s.login(second).await;
    assert_eq!(again.err().map(|e| e.code), Some("bad_request"));
}

#[tokio::test]
async fn an_email_code_is_sent_on_demand_then_goes_as_provider_1() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/api/two-factor/send-email-login"))
        .and(body_string_contains("user@example.com"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("twoFactorToken=777777"))
        .and(body_string_contains("twoFactorProvider=1"))
        .respond_with(refused("Two-step token is invalid. Try again."))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "TwoFactorProviders2": { "0": null, "1": { "Email": "u***@example.com" } }
        })))
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    match s.login(first("user@example.com", "password")).await {
        Ok(LoginOutcome::NeedTwoFactor { providers, email_sent }) => {
            assert_eq!(providers, vec!["authenticator", "email"]);
            assert!(
                !email_sent,
                "with an authenticator too, the mail waits for the person's choice"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    let resend = LoginRequest {
        email: "user@example.com",
        provider: Some("email"),
        resend: true,
        ..Default::default()
    };
    assert_eq!(
        s.login(resend).await.ok(),
        Some(LoginOutcome::NeedTwoFactor {
            providers: vec!["authenticator", "email"],
            email_sent: true
        })
    );
    let code = LoginRequest {
        email: "user@example.com",
        code: Some(" 777777 "),
        provider: Some("email"),
        ..Default::default()
    };
    assert_eq!(s.login(code).await.err().map(|e| e.code), Some("bad_credentials"));
}

#[tokio::test]
async fn an_email_only_account_has_its_code_mailed_by_the_server() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "TwoFactorProviders2": { "1": { "Email": "u***@example.com" } }
        })))
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    assert_eq!(
        s.login(first("user@example.com", "password")).await.ok(),
        Some(LoginOutcome::NeedTwoFactor {
            providers: vec!["email"],
            email_sent: true
        })
    );
}

#[tokio::test]
async fn an_account_with_only_unsupported_second_steps_is_said() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "TwoFactorProviders2": { "7": null }
        })))
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    let r = s.login(first("user@example.com", "password")).await;
    assert_eq!(r.err().map(|e| e.code), Some("unsupported_two_factor"));
}

#[tokio::test]
async fn a_new_device_code_goes_as_new_device_otp_from_the_same_device() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("newDeviceOtp=246810"))
        .respond_with(refused("Invalid new device OTP."))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "device_error",
            "error_description": "New device verification required",
            "ErrorModel": { "Message": "new device verification required", "Object": "error" }
        })))
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    assert_eq!(
        s.login(first("user@example.com", "password")).await.ok(),
        Some(LoginOutcome::NeedDeviceCode)
    );
    let code = LoginRequest {
        email: "user@example.com",
        code: Some("246810"),
        provider: Some("device"),
        ..Default::default()
    };
    assert_eq!(s.login(code).await.err().map(|e| e.code), Some("bad_credentials"));
    // both token requests named the same device: the code is for it
    let devices: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/identity/connect/token")
        .filter_map(|r| {
            url::form_urlencoded::parse(&r.body)
                .find(|(k, _)| k == "deviceIdentifier")
                .map(|(_, v)| v.into_owned())
        })
        .collect();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0], devices[1]);
}

#[tokio::test]
async fn an_api_key_login_sends_client_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=user.0f2a"))
        .and(body_string_contains("scope=api"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "invalid_client",
            "ErrorModel": { "Message": "The API key is not valid.", "Object": "error" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    let err = s
        .login_api_key(" user.0f2a ", "wrong secret", "password")
        .await
        .err()
        .unwrap();
    assert_eq!(err.code, "bad_credentials");
    assert_eq!(err.message, "The API key is not valid.");
}

#[tokio::test]
async fn a_code_without_a_waiting_login_is_refused() {
    let server = MockServer::start().await;
    let mut s = session_for(&server);
    let code = LoginRequest {
        email: "user@example.com",
        code: Some("123456"),
        ..Default::default()
    };
    assert_eq!(s.login(code).await.err().map(|e| e.code), Some("bad_request"));
}

#[tokio::test]
async fn a_server_that_does_not_answer_is_a_network_error() {
    // port 1 on loopback: nothing listens there. (A dropped mock server's port can be taken at once by another test
    // running in parallel, which would answer.)
    let mut s = session_at("http://127.0.0.1:1");
    let err = match s.login(first("user@example.com", "password")).await {
        Err(e) => e,
        Ok(_) => panic!("no server"),
    };
    assert_eq!(err.code, "network");
}

#[tokio::test]
async fn sync_fill_and_pins_need_an_unlocked_vault() {
    let server = MockServer::start().await;
    let mut s = session_for(&server);
    assert_eq!(s.sync().await.err().map(|e| e.code), Some("locked"));
    assert_eq!(
        s.fill("id", true, true, false).await.err().map(|e| e.code),
        Some("locked")
    );
    assert_eq!(
        s.fill("id", false, false, true).await.err().map(|e| e.code),
        Some("locked")
    );
    assert_eq!(s.search("git", 0).await.err().map(|e| e.code), Some("locked"));
    assert_eq!(s.totp("id").await.err().map(|e| e.code), Some("locked"));
    assert_eq!(s.pin_set("1234").err().map(|e| e.code), Some("locked"));
    // (a locked vault asks the server nothing: no request reached the mock)
    assert!(server.received_requests().await.unwrap_or_default().is_empty());
    assert_eq!(
        s.unlock(wren_vault::sdk::Unlock::Password("password"))
            .await
            .err()
            .map(|e| e.code),
        Some("no_account")
    );
}
