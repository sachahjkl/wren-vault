//! The helper's login against a mock server on loopback (wiremock). No test contacts a real server.
//!
//! A login that succeeds needs the encrypted keys of a real account: those fixtures are made once from a test account
//! (README.md, "Tests") and are not in the repository yet. These tests cover what needs none: the KDF request, the
//! token request, a wrong password, the second factor, and a server that does not answer.

use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};
use wren_vault::sdk::{Config, LoginOutcome, Session};

/// The account's KDF: PBKDF2 with the smallest count the server allows, so the test derives fast.
async fn mount_prelogin(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin/password"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "kdf": 0, "kdfIterations": 5000 })))
        .mount(server)
        .await;
}

fn session_for(server: &MockServer) -> Session {
    let mut s = Session::default();
    let config = Config {
        identity_url: format!("{}/identity", server.uri()),
        api_url: format!("{}/api", server.uri()),
        client_version: "test".into(),
    };
    s.hello(config, "", false).expect("a loopback server is allowed");
    s
}

#[tokio::test]
async fn a_wrong_password_is_bad_credentials() {
    let server = MockServer::start().await;
    mount_prelogin(&server).await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=password"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password",
            "ErrorModel": { "Message": "Username or password is incorrect. Try again.", "Object": "error" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    let err = match s.login("user@example.com", Some("wrong password"), None).await {
        Err(e) => e,
        Ok(_) => panic!("a wrong password must fail"),
    };
    assert_eq!(err.code, "bad_credentials");
    assert!(
        !err.message.contains("wrong password"),
        "the message never quotes the password"
    );
    assert!(!s.unlocked());
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
    match s.login("user@example.com", Some("password"), None).await {
        Ok(LoginOutcome::NeedTwoFactor(p)) => assert_eq!(p, vec!["authenticator"]),
        Ok(LoginOutcome::Done) => panic!("the server asked for a second factor"),
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
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password",
            "ErrorModel": { "Message": "Two-step token is invalid. Try again.", "Object": "error" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut s = session_for(&server);
    let err = match s.login("user@example.com", Some("password"), Some("123456")).await {
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
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password",
            "ErrorModel": { "Message": "Two-step token is invalid. Try again.", "Object": "error" }
        })))
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
        s.login("user@example.com", Some("password"), None).await,
        Ok(LoginOutcome::NeedTwoFactor(_))
    ));
    let err = match s.login("user@example.com", None, Some("654321")).await {
        Err(e) => e,
        Ok(_) => panic!("the mock refuses the code"),
    };
    assert_eq!(err.code, "bad_credentials");
    // the kept password went with the failed step: a code alone is not a login any more
    let again = s.login("user@example.com", None, Some("654321")).await;
    assert_eq!(again.err().map(|e| e.code), Some("bad_request"));
}

#[tokio::test]
async fn a_code_without_a_waiting_login_is_refused() {
    let server = MockServer::start().await;
    let mut s = session_for(&server);
    let r = s.login("user@example.com", None, Some("123456")).await;
    assert_eq!(r.err().map(|e| e.code), Some("bad_request"));
}

#[tokio::test]
async fn a_server_that_does_not_answer_is_a_network_error() {
    let server = MockServer::start().await;
    let mut s = session_for(&server);
    drop(server); // (nothing listens on the port any more)
    let err = match s.login("user@example.com", Some("password"), None).await {
        Err(e) => e,
        Ok(_) => panic!("no server"),
    };
    assert_eq!(err.code, "network");
}

#[tokio::test]
async fn sync_and_fill_need_an_unlocked_vault() {
    let server = MockServer::start().await;
    let mut s = session_for(&server);
    assert_eq!(s.sync().await.err().map(|e| e.code), Some("locked"));
    assert_eq!(s.fill("id", true, true).await.err().map(|e| e.code), Some("locked"));
    assert_eq!(s.unlock("password").await.err().map(|e| e.code), Some("no_account"));
}
