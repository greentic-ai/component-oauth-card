use component_oauth_card::{describe_payload, handle_message};

#[test]
fn describe_mentions_world() {
    let payload = describe_payload();
    let json: serde_json::Value = serde_json::from_str(&payload).expect("describe should be json");
    assert_eq!(
        json["component"]["world"],
        "greentic:component/component@0.4.0"
    );
}

#[test]
fn handle_returns_needs_sign_in_when_no_token() {
    let input = serde_json::json!({
        "mode": "status-card",
        "provider_id": "demo",
        "subject": "user-1",
        "scopes": ["openid"]
    })
    .to_string();
    let response = handle_message("invoke", &input);
    let json: serde_json::Value = serde_json::from_str(&response).expect("valid json");
    assert_eq!(json["status"], "needs-sign-in");
}
