//! Prints the `renderedCard` (Adaptive Card 1.5) the component emits for each
//! OAuth state, so the webchat-facing output can be eyeballed without the full
//! runtime. Run with: `cargo run --example show_cards`.

use component_oauth_card::invoke_json;
use serde_json::{Value, json};

fn show(label: &str, payload: Value) {
    println!("\n=== {label} ===");
    match invoke_json("oauth_card.handle_message", &payload) {
        Ok(out) => {
            println!("status      : {}", out["status"]);
            println!("can_continue: {}", out["can_continue"]);
            match out.get("renderedCard") {
                Some(card) if !card.is_null() => {
                    println!(
                        "renderedCard:\n{}",
                        serde_json::to_string_pretty(card).unwrap_or_default()
                    );
                }
                _ => println!("renderedCard: <none>"),
            }
        }
        Err(err) => println!("error: {err}"),
    }
}

fn main() {
    // Not signed in -> sign-in card with a Connect (Action.Submit start-sign-in).
    show(
        "status-card / not signed in (github)",
        json!({
            "mode": "status-card",
            "provider_id": "github",
            "subject": "octocat",
            "scopes": ["repo", "read:org"]
        }),
    );

    // start-sign-in with a resolved consent URL -> Connect = Action.OpenUrl.
    show(
        "start-sign-in / with consent url",
        json!({
            "mode": "start-sign-in",
            "provider_id": "github",
            "subject": "octocat",
            "scopes": ["repo", "read:org"],
            "consent_url": "https://github.com/login/oauth/authorize?client_id=abc&scope=repo"
        }),
    );

    // Connected -> status card with Refresh / switch / Disconnect actions.
    show(
        "status-card / connected",
        json!({
            "mode": "status-card",
            "provider_id": "github",
            "subject": "octocat",
            "scopes": ["repo"],
            "current_token": { "access_token": "gho_live_token", "token_type": "Bearer" }
        }),
    );

    // ensure-token with a usable token -> no card (token passes through).
    show(
        "ensure-token / has token (no card)",
        json!({
            "mode": "ensure-token",
            "provider_id": "github",
            "subject": "octocat",
            "current_token": { "access_token": "gho_live_token" }
        }),
    );
}
