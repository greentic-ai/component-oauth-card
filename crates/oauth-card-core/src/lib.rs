//! Provider-agnostic OAuth card logic: decide connection status, render the
//! card (incl. Adaptive Card), and merge config — with **no** WASM component
//! exports. Both the `component-oauth-card` component and consumers like the
//! MCP adapter depend on this so the sign-in card has a single source of truth.

#![warn(clippy::unwrap_used, clippy::expect_used)]

mod adaptive;
mod broker;
mod logic;
mod model;

pub use adaptive::render_adaptive_card;
pub use broker::{InputBroker, OAuthBackend};
pub use logic::handle;
pub use model::{
    Action, AuthContext, AuthHeader, ImageRef, MessageCard, MessageCardKind, OAuthCardInput,
    OAuthCardMode, OAuthCardOutput, OAuthStatus, OauthCard, OauthPrompt, OauthProvider,
    TokenExchangeResource, TokenSet,
};

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OAuthCardError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Run the `oauth_card.handle_message` path: merge config into the input,
/// decide the connection status, render the card, and attach `renderedCard`
/// (Adaptive Card 1.5) so channels that only render Adaptive Cards can show it.
///
/// This is the slice the MCP adapter calls to self-gate and render the sign-in
/// card without linking the component's WASM exports.
pub fn handle_message_json(payload: &Value) -> Result<Value, OAuthCardError> {
    let merged = merge_input_with_config(payload);
    let input: OAuthCardInput = serde_json::from_value(merged)
        .map_err(|err| OAuthCardError::Parse(format!("input json: {err}")))?;
    let backend = InputBroker::from_input(&input);
    let output = logic::handle(&backend, input).unwrap_or_else(error_output);
    let mut value = serde_json::to_value(&output)
        .map_err(|err| OAuthCardError::Parse(format!("output json: {err}")))?;
    // Emit an Adaptive Card alongside the channel-agnostic `card` so channels
    // that only render Adaptive Cards (e.g. webchat-gui) can show the OAuth
    // card. greentic-start surfaces a node output's `renderedCard` into the
    // channel's `adaptive_card` slot.
    if let Some(card) = &output.card {
        value["renderedCard"] = adaptive::render_adaptive_card(card);
    }
    Ok(value)
}

/// Merge a `config` object (component config / setup answers) into the input,
/// filling fields the explicit input omitted. Defaults `mode` to `status-card`.
pub fn merge_input_with_config(payload: &Value) -> Value {
    let mut object = payload.as_object().cloned().unwrap_or_default();
    if !object.contains_key("mode") {
        object.insert("mode".to_string(), Value::String("status-card".to_string()));
    }

    if let Some(config) = payload.get("config").and_then(Value::as_object) {
        copy_if_missing(&mut object, config, "provider_id", "provider_id");
        copy_if_missing(&mut object, config, "default_subject", "subject");
        copy_if_missing(&mut object, config, "scopes", "scopes");
        copy_if_missing(
            &mut object,
            config,
            "allow_auto_sign_in",
            "allow_auto_sign_in",
        );
        copy_if_missing(&mut object, config, "redirect_path", "redirect_path");
        copy_if_missing(&mut object, config, "auth_url", "auth_url");
        copy_if_missing(&mut object, config, "client_id", "client_id");
        copy_if_missing(&mut object, config, "redirect_uri", "redirect_uri");
        copy_if_missing(&mut object, config, "tenant", "tenant");
        copy_if_missing(&mut object, config, "team", "team");
    }

    Value::Object(object)
}

fn copy_if_missing(
    target: &mut serde_json::Map<String, Value>,
    source: &serde_json::Map<String, Value>,
    source_key: &str,
    target_key: &str,
) {
    if !target.contains_key(target_key)
        && let Some(value) = source.get(source_key)
    {
        target.insert(target_key.to_string(), value.clone());
    }
}

/// Build the blocking error output for a failed handle (parse/unsupported/etc.).
pub fn error_output(err: OAuthCardError) -> OAuthCardOutput {
    OAuthCardOutput {
        status: OAuthStatus::Error,
        can_continue: false,
        card: None,
        auth_context: None,
        auth_header: None,
        access_token: None,
        state_id: None,
        error: Some(err.to_string()),
    }
}
