#![warn(clippy::unwrap_used, clippy::expect_used)]

mod broker;
mod logic;
mod model;

pub use broker::{OAuthBackend, default_backend};
pub use logic::handle;
pub use model::{
    Action, AuthContext, AuthHeader, OAuthCardInput, OAuthCardMode, OAuthCardOutput, OAuthStatus,
    TokenSet,
};
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

#[cfg(target_arch = "wasm32")]
#[used]
#[unsafe(link_section = ".greentic.wasi")]
static WASI_TARGET_MARKER: [u8; 13] = *b"wasm32-wasip2";

#[cfg(target_arch = "wasm32")]
mod component {
    use greentic_interfaces_guest::component::node::{
        self, ExecCtx, InvokeResult, LifecycleStatus, StreamEvent,
    };

    use super::{describe_payload, handle_message};

    pub(super) struct Component;

    impl node::Guest for Component {
        fn get_manifest() -> String {
            describe_payload()
        }

        fn on_start(_ctx: ExecCtx) -> Result<LifecycleStatus, String> {
            Ok(LifecycleStatus::Ok)
        }

        fn on_stop(_ctx: ExecCtx, _reason: String) -> Result<LifecycleStatus, String> {
            Ok(LifecycleStatus::Ok)
        }

        fn invoke(_ctx: ExecCtx, op: String, input: String) -> InvokeResult {
            InvokeResult::Ok(handle_message(&op, &input))
        }

        fn invoke_stream(_ctx: ExecCtx, op: String, input: String) -> Vec<StreamEvent> {
            vec![
                StreamEvent::Progress(0),
                StreamEvent::Data(handle_message(&op, &input)),
                StreamEvent::Done,
            ]
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::component::Component;
    use greentic_interfaces_guest::component::node;

    #[unsafe(export_name = "greentic:component/node@0.4.0#get-manifest")]
    unsafe extern "C" fn export_get_manifest() -> *mut u8 {
        unsafe { node::_export_get_manifest_cabi::<Component>() }
    }

    #[unsafe(export_name = "cabi_post_greentic:component/node@0.4.0#get-manifest")]
    unsafe extern "C" fn post_return_get_manifest(arg0: *mut u8) {
        unsafe { node::__post_return_get_manifest::<Component>(arg0) };
    }

    #[unsafe(export_name = "greentic:component/node@0.4.0#on-start")]
    unsafe extern "C" fn export_on_start(arg0: *mut u8) -> *mut u8 {
        unsafe { node::_export_on_start_cabi::<Component>(arg0) }
    }

    #[unsafe(export_name = "cabi_post_greentic:component/node@0.4.0#on-start")]
    unsafe extern "C" fn post_return_on_start(arg0: *mut u8) {
        unsafe { node::__post_return_on_start::<Component>(arg0) };
    }

    #[unsafe(export_name = "greentic:component/node@0.4.0#on-stop")]
    unsafe extern "C" fn export_on_stop(arg0: *mut u8) -> *mut u8 {
        unsafe { node::_export_on_stop_cabi::<Component>(arg0) }
    }

    #[unsafe(export_name = "cabi_post_greentic:component/node@0.4.0#on-stop")]
    unsafe extern "C" fn post_return_on_stop(arg0: *mut u8) {
        unsafe { node::__post_return_on_stop::<Component>(arg0) };
    }

    #[unsafe(export_name = "greentic:component/node@0.4.0#invoke")]
    unsafe extern "C" fn export_invoke(arg0: *mut u8) -> *mut u8 {
        unsafe { node::_export_invoke_cabi::<Component>(arg0) }
    }

    #[unsafe(export_name = "cabi_post_greentic:component/node@0.4.0#invoke")]
    unsafe extern "C" fn post_return_invoke(arg0: *mut u8) {
        unsafe { node::__post_return_invoke::<Component>(arg0) };
    }

    #[unsafe(export_name = "greentic:component/node@0.4.0#invoke-stream")]
    unsafe extern "C" fn export_invoke_stream(arg0: *mut u8) -> *mut u8 {
        unsafe { node::_export_invoke_stream_cabi::<Component>(arg0) }
    }

    #[unsafe(export_name = "cabi_post_greentic:component/node@0.4.0#invoke-stream")]
    unsafe extern "C" fn post_return_invoke_stream(arg0: *mut u8) {
        unsafe { node::__post_return_invoke_stream::<Component>(arg0) };
    }
}

pub fn describe_payload() -> String {
    serde_json::json!({
        "component": {
            "name": "component-oauth-card",
            "org": "ai.greentic",
            "version": "0.1.0",
            "world": "greentic:component/component@0.4.0",
            "schemas": {
                "component": "schemas/component.schema.json",
                "input": "schemas/io/input.schema.json",
                "output": "schemas/io/output.schema.json"
            }
        }
    })
    .to_string()
}

pub fn handle_message(operation: &str, input: &str) -> String {
    let _ = operation;
    let backend = broker::default_backend();
    let response = broker::parse_input(input)
        .and_then(|parsed| logic::handle(&backend, parsed))
        .unwrap_or_else(|err| OAuthCardOutput {
            status: OAuthStatus::Error,
            card: None,
            auth_context: None,
            auth_header: None,
            state_id: None,
            error: Some(err.to_string()),
        });

    serde_json::to_string(&response).unwrap_or_else(|err| {
        serde_json::json!({
            "status": "error",
            "error": format!("serialization failure: {err}")
        })
        .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::MockBroker;
    use crate::model::{OAuthCardInput, OAuthCardMode, TokenSet};

    #[test]
    fn describe_payload_is_json() {
        let payload = describe_payload();
        let json: serde_json::Value =
            serde_json::from_str(&payload).unwrap_or_else(|err| panic!("valid json: {err}"));
        assert_eq!(json["component"]["name"], "component-oauth-card");
    }

    #[test]
    fn status_card_connected() {
        let backend = MockBroker {
            token: Some(TokenSet {
                access_token: "token123".into(),
                refresh_token: None,
                expires_at: Some(123),
                token_type: Some("Bearer".into()),
                extra: Some(serde_json::json!({ "email": "user@example.com" })),
            }),
            consent_url: "https://consent".into(),
        };
        let input = OAuthCardInput {
            mode: OAuthCardMode::StatusCard,
            provider_id: "msgraph".into(),
            subject: "user-1".into(),
            tenant: Some("tenant-1".into()),
            team: Some("team-1".into()),
            scopes: vec!["scope-a".into()],
            state_id: None,
            auth_code: None,
            allow_auto_sign_in: false,
            redirect_path: None,
            extra_json: None,
        };

        let output =
            logic::handle(&backend, input).unwrap_or_else(|err| panic!("status ok: {err}"));
        assert_eq!(output.status, OAuthStatus::Ok);
        assert!(output.auth_header.is_some());
        assert!(output.card.is_some());
    }

    #[test]
    fn ensure_token_prompts_sign_in() {
        let backend = MockBroker {
            token: None,
            consent_url: "https://consent/start".into(),
        };
        let input = OAuthCardInput {
            mode: OAuthCardMode::EnsureToken,
            provider_id: "msgraph".into(),
            subject: "user-1".into(),
            tenant: None,
            team: None,
            scopes: vec![],
            state_id: None,
            auth_code: None,
            allow_auto_sign_in: true,
            redirect_path: None,
            extra_json: None,
        };

        let output =
            logic::handle(&backend, input).unwrap_or_else(|err| panic!("needs sign-in: {err}"));
        assert_eq!(output.status, OAuthStatus::NeedsSignIn);
        assert!(output.card.is_some());
    }

    #[test]
    fn start_sign_in_returns_state_and_card() {
        let backend = MockBroker {
            token: None,
            consent_url: "https://consent/start".into(),
        };
        let input = OAuthCardInput {
            mode: OAuthCardMode::StartSignIn,
            provider_id: "msgraph".into(),
            subject: "user-1".into(),
            tenant: None,
            team: None,
            scopes: vec!["openid".into()],
            state_id: None,
            auth_code: None,
            allow_auto_sign_in: false,
            redirect_path: Some("/oauth/callback/msgraph".into()),
            extra_json: None,
        };

        let output =
            logic::handle(&backend, input).unwrap_or_else(|err| panic!("start sign-in: {err}"));
        assert_eq!(output.status, OAuthStatus::Ok);
        assert!(output.state_id.is_some());
        let card = if let Some(card) = output.card {
            card
        } else {
            panic!("card present")
        };
        assert_eq!(card.title.as_deref(), Some("Connect msgraph account"));
        let oauth = if let Some(oauth) = card.oauth {
            oauth
        } else {
            panic!("oauth payload")
        };
        assert_eq!(oauth.start_url.as_deref(), Some("https://consent/start"));
        assert!(card.actions.iter().any(|a| matches!(
            a,
            crate::model::Action::OpenUrl { url, .. } if url == "https://consent/start"
        )));
    }

    #[test]
    fn complete_sign_in_yields_auth_header() {
        let backend = MockBroker {
            token: Some(TokenSet {
                access_token: "token123".into(),
                refresh_token: Some("refresh".into()),
                expires_at: Some(999),
                token_type: Some("Bearer".into()),
                extra: Some(serde_json::json!({ "email": "user@example.com" })),
            }),
            consent_url: "https://consent/start".into(),
        };
        let input = OAuthCardInput {
            mode: OAuthCardMode::CompleteSignIn,
            provider_id: "msgraph".into(),
            subject: "user-1".into(),
            tenant: Some("t".into()),
            team: Some("team-1".into()),
            scopes: vec!["openid".into()],
            state_id: Some("state-1".into()),
            auth_code: Some("code-123".into()),
            allow_auto_sign_in: false,
            redirect_path: None,
            extra_json: None,
        };

        let output =
            logic::handle(&backend, input).unwrap_or_else(|err| panic!("complete sign-in: {err}"));
        assert_eq!(output.status, OAuthStatus::Ok);
        assert!(output.auth_header.is_some());
        let auth_header = output
            .auth_header
            .unwrap_or_else(|| panic!("auth header present"));
        let auth = auth_header
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.as_str());
        assert_eq!(auth, Some("Bearer token123"));
        assert_eq!(
            output.auth_context.and_then(|ctx| ctx.email).as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn disconnect_returns_reconnect_card() {
        let backend = MockBroker {
            token: None,
            consent_url: "https://consent/start".into(),
        };
        let input = OAuthCardInput {
            mode: OAuthCardMode::Disconnect,
            provider_id: "msgraph".into(),
            subject: "user-1".into(),
            tenant: None,
            team: None,
            scopes: vec!["openid".into()],
            state_id: None,
            auth_code: None,
            allow_auto_sign_in: false,
            redirect_path: None,
            extra_json: None,
        };

        let output =
            logic::handle(&backend, input).unwrap_or_else(|err| panic!("disconnect card: {err}"));
        assert_eq!(output.status, OAuthStatus::Ok);
        let card = if let Some(card) = output.card {
            card
        } else {
            panic!("card present")
        };
        assert!(
            card.title
                .as_deref()
                .unwrap_or_default()
                .contains("Disconnected")
        );
        assert!(card.actions.iter().any(|a| matches!(
            a,
            crate::model::Action::PostBack { data, .. }
                if data.get("mode").and_then(|v| v.as_str()) == Some("start-sign-in")
        )));
    }
}
