use uuid::Uuid;

use crate::OAuthCardError;
use crate::broker::OAuthBackend;
use crate::model::{
    Action, AuthContext, AuthHeader, MessageCard, MessageCardKind, OAuthCardInput, OAuthCardMode,
    OAuthCardOutput, OAuthStatus, OauthCard, OauthPrompt, OauthProvider, TokenSet,
};
use serde_json::json;

pub fn handle<B: OAuthBackend>(
    backend: &B,
    input: OAuthCardInput,
) -> Result<OAuthCardOutput, OAuthCardError> {
    match input.mode {
        OAuthCardMode::StatusCard => status_card(backend, &input),
        OAuthCardMode::StartSignIn => start_sign_in(backend, &input),
        OAuthCardMode::CompleteSignIn => complete_sign_in(backend, &input),
        OAuthCardMode::EnsureToken => ensure_token(backend, &input),
        OAuthCardMode::Disconnect => disconnect_card(&input),
    }
}

fn status_card<B: OAuthBackend>(
    backend: &B,
    input: &OAuthCardInput,
) -> Result<OAuthCardOutput, OAuthCardError> {
    let token = backend.get_token(&input.provider_id, &input.subject, &input.scopes)?;

    if let Some(token) = token {
        let card = connected_card(input, &token, "Connected");
        Ok(OAuthCardOutput {
            status: OAuthStatus::Ok,
            card: Some(card),
            auth_context: Some(auth_context(input, &token)),
            auth_header: Some(auth_header(&token)),
            state_id: None,
            error: None,
        })
    } else {
        let card = connect_prompt_card(input, None);
        Ok(OAuthCardOutput {
            status: OAuthStatus::NeedsSignIn,
            card: Some(card),
            auth_context: None,
            auth_header: None,
            state_id: None,
            error: None,
        })
    }
}

fn start_sign_in<B: OAuthBackend>(
    backend: &B,
    input: &OAuthCardInput,
) -> Result<OAuthCardOutput, OAuthCardError> {
    let state_id = input
        .state_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let redirect_path = redirect_path(input);
    let consent_url = backend
        .get_consent_url(
            &input.provider_id,
            &input.subject,
            &input.scopes,
            &redirect_path,
            input.extra_json.as_ref().map(|v| v.to_string()),
        )
        .unwrap_or_default();
    let card = sign_in_card(input, &state_id, &consent_url);

    Ok(OAuthCardOutput {
        status: OAuthStatus::Ok,
        card: Some(card),
        auth_context: None,
        auth_header: None,
        state_id: Some(state_id),
        error: None,
    })
}

fn complete_sign_in<B: OAuthBackend>(
    backend: &B,
    input: &OAuthCardInput,
) -> Result<OAuthCardOutput, OAuthCardError> {
    let code = input.auth_code.as_ref().ok_or_else(|| {
        OAuthCardError::Invalid("auth_code is required to complete sign-in".into())
    })?;
    let redirect_path = redirect_path(input);
    let token = backend.exchange_code(&input.provider_id, &input.subject, code, &redirect_path)?;
    let card = connected_card(input, &token, "Connected");

    Ok(OAuthCardOutput {
        status: OAuthStatus::Ok,
        card: Some(card),
        auth_context: Some(auth_context(input, &token)),
        auth_header: Some(auth_header(&token)),
        state_id: None,
        error: None,
    })
}

fn ensure_token<B: OAuthBackend>(
    backend: &B,
    input: &OAuthCardInput,
) -> Result<OAuthCardOutput, OAuthCardError> {
    if let Some(token) = backend.get_token(&input.provider_id, &input.subject, &input.scopes)? {
        return Ok(OAuthCardOutput {
            status: OAuthStatus::Ok,
            card: None,
            auth_context: Some(auth_context(input, &token)),
            auth_header: Some(auth_header(&token)),
            state_id: None,
            error: None,
        });
    }

    if input.allow_auto_sign_in {
        let state_id = input
            .state_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let redirect_path = redirect_path(input);
        let consent_url = backend
            .get_consent_url(
                &input.provider_id,
                &input.subject,
                &input.scopes,
                &redirect_path,
                input.extra_json.as_ref().map(|v| v.to_string()),
            )
            .unwrap_or_default();
        let card = sign_in_card(input, &state_id, &consent_url);

        Ok(OAuthCardOutput {
            status: OAuthStatus::NeedsSignIn,
            card: Some(card),
            auth_context: None,
            auth_header: None,
            state_id: Some(state_id),
            error: None,
        })
    } else {
        Ok(OAuthCardOutput {
            status: OAuthStatus::NeedsSignIn,
            card: None,
            auth_context: None,
            auth_header: None,
            state_id: None,
            error: None,
        })
    }
}

fn disconnect_card(input: &OAuthCardInput) -> Result<OAuthCardOutput, OAuthCardError> {
    let mut card = base_card(
        MessageCardKind::Oauth,
        Some(format!("Disconnected from {}", input.provider_id)),
        Some("You can reconnect this account at any time.".into()),
    );
    card.actions
        .push(action("Reconnect", OAuthCardMode::StartSignIn, input, None));
    card.oauth = Some(OauthCard {
        provider: provider_from_id(&input.provider_id),
        scopes: input.scopes.clone(),
        resource: None,
        prompt: None,
        start_url: None,
        connection_name: None,
        metadata: Some(json!({
            "provider_id": input.provider_id,
            "subject": input.subject,
        })),
    });

    Ok(OAuthCardOutput {
        status: OAuthStatus::Ok,
        card: Some(card),
        auth_context: None,
        auth_header: None,
        state_id: None,
        error: None,
    })
}

fn sign_in_card(input: &OAuthCardInput, state_id: &str, url: &str) -> MessageCard {
    let mut card = base_card(
        MessageCardKind::Oauth,
        Some(format!("Connect {} account", input.provider_id)),
        Some(format!(
            "Click Connect to sign in as {}{}.",
            input.subject,
            input
                .team
                .as_ref()
                .map(|team| format!(" (team {team})"))
                .unwrap_or_default()
        )),
    );
    if !url.is_empty() {
        card.actions.push(Action::OpenUrl {
            title: "Connect".into(),
            url: url.into(),
        });
    }
    card.actions.push(action(
        "Continue",
        OAuthCardMode::CompleteSignIn,
        input,
        Some(state_id.to_string()),
    ));
    card.oauth = Some(OauthCard {
        provider: provider_from_id(&input.provider_id),
        scopes: input.scopes.clone(),
        resource: None,
        prompt: Some(OauthPrompt::Consent),
        start_url: if url.is_empty() {
            None
        } else {
            Some(url.to_string())
        },
        connection_name: None,
        metadata: Some(json!({
            "state_id": state_id,
            "provider_id": input.provider_id,
            "subject": input.subject,
        })),
    });
    card
}

fn connect_prompt_card(input: &OAuthCardInput, existing_state: Option<String>) -> MessageCard {
    let state_id = existing_state.unwrap_or_else(|| Uuid::new_v4().to_string());
    sign_in_card(input, &state_id, "")
}

fn connected_card(input: &OAuthCardInput, token: &TokenSet, headline: &str) -> MessageCard {
    let mut card = base_card(
        MessageCardKind::Oauth,
        Some(format!("{headline}: {}", input.provider_id)),
        Some(format!(
            "Signed in as {}{}.",
            input.subject,
            input
                .team
                .as_ref()
                .map(|team| format!(" (team {team})"))
                .unwrap_or_default()
        )),
    );
    card.actions.push(action(
        "Refresh token",
        OAuthCardMode::EnsureToken,
        input,
        None,
    ));
    card.actions.push(action(
        "Use different account",
        OAuthCardMode::StartSignIn,
        input,
        None,
    ));
    card.actions
        .push(action("Disconnect", OAuthCardMode::Disconnect, input, None));
    card.oauth = Some(OauthCard {
        provider: provider_from_id(&input.provider_id),
        scopes: input.scopes.clone(),
        resource: None,
        prompt: None,
        start_url: None,
        connection_name: None,
        metadata: Some(json!({
            "expires_at": token.expires_at,
            "provider_id": input.provider_id,
            "subject": input.subject,
        })),
    });
    card
}

fn redirect_path(input: &OAuthCardInput) -> String {
    input
        .redirect_path
        .clone()
        .unwrap_or_else(|| format!("/oauth/callback/{}", input.provider_id))
}

fn auth_context(input: &OAuthCardInput, token: &TokenSet) -> AuthContext {
    AuthContext {
        provider_id: input.provider_id.clone(),
        subject: input.subject.clone(),
        email: token
            .extra
            .as_ref()
            .and_then(|extra| extra.get("email"))
            .and_then(|v| v.as_str().map(|s| s.to_string())),
        tenant: input.tenant.clone(),
        team: input.team.clone(),
        scopes: input.scopes.clone(),
        expires_at: token.expires_at,
    }
}

fn auth_header(token: &TokenSet) -> AuthHeader {
    let mut headers = Vec::new();
    let prefix = token.token_type.as_deref().unwrap_or("Bearer");
    headers.push((
        "Authorization".into(),
        format!("{prefix} {}", token.access_token),
    ));
    AuthHeader { headers }
}

fn action(
    title: &str,
    mode: OAuthCardMode,
    input: &OAuthCardInput,
    state_id: Option<String>,
) -> Action {
    Action::PostBack {
        title: title.to_string(),
        data: json!({
            "mode": mode,
            "provider_id": input.provider_id,
            "subject": input.subject,
            "state_id": state_id,
            "scopes": input.scopes,
        }),
    }
}

fn provider_from_id(id: &str) -> OauthProvider {
    match id.to_ascii_lowercase().as_str() {
        "microsoft" | "msgraph" | "m365" => OauthProvider::Microsoft,
        "google" => OauthProvider::Google,
        "github" => OauthProvider::Github,
        _ => OauthProvider::Custom,
    }
}

fn base_card(kind: MessageCardKind, title: Option<String>, text: Option<String>) -> MessageCard {
    let mut card = MessageCard {
        kind,
        title,
        text,
        ..Default::default()
    };
    card.allow_markdown = true;
    card
}
