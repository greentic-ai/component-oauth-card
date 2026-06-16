use uuid::Uuid;

use crate::OAuthCardError;
use crate::broker::OAuthBackend;
use crate::model::{
    Action, AuthContext, AuthHeader, MessageCard, MessageCardKind, OAuthCardInput, OAuthCardMode,
    OAuthCardOutput, OAuthStatus, OauthCard, OauthPrompt, OauthProvider, TokenExchangeResource,
    TokenSet,
};
use serde_json::json;

/// Default seconds before `expires_at` at which a token is treated as due for refresh.
const DEFAULT_REFRESH_SKEW_SECONDS: u64 = 60;

/// Decide whether a resolved token is expired (or within the refresh skew window).
///
/// Returns `false` when there is no expiry information or no injected clock
/// (`now_unix`), so behaviour is unchanged for callers that do not supply a
/// clock — tokens without a decidable expiry are treated as fresh.
fn token_needs_refresh(token: &TokenSet, input: &OAuthCardInput) -> bool {
    match (token.expires_at, input.now_unix) {
        (Some(expires_at), Some(now)) => {
            let skew = input
                .refresh_skew_seconds
                .unwrap_or(DEFAULT_REFRESH_SKEW_SECONDS);
            expires_at <= now.saturating_add(skew)
        }
        _ => false,
    }
}

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
        if token_needs_refresh(&token, input) {
            let card = refresh_required_card(input);
            return Ok(OAuthCardOutput {
                status: OAuthStatus::NeedsRefresh,
                can_continue: false,
                card: Some(card),
                auth_context: Some(auth_context(input, &token)),
                auth_header: None,
                access_token: None,
                state_id: None,
                error: None,
            });
        }
        let card = connected_card(input, &token, "Connected");
        Ok(OAuthCardOutput {
            status: OAuthStatus::Ok,
            can_continue: true,
            card: Some(card),
            auth_context: Some(auth_context(input, &token)),
            auth_header: Some(auth_header(&token)),
            access_token: Some(token.access_token.clone()),
            state_id: None,
            error: None,
        })
    } else {
        let card = auth_required_card(
            input,
            None,
            "Authentication required",
            "The flow cannot continue until you successfully sign in to this OAuth service.",
        );
        Ok(OAuthCardOutput {
            status: OAuthStatus::NeedsSignIn,
            can_continue: false,
            card: Some(card),
            auth_context: None,
            auth_header: None,
            access_token: None,
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
    let consent_url = resolve_consent_url(backend, input, &state_id, &redirect_path)?;
    let card = sign_in_card(input, &state_id, &consent_url);

    Ok(OAuthCardOutput {
        status: OAuthStatus::Ok,
        can_continue: false,
        card: Some(card),
        auth_context: None,
        auth_header: None,
        access_token: None,
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
    let token = match backend.exchange_code(
        &input.provider_id,
        &input.subject,
        code,
        &redirect_path,
    ) {
        Ok(token) => token,
        Err(err) => {
            let card = auth_required_card(
                input,
                input.state_id.clone(),
                "Sign-in not completed",
                "Authentication was not completed successfully. Retry sign-in to continue this flow.",
            );
            return Ok(OAuthCardOutput {
                status: OAuthStatus::NeedsSignIn,
                can_continue: false,
                card: Some(card),
                auth_context: None,
                auth_header: None,
                access_token: None,
                state_id: input.state_id.clone(),
                error: Some(err.to_string()),
            });
        }
    };
    let card = connected_card(input, &token, "Connected");

    Ok(OAuthCardOutput {
        status: OAuthStatus::Ok,
        can_continue: true,
        card: Some(card),
        auth_context: Some(auth_context(input, &token)),
        auth_header: Some(auth_header(&token)),
        access_token: Some(token.access_token.clone()),
        state_id: None,
        error: None,
    })
}

fn ensure_token<B: OAuthBackend>(
    backend: &B,
    input: &OAuthCardInput,
) -> Result<OAuthCardOutput, OAuthCardError> {
    if let Some(token) = backend.get_token(&input.provider_id, &input.subject, &input.scopes)? {
        if token_needs_refresh(&token, input) {
            return Ok(OAuthCardOutput {
                status: OAuthStatus::NeedsRefresh,
                can_continue: false,
                card: None,
                auth_context: Some(auth_context(input, &token)),
                auth_header: None,
                access_token: None,
                state_id: None,
                error: None,
            });
        }
        return Ok(OAuthCardOutput {
            status: OAuthStatus::Ok,
            can_continue: true,
            card: None,
            auth_context: Some(auth_context(input, &token)),
            auth_header: Some(auth_header(&token)),
            access_token: Some(token.access_token.clone()),
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
        let consent_url = resolve_consent_url(backend, input, &state_id, &redirect_path)?;
        let card = sign_in_card_with_message(
            input,
            &state_id,
            &consent_url,
            "Authentication required before this flow can continue.",
        );

        Ok(OAuthCardOutput {
            status: OAuthStatus::NeedsSignIn,
            can_continue: false,
            card: Some(card),
            auth_context: None,
            auth_header: None,
            access_token: None,
            state_id: Some(state_id),
            error: None,
        })
    } else {
        let card = auth_required_card(
            input,
            input.state_id.clone(),
            "Authentication required",
            "No usable access token is available. Sign in successfully before retrying this flow.",
        );
        Ok(OAuthCardOutput {
            status: OAuthStatus::NeedsSignIn,
            can_continue: false,
            card: Some(card),
            auth_context: None,
            auth_header: None,
            access_token: None,
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
    let (connection_name, token_exchange_resource) = oauth_connection(input);
    card.oauth = Some(OauthCard {
        provider: provider_from_id(&input.provider_id),
        scopes: input.scopes.clone(),
        resource: None,
        prompt: None,
        start_url: None,
        connection_name,
        token_exchange_resource,
        metadata: Some(json!({
            "provider_id": input.provider_id,
            "subject": input.subject,
        })),
    });

    Ok(OAuthCardOutput {
        status: OAuthStatus::Ok,
        can_continue: false,
        card: Some(card),
        auth_context: None,
        auth_header: None,
        access_token: None,
        state_id: None,
        error: None,
    })
}

fn sign_in_card(input: &OAuthCardInput, state_id: &str, url: &str) -> MessageCard {
    sign_in_card_with_message(
        input,
        state_id,
        url,
        &format!(
            "Click Connect to sign in as {}{}.",
            input.subject,
            input
                .team
                .as_ref()
                .map(|team| format!(" (team {team})"))
                .unwrap_or_default()
        ),
    )
}

fn sign_in_card_with_message(
    input: &OAuthCardInput,
    state_id: &str,
    url: &str,
    message: &str,
) -> MessageCard {
    let mut card = base_card(
        MessageCardKind::Oauth,
        Some(format!("Connect {} account", input.provider_id)),
        Some(message.to_string()),
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
    let (connection_name, token_exchange_resource) = oauth_connection(input);
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
        connection_name,
        token_exchange_resource,
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
    sign_in_card_with_message(
        input,
        &state_id,
        "",
        "No valid access token is available. Connect the account to continue.",
    )
}

fn auth_required_card(
    input: &OAuthCardInput,
    existing_state: Option<String>,
    title: &str,
    message: &str,
) -> MessageCard {
    let mut card = connect_prompt_card(input, existing_state);
    card.title = Some(format!("{title}: {}", input.provider_id));
    card.text = Some(format!("{message} You can retry after authenticating."));
    card
}

/// Card shown when a token exists but is expired/near-expiry. Signals the flow
/// to resolve/refresh via the broker `get-token` op; also offers a manual retry.
fn refresh_required_card(input: &OAuthCardInput) -> MessageCard {
    let (connection_name, token_exchange_resource) = oauth_connection(input);
    let mut card = base_card(
        MessageCardKind::Oauth,
        Some(format!("Refreshing {} session", input.provider_id)),
        Some("Your access token has expired. Refreshing before this flow continues.".into()),
    );
    card.actions
        .push(action("Retry", OAuthCardMode::EnsureToken, input, None));
    card.oauth = Some(OauthCard {
        provider: provider_from_id(&input.provider_id),
        scopes: input.scopes.clone(),
        resource: None,
        prompt: None,
        start_url: None,
        connection_name,
        token_exchange_resource,
        metadata: Some(json!({
            "provider_id": input.provider_id,
            "subject": input.subject,
        })),
    });
    card
}

/// Resolve the Bot Framework connection fields (`connectionName` +
/// `tokenExchangeResource`) for the rendered oauth card. The token-exchange
/// resource is only emitted when a connection name is configured, signalling
/// SSO/silent-exchange capability to clients like Teams/WebChat.
fn oauth_connection(input: &OAuthCardInput) -> (Option<String>, Option<TokenExchangeResource>) {
    let connection_name = input.connection_name.clone();
    let token_exchange_resource = connection_name.as_ref().map(|_| TokenExchangeResource {
        id: None,
        uri: None,
        provider_id: Some(input.provider_id.clone()),
    });
    (connection_name, token_exchange_resource)
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
    let (connection_name, token_exchange_resource) = oauth_connection(input);
    card.oauth = Some(OauthCard {
        provider: provider_from_id(&input.provider_id),
        scopes: input.scopes.clone(),
        resource: None,
        prompt: None,
        start_url: None,
        connection_name,
        token_exchange_resource,
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

/// Resolve the consent URL for a sign-in, provider-agnostically.
///
/// Precedence:
/// 1. An explicit `consent_url` (e.g. minted by an upstream OAuth provider op).
/// 2. A standard OAuth 2.0 authorization-code URL built from `auth_url` +
///    `client_id` (+ scopes/redirect/state) supplied at setup/config time. This
///    is the conventional flow that works for any provider without hardcoding.
/// 3. Otherwise defer to the backend broker.
fn resolve_consent_url<B: OAuthBackend>(
    backend: &B,
    input: &OAuthCardInput,
    state_id: &str,
    redirect_path: &str,
) -> Result<String, OAuthCardError> {
    if let Some(url) = &input.consent_url {
        return Ok(url.clone());
    }
    if let (Some(auth_url), Some(client_id)) = (&input.auth_url, &input.client_id) {
        return Ok(build_authorize_url(
            auth_url,
            client_id,
            input.redirect_uri.as_deref(),
            &input.scopes,
            state_id,
        ));
    }
    backend.get_consent_url(
        &input.provider_id,
        &input.subject,
        &input.scopes,
        redirect_path,
        input.extra_json.as_ref().map(|v| v.to_string()),
    )
}

/// Build a conventional OAuth 2.0 authorization-code consent URL. Provider-
/// agnostic: GitHub, Google, Microsoft, Okta, etc. differ only by `auth_url`,
/// `client_id`, and `scopes`.
fn build_authorize_url(
    auth_url: &str,
    client_id: &str,
    redirect_uri: Option<&str>,
    scopes: &[String],
    state: &str,
) -> String {
    let mut params: Vec<(&str, String)> = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
    ];
    if let Some(redirect) = redirect_uri {
        params.push(("redirect_uri", redirect.to_string()));
    }
    if !scopes.is_empty() {
        params.push(("scope", scopes.join(" ")));
    }
    params.push(("state", state.to_string()));

    let query = params
        .iter()
        .map(|(key, value)| format!("{key}={}", percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let separator = if auth_url.contains('?') { '&' } else { '?' };
    format!("{auth_url}{separator}{query}")
}

/// Percent-encode a query-parameter value (RFC 3986 unreserved set passes
/// through; everything else is `%XX`).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::OAuthBackend;

    #[derive(Default)]
    struct TestBackend {
        token: Option<TokenSet>,
        consent_url: String,
        exchange_error: Option<OAuthCardError>,
        token_error: Option<OAuthCardError>,
    }

    impl OAuthBackend for TestBackend {
        fn get_token(
            &self,
            _provider_id: &str,
            _subject: &str,
            _scopes: &[String],
        ) -> Result<Option<TokenSet>, OAuthCardError> {
            if let Some(err) = &self.token_error {
                return Err(OAuthCardError::Unsupported(err.to_string()));
            }
            Ok(self.token.clone())
        }

        fn get_consent_url(
            &self,
            _provider_id: &str,
            _subject: &str,
            _scopes: &[String],
            _redirect_path: &str,
            _extra_json: Option<String>,
        ) -> Result<String, OAuthCardError> {
            Ok(self.consent_url.clone())
        }

        fn exchange_code(
            &self,
            _provider_id: &str,
            _subject: &str,
            _code: &str,
            _redirect_path: &str,
        ) -> Result<TokenSet, OAuthCardError> {
            if let Some(err) = &self.exchange_error {
                return Err(OAuthCardError::Unsupported(err.to_string()));
            }
            self.token
                .clone()
                .ok_or_else(|| OAuthCardError::Unsupported("missing token".into()))
        }
    }

    fn sample_input(mode: OAuthCardMode) -> OAuthCardInput {
        OAuthCardInput {
            mode,
            provider_id: "msgraph".into(),
            subject: "user-1".into(),
            tenant: Some("tenant-1".into()),
            team: Some("team-1".into()),
            scopes: vec!["openid".into()],
            state_id: None,
            auth_code: None,
            allow_auto_sign_in: false,
            redirect_path: None,
            auth_url: None,
            client_id: None,
            redirect_uri: None,
            extra_json: None,
            current_token: None,
            consent_url: None,
            exchanged_token: None,
            oauth_error: None,
            now_unix: None,
            refresh_skew_seconds: None,
            connection_name: None,
        }
    }

    fn sample_token() -> TokenSet {
        TokenSet {
            access_token: "token-123".into(),
            refresh_token: Some("refresh-123".into()),
            expires_at: Some(42),
            token_type: Some("Bearer".into()),
            extra: Some(json!({ "email": "user@example.com" })),
        }
    }

    #[test]
    fn status_card_with_token_returns_connected_context() {
        let backend = TestBackend {
            token: Some(sample_token()),
            consent_url: String::new(),
            exchange_error: None,
            token_error: None,
        };

        let output = handle(&backend, sample_input(OAuthCardMode::StatusCard)).expect("status ok");
        assert_eq!(output.status, OAuthStatus::Ok);
        assert_eq!(
            output.auth_context.expect("context").email.as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            output.auth_header.expect("header").headers[0].1,
            "Bearer token-123"
        );
        assert_eq!(output.card.expect("card").actions.len(), 3);
    }

    #[test]
    fn start_sign_in_returns_open_url_and_state() {
        let backend = TestBackend {
            token: None,
            consent_url: "https://consent.example".into(),
            exchange_error: None,
            token_error: None,
        };

        let output = handle(&backend, sample_input(OAuthCardMode::StartSignIn)).expect("start ok");
        assert_eq!(output.status, OAuthStatus::Ok);
        assert!(output.state_id.is_some());
        let card = output.card.expect("card");
        assert!(card.actions.iter().any(|action| matches!(
            action,
            Action::OpenUrl { url, .. } if url == "https://consent.example"
        )));
        assert_eq!(
            card.oauth.expect("oauth").provider,
            OauthProvider::Microsoft
        );
    }

    #[test]
    fn complete_sign_in_requires_auth_code() {
        let backend = TestBackend::default();
        let err = handle(&backend, sample_input(OAuthCardMode::CompleteSignIn))
            .expect_err("missing auth_code");
        assert!(matches!(err, OAuthCardError::Invalid(_)));
    }

    #[test]
    fn complete_sign_in_uses_backend_exchange() {
        let backend = TestBackend {
            token: Some(sample_token()),
            consent_url: String::new(),
            exchange_error: None,
            token_error: None,
        };
        let mut input = sample_input(OAuthCardMode::CompleteSignIn);
        input.auth_code = Some("code-123".into());

        let output = handle(&backend, input).expect("complete ok");
        assert_eq!(output.status, OAuthStatus::Ok);
        assert_eq!(
            output.card.expect("card").title.as_deref(),
            Some("Connected: msgraph")
        );
    }

    #[test]
    fn ensure_token_without_auto_sign_in_returns_no_card() {
        let backend = TestBackend::default();
        let output = handle(&backend, sample_input(OAuthCardMode::EnsureToken)).expect("ensure ok");
        assert_eq!(output.status, OAuthStatus::NeedsSignIn);
        assert!(!output.can_continue);
        assert!(output.card.is_some());
    }

    #[test]
    fn ensure_token_with_auto_sign_in_returns_card() {
        let backend = TestBackend {
            token: None,
            consent_url: "https://consent.example".into(),
            exchange_error: None,
            token_error: None,
        };
        let mut input = sample_input(OAuthCardMode::EnsureToken);
        input.allow_auto_sign_in = true;

        let output = handle(&backend, input).expect("ensure ok");
        assert_eq!(output.status, OAuthStatus::NeedsSignIn);
        assert!(output.state_id.is_some());
        assert!(output.card.is_some());
    }

    #[test]
    fn disconnect_returns_reconnect_card() {
        let output = handle(
            &TestBackend::default(),
            sample_input(OAuthCardMode::Disconnect),
        )
        .expect("disconnect ok");
        assert_eq!(output.status, OAuthStatus::Ok);
        let card = output.card.expect("card");
        assert!(card.actions.iter().any(|action| matches!(
            action,
            Action::PostBack { title, .. } if title == "Reconnect"
        )));
    }

    #[test]
    fn status_card_with_expired_token_requests_refresh() {
        let backend = TestBackend {
            token: Some(sample_token()), // expires_at = 42
            consent_url: String::new(),
            exchange_error: None,
            token_error: None,
        };
        let mut input = sample_input(OAuthCardMode::StatusCard);
        input.now_unix = Some(1_000); // well past expiry

        let output = handle(&backend, input).expect("status ok");
        assert_eq!(output.status, OAuthStatus::NeedsRefresh);
        assert!(!output.can_continue);
        // auth_context is surfaced so the flow can drive the refresh, but no
        // usable auth_header is emitted for a stale token.
        assert!(output.auth_context.is_some());
        assert!(output.auth_header.is_none());
    }

    #[test]
    fn status_card_with_unexpired_token_stays_connected() {
        let mut token = sample_token();
        token.expires_at = Some(10_000);
        let backend = TestBackend {
            token: Some(token),
            consent_url: String::new(),
            exchange_error: None,
            token_error: None,
        };
        let mut input = sample_input(OAuthCardMode::StatusCard);
        input.now_unix = Some(100);

        let output = handle(&backend, input).expect("status ok");
        assert_eq!(output.status, OAuthStatus::Ok);
        assert!(output.can_continue);
        assert!(output.auth_header.is_some());
    }

    #[test]
    fn ensure_token_with_expired_token_requests_refresh() {
        let backend = TestBackend {
            token: Some(sample_token()), // expires_at = 42
            consent_url: String::new(),
            exchange_error: None,
            token_error: None,
        };
        let mut input = sample_input(OAuthCardMode::EnsureToken);
        input.now_unix = Some(1_000);

        let output = handle(&backend, input).expect("ensure ok");
        assert_eq!(output.status, OAuthStatus::NeedsRefresh);
        assert!(!output.can_continue);
        assert!(output.auth_header.is_none());
    }

    #[test]
    fn no_clock_treats_token_as_fresh() {
        let backend = TestBackend {
            token: Some(sample_token()), // expires_at = 42, but no now_unix supplied
            consent_url: String::new(),
            exchange_error: None,
            token_error: None,
        };
        let output = handle(&backend, sample_input(OAuthCardMode::EnsureToken)).expect("ensure ok");
        assert_eq!(output.status, OAuthStatus::Ok);
        assert!(output.can_continue);
    }

    #[test]
    fn connection_name_populates_bot_framework_fields() {
        let backend = TestBackend {
            token: None,
            consent_url: "https://consent.example".into(),
            exchange_error: None,
            token_error: None,
        };
        let mut input = sample_input(OAuthCardMode::StartSignIn);
        input.connection_name = Some("msgraph-conn".into());

        let output = handle(&backend, input).expect("start ok");
        let oauth = output.card.expect("card").oauth.expect("oauth block");
        assert_eq!(oauth.connection_name.as_deref(), Some("msgraph-conn"));
        let ter = oauth
            .token_exchange_resource
            .expect("token_exchange_resource present when connection configured");
        assert_eq!(ter.provider_id.as_deref(), Some("msgraph"));
    }

    #[test]
    fn start_sign_in_builds_authorize_url_from_provider_config() {
        // No consent_url supplied; auth_url + client_id (set at setup) drive a
        // conventional OAuth2 authorize URL — provider-agnostic.
        let backend = TestBackend::default();
        let mut input = sample_input(OAuthCardMode::StartSignIn);
        input.provider_id = "github".into();
        input.scopes = vec!["repo".into(), "read:org".into()];
        input.auth_url = Some("https://github.com/login/oauth/authorize".into());
        input.client_id = Some("abc123".into());
        input.redirect_uri = Some("https://host.example/v1/oauth/ingress/p/demo/default".into());

        let output = handle(&backend, input).expect("start ok");
        let card = output.card.expect("card");
        let url = card
            .actions
            .iter()
            .find_map(|a| match a {
                Action::OpenUrl { url, .. } => Some(url.clone()),
                _ => None,
            })
            .expect("connect open_url");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=abc123"));
        assert!(url.contains("scope=repo%20read%3Aorg"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fhost.example"));
        assert!(url.contains("state="));
    }

    #[test]
    fn explicit_consent_url_wins_over_built_url() {
        let backend = TestBackend::default();
        let mut input = sample_input(OAuthCardMode::StartSignIn);
        input.consent_url = Some("https://explicit.example/consent".into());
        input.auth_url = Some("https://github.com/login/oauth/authorize".into());
        input.client_id = Some("abc123".into());

        let output = handle(&backend, input).expect("start ok");
        let card = output.card.expect("card");
        assert!(card.actions.iter().any(|a| matches!(
            a,
            Action::OpenUrl { url, .. } if url == "https://explicit.example/consent"
        )));
    }

    #[test]
    fn provider_mapping_and_redirect_helpers_cover_variants() {
        assert_eq!(provider_from_id("github"), OauthProvider::Github);
        assert_eq!(provider_from_id("google"), OauthProvider::Google);
        assert_eq!(provider_from_id("custom-provider"), OauthProvider::Custom);

        let input = sample_input(OAuthCardMode::StatusCard);
        assert_eq!(redirect_path(&input), "/oauth/callback/msgraph");

        let mut explicit = sample_input(OAuthCardMode::StatusCard);
        explicit.redirect_path = Some("/custom/callback".into());
        assert_eq!(redirect_path(&explicit), "/custom/callback");
    }
}
