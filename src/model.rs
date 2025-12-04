use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageCard {
    #[serde(default)]
    pub kind: MessageCardKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<ImageRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
    #[serde(default = "default_true")]
    pub allow_markdown: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adaptive: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OauthCard>,
}

impl Default for MessageCard {
    fn default() -> Self {
        Self {
            kind: MessageCardKind::default(),
            title: None,
            text: None,
            footer: None,
            images: Vec::new(),
            actions: Vec::new(),
            allow_markdown: true,
            adaptive: None,
            oauth: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ImageRef {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    OpenUrl { title: String, url: String },
    PostBack { title: String, data: Value },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MessageCardKind {
    #[default]
    Standard,
    Oauth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OauthProvider {
    Microsoft,
    Google,
    Github,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OauthPrompt {
    None,
    Consent,
    Login,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OauthCard {
    pub provider: OauthProvider,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<OauthPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthCardMode {
    StatusCard,
    StartSignIn,
    CompleteSignIn,
    EnsureToken,
    Disconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCardInput {
    pub mode: OAuthCardMode,
    pub provider_id: String,
    /// Logical subject identifier (user/service) this card operates on.
    pub subject: String,
    /// Optional tenant context for routing; not enforced locally but echoed back.
    pub tenant: Option<String>,
    pub team: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Correlation handle used by sign-in flows.
    pub state_id: Option<String>,
    /// Authorization code returned by the provider (for complete-sign-in).
    pub auth_code: Option<String>,
    #[serde(default)]
    pub allow_auto_sign_in: bool,
    /// Optional redirect path (defaults to "/oauth/callback/{provider_id}").
    pub redirect_path: Option<String>,
    /// Provider-specific options forwarded to the broker.
    pub extra_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthCardOutput {
    pub status: OAuthStatus,
    pub card: Option<MessageCard>,
    pub auth_context: Option<AuthContext>,
    pub auth_header: Option<AuthHeader>,
    pub state_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthContext {
    pub provider_id: String,
    pub subject: String,
    pub email: Option<String>,
    pub tenant: Option<String>,
    pub team: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHeader {
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<u64>,
    pub token_type: Option<String>,
    pub extra: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthStatus {
    #[default]
    Ok,
    NeedsSignIn,
    Error,
}
