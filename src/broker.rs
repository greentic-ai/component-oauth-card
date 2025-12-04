use crate::OAuthCardError;
use crate::model::{OAuthCardInput, TokenSet};

pub trait OAuthBackend {
    fn get_token(
        &self,
        provider_id: &str,
        subject: &str,
        scopes: &[String],
    ) -> Result<Option<TokenSet>, OAuthCardError>;

    fn get_consent_url(
        &self,
        provider_id: &str,
        subject: &str,
        scopes: &[String],
        redirect_path: &str,
        extra_json: Option<String>,
    ) -> Result<String, OAuthCardError>;

    fn exchange_code(
        &self,
        provider_id: &str,
        subject: &str,
        code: &str,
        redirect_path: &str,
    ) -> Result<TokenSet, OAuthCardError>;
}

/// Default backend used in production (host-provided broker for wasm) or a
/// no-op placeholder on native targets to keep tests predictable.
pub fn default_backend() -> DefaultBackend {
    DefaultBackend::default()
}

#[cfg(target_arch = "wasm32")]
type DefaultBackend = HostBroker;

#[cfg(not(target_arch = "wasm32"))]
type DefaultBackend = NoopBroker;

#[cfg(target_arch = "wasm32")]
#[derive(Default, Clone)]
pub struct HostBroker;

#[cfg(target_arch = "wasm32")]
impl OAuthBackend for HostBroker {
    fn get_token(
        &self,
        provider_id: &str,
        subject: &str,
        scopes: &[String],
    ) -> Result<Option<TokenSet>, OAuthCardError> {
        let json = get_token(provider_id, subject, scopes);
        if json.is_empty() {
            return Ok(None);
        }
        let parsed: TokenSet = serde_json::from_str(&json)
            .map_err(|err| OAuthCardError::Parse(format!("token json: {err}")))?;
        Ok(Some(parsed))
    }

    fn get_consent_url(
        &self,
        provider_id: &str,
        subject: &str,
        scopes: &[String],
        redirect_path: &str,
        extra_json: Option<String>,
    ) -> Result<String, OAuthCardError> {
        let url = get_consent_url(
            provider_id,
            subject,
            scopes,
            redirect_path,
            extra_json.as_deref().unwrap_or_default(),
        );
        Ok(url)
    }

    fn exchange_code(
        &self,
        provider_id: &str,
        subject: &str,
        code: &str,
        redirect_path: &str,
    ) -> Result<TokenSet, OAuthCardError> {
        let json = exchange_code(provider_id, subject, code, redirect_path);
        let parsed: TokenSet = serde_json::from_str(&json)
            .map_err(|err| OAuthCardError::Parse(format!("exchange json: {err}")))?;
        Ok(parsed)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Default, Clone)]
pub struct NoopBroker;

#[cfg(not(target_arch = "wasm32"))]
impl OAuthBackend for NoopBroker {
    fn get_token(
        &self,
        _provider_id: &str,
        _subject: &str,
        _scopes: &[String],
    ) -> Result<Option<TokenSet>, OAuthCardError> {
        Ok(None)
    }

    fn get_consent_url(
        &self,
        _provider_id: &str,
        _subject: &str,
        _scopes: &[String],
        _redirect_path: &str,
        _extra_json: Option<String>,
    ) -> Result<String, OAuthCardError> {
        Ok(String::new())
    }

    fn exchange_code(
        &self,
        _provider_id: &str,
        _subject: &str,
        _code: &str,
        _redirect_path: &str,
    ) -> Result<TokenSet, OAuthCardError> {
        Err(OAuthCardError::Unsupported(
            "exchange_code unavailable on native test backend".into(),
        ))
    }
}

/// Simple in-memory broker used in tests.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Default, Clone)]
pub struct MockBroker {
    pub token: Option<TokenSet>,
    pub consent_url: String,
}

impl OAuthBackend for MockBroker {
    fn get_token(
        &self,
        _provider_id: &str,
        _subject: &str,
        _scopes: &[String],
    ) -> Result<Option<TokenSet>, OAuthCardError> {
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
        self.token
            .clone()
            .ok_or_else(|| OAuthCardError::Unsupported("no token in mock".into()))
    }
}

pub fn parse_input(input: &str) -> Result<OAuthCardInput, OAuthCardError> {
    serde_json::from_str::<OAuthCardInput>(input.trim())
        .map_err(|err| OAuthCardError::Parse(format!("input json: {err}")))
}
#[cfg(target_arch = "wasm32")]
use greentic_interfaces_guest::oauth_broker_client::{exchange_code, get_consent_url, get_token};
