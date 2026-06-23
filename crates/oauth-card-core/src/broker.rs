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

#[derive(Default, Clone)]
pub struct InputBroker {
    pub current_token: Option<TokenSet>,
    pub consent_url: Option<String>,
    pub exchanged_token: Option<TokenSet>,
    pub oauth_error: Option<String>,
}

impl InputBroker {
    pub fn from_input(input: &OAuthCardInput) -> Self {
        Self {
            current_token: input.current_token.clone(),
            consent_url: input.consent_url.clone(),
            exchanged_token: input.exchanged_token.clone(),
            oauth_error: input.oauth_error.clone(),
        }
    }
}

impl OAuthBackend for InputBroker {
    fn get_token(
        &self,
        _provider_id: &str,
        _subject: &str,
        _scopes: &[String],
    ) -> Result<Option<TokenSet>, OAuthCardError> {
        Ok(self.current_token.clone())
    }

    fn get_consent_url(
        &self,
        _provider_id: &str,
        _subject: &str,
        _scopes: &[String],
        _redirect_path: &str,
        _extra_json: Option<String>,
    ) -> Result<String, OAuthCardError> {
        self.consent_url.clone().ok_or_else(|| {
            OAuthCardError::Invalid("consent_url is required for start-sign-in".into())
        })
    }

    fn exchange_code(
        &self,
        _provider_id: &str,
        _subject: &str,
        _code: &str,
        _redirect_path: &str,
    ) -> Result<TokenSet, OAuthCardError> {
        if let Some(err) = &self.oauth_error {
            return Err(OAuthCardError::Invalid(err.clone()));
        }
        self.exchanged_token.clone().ok_or_else(|| {
            OAuthCardError::Invalid("exchanged_token is required for complete-sign-in".into())
        })
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

#[cfg_attr(not(test), allow(dead_code))]
pub fn parse_input(input: &str) -> Result<OAuthCardInput, OAuthCardError> {
    serde_json::from_str::<OAuthCardInput>(input.trim())
        .map_err(|err| OAuthCardError::Parse(format!("input json: {err}")))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_input_accepts_trimmed_json() {
        let input = parse_input(
            r#"
            {
              "mode": "status-card",
              "provider_id": "github",
              "subject": "user-1"
            }
            "#,
        )
        .expect("parse ok");

        assert_eq!(input.provider_id, "github");
        assert_eq!(input.subject, "user-1");
        assert!(input.scopes.is_empty());
        assert!(input.current_token.is_none());
    }

    #[test]
    fn parse_input_reports_parse_errors() {
        let err = parse_input("{").expect_err("should fail");
        assert!(matches!(err, OAuthCardError::Parse(_)));
    }

    #[test]
    fn mock_broker_round_trips_token_and_consent_url() {
        let broker = MockBroker {
            token: Some(TokenSet {
                access_token: "token".into(),
                refresh_token: None,
                expires_at: None,
                token_type: Some("Bearer".into()),
                extra: None,
            }),
            consent_url: "https://consent.example".into(),
        };

        assert!(
            broker
                .get_token("provider", "subject", &[])
                .expect("token ok")
                .is_some()
        );
        assert_eq!(
            broker
                .get_consent_url("provider", "subject", &[], "/cb", None)
                .expect("consent ok"),
            "https://consent.example"
        );
        assert_eq!(
            broker
                .exchange_code("provider", "subject", "code", "/cb")
                .expect("exchange ok")
                .access_token,
            "token"
        );
    }
}
