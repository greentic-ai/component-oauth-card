use greentic_types::i18n_text::I18nText;
use greentic_types::schemas::component::v0_6_0::{Question, QuestionKind};
use serde_json::{Value as JsonValue, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizedMode {
    Setup,
    Update,
    Remove,
}

impl NormalizedMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Update => "update",
            Self::Remove => "remove",
        }
    }
}

pub fn normalize_mode(raw: &str) -> Option<NormalizedMode> {
    match raw {
        "default" | "setup" | "install" => Some(NormalizedMode::Setup),
        "update" | "upgrade" => Some(NormalizedMode::Update),
        "remove" => Some(NormalizedMode::Remove),
        _ => None,
    }
}

pub fn qa_spec_json(mode: NormalizedMode) -> JsonValue {
    let (title_key, description_key, questions) = match mode {
        NormalizedMode::Setup => (
            "qa.setup.title",
            Some("qa.setup.description"),
            vec![
                text_question(
                    "provider_id",
                    "qa.field.provider_id.label",
                    "qa.field.provider_id.help",
                    true,
                ),
                text_question(
                    "default_subject",
                    "qa.field.default_subject.label",
                    "qa.field.default_subject.help",
                    false,
                ),
                text_question(
                    "scopes_csv",
                    "qa.field.scopes_csv.label",
                    "qa.field.scopes_csv.help",
                    false,
                ),
                text_question(
                    "tenant",
                    "qa.field.tenant.label",
                    "qa.field.tenant.help",
                    false,
                ),
                text_question("team", "qa.field.team.label", "qa.field.team.help", false),
                text_question(
                    "redirect_path",
                    "qa.field.redirect_path.label",
                    "qa.field.redirect_path.help",
                    false,
                ),
                connection_question(
                    "auth_url",
                    "qa.field.auth_url.label",
                    "Authorization URL",
                    "qa.field.auth_url.help",
                    "Provider OAuth 2.0 authorize endpoint, e.g. https://github.com/login/oauth/authorize",
                    true,
                ),
                connection_question(
                    "client_id",
                    "qa.field.client_id.label",
                    "OAuth client ID (public)",
                    "qa.field.client_id.help",
                    "Public OAuth app client id — NOT a secret. Set the matching client SECRET on the OAuth provider extension, not here.",
                    true,
                ),
                connection_question(
                    "redirect_uri",
                    "qa.field.redirect_uri.label",
                    "Redirect / callback URL",
                    "qa.field.redirect_uri.help",
                    "Where the provider redirects after consent — the OAuth provider extension's ingress URL.",
                    false,
                ),
                bool_question(
                    "allow_auto_sign_in",
                    "qa.field.allow_auto_sign_in.label",
                    "qa.field.allow_auto_sign_in.help",
                    false,
                    Some(false),
                ),
            ],
        ),
        NormalizedMode::Update => (
            "qa.update.title",
            Some("qa.update.description"),
            vec![
                text_question(
                    "provider_id",
                    "qa.field.provider_id.label",
                    "qa.field.provider_id.help",
                    false,
                ),
                text_question(
                    "default_subject",
                    "qa.field.default_subject.label",
                    "qa.field.default_subject.help",
                    false,
                ),
                text_question(
                    "scopes_csv",
                    "qa.field.scopes_csv.label",
                    "qa.field.scopes_csv.help",
                    false,
                ),
                text_question(
                    "tenant",
                    "qa.field.tenant.label",
                    "qa.field.tenant.help",
                    false,
                ),
                text_question("team", "qa.field.team.label", "qa.field.team.help", false),
                text_question(
                    "redirect_path",
                    "qa.field.redirect_path.label",
                    "qa.field.redirect_path.help",
                    false,
                ),
                connection_question(
                    "auth_url",
                    "qa.field.auth_url.label",
                    "Authorization URL",
                    "qa.field.auth_url.help",
                    "Provider OAuth 2.0 authorize endpoint, e.g. https://github.com/login/oauth/authorize",
                    false,
                ),
                connection_question(
                    "client_id",
                    "qa.field.client_id.label",
                    "OAuth client ID (public)",
                    "qa.field.client_id.help",
                    "Public OAuth app client id — NOT a secret. Set the matching client SECRET on the OAuth provider extension, not here.",
                    false,
                ),
                connection_question(
                    "redirect_uri",
                    "qa.field.redirect_uri.label",
                    "Redirect / callback URL",
                    "qa.field.redirect_uri.help",
                    "Where the provider redirects after consent — the OAuth provider extension's ingress URL.",
                    false,
                ),
                bool_question(
                    "allow_auto_sign_in",
                    "qa.field.allow_auto_sign_in.label",
                    "qa.field.allow_auto_sign_in.help",
                    false,
                    None,
                ),
            ],
        ),
        NormalizedMode::Remove => (
            "qa.remove.title",
            Some("qa.remove.description"),
            vec![bool_question(
                "confirm_remove",
                "qa.field.confirm_remove.label",
                "qa.field.confirm_remove.help",
                true,
                Some(false),
            )],
        ),
    };

    json!({
        "mode": mode.as_str(),
        "title": I18nText::new(title_key, None),
        "description": description_key.map(|key| I18nText::new(key, None)),
        "questions": questions,
        "defaults": {
            "allow_auto_sign_in": false,
            "confirm_remove": false
        }
    })
}

fn text_question(id: &str, label_key: &str, help_key: &str, required: bool) -> Question {
    Question {
        id: id.to_string(),
        label: I18nText::new(label_key, None),
        help: Some(I18nText::new(help_key, None)),
        error: None,
        kind: QuestionKind::Text,
        required,
        default: None,
        skip_if: None,
    }
}

/// A text question for provider connection config, with inline fallback text so
/// labels render even before i18n translations are added for these keys.
fn connection_question(
    id: &str,
    label_key: &str,
    label_fallback: &str,
    help_key: &str,
    help_fallback: &str,
    required: bool,
) -> Question {
    Question {
        id: id.to_string(),
        label: I18nText::new(label_key, Some(label_fallback.to_string())),
        help: Some(I18nText::new(help_key, Some(help_fallback.to_string()))),
        error: None,
        kind: QuestionKind::Text,
        required,
        default: None,
        skip_if: None,
    }
}

fn bool_question(
    id: &str,
    label_key: &str,
    help_key: &str,
    required: bool,
    _default: Option<bool>,
) -> Question {
    Question {
        id: id.to_string(),
        label: I18nText::new(label_key, None),
        help: Some(I18nText::new(help_key, None)),
        error: None,
        kind: QuestionKind::Bool,
        required,
        default: None,
        skip_if: None,
    }
}

pub fn i18n_keys() -> Vec<String> {
    crate::i18n::all_keys()
}

pub fn apply_answers(mode: NormalizedMode, payload: &JsonValue) -> JsonValue {
    let answers = payload.get("answers").cloned().unwrap_or_else(|| json!({}));
    let current_config = payload
        .get("current_config")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    match mode {
        NormalizedMode::Setup => {}
        NormalizedMode::Update => {}
        NormalizedMode::Remove => {
            if !bool_answer(&answers, "confirm_remove").unwrap_or(false) {
                errors.push(json!({
                    "key": "qa.error.remove_confirmation",
                    "msg_key": "qa.error.remove_confirmation",
                    "fields": ["confirm_remove"]
                }));
            }
        }
    }

    if !errors.is_empty() {
        return json!({
            "ok": false,
            "warnings": warnings,
            "errors": errors,
            "meta": {
                "mode": mode.as_str(),
                "version": "v1"
            }
        });
    }

    let mut config = match current_config {
        JsonValue::Object(map) => map,
        _ => serde_json::Map::new(),
    };

    if mode != NormalizedMode::Remove {
        apply_text(&answers, "provider_id", &mut config);
        apply_text(&answers, "default_subject", &mut config);
        apply_text(&answers, "tenant", &mut config);
        apply_text(&answers, "team", &mut config);
        apply_nullable_text(&answers, "redirect_path", &mut config);
        // Provider-agnostic connection config (public; no secret here).
        apply_text(&answers, "auth_url", &mut config);
        apply_text(&answers, "client_id", &mut config);
        apply_nullable_text(&answers, "redirect_uri", &mut config);
        if let Some(value) = bool_answer(&answers, "allow_auto_sign_in") {
            config.insert("allow_auto_sign_in".to_string(), JsonValue::Bool(value));
        }
        if let Some(scopes) = scopes_answer(&answers) {
            config.insert(
                "scopes".to_string(),
                JsonValue::Array(scopes.into_iter().map(JsonValue::String).collect()),
            );
        }
    }

    if !config.contains_key("provider_id") {
        warnings.push(field_error("provider_id"));
        config.insert(
            "provider_id".to_string(),
            JsonValue::String("oauth-provider".to_string()),
        );
    }

    json!({
        "ok": true,
        "config": JsonValue::Object(config),
        "warnings": warnings,
        "errors": [],
        "meta": {
            "mode": mode.as_str(),
            "version": "v1"
        },
        "audit": {
            "reasons": ["qa.apply_answers"],
            "timings_ms": {}
        }
    })
}

fn field_error(field: &str) -> JsonValue {
    json!({
        "key": "qa.error.required",
        "msg_key": "qa.error.required",
        "fields": [field]
    })
}

fn string_answer(answers: &JsonValue, key: &str) -> Option<String> {
    answers
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn bool_answer(answers: &JsonValue, key: &str) -> Option<bool> {
    match answers.get(key) {
        Some(JsonValue::Bool(value)) => Some(*value),
        Some(JsonValue::String(value)) => match value.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn scopes_answer(answers: &JsonValue) -> Option<Vec<String>> {
    let value = string_answer(answers, "scopes_csv")?;
    let scopes = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    Some(scopes)
}

fn apply_text(answers: &JsonValue, key: &str, config: &mut serde_json::Map<String, JsonValue>) {
    if let Some(value) = string_answer(answers, key) {
        config.insert(key.to_string(), JsonValue::String(value));
    }
}

fn apply_nullable_text(
    answers: &JsonValue,
    key: &str,
    config: &mut serde_json::Map<String, JsonValue>,
) {
    if let Some(raw) = answers.get(key) {
        match raw {
            JsonValue::Null => {
                config.insert(key.to_string(), JsonValue::Null);
            }
            JsonValue::String(value) if value.trim().is_empty() => {
                config.insert(key.to_string(), JsonValue::Null);
            }
            JsonValue::String(value) => {
                config.insert(key.to_string(), JsonValue::String(value.trim().to_string()));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mode_handles_aliases() {
        assert_eq!(normalize_mode("default"), Some(NormalizedMode::Setup));
        assert_eq!(normalize_mode("install"), Some(NormalizedMode::Setup));
        assert_eq!(normalize_mode("upgrade"), Some(NormalizedMode::Update));
        assert_eq!(normalize_mode("remove"), Some(NormalizedMode::Remove));
        assert_eq!(normalize_mode("weird"), None);
    }

    #[test]
    fn qa_spec_json_contains_expected_questions_for_each_mode() {
        let setup = qa_spec_json(NormalizedMode::Setup);
        assert_eq!(setup["mode"], "setup");
        assert_eq!(setup["questions"].as_array().expect("array").len(), 10);

        let update = qa_spec_json(NormalizedMode::Update);
        assert_eq!(update["mode"], "update");
        assert_eq!(update["questions"].as_array().expect("array").len(), 10);

        let remove = qa_spec_json(NormalizedMode::Remove);
        assert_eq!(remove["mode"], "remove");
        assert_eq!(remove["questions"].as_array().expect("array").len(), 1);
    }

    #[test]
    fn answer_helpers_normalize_values() {
        let answers = json!({
            "provider_id": "  github  ",
            "allow_auto_sign_in": "true",
            "scopes_csv": "openid, profile , ,email"
        });

        assert_eq!(
            string_answer(&answers, "provider_id").as_deref(),
            Some("github")
        );
        assert_eq!(bool_answer(&answers, "allow_auto_sign_in"), Some(true));
        assert_eq!(
            scopes_answer(&answers).expect("scopes"),
            vec!["openid", "profile", "email"]
        );
    }

    #[test]
    fn apply_answers_setup_builds_config_and_nulls_blank_redirect() {
        let value = apply_answers(
            NormalizedMode::Setup,
            &json!({
                "answers": {
                    "provider_id": "github",
                    "default_subject": "user-1",
                    "tenant": "tenant-a",
                    "team": "team-a",
                    "redirect_path": "  ",
                    "allow_auto_sign_in": true,
                    "scopes_csv": "repo,read:user"
                }
            }),
        );

        assert_eq!(value["ok"], true);
        assert_eq!(value["config"]["provider_id"], "github");
        assert_eq!(value["config"]["default_subject"], "user-1");
        assert_eq!(value["config"]["redirect_path"], JsonValue::Null);
        assert_eq!(value["config"]["allow_auto_sign_in"], true);
        assert_eq!(value["config"]["scopes"][1], "read:user");
    }

    #[test]
    fn apply_answers_setup_captures_connection_config() {
        let value = apply_answers(
            NormalizedMode::Setup,
            &json!({
                "answers": {
                    "provider_id": "github",
                    "auth_url": "https://github.com/login/oauth/authorize",
                    "client_id": "Ov23liExample",
                    "redirect_uri": "https://host.example/v1/oauth/ingress/oauth-oidc-executable/demo/default",
                    "scopes_csv": "repo,read:org"
                }
            }),
        );

        assert_eq!(value["ok"], true);
        assert_eq!(
            value["config"]["auth_url"],
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(value["config"]["client_id"], "Ov23liExample");
        assert_eq!(
            value["config"]["redirect_uri"],
            "https://host.example/v1/oauth/ingress/oauth-oidc-executable/demo/default"
        );
        // The card never collects or stores a client secret.
        assert!(value["config"].get("client_secret").is_none());
    }

    #[test]
    fn apply_answers_remove_requires_confirmation() {
        let rejected = apply_answers(
            NormalizedMode::Remove,
            &json!({
                "answers": {
                    "confirm_remove": false
                }
            }),
        );
        assert_eq!(rejected["ok"], false);

        let accepted = apply_answers(
            NormalizedMode::Remove,
            &json!({
                "answers": {
                    "confirm_remove": "true"
                }
            }),
        );
        assert_eq!(accepted["ok"], true);
    }

    #[test]
    fn apply_answers_update_keeps_existing_config_when_answers_missing() {
        let value = apply_answers(
            NormalizedMode::Update,
            &json!({
                "answers": {},
                "current_config": {
                    "provider_id": "msgraph",
                    "allow_auto_sign_in": false
                }
            }),
        );

        assert_eq!(value["ok"], true);
        assert_eq!(value["config"]["provider_id"], "msgraph");
        assert_eq!(value["config"]["allow_auto_sign_in"], false);
    }
}
