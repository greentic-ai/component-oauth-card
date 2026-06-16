#![warn(clippy::unwrap_used, clippy::expect_used)]

pub mod i18n;
pub mod i18n_bundle;
pub mod qa;
mod schema;

// Card decision + Adaptive Card rendering live in the export-free `oauth-card-core`
// crate so consumers (e.g. the MCP adapter) can reuse them without linking this
// component's WASM exports.
pub use oauth_card_core::{
    Action, AuthContext, AuthHeader, OAuthBackend, OAuthCardError, OAuthCardInput, OAuthCardMode,
    OAuthCardOutput, OAuthStatus, TokenSet, handle,
};
pub use schema::oauth_config_schema_json;

use greentic_types::i18n_text::I18nText;
use greentic_types::schemas::common::schema_ir::{AdditionalProperties, SchemaIr};
use greentic_types::schemas::component::v0_6_0::{
    ComponentDescribe, ComponentInfo, ComponentOperation, ComponentRunInput, ComponentRunOutput,
    schema_hash,
};
use serde_json::{Value, json};

#[cfg(target_arch = "wasm32")]
use greentic_interfaces_guest::component_v0_6::node;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const COMPONENT_NAME: &str = "component-oauth-card";
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const COMPONENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_OPERATION: &str = "oauth_card.handle_message";
const COMPONENT_INFO_OPERATION: &str = "component-info";

#[cfg(target_arch = "wasm32")]
#[used]
#[unsafe(link_section = ".greentic.wasi")]
static WASI_TARGET_MARKER: [u8; 13] = *b"wasm32-wasip2";

#[cfg(target_arch = "wasm32")]
use greentic_types::cbor::canonical;

// Bindings for the greentic:component@0.6.0 interface family (descriptor /
// schema / runtime / qa / i18n) that greentic-start 0.5.x binds. See
// /Users/osoro/Documents/greetic/TODO/component-v0.6.0-family-export.md.
#[cfg(target_arch = "wasm32")]
mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "component-v0-v6-v0",
    });
}

#[cfg(target_arch = "wasm32")]
use bindings::exports::greentic::component::{
    component_descriptor, component_i18n,
    component_qa::{self, QaMode},
    component_runtime, component_schema,
};

/// Implements the `greentic:component@0.6.0` family; all methods delegate to the
/// same `invoke_json` / schema / qa helpers used by the host (`invoke_json`) path.
#[cfg(target_arch = "wasm32")]
struct Component;

/// Legacy `greentic:component/node@0.6.0` export, kept so older runtimes that
/// resolve components by the `node` interface continue to work.
#[cfg(target_arch = "wasm32")]
struct NodeCompat;

#[cfg(target_arch = "wasm32")]
impl node::Guest for NodeCompat {
    fn describe() -> node::ComponentDescriptor {
        node::ComponentDescriptor {
            name: COMPONENT_NAME.to_string(),
            version: COMPONENT_VERSION.to_string(),
            summary: Some(i18n::t("en", "component.summary")),
            capabilities: Vec::new(),
            ops: vec![
                node_op(
                    DEFAULT_OPERATION,
                    "component.operation.oauth_card.handle_message.summary",
                    oauth_input_schema_ir(),
                    oauth_output_schema_ir(),
                ),
                node_op(
                    COMPONENT_INFO_OPERATION,
                    "component.operation.component_info.summary",
                    component_info_input_schema_ir(),
                    component_info_output_schema_ir(),
                ),
                node_op(
                    "qa-spec",
                    "component.operation.qa_spec.summary",
                    qa_spec_input_schema_ir(),
                    qa_spec_output_schema_ir(),
                ),
                node_op(
                    "apply-answers",
                    "component.operation.apply_answers.summary",
                    apply_answers_input_schema_ir(),
                    apply_answers_output_schema_ir(),
                ),
                node_op(
                    "i18n-keys",
                    "component.operation.i18n_keys.summary",
                    i18n_keys_input_schema_ir(),
                    i18n_keys_output_schema_ir(),
                ),
            ],
            schemas: Vec::new(),
            setup: None,
        }
    }

    fn invoke(
        operation: String,
        envelope: node::InvocationEnvelope,
    ) -> Result<node::InvocationResult, node::NodeError> {
        Ok(node::InvocationResult {
            ok: true,
            output_cbor: run_component_cbor(&operation, envelope.payload_cbor),
            output_metadata_cbor: None,
        })
    }
}

#[cfg(target_arch = "wasm32")]
fn qa_mode_to_model(mode: QaMode) -> qa::NormalizedMode {
    match mode {
        QaMode::Default | QaMode::Setup => qa::NormalizedMode::Setup,
        QaMode::Update => qa::NormalizedMode::Update,
        QaMode::Remove => qa::NormalizedMode::Remove,
    }
}

#[cfg(target_arch = "wasm32")]
impl component_descriptor::Guest for Component {
    fn get_component_info() -> Vec<u8> {
        encode_cbor(&component_info_json(&json!({ "locale": "en" })))
    }
    fn describe() -> Vec<u8> {
        encode_cbor(&component_describe_struct())
    }
}

#[cfg(target_arch = "wasm32")]
impl component_schema::Guest for Component {
    fn input_schema() -> Vec<u8> {
        encode_cbor(&oauth_input_schema_ir())
    }
    fn output_schema() -> Vec<u8> {
        encode_cbor(&oauth_output_schema_ir())
    }
    fn config_schema() -> Vec<u8> {
        encode_cbor(&oauth_config_schema_ir())
    }
}

#[cfg(target_arch = "wasm32")]
impl component_runtime::Guest for Component {
    fn run(input: Vec<u8>, state: Vec<u8>) -> component_runtime::RunResult {
        // oauth-card is stateless: run the default op and pass state through.
        component_runtime::RunResult {
            output: run_component_cbor(DEFAULT_OPERATION, input),
            new_state: state,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl component_qa::Guest for Component {
    fn qa_spec(mode: QaMode) -> Vec<u8> {
        encode_cbor(&qa::qa_spec_json(qa_mode_to_model(mode)))
    }
    fn apply_answers(mode: QaMode, current_config: Vec<u8>, answers: Vec<u8>) -> Vec<u8> {
        let payload = json!({
            "answers": decode_payload(&answers),
            "current_config": decode_payload(&current_config),
        });
        encode_cbor(&qa::apply_answers(qa_mode_to_model(mode), &payload))
    }
}

#[cfg(target_arch = "wasm32")]
impl component_i18n::Guest for Component {
    fn i18n_keys() -> Vec<String> {
        qa::i18n_keys()
    }
}

#[cfg(target_arch = "wasm32")]
bindings::export!(Component with_types_in bindings);

#[cfg(target_arch = "wasm32")]
greentic_interfaces_guest::export_component_v060!(NodeCompat);

pub fn invoke_json(operation: &str, payload: &Value) -> Result<Value, OAuthCardError> {
    match operation {
        DEFAULT_OPERATION | "handle_message" => oauth_card_core::handle_message_json(payload),
        COMPONENT_INFO_OPERATION => Ok(component_info_json(payload)),
        "qa-spec" => Ok(qa::qa_spec_json(normalized_mode(payload))),
        "apply-answers" => Ok(qa::apply_answers(normalized_mode(payload), payload)),
        "i18n-keys" => Ok(Value::Array(
            qa::i18n_keys().into_iter().map(Value::String).collect(),
        )),
        _ => Err(OAuthCardError::Unsupported(format!(
            "unsupported operation: {operation}"
        ))),
    }
}

fn normalized_mode(payload: &Value) -> qa::NormalizedMode {
    payload
        .get("mode")
        .and_then(Value::as_str)
        .or_else(|| payload.get("operation").and_then(Value::as_str))
        .and_then(qa::normalize_mode)
        .unwrap_or(qa::NormalizedMode::Setup)
}

fn component_info_json(payload: &Value) -> Value {
    let locale = payload
        .get("locale")
        .and_then(Value::as_str)
        .unwrap_or("en");

    json!({
        "id": "ai.greentic.component-oauth-card",
        "name": COMPONENT_NAME,
        "version": COMPONENT_VERSION,
        "display_name": {
            "key": "component.display_name",
            "fallback": i18n::t(locale, "component.display_name")
        },
        "summary": {
            "key": "component.summary",
            "fallback": i18n::t(locale, "component.summary")
        },
        "details": {
            "key": "component.details",
            "fallback": i18n::t(locale, "component.details")
        },
        "use_cases": [
            {
                "key": "component.use_case.status_card",
                "fallback": i18n::t(locale, "component.use_case.status_card")
            },
            {
                "key": "component.use_case.ensure_token",
                "fallback": i18n::t(locale, "component.use_case.ensure_token")
            },
            {
                "key": "component.use_case.complete_sign_in",
                "fallback": i18n::t(locale, "component.use_case.complete_sign_in")
            }
        ],
        "operations": [
            {
                "name": DEFAULT_OPERATION,
                "summary": {
                    "key": "component.operation.oauth_card.handle_message.summary",
                    "fallback": i18n::t(locale, "component.operation.oauth_card.handle_message.summary")
                }
            },
            {
                "name": COMPONENT_INFO_OPERATION,
                "summary": {
                    "key": "component.operation.component_info.summary",
                    "fallback": i18n::t(locale, "component.operation.component_info.summary")
                }
            },
            {
                "name": "qa-spec",
                "summary": {
                    "key": "component.operation.qa_spec.summary",
                    "fallback": i18n::t(locale, "component.operation.qa_spec.summary")
                }
            },
            {
                "name": "apply-answers",
                "summary": {
                    "key": "component.operation.apply_answers.summary",
                    "fallback": i18n::t(locale, "component.operation.apply_answers.summary")
                }
            },
            {
                "name": "i18n-keys",
                "summary": {
                    "key": "component.operation.i18n_keys.summary",
                    "fallback": i18n::t(locale, "component.operation.i18n_keys.summary")
                }
            }
        ]
    })
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn component_info_struct() -> ComponentInfo {
    ComponentInfo {
        id: "ai.greentic.component-oauth-card".to_string(),
        version: COMPONENT_VERSION.to_string(),
        role: "runtime".to_string(),
        display_name: Some(I18nText::new(
            "component.display_name",
            Some(i18n::t("en", "component.display_name")),
        )),
    }
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn component_describe_struct() -> ComponentDescribe {
    let config_schema = oauth_config_schema_ir();
    let operations = [
        (
            DEFAULT_OPERATION,
            oauth_input_schema_ir(),
            oauth_output_schema_ir(),
        ),
        (
            COMPONENT_INFO_OPERATION,
            component_info_input_schema_ir(),
            component_info_output_schema_ir(),
        ),
        (
            "qa-spec",
            qa_spec_input_schema_ir(),
            qa_spec_output_schema_ir(),
        ),
        (
            "apply-answers",
            apply_answers_input_schema_ir(),
            apply_answers_output_schema_ir(),
        ),
        (
            "i18n-keys",
            i18n_keys_input_schema_ir(),
            i18n_keys_output_schema_ir(),
        ),
    ]
    .into_iter()
    .map(|(id, input, output)| ComponentOperation {
        id: id.to_string(),
        display_name: None,
        input: ComponentRunInput {
            schema: input.clone(),
        },
        output: ComponentRunOutput {
            schema: output.clone(),
        },
        defaults: std::collections::BTreeMap::new(),
        redactions: Vec::new(),
        constraints: std::collections::BTreeMap::new(),
        schema_hash: compute_schema_hash(&input, &output, &config_schema),
    })
    .collect();

    ComponentDescribe {
        info: component_info_struct(),
        provided_capabilities: vec!["messaging".to_string()],
        required_capabilities: vec!["oauth-operation-results".to_string()],
        metadata: std::collections::BTreeMap::new(),
        operations,
        config_schema,
    }
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn oauth_input_schema_ir() -> SchemaIr {
    object_schema(
        vec![
            (
                "mode",
                enum_string_schema(&[
                    "status-card",
                    "start-sign-in",
                    "complete-sign-in",
                    "ensure-token",
                    "disconnect",
                ]),
            ),
            ("provider_id", bounded_string_schema(1, 128)),
            ("subject", bounded_string_schema(1, 256)),
            ("tenant", nullable_string_schema()),
            ("team", nullable_string_schema()),
            ("scopes", string_array_schema()),
            ("state_id", nullable_string_schema()),
            ("auth_code", nullable_string_schema()),
            ("allow_auto_sign_in", SchemaIr::Bool),
            ("redirect_path", nullable_string_schema()),
            ("auth_url", nullable_string_schema()),
            ("client_id", nullable_string_schema()),
            ("redirect_uri", nullable_string_schema()),
            ("extra_json", optional_json_object_schema()),
            ("current_token", nullable_token_schema()),
            ("consent_url", nullable_string_schema()),
            ("exchanged_token", nullable_token_schema()),
            ("oauth_error", nullable_string_schema()),
            ("now_unix", nullable_u64_schema()),
            ("refresh_skew_seconds", nullable_u64_schema()),
            ("connection_name", nullable_string_schema()),
        ],
        &["mode", "provider_id", "subject"],
        AdditionalProperties::Forbid,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn oauth_output_schema_ir() -> SchemaIr {
    object_schema(
        vec![
            (
                "status",
                enum_string_schema(&["ok", "needs-sign-in", "needs-refresh", "error"]),
            ),
            ("card", nullable_message_card_schema()),
            ("renderedCard", nullable_open_object_schema()),
            ("can_continue", SchemaIr::Bool),
            ("auth_context", nullable_auth_context_schema()),
            ("auth_header", nullable_auth_header_schema()),
            ("access_token", nullable_string_schema()),
            ("state_id", nullable_string_schema()),
            ("error", nullable_string_schema()),
        ],
        &["status", "can_continue"],
        AdditionalProperties::Forbid,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn oauth_config_schema_ir() -> SchemaIr {
    object_schema(
        vec![
            ("provider_id", bounded_string_schema(1, 128)),
            ("default_subject", nullable_string_schema()),
            ("scopes", string_array_schema()),
            ("tenant", nullable_string_schema()),
            ("team", nullable_string_schema()),
            ("redirect_path", nullable_string_schema()),
            ("auth_url", nullable_string_schema()),
            ("client_id", nullable_string_schema()),
            ("redirect_uri", nullable_string_schema()),
            ("allow_auto_sign_in", SchemaIr::Bool),
        ],
        &[],
        AdditionalProperties::Forbid,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn qa_spec_input_schema_ir() -> SchemaIr {
    object_schema(
        vec![(
            "mode",
            enum_string_schema(&["default", "setup", "install", "update", "upgrade", "remove"]),
        )],
        &["mode"],
        AdditionalProperties::Forbid,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn qa_spec_output_schema_ir() -> SchemaIr {
    object_schema(
        vec![
            ("mode", enum_string_schema(&["setup", "update", "remove"])),
            ("title", i18n_text_schema()),
            ("description", nullable_i18n_text_schema()),
            ("questions", questions_array_schema()),
            ("defaults", qa_defaults_schema()),
        ],
        &["mode", "questions", "defaults"],
        AdditionalProperties::Allow,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn component_info_input_schema_ir() -> SchemaIr {
    object_schema(
        vec![("locale", bounded_string_schema(2, 16))],
        &[],
        AdditionalProperties::Forbid,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn component_info_output_schema_ir() -> SchemaIr {
    object_schema(
        vec![
            ("id", bounded_string_schema(1, 128)),
            ("name", bounded_string_schema(1, 128)),
            ("version", bounded_string_schema(1, 32)),
            ("display_name", i18n_text_schema()),
            ("summary", i18n_text_schema()),
            ("details", i18n_text_schema()),
            ("use_cases", i18n_text_array_schema()),
            ("operations", component_info_operations_schema()),
        ],
        &[
            "id",
            "name",
            "version",
            "display_name",
            "summary",
            "details",
            "use_cases",
            "operations",
        ],
        AdditionalProperties::Forbid,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn apply_answers_input_schema_ir() -> SchemaIr {
    object_schema(
        vec![
            (
                "mode",
                enum_string_schema(&["default", "setup", "install", "update", "upgrade", "remove"]),
            ),
            ("answers", optional_json_object_schema()),
            ("current_config", oauth_config_schema_ir()),
        ],
        &["answers"],
        AdditionalProperties::Allow,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn apply_answers_output_schema_ir() -> SchemaIr {
    object_schema(
        vec![
            ("ok", SchemaIr::Bool),
            ("warnings", diagnostic_array_schema()),
            ("errors", diagnostic_array_schema()),
            ("config", oauth_config_schema_ir()),
            ("meta", meta_schema()),
            ("audit", audit_schema()),
        ],
        &["ok", "warnings", "errors"],
        AdditionalProperties::Allow,
    )
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn i18n_keys_input_schema_ir() -> SchemaIr {
    object_schema(vec![], &[], AdditionalProperties::Forbid)
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn i18n_keys_output_schema_ir() -> SchemaIr {
    string_array_schema()
}

fn object_schema(
    properties: Vec<(&str, SchemaIr)>,
    required: &[&str],
    additional: AdditionalProperties,
) -> SchemaIr {
    let properties = properties
        .into_iter()
        .map(|(name, schema)| (name.to_string(), schema))
        .collect();
    let required = required.iter().map(|name| (*name).to_string()).collect();
    SchemaIr::Object {
        properties,
        required,
        additional,
    }
}

fn string_schema() -> SchemaIr {
    bounded_string_schema(0, 4096)
}

fn bounded_string_schema(min: u64, max: u64) -> SchemaIr {
    SchemaIr::String {
        min_len: Some(min),
        max_len: Some(max),
        regex: None,
        format: None,
    }
}

fn nullable_string_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![string_schema(), SchemaIr::Null],
    }
}

fn nullable_u64_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![
            SchemaIr::Int {
                min: Some(0),
                max: Some(9_007_199_254_740_991),
            },
            SchemaIr::Null,
        ],
    }
}

fn string_array_schema() -> SchemaIr {
    SchemaIr::Array {
        items: Box::new(bounded_string_schema(1, 256)),
        min_items: Some(0),
        max_items: Some(64),
    }
}

fn enum_string_schema(values: &[&str]) -> SchemaIr {
    SchemaIr::Enum {
        values: values
            .iter()
            .map(|value| ciborium::value::Value::Text((*value).to_string()))
            .collect(),
    }
}

fn compute_schema_hash(input: &SchemaIr, output: &SchemaIr, config: &SchemaIr) -> String {
    schema_hash(input, output, config).unwrap_or_default()
}

fn i18n_text_schema() -> SchemaIr {
    object_schema(
        vec![
            ("key", bounded_string_schema(1, 256)),
            ("fallback", nullable_string_schema()),
        ],
        &["key"],
        AdditionalProperties::Forbid,
    )
}

fn nullable_i18n_text_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![i18n_text_schema(), SchemaIr::Null],
    }
}

fn i18n_text_array_schema() -> SchemaIr {
    SchemaIr::Array {
        items: Box::new(i18n_text_schema()),
        min_items: Some(0),
        max_items: Some(32),
    }
}

fn component_info_operations_schema() -> SchemaIr {
    SchemaIr::Array {
        items: Box::new(object_schema(
            vec![
                ("name", bounded_string_schema(1, 128)),
                ("summary", i18n_text_schema()),
            ],
            &["name", "summary"],
            AdditionalProperties::Forbid,
        )),
        min_items: Some(1),
        max_items: Some(16),
    }
}

fn optional_json_object_schema() -> SchemaIr {
    object_schema(
        vec![
            ("note", nullable_string_schema()),
            ("prompt", nullable_string_schema()),
            ("resource", nullable_string_schema()),
        ],
        &[],
        AdditionalProperties::Schema(Box::new(bounded_string_schema(0, 4096))),
    )
}

fn token_schema() -> SchemaIr {
    object_schema(
        vec![
            ("access_token", bounded_string_schema(1, 8192)),
            ("refresh_token", nullable_string_schema()),
            (
                "expires_at",
                SchemaIr::OneOf {
                    variants: vec![
                        SchemaIr::Int {
                            min: Some(0),
                            max: Some(9_007_199_254_740_991),
                        },
                        SchemaIr::Null,
                    ],
                },
            ),
            ("token_type", nullable_string_schema()),
            (
                "extra",
                SchemaIr::OneOf {
                    variants: vec![optional_json_object_schema(), SchemaIr::Null],
                },
            ),
        ],
        &["access_token"],
        AdditionalProperties::Forbid,
    )
}

fn nullable_token_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![token_schema(), SchemaIr::Null],
    }
}

fn auth_context_schema() -> SchemaIr {
    object_schema(
        vec![
            ("provider_id", bounded_string_schema(1, 128)),
            ("subject", bounded_string_schema(1, 256)),
            ("email", nullable_string_schema()),
            ("tenant", nullable_string_schema()),
            ("team", nullable_string_schema()),
            ("scopes", string_array_schema()),
            (
                "expires_at",
                SchemaIr::OneOf {
                    variants: vec![
                        SchemaIr::Int {
                            min: Some(0),
                            max: Some(9_007_199_254_740_991),
                        },
                        SchemaIr::Null,
                    ],
                },
            ),
        ],
        &["provider_id", "subject", "scopes"],
        AdditionalProperties::Forbid,
    )
}

fn nullable_auth_context_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![auth_context_schema(), SchemaIr::Null],
    }
}

fn auth_header_schema() -> SchemaIr {
    object_schema(
        vec![(
            "headers",
            SchemaIr::Array {
                items: Box::new(SchemaIr::Array {
                    items: Box::new(bounded_string_schema(1, 8192)),
                    min_items: Some(2),
                    max_items: Some(2),
                }),
                min_items: Some(1),
                max_items: Some(16),
            },
        )],
        &["headers"],
        AdditionalProperties::Forbid,
    )
}

fn nullable_auth_header_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![auth_header_schema(), SchemaIr::Null],
    }
}

fn message_card_schema() -> SchemaIr {
    object_schema(
        vec![
            ("kind", enum_string_schema(&["standard", "oauth"])),
            ("title", nullable_string_schema()),
            ("text", nullable_string_schema()),
            ("footer", nullable_string_schema()),
            (
                "images",
                SchemaIr::Array {
                    items: Box::new(object_schema(
                        vec![
                            ("url", bounded_string_schema(1, 4096)),
                            ("alt", nullable_string_schema()),
                        ],
                        &["url"],
                        AdditionalProperties::Forbid,
                    )),
                    min_items: Some(0),
                    max_items: Some(8),
                },
            ),
            (
                "actions",
                SchemaIr::Array {
                    items: Box::new(object_schema(
                        vec![
                            ("type", enum_string_schema(&["open_url", "post_back"])),
                            ("title", bounded_string_schema(1, 128)),
                            ("url", nullable_string_schema()),
                            (
                                "data",
                                SchemaIr::OneOf {
                                    variants: vec![optional_json_object_schema(), SchemaIr::Null],
                                },
                            ),
                        ],
                        &["type", "title"],
                        AdditionalProperties::Forbid,
                    )),
                    min_items: Some(0),
                    max_items: Some(8),
                },
            ),
            ("allow_markdown", SchemaIr::Bool),
            (
                "adaptive",
                SchemaIr::OneOf {
                    variants: vec![optional_json_object_schema(), SchemaIr::Null],
                },
            ),
            (
                "oauth",
                SchemaIr::OneOf {
                    variants: vec![oauth_card_schema(), SchemaIr::Null],
                },
            ),
        ],
        &["kind", "images", "actions", "allow_markdown"],
        AdditionalProperties::Forbid,
    )
}

fn nullable_message_card_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![message_card_schema(), SchemaIr::Null],
    }
}

/// Schema for the optional `renderedCard` field: an Adaptive Card document
/// (free-form object) or null. Adaptive Card payloads are open-ended, so we
/// allow additional properties rather than enumerate the full schema here.
fn nullable_open_object_schema() -> SchemaIr {
    SchemaIr::OneOf {
        variants: vec![
            object_schema(vec![], &[], AdditionalProperties::Allow),
            SchemaIr::Null,
        ],
    }
}

fn oauth_card_schema() -> SchemaIr {
    object_schema(
        vec![
            (
                "provider",
                enum_string_schema(&["microsoft", "google", "github", "custom"]),
            ),
            ("scopes", string_array_schema()),
            ("resource", nullable_string_schema()),
            (
                "prompt",
                SchemaIr::OneOf {
                    variants: vec![
                        enum_string_schema(&["none", "consent", "login"]),
                        SchemaIr::Null,
                    ],
                },
            ),
            ("start_url", nullable_string_schema()),
            ("connection_name", nullable_string_schema()),
            (
                "token_exchange_resource",
                SchemaIr::OneOf {
                    variants: vec![token_exchange_resource_schema(), SchemaIr::Null],
                },
            ),
            (
                "metadata",
                SchemaIr::OneOf {
                    variants: vec![optional_json_object_schema(), SchemaIr::Null],
                },
            ),
        ],
        &["provider", "scopes"],
        AdditionalProperties::Forbid,
    )
}

fn token_exchange_resource_schema() -> SchemaIr {
    object_schema(
        vec![
            ("id", nullable_string_schema()),
            ("uri", nullable_string_schema()),
            ("provider_id", nullable_string_schema()),
        ],
        &[],
        AdditionalProperties::Forbid,
    )
}

fn questions_array_schema() -> SchemaIr {
    SchemaIr::Array {
        items: Box::new(object_schema(
            vec![
                ("id", bounded_string_schema(1, 128)),
                ("label", i18n_text_schema()),
                ("help", nullable_i18n_text_schema()),
                ("error", nullable_i18n_text_schema()),
                ("kind", enum_string_schema(&["text", "bool", "select"])),
                ("required", SchemaIr::Bool),
            ],
            &["id", "label", "kind", "required"],
            AdditionalProperties::Forbid,
        )),
        min_items: Some(1),
        max_items: Some(16),
    }
}

fn qa_defaults_schema() -> SchemaIr {
    object_schema(
        vec![
            ("allow_auto_sign_in", SchemaIr::Bool),
            ("confirm_remove", SchemaIr::Bool),
        ],
        &[],
        AdditionalProperties::Forbid,
    )
}

fn diagnostic_array_schema() -> SchemaIr {
    SchemaIr::Array {
        items: Box::new(object_schema(
            vec![
                ("key", bounded_string_schema(1, 128)),
                ("msg_key", bounded_string_schema(1, 128)),
                ("fields", string_array_schema()),
            ],
            &["key", "msg_key", "fields"],
            AdditionalProperties::Forbid,
        )),
        min_items: Some(0),
        max_items: Some(32),
    }
}

fn meta_schema() -> SchemaIr {
    object_schema(
        vec![
            ("mode", bounded_string_schema(1, 32)),
            ("version", bounded_string_schema(1, 16)),
        ],
        &["mode", "version"],
        AdditionalProperties::Forbid,
    )
}

fn audit_schema() -> SchemaIr {
    object_schema(
        vec![
            ("reasons", string_array_schema()),
            (
                "timings_ms",
                object_schema(vec![], &[], AdditionalProperties::Forbid),
            ),
        ],
        &["reasons", "timings_ms"],
        AdditionalProperties::Forbid,
    )
}

pub fn oauth_input_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card oauth_card.handle_message input",
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["status-card", "start-sign-in", "complete-sign-in", "ensure-token", "disconnect"],
                "default": "status-card"
            },
            "provider_id": { "type": "string" },
            "subject": { "type": "string" },
            "tenant": { "type": ["string", "null"] },
            "team": { "type": ["string", "null"] },
            "scopes": {
                "type": "array",
                "items": { "type": "string" },
                "default": []
            },
            "state_id": { "type": ["string", "null"] },
            "auth_code": { "type": ["string", "null"] },
            "allow_auto_sign_in": {
                "type": "boolean",
                "default": false
            },
            "redirect_path": { "type": ["string", "null"] },
            "auth_url": { "type": ["string", "null"] },
            "client_id": { "type": ["string", "null"] },
            "redirect_uri": { "type": ["string", "null"] },
            "extra_json": {},
            "current_token": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "consent_url": {
                "type": ["string", "null"]
            },
            "exchanged_token": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "oauth_error": {
                "type": ["string", "null"]
            },
            "now_unix": {
                "type": ["integer", "null"],
                "minimum": 0
            },
            "refresh_skew_seconds": {
                "type": ["integer", "null"],
                "minimum": 0
            },
            "connection_name": {
                "type": ["string", "null"]
            }
        },
        "required": ["mode", "provider_id", "subject"],
        "additionalProperties": false
    })
}

pub fn oauth_output_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card oauth_card.handle_message output",
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["ok", "needs-sign-in", "needs-refresh", "error"]
            },
            "card": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "renderedCard": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "can_continue": {
                "type": "boolean"
            },
            "auth_context": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "auth_header": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "access_token": { "type": ["string", "null"] },
            "state_id": { "type": ["string", "null"] },
            "error": { "type": ["string", "null"] }
        },
        "required": ["status", "can_continue"],
        "additionalProperties": false
    })
}

pub fn qa_spec_input_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card qa-spec input",
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["default", "setup", "install", "update", "upgrade", "remove"]
            }
        },
        "required": ["mode"],
        "additionalProperties": false
    })
}

pub fn component_info_input_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card component-info input",
        "type": "object",
        "properties": {
            "locale": {
                "type": "string",
                "default": "en"
            }
        },
        "additionalProperties": false
    })
}

pub fn component_info_output_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card component-info output",
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "name": { "type": "string" },
            "version": { "type": "string" },
            "display_name": { "type": "object", "additionalProperties": true },
            "summary": { "type": "object", "additionalProperties": true },
            "details": { "type": "object", "additionalProperties": true },
            "use_cases": { "type": "array", "items": { "type": "object", "additionalProperties": true } },
            "operations": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
        },
        "required": ["id", "name", "version", "display_name", "summary", "details", "use_cases", "operations"],
        "additionalProperties": false
    })
}

pub fn qa_spec_output_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card qa-spec output",
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["setup", "update", "remove"]
            },
            "title": {
                "type": "object",
                "additionalProperties": true
            },
            "description": {
                "type": ["object", "null"],
                "additionalProperties": true
            },
            "questions": {
                "type": "array",
                "items": { "type": "object", "additionalProperties": true }
            },
            "defaults": {
                "type": "object",
                "additionalProperties": true
            }
        },
        "required": ["mode", "questions", "defaults"],
        "additionalProperties": true
    })
}

pub fn apply_answers_input_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card apply-answers input",
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["default", "setup", "install", "update", "upgrade", "remove"]
            },
            "answers": {
                "type": "object",
                "additionalProperties": true
            },
            "current_config": oauth_config_schema_json()
        },
        "required": ["answers"],
        "additionalProperties": true
    })
}

pub fn apply_answers_output_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card apply-answers output",
        "type": "object",
        "properties": {
            "ok": { "type": "boolean" },
            "warnings": {
                "type": "array",
                "items": {}
            },
            "errors": {
                "type": "array",
                "items": {}
            },
            "config": oauth_config_schema_json(),
            "meta": {
                "type": "object",
                "additionalProperties": true
            },
            "audit": {
                "type": "object",
                "additionalProperties": true
            }
        },
        "required": ["ok", "warnings", "errors"],
        "additionalProperties": true
    })
}

pub fn i18n_keys_input_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card i18n-keys input",
        "type": "object",
        "additionalProperties": false
    })
}

pub fn i18n_keys_output_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "component-oauth-card i18n-keys output",
        "type": "array",
        "items": { "type": "string" }
    })
}

#[cfg(target_arch = "wasm32")]
fn encode_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    canonical::to_canonical_cbor_allow_floats(value).expect("encode cbor")
}

#[cfg(target_arch = "wasm32")]
fn decode_payload(bytes: &[u8]) -> Value {
    canonical::from_cbor::<Value>(bytes)
        .or_else(|_| serde_json::from_slice(bytes))
        .unwrap_or_else(|_| json!({}))
}

#[cfg(target_arch = "wasm32")]
fn node_op(name: &str, summary_key: &str, input: SchemaIr, output: SchemaIr) -> node::Op {
    node::Op {
        name: name.to_string(),
        summary: Some(i18n::t("en", summary_key)),
        input: node::IoSchema {
            schema: node::SchemaSource::InlineCbor(encode_cbor(&input)),
            content_type: "application/cbor".to_string(),
            schema_version: None,
        },
        output: node::IoSchema {
            schema: node::SchemaSource::InlineCbor(encode_cbor(&output)),
            content_type: "application/cbor".to_string(),
            schema_version: None,
        },
        examples: Vec::new(),
    }
}

#[cfg(target_arch = "wasm32")]
fn run_component_cbor(operation: &str, input: Vec<u8>) -> Vec<u8> {
    let payload = decode_payload(&input);
    let output = invoke_json(operation, &payload)
        .unwrap_or_else(|err| json!(oauth_card_core::error_output(err)));
    encode_cbor(&output)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn component_version_tracks_cargo_package_version() {
        assert_eq!(COMPONENT_VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn handle_returns_needs_sign_in_when_no_token() {
        let payload = json!({
            "mode": "status-card",
            "provider_id": "demo",
            "subject": "user-1",
            "scopes": ["openid"]
        });
        let response = invoke_json(DEFAULT_OPERATION, &payload).expect("invoke should succeed");
        assert_eq!(response["status"], "needs-sign-in");
        assert_eq!(response["can_continue"], false);
    }

    #[test]
    fn qa_spec_accepts_default_alias() {
        let response =
            invoke_json("qa-spec", &json!({ "mode": "default" })).expect("qa-spec should succeed");
        assert_eq!(response["mode"], "setup");
        assert!(response["questions"].is_array());
    }

    #[test]
    fn i18n_keys_include_setup_title() {
        let response = invoke_json("i18n-keys", &json!({})).expect("i18n-keys should succeed");
        let keys = response.as_array().expect("array");
        assert!(keys.iter().any(|key| key == "qa.setup.title"));
        assert!(keys.iter().any(|key| key == "component.summary"));
    }

    #[test]
    fn apply_answers_builds_config() {
        let response = invoke_json(
            "apply-answers",
            &json!({
                "mode": "setup",
                "answers": {
                    "provider_id": "msgraph",
                    "default_subject": "user-1",
                    "scopes_csv": "openid,offline_access",
                    "allow_auto_sign_in": true
                }
            }),
        )
        .expect("apply-answers should succeed");

        assert_eq!(response["ok"], true);
        assert_eq!(response["config"]["provider_id"], "msgraph");
        assert_eq!(response["config"]["allow_auto_sign_in"], true);
        assert_eq!(response["config"]["scopes"][0], "openid");
    }

    #[test]
    fn invoke_json_reports_unsupported_operation() {
        let err = invoke_json("unknown.operation", &json!({})).expect_err("should fail");
        assert!(matches!(err, OAuthCardError::Unsupported(_)));
        assert!(err.to_string().contains("unsupported operation"));
    }

    #[test]
    fn invoke_json_merges_config_defaults_into_handle_input() {
        let response = invoke_json(
            DEFAULT_OPERATION,
            &json!({
                "config": {
                    "provider_id": "github",
                    "default_subject": "user-from-config",
                    "scopes": ["repo"],
                    "tenant": "tenant-a",
                    "team": "team-a",
                    "allow_auto_sign_in": true
                }
            }),
        )
        .expect("invoke should succeed");

        assert_eq!(response["status"], "needs-sign-in");
        assert_eq!(response["can_continue"], false);
        assert_eq!(response["card"]["oauth"]["provider"], "github");
        assert_eq!(response["card"]["oauth"]["scopes"][0], "repo");
    }

    #[test]
    fn invoke_json_preserves_explicit_input_over_config_defaults() {
        let response = invoke_json(
            DEFAULT_OPERATION,
            &json!({
                "mode": "status-card",
                "provider_id": "google",
                "subject": "explicit-user",
                "scopes": ["openid"],
                "config": {
                    "provider_id": "github",
                    "default_subject": "config-user",
                    "scopes": ["repo"]
                }
            }),
        )
        .expect("invoke should succeed");

        assert_eq!(response["card"]["oauth"]["provider"], "google");
        assert_eq!(response["can_continue"], false);
        assert_eq!(response["card"]["oauth"]["scopes"][0], "openid");
        assert!(
            response["card"]["text"]
                .as_str()
                .expect("card text")
                .contains("flow cannot continue")
        );
    }

    #[test]
    fn handle_emits_rendered_adaptive_card_for_sign_in() {
        let response = invoke_json(
            DEFAULT_OPERATION,
            &json!({
                "mode": "status-card",
                "provider_id": "github",
                "subject": "user-1",
                "scopes": ["repo"]
            }),
        )
        .expect("invoke should succeed");

        // needs-sign-in produces a card, so an Adaptive Card must be rendered
        // for channels (e.g. webchat) that only understand Adaptive Cards.
        assert_eq!(response["status"], "needs-sign-in");
        assert_eq!(response["renderedCard"]["type"], "AdaptiveCard");
        assert_eq!(response["renderedCard"]["version"], "1.5");
        assert!(response["renderedCard"]["body"].is_array());
    }

    #[test]
    fn handle_omits_rendered_card_when_no_card_present() {
        // ensure-token with a usable token returns `card: None` (just passes the
        // token through) -> no renderedCard should be emitted.
        let response = invoke_json(
            DEFAULT_OPERATION,
            &json!({
                "mode": "ensure-token",
                "provider_id": "github",
                "subject": "user-1",
                "current_token": { "access_token": "abc" }
            }),
        )
        .expect("invoke should succeed");

        assert_eq!(response["status"], "ok");
        assert!(response.get("renderedCard").is_none());
    }

    #[test]
    fn handle_message_alias_uses_same_path() {
        let response = invoke_json(
            "handle_message",
            &json!({
                "mode": "status-card",
                "provider_id": "m365",
                "subject": "user-1"
            }),
        )
        .expect("alias should succeed");

        assert_eq!(response["status"], "needs-sign-in");
        assert_eq!(response["can_continue"], false);
        assert_eq!(response["card"]["oauth"]["provider"], "microsoft");
    }

    #[test]
    fn apply_answers_remove_mode_returns_success_without_config() {
        let response = invoke_json(
            "apply-answers",
            &json!({
                "mode": "remove",
                "answers": {
                    "confirm_remove": true
                },
                "current_config": {
                    "provider_id": "github"
                }
            }),
        )
        .expect("apply-answers should succeed");

        assert_eq!(response["ok"], true);
        assert_eq!(response["config"]["provider_id"], "github");
    }

    #[test]
    fn apply_answers_setup_defaults_missing_provider() {
        let response = invoke_json(
            "apply-answers",
            &json!({
                "mode": "setup",
                "answers": {
                    "default_subject": "user-1"
                }
            }),
        )
        .expect("apply-answers should succeed");

        assert_eq!(response["ok"], true);
        assert_eq!(response["warnings"][0]["fields"][0], "provider_id");
        assert_eq!(response["config"]["provider_id"], "oauth-provider");
    }

    #[test]
    fn normalized_mode_prefers_mode_then_operation_alias() {
        assert_eq!(
            normalized_mode(&json!({ "mode": "upgrade" })),
            qa::NormalizedMode::Update
        );
        assert_eq!(
            normalized_mode(&json!({ "operation": "remove" })),
            qa::NormalizedMode::Remove
        );
        assert_eq!(normalized_mode(&json!({})), qa::NormalizedMode::Setup);
    }

    #[test]
    fn schema_helpers_expose_expected_required_fields() {
        assert!(
            oauth_config_schema_json()["required"]
                .as_array()
                .expect("required array")
                .is_empty()
        );
        assert_eq!(oauth_input_schema_json()["required"][0], "mode");
        assert_eq!(qa_spec_input_schema_json()["required"][0], "mode");
        assert_eq!(apply_answers_input_schema_json()["required"][0], "answers");
        assert_eq!(component_info_input_schema_json()["type"], "object");
        assert_eq!(i18n_keys_output_schema_json()["type"], "array");
    }

    #[test]
    fn component_info_returns_i18n_aware_self_description() {
        let response = invoke_json(COMPONENT_INFO_OPERATION, &json!({ "locale": "en-GB" }))
            .expect("component-info should succeed");

        assert_eq!(response["name"], COMPONENT_NAME);
        assert_eq!(response["version"], COMPONENT_VERSION);
        assert_eq!(response["display_name"]["key"], "component.display_name");
        assert_eq!(
            response["summary"]["fallback"],
            "Shows OAuth connection status and sign-in actions for a chosen provider, using results from upstream Greentic OAuth operations and the provider extension."
        );
        assert!(
            response["details"]["fallback"]
                .as_str()
                .expect("details fallback should be string")
                .contains("Greentic OAuth provider extension")
        );
        assert_eq!(response["operations"][0]["name"], DEFAULT_OPERATION);
    }

    #[test]
    fn canonical_describe_struct_builds() {
        let describe = component_describe_struct();
        assert_eq!(describe.info.id, "ai.greentic.component-oauth-card");
        assert_eq!(describe.operations.len(), 5);
    }

    #[test]
    fn handle_returns_ok_when_current_token_is_supplied() {
        let response = invoke_json(
            DEFAULT_OPERATION,
            &json!({
                "mode": "ensure-token",
                "provider_id": "demo",
                "subject": "user-1",
                "current_token": {
                    "access_token": "abc",
                    "refresh_token": "refresh",
                    "expires_at": 123,
                    "token_type": "Bearer",
                    "extra": null
                }
            }),
        )
        .expect("invoke should succeed");

        assert_eq!(response["status"], "ok");
        assert_eq!(response["can_continue"], true);
        assert_eq!(response["auth_header"]["headers"][0][1], "Bearer abc");
        // Raw token is surfaced for downstream flow nodes (e.g. an API component).
        assert_eq!(response["access_token"], "abc");
    }

    #[test]
    fn start_sign_in_requires_supplied_consent_url() {
        let response = invoke_json(
            DEFAULT_OPERATION,
            &json!({
                "mode": "start-sign-in",
                "provider_id": "demo",
                "subject": "user-1"
            }),
        )
        .expect("invoke should succeed");

        assert_eq!(response["status"], "error");
        assert_eq!(response["can_continue"], false);
        assert!(
            response["error"]
                .as_str()
                .expect("error string")
                .contains("consent_url is required")
        );
    }

    #[test]
    fn complete_sign_in_uses_exchanged_token_from_payload() {
        let response = invoke_json(
            DEFAULT_OPERATION,
            &json!({
                "mode": "complete-sign-in",
                "provider_id": "demo",
                "subject": "user-1",
                "auth_code": "code",
                "exchanged_token": {
                    "access_token": "new-token",
                    "refresh_token": "refresh",
                    "expires_at": 123,
                    "token_type": "Bearer",
                    "extra": null
                }
            }),
        )
        .expect("invoke should succeed");

        assert_eq!(response["status"], "ok");
        assert_eq!(response["can_continue"], true);
        assert_eq!(response["auth_context"]["provider_id"], "demo");
    }
}
