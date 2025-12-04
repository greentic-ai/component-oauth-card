# Repository Overview

## 1. High-Level Purpose
Greentic OAuth card component implemented for wasm32-wasip2. It exposes the Greentic component-node interface and drives OAuth connect/status flows by talking to the host `greentic:oauth-broker` bindings. The component returns structured JSON with card metadata, auth context, and headers for downstream API calls instead of simple echo output.

## 2. Main Components and Functionality
- **Path:** `src/lib.rs`  
  **Role:** Component entrypoint and wasm exports.  
  **Key functionality:** Implements component-node guest, parses incoming JSON requests, and dispatches to OAuth card logic. Exports structured errors and uses `greentic-interfaces-guest` (feature: `component-node`) on wasm. Supports crate-type `cdylib` and `rlib` for testing.
- **Path:** `src/model.rs`  
  **Role:** Data model for inputs/outputs.  
  **Key functionality:** Defines `OAuthCardInput`/`OAuthCardOutput`, modes (status-card, start-sign-in, complete-sign-in, ensure-token, disconnect), token sets, and status enum. Includes local `MessageCard`/`Action`/`OauthCard` structs mirroring `gsm_core::messaging_card::types` (kind/title/text/images/actions/allow_markdown/adaptive/oauth).
- **Path:** `src/broker.rs`  
  **Role:** Abstraction over the OAuth broker.  
  **Key functionality:** Trait `OAuthBackend`; native `NoopBroker` keeps tests deterministic; `MockBroker` for unit tests; input parser helper. Wasm `HostBroker` currently reports `Unsupported` because oauth-broker bindings are exposed as exports rather than imports in `greentic-interfaces-guest`.
- **Path:** `src/logic.rs`  
  **Role:** Mode handlers.  
  **Key functionality:** status-card queries broker token; start-sign-in builds consent card and state; complete-sign-in exchanges code and returns auth header/context; ensure-token returns header or sign-in card (auto); disconnect returns a reconnect card. Cards are `MessageCard` with PostBack/OpenUrl actions and `OauthCard` metadata including state/consent URL.
- **Path:** `schemas/` (`component.schema.json`, `io/input.schema.json`, `io/output.schema.json`)  
  **Role:** JSON Schemas describing component configuration, input, and output payloads.  
  **Key functionality:** Component config is currently empty/optional; input schema models OAuthCardInput (mode enum, provider/subject, scopes, state/auth_code, auto sign-in flag, redirect path, extra JSON); output schema models OAuthCardOutput (status, MessageCard shape with actions/adaptive/oauth metadata, auth_context, auth_header header pairs, state_id, error).
- **Path:** `component.manifest.json`  
  **Role:** Greentic component manifest describing identity, supported world (`greentic:component/component@0.4.0`), messaging capability, WASI allowances, limits, and artifact path `target/wasm32-wasip2/release/component_oauth_card.wasm`.  
  **Key functionality:** Hash currently placeholder (`blake3:000…000`) because wasm build with oauth-broker guest imports is blocked by linker export expectations; needs rebuild once bindings issue is resolved.
- **Path:** `tests/conformance.rs` and unit tests in `src/lib.rs`  
  **Role:** Verify manifest world name and OAuth card logic paths.  
  **Key functionality:** Status-card returns `needs-sign-in` when no token; unit tests cover connected status, ensure-token auto sign-in prompt, start-sign-in card/state, complete-sign-in auth header/context, and disconnect reconnect card.
- **Path:** `Makefile`  
  **Role:** Convenience targets for `build`/`check` (wasm target), `lint` (fmt+clippy), and `test` (workspace all targets).
- **Path:** `ci/local_check.sh`  
  **Role:** CI helper to run `cargo fmt`, `cargo clippy --workspace --all-targets -D warnings`, and `cargo test --workspace --all-targets`.

## 3. Work In Progress, TODOs, and Stubs
- OAuth broker host bindings are not wired on wasm: `HostBroker` uses the `oauth_broker_client` imports, but enabling the oauth-broker feature in `greentic-interfaces-guest` causes the linker to require broker exports, so wasm builds currently fail; awaiting a client-only import setup or adjusted bindings.
- Manifest hash reset to placeholder until a successful wasm build with the broker imports is available.

## 4. Broken, Failing, or Conflicting Areas
- Wasm build fails: `failed to find export of interface greentic:oauth-broker/broker-v1@1.0.0#get-consent-url` when using `greentic-interfaces-guest` with `oauth-broker` feature; current client bindings generate export expectations. Host/native tests pass.

## 5. Notes for Future Work
- Add richer messaging/card integration once a canonical Greentic messaging card abstraction is published as a standalone dependency (local MessageCard mirrors gsm-core types).
