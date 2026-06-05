# component-oauth-card

OAuth card component for Greentic `component@0.6.0`.

This component shows OAuth status, sign-in, and blocking messages for a flow. It
does not import the OAuth broker directly. Instead, your flow calls the
Greentic OAuth operations from `../greentic-oauth` first, then passes their
results into this component.

## Requirements

- Rust 1.91+
- `wasm32-wasip2` target (`rustup target add wasm32-wasip2`)

This repository follows the self-describing 0.6.0 shape instead of legacy
`flows/default.ygtc` and `flows/custom.ygtc`.

## Required Greentic OAuth Extension

This component cannot work on its own.

It requires the Greentic OAuth provider extension and operations from
`../greentic-oauth` to be installed in the environment where the flow runs.
That extension is what:

- knows which OAuth providers exist
- stores and refreshes OAuth credentials
- returns consent URLs
- exchanges authorization codes for tokens

If the Greentic OAuth provider extension is missing, or if `provider_id` does
not match a provider that extension exposes, the upstream OAuth operations
cannot produce the data this component needs and the flow stays blocked.

## What This Component Does

- Shows a connected or needs-sign-in card for a chosen OAuth provider.
- Returns an authorization header only when a usable token is available.
- Marks the response as `can_continue: false` when authentication is still required.
- Exposes setup questions so Greentic can configure it without custom flow files.
- Exposes i18n-aware self-description data through `component-info`.

## Main Operations

- `oauth_card.handle_message`
- `component-info`
- `qa-spec`
- `apply-answers`
- `i18n-keys`

## Typical Flow

1. Make sure the Greentic OAuth provider extension is installed and that your chosen provider ID exists there.
2. Configure the component once with a default provider ID and optional scopes.
3. Call a Greentic OAuth operation to check for a usable token.
4. Call `oauth_card.handle_message` with `mode: "status-card"` or `mode: "ensure-token"` and pass that token as `current_token`.
5. If the component says `needs-sign-in`, call a Greentic OAuth operation that returns a consent URL.
6. Call the component with `mode: "start-sign-in"` and pass that URL as `consent_url`.
7. After your callback endpoint receives an auth code, call a Greentic OAuth operation that exchanges the code.
8. Call the component with `mode: "complete-sign-in"` and pass the returned token as `exchanged_token`.
9. Only continue the flow when the response has `can_continue: true`.

## Authentication Rules

The intended behavior is:

1. You configure which OAuth service/provider this component is for.
2. That provider must exist in the installed Greentic OAuth provider extension.
3. A separate Greentic OAuth operation checks for a usable token for that provider, user, and scope.
4. That OAuth operation may use a stored refresh token to refresh the access token and persist the updated token set.
5. If no usable token exists, or reauthentication is needed, this component returns `needs-sign-in` and `can_continue: false`.
6. The flow should not continue until the user completes sign-in successfully.
7. The user may retry, but no downstream authenticated step should proceed until `can_continue: true`.

## Runtime Input Fields

`oauth_card.handle_message` expects the usual `mode`, `provider_id`, and
`subject`, plus upstream OAuth operation results when relevant:

- `current_token`: token already checked or refreshed upstream
- `consent_url`: URL that starts the sign-in step
- `exchanged_token`: token returned after exchanging an authorization code
- `oauth_error`: upstream OAuth error to show to the user
- `now_unix`: current time (epoch seconds), injected by the flow/runtime so the
  card can decide whether `current_token` is expired. When omitted, the token is
  treated as fresh and no refresh is requested.
- `refresh_skew_seconds`: refresh a token this many seconds before `expires_at`
  (default 60)
- `connection_name`: Bot Framework registered connection name; echoed into the
  rendered oauth card as `connectionName` / `tokenExchangeResource`

### Token refresh

When `current_token` carries an `expires_at` and the flow supplies `now_unix`,
the card returns `status: "needs-refresh"` with `can_continue: false` once the
token is at or past expiry (minus `refresh_skew_seconds`). The flow should then
resolve a fresh token via the Greentic OAuth broker `get-token` op (which
refreshes using a stored refresh token when `offline_access` was granted) and
re-invoke the card with the refreshed `current_token`. The component never
performs the token call itself — its component world (`component@0.6.0`) does
not import the OAuth broker directly.

## Configuration

The component stores a small runtime configuration:

- `provider_id`: the OAuth provider name, such as `msgraph` or `github`; this must be exposed by the installed Greentic OAuth provider extension
- `default_subject`: optional fallback user identifier
- `scopes`: default scopes to request
- `tenant`: optional tenant context
- `team`: optional team context
- `redirect_path`: optional callback path override
- `allow_auto_sign_in`: whether `ensure-token` should create a sign-in card automatically

Greentic can build this configuration automatically through:

- `qa-spec`: asks the setup/update/remove questions
- `apply-answers`: converts those answers into saved config JSON

## i18n

English source strings live in `assets/i18n/en.json`. `build.rs` embeds every
locale JSON file under `assets/i18n/` into the final wasm at build time.
The same build step also renders `component.manifest.json` from
`component.manifest.template.json`, so the manifest version tracks
`Cargo.toml` automatically.

Use `./tools/i18n.sh` to generate or refresh translated locale files.

## Output Contract

The main runtime output includes:

- `status`: `ok`, `needs-sign-in`, `needs-refresh`, or `error`
- `can_continue`: whether the flow is allowed to proceed
- `card`: what to show the user
- `auth_header`: only present when a usable token is available
- `auth_context`: token/provider context for downstream logic

If `can_continue` is `false`, treat that as a hard stop for the current flow
path until the user finishes authentication successfully.

## Development Checks

```bash
cargo test
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

For a component artifact, manifest hash, and doctor validation:

```bash
make wasm
make doctor
```

## Live OAuth Runner

This repo now includes a typed live OAuth runner that replaces most of the old
shell orchestration:

- binary: `cargo run --offline --bin oauth_live_test -- <repo-url>`
- wrapper: `./tools/live_test_oauth_interactive.sh <repo-url>`

The runner keeps the live OAuth path through extension capability calls:

- `oauth.initiate_auth`
- `oauth.get_access_token`

It also handles:

- runtime start + ngrok URL resolution
- setup answer apply (`AUTO_APPLY_SETUP=true` by default)
- callback polling via ngrok inspector
- commit fetch and `gtc op demo run` card render

Key env vars are kept compatible with the legacy script:
`TENANT`, `TEAM`, `FLOW_ENV`, `PROVIDER`, `RUNTIME_PROVIDER_ID`,
`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_CLIENT_ID_KEY`,
`OIDC_CLIENT_SECRET_KEY`, `OIDC_AUTH_URL`, `OIDC_TOKEN_URL`,
`OAUTH_SCOPES_CSV`, `OAUTH_BROKER_CAP_ID`, `SKIP_START`, `SKIP_SETUP`,
`AUTO_APPLY_SETUP`, and callback overrides (`OAUTH_CALLBACK_*`).

## Demo (GitHub sign-in in webchat-gui)

A runnable demo bundle lives under [`demo/`](demo/), modelled on `greentic-demo`.
It renders the OAuth status / sign-in card in webchat-gui in a browser, using
GitHub because an OAuth App is quick to create. (Switching to Microsoft Entra is
just a provider/scope swap — see [`pack/flows/main.ygtc`](pack/flows/main.ygtc).)

**Outcome:** open webchat, the assistant shows a "Connect github account" card;
completing sign-in flips it to a connected status card, and an expired token
yields a `needs-refresh` card that the runtime refreshes via the broker.

**Prerequisites (one-time):**

- A GitHub OAuth App (github.com → Settings → Developer settings → OAuth Apps →
  New). It takes ~2 minutes and yields a Client ID + Client Secret.
- Set its **Authorization callback URL** to the runtime ingress (substitute the
  public base URL `greentic-start` prints, e.g. your ngrok URL):
  `https://<public-base-url>/v1/oauth/ingress/oauth-oidc-executable/demo/default`
- Scopes used by the demo: `repo read:org`.

**Run:**

```bash
# 1. Build the component + provider pack, stage it into the demo bundle
make wasm
cp target/wasm32-wasip2/release/component_oauth_card.wasm \
   pack/components/oauth-card/component_oauth_card.wasm
greentic-pack build --in pack --gtpack-out demo/packs/oauth-card-pack.gtpack

# 2. Resolve providers (pulls webchat-gui / state / oauth from GHCR) and
#    validate the bundle is loadable
gtc setup ./demo --tenant demo --team default --env dev

# 3. Configure the GitHub provider + credentials. The oauth provider persists
#    client_id/client_secret under its provider keys; the dev secrets store lives
#    at demo/.greentic/dev/.dev.secrets.env. The simplest path is to let the live
#    runner apply the setup answers for you (it builds the provider envelope and
#    seeds the keys — these are the runner's GitHub defaults):
PROVIDER=github \
OIDC_AUTH_URL=https://github.com/login/oauth/authorize \
OIDC_TOKEN_URL=https://github.com/login/oauth/access_token \
OAUTH_SCOPES_CSV="repo,read:org" \
OIDC_CLIENT_ID=<github-client-id> OIDC_CLIENT_SECRET=<github-client-secret> \
TENANT=demo TEAM=default \
BUNDLE_DIR=./demo SKIP_START=true \
  ./tools/live_test_oauth_interactive.sh

# 4. Start the runtime with a public tunnel
greentic-start start --bundle ./demo --ngrok on

# 5. Set the callback URL shown by the runtime in your GitHub OAuth App, then
#    open webchat in a browser and say "hi" to trigger the card
open "http://localhost:8080/v1/web/webchat/demo"
```

Secrets are never committed: the bundle declares the provider's secret keys and
`greentic-start` resolves them from the dev secrets store (or your configured
secrets backend) at runtime. The card itself holds no secrets — the operator
resolves/refreshes the token via the broker and injects it around
`component.exec` (see "Token refresh" above).
