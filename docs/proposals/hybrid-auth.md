# Hybrid Auth — native `greentic:oauth` host capability + tiered providers

## Decision
OAuth/OIDC is a **native runtime capability** exposed to components as a WIT **host import**
(`greentic:oauth`), exactly like `secrets-store` / `wasi:http` / `telemetry`. It is **not** a
bundled WASM provider and **not** compiled into the adapter. The bundle author ships only an
OpenAPI spec that declares `oauth2`; everything else is provided by the runtime.

## Before → After
- **Before:** bundle ships `oauth-oidc-generic` provider (`oidc-ingress.wasm` +
  `oidc-provider-runtime.wasm`) AND greentic-start has a parallel native `/oauth/callback`.
  Duplicated, author-bundled, GitHub-shaped (client_id+secret, no PKCE/refresh).
- **After:** one **native `greentic-oauth` engine** in greentic-start (owns the socket +
  callback, exchange, refresh, PKCE, signed state, ID-JAG), exposed as `greentic:oauth`.
  Adapter stays thin (gate + card via `oauth-card-core`) and *imports* the capability.
  The bundled OIDC provider is deleted.

## Tiers (one token gate, selected per provider)
1. **OAuth + PKCE + refresh** — default for most providers; author registers a public
   `client_id` (no secret via PKCE), `offline` scope for refresh. **Google, Microsoft, Okta/Auth0.**
2. **PAT** — paste a token; zero registration. **GitHub-style.**
3. **EMA / ID-JAG** — enterprise, admin-managed, zero user consent; only for documented
   providers via a supporting IdP. **Asana/Atlassian/Figma/Linear/… via Okta XAA.**

Provider → tier is gated by docs/support; everything else falls back to OAuth+PKCE.

## `greentic:oauth` WIT interface (sketch)
```
package greentic:oauth;
interface oauth {
  record sign-in { mode: string, consent-url: option<string>, state: string }
  // Begin/confirm sign-in for a tool's oauth declaration. Returns a card payload
  // (consent URL + signed state) or "already authorized".
  start-sign-in: func(provider: string, scheme: string, scopes: list<string>) -> sign-in;
  // Return a valid (refreshed if needed) token for the pack-scoped key, or none.
  ensure-token: func(provider: string, scheme: string) -> option<string>;
  // Drop the stored token (disconnect).
  disconnect: func(provider: string, scheme: string);
}
world host-oauth { export oauth; }   // runtime implements; component imports
```
The runtime owns the `/oauth/callback` route, verifies the signed state, exchanges the code,
persists the token, and refreshes — all native. The adapter only calls `start-sign-in` /
`ensure-token` and gates on the result.

## Demo: Google Sheets (replaces the GitHub demo in greentic-demo)
Sign in with Google (PKCE + `offline`), then a wizard:
- `list_spreadsheets` — Drive API `GET /drive/v3/files?q=mimeType='application/vnd.google-apps.spreadsheet'`
- `get_spreadsheet` — Sheets API `GET /v4/spreadsheets/{id}` (tabs/metadata)
- `read_values` — Sheets API `GET /v4/spreadsheets/{id}/values/{range}`

Wizard: list spreadsheets → pick one → list tabs → read/summarize a range.
Scopes: `drive.metadata.readonly`, `spreadsheets.readonly`, `offline`.

**Author prerequisite:** a Google Cloud OAuth client of type *Desktop/Installed* (PKCE) →
provides a `client_id`, **no secret**. Entered once at `gtc setup` (pack-scoped). Customer
just signs in; the runtime keeps tokens fresh via the refresh token.

## Build order
- **Phase 1 — `greentic:oauth` interface + native engine:** define the WIT, implement the
  native engine in greentic-start (consent URL, PKCE, exchange, refresh, signed state,
  callback route), wired to secrets-store. Adapter imports + calls it; remove the bundled
  OIDC provider.
- **Phase 2 — Google Sheets spec + generator:** author the Sheets/Drive OpenAPI (oauth2 +
  PKCE + offline), generate the router, recompose.
- **Phase 3 — demo in greentic-demo:** the list→pick→read wizard cards; replace
  `crates/github-mcp-demo`; README `wizard`/`setup`/`start` lines.
- **Phase 4 — PAT + EMA tiers:** add PAT mode; add ID-JAG/Okta XAA for the documented cohort.

## Removed
- `oauth-oidc-generic` provider (oidc-ingress + oidc-provider-runtime) from bundles.
- greentic-start's ad-hoc `/oauth/callback` exchange logic (absorbed into the native engine
  behind the `greentic:oauth` interface).
