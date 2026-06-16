# Implementation Plan: OAuth Bake-In (phased)

Companion to [oauth-bake-in.md](oauth-bake-in.md). Centered on the **MCP adapter**
as the OAuth-declaration carrier and the **designer** as the auto-pairing engine.

**Branch (all repos):** `feature/oauth-bake-in`

**Repos in scope:** `greentic-mcp-generator`, `greentic-mcp` (adapter),
`component-oauth-card`, `greentic-designer` (flow_generator + admin), `greentic-oauth`
(broker; v1.1), and the admin platform (oauth-providers endpoint).

## Shape of the solution

```
OpenAPI oauth2 scheme ──gen──► router (carries auth_url/token_url/scopes in tool meta,
                                        already injects `access_token`)
                                  │ composed with
                                  ▼
                            MCP adapter
                              ├─ describe() surfaces an `oauth` block (declaration)
                              └─ self-gates at runtime: resolve token →
                                   present → call API
                                   absent  → return oauth-card sign-in card
                                  │  node output (result OR card) → channel render bridge
                                  ▼
                admin: client_id (public→card) / client_secret (sealed→broker),
                       per-team broker enablement gate
                designer: reads describe().oauth for awareness (palette/UX) — not required for function
```

Token injection is already wired (router reads `access_token`). The **broker**
builds the consent URL and does the exchange — the card renders the `start_url`.

## Where the token-check + sign-in lives: **baked into the adapter** (not the flow)

The "find a token, else sign in" loop is baked into the **MCP adapter**, so the
flow is just the MCP node — OAuth works out of the box in *any* flow (hand-authored
or designer-generated), and there's no companion node or branch to wire.

```
   invoke OAuth tool
        │
        ▼
   ┌──────────────────────────── MCP adapter (self-gates) ────────────────────────────┐
   │  resolve token for (provider, subject=user-from-envelope)   [fetch_oauth_token]   │
   │      • token present  → call the API (existing router path)         → API result  │
   │      • absent/expired → return the oauth-card `renderedCard`         → sign-in card│
   └───────────────────────────────────────────────────────────────────────────────────┘
        │  node output (result OR sign-in card)
        ▼
   normal node-output → channel render bridge  (renderedCard → adaptive_card → webchat)
```

- **Surfacing** reuses the proven path: the node's `renderedCard` is mapped by
  greentic-start into the channel's `adaptive_card` slot and webchat renders it
  natively (verified live this session). The card is just the MCP node's output
  when there's no token — no special routing.
- The adapter depends on the **oauth-card** (as a crate) to render the sign-in
  card, and uses greentic-mcp's existing OAuth token-fetch to resolve the token.
  The **broker** still builds the consent URL + does the exchange.
- Requires an **interactive messaging surface**. Non-interactive tool calls take
  the token from admin/stored creds; no card.
- **v1** renders the sign-in card. **v1.1** adds the broker callback ingress so
  completing sign-in resumes the *same* conversation; until then the user
  re-invokes and the adapter finds the now-stored token.

> **Decision:** revert/gate the session-local `build_authorize_url` on the card
> (card renders a broker-provided `start_url`; it does not assemble the URL in the
> designer path). Keep only as an optional broker-less fallback if wanted.

## Phases

### Phase 0 — Declaration shape  (`component-oauth-card` + agree the schema)
Define the `oauth` declaration block (the contract everything keys off):
`{ provider_id, auth_url, token_url, scopes[], token_input="access_token" }`.
Carrier = the component's `describe()` (not manifest.json). Land the card-vs-broker
URL decision above. *Small; unblocks all others.*

### Phase 1 — Generator detects OAuth + carries the metadata  (`greentic-mcp-generator`)

**Detection gate (the on/off switch for the whole feature):** the OpenAPI spec is
the trigger. Emit the `oauth` declaration **only when** the spec declares an
`oauth2` (or `openIdConnect`) security scheme that is referenced by `security`
(global or per-operation). The generator already classifies scheme kind
(`SecuritySchemeKind::OAuth2` vs `HttpBearer`/`ApiKey`/`Other`) — gate on `OAuth2`.

- **Match** → emit the `oauth` block → adapter declares it (describe) and
  self-gates at runtime.
- **No match** (no `security`, or only apiKey / http-bearer) → **emit no `oauth`
  block**. Nothing downstream to pair, so the card wiring is skipped
  automatically — no special-casing needed. Non-OAuth auth keeps the existing
  `secret_requirements` path (token/key from input/secret-store), unchanged.

Detection is purely spec-driven — no override flag.

Then carry the URLs (today they're dropped):
- `…-core/src/ir.rs:107` — add `OAuth2Flow { auth_url, token_url, scopes, flow_type }`
  to `SecurityScheme`.
- `…-core/src/openapi.rs:774` (`map_security_scheme`) — populate it from the
  `authorizationCode` flow.
- `…-core/src/mcp.rs` — when the gate matches, carry the oauth metadata into the
  tool model and emit it into the router tool `meta` (since `router::Tool` has no
  auth fields).
- **Output:** OAuth specs → router tools carry `auth_url`/`token_url`/`scopes`;
  non-OAuth specs → no oauth metadata, identical to today.

### Phase 2 — Adapter: declare + self-gate  (`greentic-mcp` adapter) ← the engine
This is where the bake-in lives.
- **Declare:** `crates/mcp-adapter/src/lib.rs` (tool-list render ~308,
  `meta_to_value` ~522) — read the oauth meta off the router tools and surface an
  `oauth` block in the component `describe()` response.
- **Self-gate (runtime):** on invoke of an OAuth tool, resolve the token for
  `(provider, subject=user from envelope)` via greentic-mcp's `fetch_oauth_token`.
  - token present → existing router path injects `access_token` → API result.
  - absent/expired → return the oauth-card `renderedCard` (depend on the
    `component-oauth-card` crate to render it; `start_url` from the broker).
- **Output (v1 engine):** an OAuth MCP node returns either the API result or a
  sign-in card — surfaced by the normal node-output → channel bridge. No flow
  branching, works in any flow.

### Phase 3 — Designer awareness  (`greentic-designer`) — not the engine
The adapter self-gates, so the designer does **not** need to inject companion
nodes for OAuth to work. Designer's job is awareness only:
- read `describe().oauth` so an OAuth tool is shown/labelled in the palette/canvas
  (ties into the in-flight `runtime_ref` decouple so the catalog reads describe);
- signal to admin which provider creds need wiring (Phase 4).
- *(Optional later: a visual "sign-in" affordance on the node — UX only, not
  required for function.)*

### Phase 4 — Admin OAuth slice  (`greentic-designer` admin + admin platform)
Mostly net-new (admin is tenant-scoped today, no oauth surface, creds env-only).
- New admin oauth-providers config (per provider: public `client_id`, sealed
  `client_secret`), resolved env→tenant→team.
- Team context (`X-Greentic-Team`) + per-team broker **enablement gate**;
  auto-pairing only fires when the team has the OAuth broker enabled.
- `src/admin/client.rs` (ETag/TTL pattern) — extend to fetch the oauth config.
- **Output:** card gets public `client_id`; broker gets sealed secret; disabled
  teams aren't auto-paired.

### Phase 5 (v1.1) — Callback ingress + exchange  (`greentic-oauth`)
- Broker builds the consent URL, handles the callback, exchanges the code, stores
  the token; flow resumes and the MCP op runs authenticated.
- **Output:** "lists repos after auth" works end-to-end.

## v1 vs v1.1

- **v1 = Phases 0–2 (+ minimal Phase 4 creds):** *spec declares OAuth → adapter
  self-gates → an OAuth tool with no token returns the sign-in card.* (Phase 3 is
  designer awareness, not required for function.)
- **v1.1 = full Phase 4 + Phase 5:** completes real sign-in (callback/exchange)
  and "lists repos after auth".

## Running acceptance (GitHub)
Use `demo/github/github_ops.yaml` (already declares the `githubOAuth` scheme) as
the test case through every phase: Phase 1 carries its URLs → Phase 2 declares
them in describe() and self-gates → invoking with no token renders the sign-in
card → Phase 5 completes auth and lists repos.

## Build order
Phase 0 → 1 → 2 is the engine and gives the v1 demo (any flow, no designer
needed). Phase 3 (designer awareness) and Phase 4 creds can land in parallel;
Phase 5 last.

## Open / decisions
- describe() `oauth` placement: top-level vs under a capabilities block.
- One card per declared scheme vs one per tool when several exist.
- Adapter ↔ oauth-card coupling: depend on the crate to render, vs a shared
  render helper — confirm during Phase 2.
- Subject resolution: confirm the user/subject is reliably on the invocation
  envelope for the token key in non-chat contexts.
- Team-context rollout in admin (currently tenant-only) — size before Phase 4.
