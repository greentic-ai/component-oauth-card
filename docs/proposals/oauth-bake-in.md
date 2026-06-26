# Proposal: OAuth Out-of-the-Box for Greentic Components

**Status:** Draft / touch-and-go spec
**Owner:** (tbd)
**Related:** `greentic-component`, `component-oauth-card`, `greentic-oauth` (oidc provider), `greentic-pack`, `greentic-mcp-generator`

## Summary

Any component that **declares it needs OAuth** should automatically get a wired
sign-in card + OAuth provider — out of the box. The pairing happens at the
**greentic-component layer**. A component only ever *declares* the OAuth need;
greentic-component detects the declaration and does the wiring. Because the
trigger is a component-level declaration, this works for any component — whether
it was generated from an API spec or hand-authored.

## Background — the pieces (for newcomers)

A few moving parts, in plain terms:

- **Component** — a sandboxed WASM module that does one job (call an API, render a
  card, etc.). Components declare what they need (capabilities, secrets) in a
  `component.manifest.json`.
- **greentic-component** — the tooling/"component repository" layer that
  **assembles** components: it composes WASM pieces together, resolves a
  component's dependencies from the repository, and bundles them so they can run.
  Think of it as the build-and-package step for components. *This is where the
  OAuth pairing in this proposal lives.*
- **oauth-card** (`component-oauth-card`) — a small, provider-agnostic component
  that renders the sign-in / status card and decides "signed in / needs sign-in /
  refresh". Given a provider's `auth_url` + public `client_id` + `scopes`, it
  builds the standard authorize URL itself. It holds no secret.
- **OAuth provider extension** (`oidc`) — does the parts that need a secret and a
  server: exchanging the auth code for a token, storing/refreshing it.
- **Pack + flow** — a *pack* bundles components together; a *flow* (`.ygtc`)
  wires them in order (e.g. sign-in → call API → render result).

So today, making an API component "log in" means hand-wiring the card, the
provider, and the flow every time. This proposal makes greentic-component do that
automatically when a component says it needs OAuth.

## How it fits together

```
                 ┌──────────────────────────────────────────────┐
   component  ──►│  greentic-component   (assemble + pair)        │
   declares:     │                                                │
   oauth {       │   sees oauth{} declaration  ──►  AUTO-PAIR:    │
     auth_url    │     • include oauth-card                       │
     token_url   │     • include OAuth provider (oidc)            │
     scopes      │     • generate flow wiring                     │
   }             │     • surface setup questions                  │
                 └───────────────────────┬──────────────────────-┘
                                         │ produces
                                         ▼
        pack/bundle with the generated flow:

        ┌────────────┐   token    ┌───────────────┐        ┌──────────┐
        │ oauth-card │ ─────────► │ your component │ ─────► │  render  │
        │ (sign in)  │            │  (call API)    │        │  result  │
        └────────────┘            └───────────────┘        └──────────┘
              ▲                          │
              │ client_secret/exchange   │ access_token injected
        ┌───────────────────┐           ─┘
        │ OAuth provider     │
        │ (oidc extension)   │
        └───────────────────┘

   setup once:  client_id (public → card)   client_secret (→ provider)
```

## The declaration (the contract)

A component declares its OAuth requirement in its manifest — provider-agnostic,
public config only (no secret):

```jsonc
// component.manifest.json (sketch)
"oauth": {
  "provider_id": "github",
  "auth_url":  "https://github.com/login/oauth/authorize",
  "token_url": "https://github.com/login/oauth/access_token",
  "scopes":    ["repo", "read:user"],
  "token_input": "access_token"   // where the component wants the token injected
}
```

This is exactly what an OpenAPI `oauth2` security scheme already carries
(`authorizationUrl` / `tokenUrl` / `scopes`), so components generated from a spec
can fill it automatically; hand-written ones can set it directly.

## Mechanics (high level — detail later)

1. **Declaration carrier.** Add an `oauth` block to the component manifest /
   describe schema (provider_id, auth_url, token_url, scopes, token_input).

2. **greentic-component pairing step.** When assembling a component that has an
   `oauth` declaration, greentic-component:
   - includes the oauth-card (and the oidc provider) as paired components,
   - generates the default flow wiring (oauth-card → declaring component),
   - validates the provider extension resolves from the component repository.
   This is the new behavior and the bulk of the work.

3. **Spec-generated components fill the declaration.** `greentic-mcp-generator`
   already parses `securitySchemes` but currently **drops
   `authorizationUrl`/`tokenUrl`**; it just needs to carry those through into the
   generated component's `oauth` declaration.

4. **Card stays agnostic.** The oauth-card already takes `auth_url` / `client_id`
   / `redirect_uri` / `scopes` and builds the authorize URL; pairing just feeds it
   the declared values.

5. **Secrets unchanged.** client_id (public) flows to the card; client_secret
   stays in the OAuth provider. No new secret handling.

## Minimal first implementation (GitHub)

1. Define the `oauth` declaration block; set it on the github_api component
   (and, in parallel, teach the generator to fill it from
   `demo/github/github_ops.yaml`'s securityScheme).
2. greentic-component: on seeing the declaration, pair the oauth-card + oidc
   provider and generate the `oauth-card → list_authenticated_user_repos →
   render` flow automatically (the demo flow we currently hand-write).
3. Operator supplies client_id / client_secret via setup; run.

Success = a component that declares OAuth, run through greentic-component,
produces a bundle that shows the sign-in card and (after auth) lists repos — with
zero hand-wiring.

## Then: more providers

Same path, different declaration — Google, Microsoft, Slack, etc. Each is just a
different `auth_url` / `token_url` / `scopes`. Add a small provider-id inference
table (host → `github`/`google`/`microsoft`/…) for branding. Test each against
the same oauth-card.

## Out of scope (for v1)

- Browser callback ingress + chat-session resume (still the provider's job; needs
  NATS / public URL — see the disconnects analysis).
- `clientCredentials` / device-code flows (device-code is attractive later: no
  redirect needed).
- Auto-registering the OAuth app with the provider.

## Open questions

- Exact home of the pairing step: `greentic-component` composition vs.
  `greentic-pack` build (both are component-repository tooling).
- Declaration schema: a manifest `oauth` block vs. a capability
  (`requires: oauth:sign-in`) + config. Manifest block is simplest.
- Provider-id inference: scheme name, server host, or explicit hint.
- One oauth-card per declared scheme vs. one per pack when several exist.
- Where client_id is stored so card (public) and provider (with secret) agree.
