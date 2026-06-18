# ai.greentic.oauth-card provider pack

Packages `component-oauth-card` as a Greentic provider pack so it can serve as
the standard OAuth interaction surface (status / sign-in / refresh) alongside
webchat-gui.

## What's in source control

- `pack.yaml` — pack manifest (component + flow declarations).
- `flows/main.ygtc` — default messaging flow that renders the Microsoft OAuth
  status card via `component.exec` on `oauth_card.handle_message`.
- `flows/*.resolve.json` / `*.resolve.summary.json` — resolve sidecars pinning
  the component digest for the flow node.
- `components/oauth-card/component.manifest.json` — the component manifest.

The component wasm (`components/oauth-card/component_oauth_card.wasm`), the built
`.gtpack`, `pack.lock.cbor`, and the `.greentic/` cache are build artifacts and
are gitignored.

## Build

```bash
# 1. Build the component wasm from the repo root
make wasm

# 2. Stage the freshly built wasm into the pack
cp target/wasm32-wasip2/release/component_oauth_card.wasm \
   pack/components/oauth-card/component_oauth_card.wasm

# 3. Refresh the resolve sidecar digests for the new wasm
DIGEST=$(shasum -a 256 pack/components/oauth-card/component_oauth_card.wasm | awk '{print $1}')
#    (update the "digest": "sha256:<DIGEST>" fields in flows/main.ygtc.resolve*.json)

# 4. Lint, resolve, build, and validate
greentic-pack lint    --in pack
greentic-pack resolve --in pack
greentic-pack build   --in pack --gtpack-out pack/dist/oauth-card-pack.gtpack
greentic-pack doctor  pack/dist/oauth-card-pack.gtpack
```

## Known integration gaps

`greentic-pack doctor` currently reports one error for the component:

```
PACK_LOCK_COMPONENT_DESCRIBE_FAILED ... describe() failed: missing exported
descriptor instance — ensure the component exports greentic:component@0.6.0
```

This is a toolchain/version skew, not a flaw in this pack or the card logic: the
guest crate `greentic-interfaces-guest 0.4.x` does not emit the descriptor
instance that `greentic-pack 0.5.6` validation expects (the same component fails
identically under the prior `scratch-oauth/oauth-card-pack`). Resolving it means
bumping the component to a `greentic-interfaces-guest` release whose
`export_component_v0_6` emits the `greentic:component@0.6.0` descriptor — a
separate dependency-bump change.

## Live refresh & webchat-gui

Flows cannot call the OAuth broker directly; the operator/runtime resolves the
token (refreshing via the broker `get-token` op when `offline_access` was
granted) around `component.exec` and injects `current_token` + `now_unix` into
the card. The card then returns `ok` / `needs-sign-in` / `needs-refresh`. For
the `needs-refresh` decision to fire live, the operator must inject `now_unix`
(epoch seconds) into the component input. Use `tools/live_test_oauth_interactive.sh`
to exercise the live OAuth path end-to-end.
