//! Render a visual gallery of every OAuth card state, for eyeballing the cards
//! before wiring real OAuth.
//!
//! Runs the component (`invoke_json`) across a matrix of modes / providers /
//! states, collects each `renderedCard` (Adaptive Card 1.5), and writes a single
//! self-contained HTML page that renders them with the Adaptive Cards JS library.
//!
//!   cargo run --example render_gallery   # writes target/oauth-card-gallery.html
//!
//! Then open the printed path in a browser.

use component_oauth_card::invoke_json;
use serde_json::{Value, json};

struct Scenario {
    label: &'static str,
    note: &'static str,
    payload: Value,
}

fn scenarios() -> Vec<Scenario> {
    let mut out = Vec::new();

    // start-sign-in for each provider: the card builds the authorize URL itself
    // from auth_url + client_id (provider-agnostic). Connect button should point
    // at the right provider.
    let providers = [
        (
            "github",
            "https://github.com/login/oauth/authorize",
            vec!["repo", "read:org"],
        ),
        (
            "google",
            "https://accounts.google.com/o/oauth2/v2/auth",
            vec!["openid", "email"],
        ),
        (
            "microsoft",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            vec!["User.Read"],
        ),
        (
            "acme",
            "https://auth.acme.example/oauth/authorize",
            vec!["read"],
        ),
    ];
    for (provider, auth_url, scopes) in providers {
        out.push(Scenario {
            label: leak(format!("start-sign-in · {provider}")),
            note: "Connect = Action.OpenUrl to the provider authorize URL (built by the card)",
            payload: json!({
                "mode": "start-sign-in",
                "provider_id": provider,
                "subject": "demo-user",
                "scopes": scopes,
                "auth_url": auth_url,
                "client_id": "demo-client-id",
                "redirect_uri": "https://host.example/v1/oauth/ingress/oauth-oidc-executable/demo/default"
            }),
        });
    }

    // status-card, not signed in -> needs-sign-in prompt.
    out.push(Scenario {
        label: "status-card · not signed in (github)",
        note: "needs-sign-in prompt (no token)",
        payload: json!({
            "mode": "status-card", "provider_id": "github",
            "subject": "demo-user", "scopes": ["repo"]
        }),
    });

    // status-card, connected.
    out.push(Scenario {
        label: "status-card · connected (github)",
        note: "Connected: Refresh / switch / Disconnect",
        payload: json!({
            "mode": "status-card", "provider_id": "github", "subject": "demo-user",
            "scopes": ["repo"],
            "current_token": { "access_token": "gho_demo", "token_type": "Bearer" }
        }),
    });

    // status-card, expired token -> needs-refresh.
    out.push(Scenario {
        label: "status-card · expired (needs-refresh)",
        note: "token past expiry + now_unix supplied",
        payload: json!({
            "mode": "status-card", "provider_id": "google", "subject": "demo-user",
            "scopes": ["openid"],
            "current_token": { "access_token": "g_demo", "expires_at": 100 },
            "now_unix": 100000
        }),
    });

    // disconnect.
    out.push(Scenario {
        label: "disconnect (github)",
        note: "Disconnected, offers Reconnect",
        payload: json!({
            "mode": "disconnect", "provider_id": "github", "subject": "demo-user"
        }),
    });

    out
}

// Small helper to get a 'static str from a runtime String for labels.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn main() {
    let mut cards: Vec<Value> = Vec::new();
    for sc in scenarios() {
        let resp = invoke_json("oauth_card.handle_message", &sc.payload)
            .unwrap_or_else(|e| json!({ "status": "error", "error": e.to_string() }));
        cards.push(json!({
            "label": sc.label,
            "note": sc.note,
            "status": resp.get("status").cloned().unwrap_or(Value::Null),
            "renderedCard": resp.get("renderedCard").cloned().unwrap_or(Value::Null),
        }));
    }

    let data = serde_json::to_string(&cards).unwrap_or_else(|_| "[]".to_string());
    let html = HTML_TEMPLATE.replace("/*DATA*/", &data);
    let out_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/oauth-card-gallery.html"
    );
    std::fs::write(out_path, html).expect("write gallery html");
    println!("Wrote gallery: {out_path}");
    println!("Open it:  open {out_path}");
}

const HTML_TEMPLATE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>OAuth Card Gallery</title>
<script src="https://unpkg.com/adaptivecards@3/dist/adaptivecards.min.js"></script>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background:#f3f4f6; margin:0; padding:24px; }
  h1 { font-size:18px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:20px; }
  .cell { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:14px; box-shadow:0 1px 3px rgba(0,0,0,.06); }
  .lbl { font-weight:600; font-size:13px; margin-bottom:2px; }
  .note { color:#6b7280; font-size:11px; margin-bottom:6px; }
  .badge { display:inline-block; font-size:10px; padding:1px 6px; border-radius:10px; background:#eef2ff; color:#3730a3; margin-bottom:8px; }
  .none { color:#9ca3af; font-style:italic; font-size:12px; }
  .ac-container { border-top:1px dashed #e5e7eb; padding-top:10px; }
  details { margin-top:8px; } summary { cursor:pointer; font-size:11px; color:#6b7280; }
  pre { background:#0b1021; color:#cbd5e1; padding:8px; border-radius:6px; overflow:auto; font-size:10px; }
</style></head>
<body>
<h1>OAuth Card Gallery <span class="note">(component-oauth-card renderedCard, Adaptive Cards 1.5)</span></h1>
<div class="grid" id="grid"></div>
<script>
const DATA = /*DATA*/;
const grid = document.getElementById('grid');
for (const item of DATA) {
  const cell = document.createElement('div'); cell.className='cell';
  cell.innerHTML = '<div class="lbl">'+item.label+'</div>'
    + '<div class="note">'+item.note+'</div>'
    + '<span class="badge">status: '+(item.status ?? '—')+'</span>';
  const holder = document.createElement('div'); holder.className='ac-container';
  if (item.renderedCard) {
    try {
      const ac = new AdaptiveCards.AdaptiveCard();
      ac.parse(item.renderedCard);
      holder.appendChild(ac.render());
    } catch (e) { holder.innerHTML = '<span class="none">render error: '+e+'</span>'; }
    const d = document.createElement('details');
    d.innerHTML = '<summary>JSON</summary><pre>'+JSON.stringify(item.renderedCard,null,2)+'</pre>';
    cell.appendChild(holder); cell.appendChild(d);
  } else {
    holder.innerHTML = '<span class="none">no card (e.g. ok/token passthrough, or error)</span>';
    cell.appendChild(holder);
  }
  grid.appendChild(cell);
}
</script>
</body></html>"#;
