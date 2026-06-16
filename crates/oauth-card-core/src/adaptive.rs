//! Render a [`MessageCard`] into Adaptive Card 1.5 JSON.
//!
//! Channels like webchat-gui (Bot Framework Web Chat) render Adaptive Cards
//! natively and do not understand this component's bespoke `MessageCard` shape.
//! The greentic-start messaging bridge surfaces a node output's `renderedCard`
//! field into `metadata.adaptive_card` (and the `adaptive_card` extension),
//! which the channel then renders. We therefore emit `renderedCard` alongside
//! the channel-agnostic `card` so the OAuth sign-in / status card is actually
//! shown to the user.

use crate::model::{Action, MessageCard};
use serde_json::{Value, json};

const ADAPTIVE_CARD_SCHEMA: &str = "http://adaptivecards.io/schemas/adaptive-card.json";
const ADAPTIVE_CARD_VERSION: &str = "1.5";

/// Convert a [`MessageCard`] into an Adaptive Card 1.5 document.
///
/// `open_url` actions become `Action.OpenUrl` (e.g. the OAuth Connect button
/// pointing at the consent / sign-in URL); `post_back` actions become
/// `Action.Submit` carrying their `data` so the channel posts it back to the
/// flow. If the card already carries a fully-formed Adaptive Card in its
/// `adaptive` field, that payload is passed through unchanged.
pub fn render_adaptive_card(card: &MessageCard) -> Value {
    if let Some(adaptive) = &card.adaptive
        && adaptive.get("type").and_then(Value::as_str) == Some("AdaptiveCard")
    {
        return adaptive.clone();
    }

    let mut body: Vec<Value> = Vec::new();
    if let Some(title) = &card.title {
        body.push(json!({
            "type": "TextBlock",
            "text": title,
            "weight": "Bolder",
            "size": "Large",
            "wrap": true
        }));
    }
    if let Some(text) = &card.text {
        body.push(json!({
            "type": "TextBlock",
            "text": text,
            "wrap": true,
            "spacing": "Small"
        }));
    }
    for image in &card.images {
        let mut img = json!({ "type": "Image", "url": image.url });
        if let Some(alt) = &image.alt {
            img["altText"] = Value::String(alt.clone());
        }
        body.push(img);
    }
    if let Some(footer) = &card.footer {
        body.push(json!({
            "type": "TextBlock",
            "text": footer,
            "wrap": true,
            "isSubtle": true,
            "size": "Small",
            "spacing": "Medium"
        }));
    }

    let actions: Vec<Value> = card
        .actions
        .iter()
        .map(|action| match action {
            Action::OpenUrl { title, url } => json!({
                "type": "Action.OpenUrl",
                "title": title,
                "url": url
            }),
            Action::PostBack { title, data } => json!({
                "type": "Action.Submit",
                "title": title,
                "data": data
            }),
        })
        .collect();

    json!({
        "$schema": ADAPTIVE_CARD_SCHEMA,
        "type": "AdaptiveCard",
        "version": ADAPTIVE_CARD_VERSION,
        "body": body,
        "actions": actions
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::{ImageRef, MessageCard, MessageCardKind};

    fn sign_in_card() -> MessageCard {
        MessageCard {
            kind: MessageCardKind::Oauth,
            title: Some("Connect github account".into()),
            text: Some("Click Connect to sign in.".into()),
            footer: None,
            images: vec![ImageRef {
                url: "https://example.com/logo.png".into(),
                alt: Some("logo".into()),
            }],
            actions: vec![
                Action::OpenUrl {
                    title: "Connect".into(),
                    url: "https://consent.example".into(),
                },
                Action::PostBack {
                    title: "Continue".into(),
                    data: json!({ "mode": "complete-sign-in" }),
                },
            ],
            allow_markdown: true,
            adaptive: None,
            oauth: None,
        }
    }

    #[test]
    fn renders_adaptive_card_envelope() {
        let card = render_adaptive_card(&sign_in_card());
        assert_eq!(card["type"], "AdaptiveCard");
        assert_eq!(card["version"], "1.5");
        // title + text + image => 3 body elements
        assert_eq!(card["body"].as_array().expect("body").len(), 3);
        assert_eq!(card["body"][2]["type"], "Image");
        assert_eq!(card["body"][2]["altText"], "logo");
    }

    #[test]
    fn maps_open_url_and_post_back_actions() {
        let card = render_adaptive_card(&sign_in_card());
        let actions = card["actions"].as_array().expect("actions");
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0]["type"], "Action.OpenUrl");
        assert_eq!(actions[0]["url"], "https://consent.example");
        assert_eq!(actions[1]["type"], "Action.Submit");
        assert_eq!(actions[1]["data"]["mode"], "complete-sign-in");
    }

    #[test]
    fn passes_through_prebuilt_adaptive_payload() {
        let mut card = sign_in_card();
        card.adaptive = Some(json!({
            "type": "AdaptiveCard",
            "version": "1.5",
            "body": [{ "type": "TextBlock", "text": "custom" }]
        }));
        let rendered = render_adaptive_card(&card);
        assert_eq!(rendered["body"][0]["text"], "custom");
        // The pre-built payload wins: no generated actions are appended.
        assert!(rendered.get("actions").is_none());
    }
}
