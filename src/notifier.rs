use crate::pp::{self, PP};
use reqwest::Client;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Message {
    pub lines: Vec<String>,
    pub ok: bool,
}

impl Message {
    pub fn new_ok(msg: &str) -> Self {
        Self {
            lines: vec![msg.to_string()],
            ok: true,
        }
    }

    pub fn new_fail(msg: &str) -> Self {
        Self {
            lines: vec![msg.to_string()],
            ok: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn format(&self) -> String {
        self.lines.join("\n")
    }

    pub fn merge(messages: Vec<Message>) -> Self {
        let mut lines = Vec::new();
        let mut ok = true;
        for message in messages {
            lines.extend(message.lines);
            ok &= message.ok;
        }
        Self { lines, ok }
    }
}

pub struct Notifier {
    telegram: Option<TelegramNotifier>,
}

impl Notifier {
    pub fn disabled() -> Self {
        Self { telegram: None }
    }

    pub fn telegram(notifier: TelegramNotifier) -> Self {
        Self {
            telegram: Some(notifier),
        }
    }

    pub async fn send(&self, message: &Message, ppfmt: &PP) {
        if message.is_empty() {
            return;
        }

        if let Some(telegram) = &self.telegram {
            if !telegram.send(message).await {
                ppfmt.warningf(pp::EMOJI_WARNING, "Failed to send Telegram notification");
            }
        }
    }
}

pub struct TelegramNotifier {
    client: Client,
    api_base: String,
    bot_token: String,
    chat_id: String,
}

impl TelegramNotifier {
    pub fn new(bot_token: &str, chat_id: &str) -> Result<Self, String> {
        Self::with_api_base(bot_token, chat_id, "https://api.telegram.org")
    }

    fn with_api_base(bot_token: &str, chat_id: &str, api_base: &str) -> Result<Self, String> {
        let client_builder = Client::builder().timeout(Duration::from_secs(10));
        #[cfg(test)]
        let client_builder = client_builder.no_proxy();
        let client = client_builder
            .build()
            .map_err(|error| format!("Failed to build Telegram HTTP client: {error}"))?;

        Ok(Self {
            client,
            api_base: api_base.trim_end_matches('/').to_string(),
            bot_token: bot_token.to_string(),
            chat_id: chat_id.to_string(),
        })
    }

    async fn send(&self, message: &Message) -> bool {
        let url = format!("{}/bot{}/sendMessage", self.api_base, self.bot_token);
        self.client
            .post(url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": message.format()
            }))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn merges_messages_and_preserves_failure() {
        let merged = Message::merge(vec![
            Message::new_ok("updated example.com"),
            Message::new_fail("failed example.net"),
        ]);

        assert_eq!(merged.format(), "updated example.com\nfailed example.net");
        assert!(!merged.ok);
    }

    #[test]
    fn merges_empty_messages() {
        let merged = Message::merge(Vec::new());
        assert!(merged.is_empty());
        assert!(merged.ok);
    }

    #[tokio::test]
    async fn sends_telegram_json() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bottest-token/sendMessage"))
            .and(body_partial_json(serde_json::json!({
                "chat_id": "-100123",
                "text": "updated example.com"
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier =
            TelegramNotifier::with_api_base("test-token", "-100123", &server.uri()).unwrap();

        assert!(notifier.send(&Message::new_ok("updated example.com")).await);
    }

    #[tokio::test]
    async fn reports_telegram_http_failure() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bottest-token/sendMessage"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = TelegramNotifier::with_api_base("test-token", "123", &server.uri()).unwrap();

        assert!(!notifier.send(&Message::new_fail("failed")).await);
    }
}
