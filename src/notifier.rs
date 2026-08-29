use crate::pp::PP;
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
    name: Option<String>,
}

impl Notifier {
    pub fn disabled() -> Self {
        Self {
            telegram: None,
            name: None,
        }
    }

    pub fn telegram(notifier: TelegramNotifier) -> Self {
        Self {
            telegram: Some(notifier),
            name: None,
        }
    }

    /// Instance name shown at the front of the summary line, so notifications
    /// from several instances sharing one bot can be told apart.
    pub fn named(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub async fn send(&self, message: &Message, ppfmt: &PP) {
        if message.is_empty() {
            return;
        }

        if let Some(telegram) = &self.telegram {
            let text = self.render(message);
            if !telegram.send_text(&text).await {
                ppfmt.warningf("Failed to send Telegram notification");
            }
        }
    }

    /// The first line summarizes the outcome (`Message::ok`) so it is readable
    /// in the notification tray; the per-target lines follow.
    fn render(&self, message: &Message) -> String {
        let status = if message.ok {
            "更新成功"
        } else {
            "更新失败"
        };
        match &self.name {
            Some(name) => format!("【{name}】ipflare {status}\n{}", message.format()),
            None => format!("ipflare {status}\n{}", message.format()),
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

    pub(crate) fn with_api_base(
        bot_token: &str,
        chat_id: &str,
        api_base: &str,
    ) -> Result<Self, String> {
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

    async fn send_text(&self, text: &str) -> bool {
        let url = format!("{}/bot{}/sendMessage", self.api_base, self.bot_token);
        self.client
            .post(url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text
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

        assert!(notifier.send_text("updated example.com").await);
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

        assert!(!notifier.send_text("failed").await);
    }

    #[tokio::test]
    async fn prefixes_summary_with_instance_name() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bottest-token/sendMessage"))
            .and(body_partial_json(serde_json::json!({
                "text": "【home】ipflare 更新成功\nupdated example.com"
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = Notifier::telegram(
            TelegramNotifier::with_api_base("test-token", "-100123", &server.uri()).unwrap(),
        )
        .named(Some("home".to_string()));

        notifier
            .send(&Message::new_ok("updated example.com"), &PP::new(true))
            .await;
    }
}
