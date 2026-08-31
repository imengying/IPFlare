use crate::pp::PP;
use reqwest::Client;
use std::time::Duration;

pub struct Notifier {
    telegram: Option<TelegramNotifier>,
    /// Shown at the front of the summary line, so notifications from several
    /// instances sharing one bot can be told apart.
    name: Option<String>,
}

impl Notifier {
    pub fn disabled() -> Self {
        Self {
            telegram: None,
            name: None,
        }
    }

    pub fn telegram(notifier: TelegramNotifier, name: Option<String>) -> Self {
        Self {
            telegram: Some(notifier),
            name,
        }
    }

    /// Send one notification listing `lines`, or nothing when there is nothing
    /// to report.
    pub async fn send(&self, lines: &[String], ppfmt: &PP) {
        if lines.is_empty() {
            return;
        }

        if let Some(telegram) = &self.telegram {
            let text = self.render(lines);
            if !telegram.send_text(&text).await {
                ppfmt.warningf("Failed to send Telegram notification");
            }
        }
    }

    /// The first line identifies the instance in the notification tray; the
    /// per-target change lines follow. Only content changes are notified.
    fn render(&self, lines: &[String]) -> String {
        let body = lines.join("\n");
        match &self.name {
            Some(name) => format!("【{name}】ipflare 更新成功\n{body}"),
            None => format!("ipflare 更新成功\n{body}"),
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

    /// Several change lines are joined under one summary header.
    #[test]
    fn joins_lines_under_the_summary_header() {
        let notifier = Notifier::disabled();
        assert_eq!(
            notifier.render(&[
                "updated example.com".to_string(),
                "updated example.net".to_string(),
            ]),
            "ipflare 更新成功\nupdated example.com\nupdated example.net"
        );
    }

    /// Nothing to report means no request at all, not an empty message.
    #[tokio::test]
    async fn sends_nothing_when_there_are_no_lines() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bottest-token/sendMessage"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let notifier = Notifier::telegram(
            TelegramNotifier::with_api_base("test-token", "1", &server.uri()).unwrap(),
            None,
        );
        notifier.send(&[], &PP::new(true)).await;
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
            Some("home".to_string()),
        );

        notifier
            .send(&["updated example.com".to_string()], &PP::new(true))
            .await;
    }
}
