use crate::pp::PP;
use reqwest::Client;
use std::time::Duration;

pub struct Notifier {
    telegram: Option<TelegramNotifier>,
    bark: Option<BarkNotifier>,
    /// Shown at the front of the summary line, so notifications from several
    /// instances sharing one account can be told apart.
    name: Option<String>,
}

impl Notifier {
    /// A notifier without channels; add the configured ones with
    /// [`Notifier::with_telegram`] and [`Notifier::with_bark`]. With nothing
    /// added the notifier simply never sends.
    pub fn new(name: Option<String>) -> Self {
        Self {
            telegram: None,
            bark: None,
            name,
        }
    }

    pub fn with_telegram(mut self, notifier: TelegramNotifier) -> Self {
        self.telegram = Some(notifier);
        self
    }

    pub fn with_bark(mut self, notifier: BarkNotifier) -> Self {
        self.bark = Some(notifier);
        self
    }

    /// Send one notification listing `lines` to every configured channel, or
    /// nothing when there is nothing to report.
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

        if let Some(bark) = &self.bark {
            // Bark splits the message into a title and a body, so the summary
            // line becomes the title instead of the first body line.
            let body = lines.join("\n");
            if !bark.send(&self.summary(), &body).await {
                ppfmt.warningf("Failed to send Bark notification");
            }
        }
    }

    /// The first line identifies the instance in the notification tray; the
    /// per-target change lines follow. Only content changes are notified.
    fn render(&self, lines: &[String]) -> String {
        format!("{}\n{}", self.summary(), lines.join("\n"))
    }

    fn summary(&self) -> String {
        match &self.name {
            Some(name) => format!("【{name}】ipflare 更新成功"),
            None => "ipflare 更新成功".to_string(),
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

/// Bark (https://github.com/Finb/Bark) push client, usable against the public
/// server or a self-hosted one.
pub struct BarkNotifier {
    client: Client,
    server: String,
    device_key: String,
    group: Option<String>,
}

impl BarkNotifier {
    /// `server` is the base URL without a trailing slash.
    pub fn new(device_key: &str, server: &str, group: Option<String>) -> Result<Self, String> {
        let client_builder = Client::builder().timeout(Duration::from_secs(10));
        #[cfg(test)]
        let client_builder = client_builder.no_proxy();
        let client = client_builder
            .build()
            .map_err(|error| format!("Failed to build Bark HTTP client: {error}"))?;

        Ok(Self {
            client,
            server: server.trim_end_matches('/').to_string(),
            device_key: device_key.to_string(),
            group,
        })
    }

    /// Bark has distinct title and body fields, so the summary does not have to
    /// be the first line of one long message as it is for Telegram.
    async fn send(&self, title: &str, body: &str) -> bool {
        let url = format!("{}/push", self.server);
        let mut payload = serde_json::json!({
            "device_key": self.device_key,
            "title": title,
            "body": body,
        });
        if let Some(group) = &self.group {
            payload["group"] = serde_json::Value::String(group.clone());
        }

        self.client
            .post(url)
            .json(&payload)
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
        let notifier = Notifier::new(None);
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
        Mock::given(method("POST"))
            .and(path("/push"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let notifier = Notifier::new(None)
            .with_telegram(
                TelegramNotifier::with_api_base("test-token", "1", &server.uri()).unwrap(),
            )
            .with_bark(BarkNotifier::new("device-key", &server.uri(), None).unwrap());
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

        let notifier = Notifier::new(Some("home".to_string())).with_telegram(
            TelegramNotifier::with_api_base("test-token", "-100123", &server.uri()).unwrap(),
        );

        notifier
            .send(&["updated example.com".to_string()], &PP::new(true))
            .await;
    }

    #[tokio::test]
    async fn sends_bark_json_and_prefixes_the_title() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .and(body_partial_json(serde_json::json!({
                "device_key": "test-key",
                "title": "【home】ipflare 更新成功",
                "body": "updated example.com"
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = Notifier::new(Some("home".to_string()))
            .with_bark(BarkNotifier::new("test-key", &server.uri(), None).unwrap());

        notifier
            .send(&["updated example.com".to_string()], &PP::new(true))
            .await;
    }

    /// A configured group is forwarded so the push can be filed separately.
    #[tokio::test]
    async fn sends_bark_group_when_configured() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .and(body_partial_json(serde_json::json!({
                "device_key": "test-key",
                "group": "ipflare"
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = Notifier::new(None).with_bark(
            BarkNotifier::new("test-key", &server.uri(), Some("ipflare".to_string())).unwrap(),
        );

        notifier
            .send(&["updated example.com".to_string()], &PP::new(true))
            .await;
    }

    /// Both channels are pushed independently, with a failure on neither
    /// suppressing the other.
    #[tokio::test]
    async fn sends_to_every_configured_channel() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bottest-token/sendMessage"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = Notifier::new(None)
            .with_telegram(
                TelegramNotifier::with_api_base("test-token", "1", &server.uri()).unwrap(),
            )
            .with_bark(BarkNotifier::new("test-key", &server.uri(), None).unwrap());

        notifier
            .send(&["updated example.com".to_string()], &PP::new(true))
            .await;
    }

    /// A failing Bark server must not stop the Telegram push, and the failure
    /// must be reported rather than silently ignored.
    #[tokio::test]
    async fn a_failing_bark_server_does_not_block_telegram() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/bottest-token/sendMessage"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = Notifier::new(None)
            .with_bark(BarkNotifier::new("test-key", &server.uri(), None).unwrap())
            .with_telegram(
                TelegramNotifier::with_api_base("test-token", "1", &server.uri()).unwrap(),
            );

        notifier
            .send(&["updated example.com".to_string()], &PP::new(true))
            .await;
    }

    #[tokio::test]
    async fn reports_bark_http_failure() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = BarkNotifier::new("test-key", &server.uri(), None).unwrap();

        assert!(!notifier.send("title", "body").await);
    }

    /// A self-hosted server configured with a trailing slash must not produce a
    /// doubled path separator.
    #[tokio::test]
    async fn trims_trailing_slash_from_the_bark_server() {
        crate::init_crypto();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = BarkNotifier::new("test-key", &format!("{}/", server.uri()), None).unwrap();

        assert!(notifier.send("title", "body").await);
    }
}
