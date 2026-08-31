use crate::cloudflare::{Auth, Ttl, WAFList};
use crate::domain;
use crate::notifier::{Notifier, TelegramNotifier};
use crate::pp::PP;
use crate::provider::{IpType, ProviderType};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

const CONFIG_FILE: &str = "config.json";

/// Runtime configuration after parsing and validating `config.json`.
pub struct AppConfig {
    pub auth: Auth,
    pub account_id: String,
    pub zone_id: String,
    pub providers: HashMap<IpType, ProviderType>,
    pub domains: HashMap<IpType, Vec<String>>,
    pub waf_lists: Vec<WAFList>,
    pub update_cron: CronSchedule,
    pub update_on_start: bool,
    pub delete_on_stop: bool,
    pub delete_on_failure: bool,
    pub ttl: Ttl,
    pub proxied: bool,
    pub record_comment: Option<String>,
    pub managed_comment_regex: Option<regex_lite::Regex>,
    pub waf_list_item_comment: Option<String>,
    pub managed_waf_comment_regex: Option<regex_lite::Regex>,
    pub detection_timeout: Duration,
    pub update_timeout: Duration,
    pub reject_cloudflare_ips: bool,
    pub dry_run: bool,
    pub quiet: bool,
    pub name: Option<String>,
    pub telegram: Option<TelegramConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Debug, Clone)]
pub enum CronSchedule {
    Every(Duration),
    Once,
}

impl CronSchedule {
    pub fn describe(&self) -> String {
        match self {
            CronSchedule::Every(duration) => format!("@every {}s", duration.as_secs()),
            CronSchedule::Once => "@once".to_string(),
        }
    }

    pub fn next_duration(&self) -> Option<Duration> {
        match self {
            CronSchedule::Every(duration) => Some(*duration),
            CronSchedule::Once => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    api_token: String,
    account_id: String,
    zone_id: String,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ipv4_domains: Vec<String>,
    #[serde(default)]
    ipv6_domains: Vec<String>,
    #[serde(default = "default_ipv4_provider")]
    ipv4_provider: String,
    #[serde(default = "default_ipv6_provider")]
    ipv6_provider: String,
    #[serde(default)]
    waf_lists: Vec<String>,
    #[serde(default = "default_schedule")]
    schedule: String,
    #[serde(default = "default_true")]
    update_on_start: bool,
    #[serde(default)]
    delete_on_stop: bool,
    #[serde(default)]
    delete_on_failure: bool,
    #[serde(default = "default_ttl")]
    ttl: i64,
    #[serde(default)]
    proxied: bool,
    #[serde(default)]
    record_comment: Option<String>,
    #[serde(default)]
    managed_records_comment_regex: Option<String>,
    #[serde(default)]
    waf_list_item_comment: Option<String>,
    #[serde(default)]
    managed_waf_list_items_comment_regex: Option<String>,
    #[serde(default = "default_detection_timeout")]
    detection_timeout: String,
    #[serde(default = "default_update_timeout")]
    update_timeout: String,
    #[serde(default = "default_true")]
    reject_cloudflare_ips: bool,
    #[serde(default)]
    quiet: bool,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    telegram: Option<TelegramConfig>,
}

fn default_true() -> bool {
    true
}

fn default_ipv4_provider() -> String {
    "cloudflare.trace".to_string()
}

fn default_ipv6_provider() -> String {
    "none".to_string()
}

fn default_schedule() -> String {
    "@every 5m".to_string()
}

fn default_ttl() -> i64 {
    1
}

fn default_detection_timeout() -> String {
    "10s".to_string()
}

fn default_update_timeout() -> String {
    "30s".to_string()
}

fn parse_duration(input: &str, field: &str) -> Result<Duration, String> {
    let input = input.trim();
    let (number, multiplier) = if let Some(value) = input.strip_suffix('s') {
        (value, 1)
    } else if let Some(value) = input.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = input.strip_suffix('h') {
        (value, 60 * 60)
    } else {
        (input, 1)
    };

    let value = number
        .parse::<u64>()
        .map_err(|_| format!("Invalid {field} duration '{input}'"))?;
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("{field} duration is too large"))?;
    if seconds == 0 {
        return Err(format!("{field} duration must be greater than zero"));
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_schedule(input: &str) -> Result<CronSchedule, String> {
    let input = input.trim();
    if input == "@once" {
        return Ok(CronSchedule::Once);
    }
    let duration = input.strip_prefix("@every ").ok_or_else(|| {
        format!("Invalid schedule '{input}'; expected '@every <duration>' or '@once'")
    })?;
    Ok(CronSchedule::Every(parse_duration(duration, "schedule")?))
}

fn parse_regex(value: Option<String>, field: &str) -> Result<Option<regex_lite::Regex>, String> {
    non_empty(value)
        .map(|pattern| {
            regex_lite::Regex::new(&pattern)
                .map_err(|error| format!("Invalid {field} regex: {error}"))
        })
        .transpose()
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn clean_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn clean_domains(values: Vec<String>, field: &str) -> Result<Vec<String>, String> {
    let mut domains = Vec::new();
    for value in values {
        if value.trim().is_empty() {
            continue;
        }
        let normalized = domain::normalize_name(&value)
            .map_err(|error| format!("Invalid {field} entry: {error}"))?;
        if !domains.contains(&normalized) {
            domains.push(normalized);
        }
    }
    Ok(domains)
}

fn parse_resource_id(value: &str, field: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() != 32 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(format!(
            "{field} must be a 32-character hexadecimal Cloudflare ID"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_telegram(config: Option<TelegramConfig>) -> Result<Option<TelegramConfig>, String> {
    config
        .map(|config| {
            let bot_token = config.bot_token.trim().to_string();
            let chat_id = config.chat_id.trim().to_string();
            if bot_token.is_empty() {
                return Err("telegram.bot_token must not be empty".to_string());
            }
            if chat_id.is_empty() {
                return Err("telegram.chat_id must not be empty".to_string());
            }
            Ok(TelegramConfig { bot_token, chat_id })
        })
        .transpose()
}

fn parse_config_content(content: &str, dry_run: bool) -> Result<AppConfig, String> {
    let file: FileConfig = serde_json::from_str(content)
        .map_err(|error| format!("Error parsing {CONFIG_FILE}: {error}"))?;

    let api_token = file.api_token.trim();
    if api_token.is_empty() {
        return Err("api_token must not be empty".to_string());
    }
    let account_id = parse_resource_id(&file.account_id, "account_id")?;
    let zone_id = parse_resource_id(&file.zone_id, "zone_id")?;

    let ipv4_provider = ProviderType::parse(&file.ipv4_provider)
        .map_err(|error| format!("Invalid ipv4_provider: {error}"))?;
    let ipv6_provider = ProviderType::parse(&file.ipv6_provider)
        .map_err(|error| format!("Invalid ipv6_provider: {error}"))?;
    let ipv4_enabled = !matches!(ipv4_provider, ProviderType::None);
    let ipv6_enabled = !matches!(ipv6_provider, ProviderType::None);
    let mut providers = HashMap::new();
    if ipv4_enabled {
        providers.insert(IpType::V4, ipv4_provider);
    }
    if ipv6_enabled {
        providers.insert(IpType::V6, ipv6_provider);
    }

    let shared_domains = clean_domains(file.domains, "domains")?;
    let mut ipv4_domains = shared_domains.clone();
    ipv4_domains.extend(clean_domains(file.ipv4_domains, "ipv4_domains")?);
    ipv4_domains.sort();
    ipv4_domains.dedup();
    let mut ipv6_domains = shared_domains;
    ipv6_domains.extend(clean_domains(file.ipv6_domains, "ipv6_domains")?);
    ipv6_domains.sort();
    ipv6_domains.dedup();
    let mut domains = HashMap::new();
    if ipv4_enabled && !ipv4_domains.is_empty() {
        domains.insert(IpType::V4, ipv4_domains);
    }
    if ipv6_enabled && !ipv6_domains.is_empty() {
        domains.insert(IpType::V6, ipv6_domains);
    }

    let waf_lists = clean_list(file.waf_lists)
        .into_iter()
        .map(|value| WAFList::new(&account_id, &value))
        .collect::<Result<Vec<_>, _>>()?;
    if domains.is_empty() && waf_lists.is_empty() {
        return Err(
            "No update targets configured; add domains, ipv4_domains, ipv6_domains, or waf_lists"
                .to_string(),
        );
    }

    let update_cron = parse_schedule(&file.schedule)?;
    if matches!(update_cron, CronSchedule::Once) {
        if !file.update_on_start {
            return Err("update_on_start must be true when schedule is @once".to_string());
        }
        if file.delete_on_stop {
            return Err("delete_on_stop must be false when schedule is @once".to_string());
        }
    }

    let record_comment = non_empty(file.record_comment);
    let managed_comment_regex = parse_regex(
        file.managed_records_comment_regex,
        "managed_records_comment_regex",
    )?;
    if let Some(regex) = &managed_comment_regex {
        let comment = record_comment.as_deref().unwrap_or("");
        if !regex.is_match(comment) {
            return Err(format!(
                "record_comment '{comment}' does not match managed_records_comment_regex '{}'",
                regex.as_str()
            ));
        }
    }
    let waf_list_item_comment = non_empty(file.waf_list_item_comment);
    let managed_waf_comment_regex = parse_regex(
        file.managed_waf_list_items_comment_regex,
        "managed_waf_list_items_comment_regex",
    )?;
    if let Some(regex) = &managed_waf_comment_regex {
        let comment = waf_list_item_comment.as_deref().unwrap_or("");
        if !regex.is_match(comment) {
            return Err(format!(
                "waf_list_item_comment '{comment}' does not match managed_waf_list_items_comment_regex '{}'",
                regex.as_str()
            ));
        }
    }

    Ok(AppConfig {
        auth: Auth::token(api_token),
        account_id,
        zone_id,
        providers,
        domains,
        waf_lists,
        update_cron,
        update_on_start: file.update_on_start,
        delete_on_stop: file.delete_on_stop,
        delete_on_failure: file.delete_on_failure,
        ttl: Ttl::new(file.ttl),
        proxied: file.proxied,
        record_comment,
        managed_comment_regex,
        waf_list_item_comment,
        managed_waf_comment_regex,
        detection_timeout: parse_duration(&file.detection_timeout, "detection_timeout")?,
        update_timeout: parse_duration(&file.update_timeout, "update_timeout")?,
        reject_cloudflare_ips: file.reject_cloudflare_ips,
        dry_run,
        quiet: file.quiet,
        name: non_empty(file.name),
        telegram: parse_telegram(file.telegram)?,
    })
}

pub fn load_config(dry_run: bool) -> Result<AppConfig, String> {
    let content = std::fs::read_to_string(CONFIG_FILE)
        .map_err(|error| format!("Error reading {CONFIG_FILE}: {error}"))?;
    parse_config_content(&content, dry_run)
}

pub fn setup_notifier(config: &AppConfig, ppfmt: &PP) -> Notifier {
    let Some(telegram) = &config.telegram else {
        return Notifier::disabled();
    };

    match TelegramNotifier::new(&telegram.bot_token, &telegram.chat_id) {
        Ok(notifier) => {
            ppfmt.infof("Notifications: Telegram");
            Notifier::telegram(notifier, config.name.clone())
        }
        Err(error) => {
            ppfmt.warningf(&format!("Failed to setup Telegram notifications: {error}"));
            Notifier::disabled()
        }
    }
}

pub fn print_config_summary(config: &AppConfig, ppfmt: &PP) {
    let inner = ppfmt.indent();
    ppfmt.infof("Configuration:");
    if let Some(name) = &config.name {
        inner.infof(&format!("Instance name: {name}"));
    }
    inner.infof(&format!("Account ID: {}", config.account_id));
    inner.infof(&format!("Zone ID: {}", config.zone_id));

    for ip_type in [IpType::V4, IpType::V6] {
        if let Some(domains) = config.domains.get(&ip_type) {
            inner.infof(&format!(
                "{} domains: {}",
                ip_type.describe(),
                domains.join(", ")
            ));
        }
        if let Some(provider) = config.providers.get(&ip_type) {
            inner.infof(&format!(
                "{} provider: {}",
                ip_type.describe(),
                provider.name()
            ));
        }
    }

    for waf_list in &config.waf_lists {
        inner.infof(&format!("WAF list: {}", waf_list.describe()));
    }
    inner.infof(&format!("TTL: {}", config.ttl.describe()));
    inner.infof(&format!("Schedule: {}", config.update_cron.describe()));
    if config.delete_on_stop {
        inner.infof("Delete on stop: enabled");
    }
    if !config.reject_cloudflare_ips {
        inner.warningf("Cloudflare IP rejection: disabled");
    }
    if let Some(comment) = &config.record_comment {
        inner.infof(&format!("Record comment: {comment}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(extra: &str) -> String {
        format!(
            r#"{{
                "api_token": "test-token",
                "account_id": "11111111111111111111111111111111",
                "zone_id": "22222222222222222222222222222222",
                "domains": ["example.com"],
                {extra}
                "quiet": true
            }}"#
        )
    }

    #[test]
    fn parses_minimal_config_with_defaults() {
        let config = parse_config_content(&minimal_config(""), false).unwrap();
        assert_eq!(config.auth.0, "test-token");
        assert_eq!(config.domains[&IpType::V4], ["example.com"]);
        assert!(!config.domains.contains_key(&IpType::V6));
        assert!(
            matches!(config.update_cron, CronSchedule::Every(duration) if duration == Duration::from_secs(300))
        );
        assert_eq!(config.ttl, Ttl::AUTO);
    }

    #[test]
    fn example_config_is_valid() {
        parse_config_content(include_str!("../config-example.json"), false).unwrap();
    }

    #[test]
    fn separates_ip_specific_domains() {
        let config = parse_config_content(
            r#"{
                "api_token": "test-token",
                "account_id": "11111111111111111111111111111111",
                "zone_id": "22222222222222222222222222222222",
                "ipv4_domains": ["v4.example.com"],
                "ipv6_domains": ["v6.example.com"],
                "ipv6_provider": "cloudflare.trace"
            }"#,
            false,
        )
        .unwrap();
        assert_eq!(config.domains[&IpType::V4], ["v4.example.com"]);
        assert_eq!(config.domains[&IpType::V6], ["v6.example.com"]);
    }

    #[test]
    fn normalizes_and_deduplicates_idn_domains() {
        let config = parse_config_content(
            &minimal_config(r#""ipv4_domains": ["例子.COM", "xn--fsqu00a.com"],"#),
            false,
        )
        .unwrap();
        assert_eq!(
            config.domains[&IpType::V4],
            ["example.com", "xn--fsqu00a.com"]
        );
    }

    #[test]
    fn rejects_mismatched_waf_managed_comment() {
        let error = parse_config_content(
            &minimal_config(
                r#""waf_list_item_comment": "ipflare", "managed_waf_list_items_comment_regex": "^other$","#,
            ),
            false,
        )
        .err()
        .unwrap();
        assert!(error.contains("waf_list_item_comment"));
    }

    #[test]
    fn rejects_missing_comments_when_managed_regex_requires_them() {
        let dns = minimal_config(r#""managed_records_comment_regex": "^ipflare$","#);
        let error = parse_config_content(&dns, false).err().unwrap();
        assert!(error.contains("record_comment"));

        let waf = minimal_config(r#""managed_waf_list_items_comment_regex": "^ipflare$","#);
        let error = parse_config_content(&waf, false).err().unwrap();
        assert!(error.contains("waf_list_item_comment"));
    }

    #[test]
    fn disabled_provider_removes_that_address_family() {
        let config =
            parse_config_content(&minimal_config(r#""ipv6_provider": "none","#), false).unwrap();
        assert!(config.domains.contains_key(&IpType::V4));
        assert!(!config.domains.contains_key(&IpType::V6));
        assert!(!config.providers.contains_key(&IpType::V6));
    }

    #[test]
    fn parses_instance_name() {
        let config = parse_config_content(&minimal_config(r#""name": " home ","#), false).unwrap();
        assert_eq!(config.name.as_deref(), Some("home"));
        let config = parse_config_content(&minimal_config(""), false).unwrap();
        assert_eq!(config.name, None);
    }

    #[test]
    fn parses_telegram_notification() {
        let config = parse_config_content(
            &minimal_config(
                r#""telegram": {
                       "bot_token": "bot-token",
                       "chat_id": "-100123"
                   },
                "#,
            ),
            false,
        )
        .unwrap();
        let telegram = config.telegram.unwrap();
        assert_eq!(telegram.bot_token, "bot-token");
        assert_eq!(telegram.chat_id, "-100123");
    }

    #[test]
    fn rejects_invalid_fields() {
        let error = parse_config_content(
            r#"{
                "api_token": "test-token",
                "account_id": "11111111111111111111111111111111",
                "zone_id": "22222222222222222222222222222222",
                "domains": ["example.com"],
                "unsupported": true
            }"#,
            false,
        )
        .err()
        .unwrap();
        assert!(error.contains("unknown field `unsupported`"));
    }

    #[test]
    fn rejects_invalid_schedule() {
        let error = parse_config_content(&minimal_config(r#""schedule": "*/5 * * * *","#), false)
            .err()
            .unwrap();
        assert!(error.contains("Invalid schedule"));
    }

    #[test]
    fn rejects_zero_interval() {
        let error = parse_config_content(&minimal_config(r#""schedule": "@every 0s","#), false)
            .err()
            .unwrap();
        assert!(error.contains("greater than zero"));
    }

    #[test]
    fn rejects_once_with_delete_on_stop() {
        let error = parse_config_content(
            &minimal_config(r#""schedule": "@once", "delete_on_stop": true,"#),
            false,
        )
        .err()
        .unwrap();
        assert!(error.contains("delete_on_stop"));
    }

    #[test]
    fn rejects_invalid_provider() {
        let error = parse_config_content(&minimal_config(r#""ipv4_provider": "unknown","#), false)
            .err()
            .unwrap();
        assert!(error.contains("Invalid ipv4_provider"));
    }

    #[test]
    fn rejects_empty_targets() {
        let error = parse_config_content(
            r#"{
                "api_token":"test-token",
                "account_id":"11111111111111111111111111111111",
                "zone_id":"22222222222222222222222222222222"
            }"#,
            false,
        )
        .err()
        .unwrap();
        assert!(error.contains("No update targets"));
    }

    #[test]
    fn rejects_invalid_cloudflare_ids() {
        let error = parse_config_content(
            r#"{
                "api_token": "test-token",
                "account_id": "11111111111111111111111111111111",
                "zone_id": "not-a-zone-id",
                "domains": ["example.com"]
            }"#,
            false,
        )
        .err()
        .unwrap();
        assert!(error.contains("zone_id must be a 32-character hexadecimal"));
    }

    #[test]
    fn parses_duration_units() {
        assert_eq!(
            parse_duration("30s", "test").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration("5m", "test").unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            parse_duration("2h", "test").unwrap(),
            Duration::from_secs(7200)
        );
    }
}
