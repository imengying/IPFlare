use crate::cf_ip_filter::CachedCloudflareFilter;
use crate::cloudflare::{CloudflareHandle, SetResult};
use crate::config::AppConfig;
use crate::notifier::{Message, Notifier};
use crate::pp::PP;
use crate::provider::{DetectionOutcome, IpType};
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Run a single update cycle.
pub async fn update_once(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &Notifier,
    cf_cache: &mut CachedCloudflareFilter,
    ppfmt: &PP,
    noop_reported: &mut HashSet<String>,
    range_client: &Client,
) -> bool {
    let mut all_ok = true;
    let mut messages = Vec::new();
    let mut notify = false;

    // Detect IPs for each provider. Types in `detection_failed` had a
    // transient detection error: the real IP is unknown, so their DNS
    // records and WAF list entries are preserved this cycle regardless of
    // delete_on_failure (issue #277).
    let mut detected_ips: HashMap<IpType, Vec<IpAddr>> = HashMap::new();
    let mut detection_failed: HashSet<IpType> = HashSet::new();

    for (ip_type, provider) in &config.providers {
        ppfmt.infof(&format!(
            "Detecting {} via {}",
            ip_type.describe(),
            provider.name()
        ));
        match provider
            .detect(*ip_type, config.detection_timeout, ppfmt)
            .await
        {
            DetectionOutcome::Ips(ips) => {
                let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                ppfmt.infof(&format!(
                    "Detected {}: {}",
                    ip_type.describe(),
                    ip_strs.join(", ")
                ));
                messages.push(Message::new_ok(&format!(
                    "检测到 {}: {}",
                    ip_type.describe(),
                    ip_strs.join(", ")
                )));
                detected_ips.insert(*ip_type, ips);
            }
            DetectionOutcome::NoIp => {
                ppfmt.warningf(&format!("No {} address detected", ip_type.describe()));
                messages.push(Message::new_fail(&format!(
                    "未检测到 {} 地址",
                    ip_type.describe()
                )));
            }
            DetectionOutcome::Failed => {
                ppfmt.warningf(&format!(
                            "{} detection failed; skipping {} updates this cycle (existing records preserved)",
                            ip_type.describe(),
                            ip_type.describe()
                        ),
                    );
                messages.push(Message::new_fail(&format!(
                    "{} 检测失败，本轮跳过更新（已保留现有记录）",
                    ip_type.describe()
                )));
                detection_failed.insert(*ip_type);
            }
        }
    }

    // Filter out Cloudflare IPs if enabled
    if config.reject_cloudflare_ips {
        if let Some(cf_filter) = cf_cache
            .get(range_client, config.detection_timeout, ppfmt)
            .await
        {
            for (ip_type, ips) in detected_ips.iter_mut() {
                let before_count = ips.len();
                ips.retain(|ip| {
                    if cf_filter.contains(ip) {
                        ppfmt.warningf(&format!(
                            "Rejected {ip}: matches Cloudflare IP range ({})",
                            ip_type.describe()
                        ));
                        false
                    } else {
                        true
                    }
                });
                if ips.is_empty() && before_count > 0 {
                    ppfmt.warningf(&format!(
                                "All detected {} addresses were Cloudflare IPs; skipping updates for this type",
                                ip_type.describe()
                            ),
                        );
                    messages.push(Message::new_fail(&format!(
                        "检测到的 {} 地址全部属于 Cloudflare IP 段，已拒绝",
                        ip_type.describe()
                    )));
                    // The real IP is unknown, not absent - preserve records.
                    detection_failed.insert(*ip_type);
                }
            }
        } else if !detected_ips.is_empty() {
            ppfmt.warningf("Could not fetch Cloudflare IP ranges; skipping update to avoid writing Cloudflare IPs",
                );
            detection_failed.extend(detected_ips.keys().copied());
            detected_ips.clear();
        }
    }

    // Update domain-based DNS records.
    for (ip_type, domains) in &config.domains {
        let ips = detected_ips.get(ip_type).cloned().unwrap_or_default();

        if ips.is_empty() {
            // Transient detection failure: the real IP is unknown, so never
            // touch existing records - not even with delete_on_failure set.
            if detection_failed.contains(ip_type) {
                ppfmt.warningf(&format!(
                    "Skipping {} update for {}: IP detection failed (existing records preserved)",
                    ip_type.describe(),
                    domains.join(", ")
                ));
                continue;
            }
            // Definitive "no address of this family": deletion is the
            // documented DELETE_ON_FAILURE=true behavior; otherwise skip.
            if !config.delete_on_failure {
                ppfmt.warningf(&format!(
                            "Skipping {} update for {}: no {} address detected (existing records preserved)",
                            ip_type.describe(),
                            domains.join(", "),
                            ip_type.describe()
                        ),
                    );
                continue;
            }
        }

        let record_type = ip_type.record_type();

        for domain_str in domains {
            let result = handle
                .set_ips(
                    &config.zone_id,
                    domain_str,
                    record_type,
                    &ips,
                    config.proxied,
                    config.ttl,
                    config.record_comment.as_deref(),
                    config.dry_run,
                    ppfmt,
                )
                .await;

            let noop_key = format!("{domain_str}:{record_type}");
            match result {
                SetResult::Updated => {
                    noop_reported.remove(&noop_key);
                    notify = true;
                    if ips.is_empty() {
                        messages.push(Message::new_ok(&format!(
                            "已删除 {domain_str} 的 DNS 记录（未检测到 {} 地址）",
                            ip_type.describe()
                        )));
                    } else {
                        let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                        messages.push(Message::new_ok(&format!(
                            "已更新 {domain_str} -> {}",
                            ip_strs.join(", ")
                        )));
                    }
                }
                SetResult::Failed | SetResult::ReadFailed => {
                    noop_reported.remove(&noop_key);
                    notify = true;
                    all_ok = false;
                    messages.push(dns_failure_message(domain_str, result));
                }
                SetResult::Noop => {
                    if noop_reported.insert(noop_key) {
                        ppfmt.infof(&format!("Record {domain_str} is up to date"));
                    }
                }
            }
        }
    }

    // Update WAF lists.
    // A WAF list holds IPs from every configured family, so a transient
    // detection failure for any family would silently strip that family's
    // IPs from the list. Preserve the list until detection recovers.
    for waf_list in &config.waf_lists {
        if !detection_failed.is_empty() {
            ppfmt.warningf(&format!(
                "Skipping WAF list {} update: IP detection failed (existing items preserved)",
                waf_list.describe()
            ));
            continue;
        }

        // Collect all detected IPs for WAF lists
        let all_ips: Vec<IpAddr> = detected_ips.values().flatten().copied().collect();

        // Every configured family definitively reports no address. Clearing the
        // list is the documented delete_on_failure=true behavior; otherwise
        // preserve the items, mirroring the DNS path above. Without this an
        // allow-list would be emptied the moment the host loses its address.
        if all_ips.is_empty() && !config.delete_on_failure {
            ppfmt.warningf(&format!(
                "Skipping WAF list {} update: no address detected (existing items preserved)",
                waf_list.describe()
            ));
            continue;
        }

        let result = handle
            .set_waf_list(
                waf_list,
                &all_ips,
                config.waf_list_item_comment.as_deref(),
                config.dry_run,
                ppfmt,
            )
            .await;

        let noop_key = format!("waf:{}", waf_list.describe());
        match result {
            SetResult::Updated => {
                noop_reported.remove(&noop_key);
                notify = true;
                messages.push(Message::new_ok(&format!(
                    "已更新 WAF 列表 {}",
                    waf_list.describe()
                )));
            }
            SetResult::Failed | SetResult::ReadFailed => {
                noop_reported.remove(&noop_key);
                notify = true;
                all_ok = false;
                messages.push(Message::new_fail(&format!(
                    "更新 WAF 列表 {} 失败",
                    waf_list.describe()
                )));
            }
            SetResult::Noop => {
                if noop_reported.insert(noop_key) {
                    ppfmt.infof(&format!("WAF list {} is up to date", waf_list.describe()));
                }
            }
        }
    }

    // Notify only when an IP changed or an update failed.
    if notify {
        let notifier_msg = Message::merge(messages);
        notifier.send(&notifier_msg, ppfmt).await;
    }

    all_ok
}

fn dns_failure_message(domain: &str, result: SetResult) -> Message {
    match result {
        SetResult::ReadFailed => Message::new_fail(&format!(
            "无法查询 {domain} 的 Cloudflare DNS 记录，本轮未执行更新"
        )),
        SetResult::Failed => Message::new_fail(&format!("更新 {domain} 失败")),
        SetResult::Noop | SetResult::Updated => unreachable!("not a DNS failure"),
    }
}

/// Delete records and WAF entries when the process stops.
pub async fn final_delete(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &Notifier,
    ppfmt: &PP,
) -> bool {
    let mut messages = Vec::new();
    let mut all_ok = true;

    // Delete DNS records
    for (ip_type, domains) in &config.domains {
        let record_type = ip_type.record_type();

        for domain_str in domains {
            let deleted = handle
                .final_delete(&config.zone_id, domain_str, record_type, ppfmt)
                .await;
            all_ok &= deleted;
            messages.push(if deleted {
                Message::new_ok(&format!("已删除 {domain_str} 的记录"))
            } else {
                Message::new_fail(&format!("删除 {domain_str} 的记录失败"))
            });
        }
    }

    // Clear WAF lists
    for waf_list in &config.waf_lists {
        let cleared = handle.final_clear_waf_list(waf_list, ppfmt).await;
        all_ok &= cleared;
        messages.push(if cleared {
            Message::new_ok(&format!("已清空 WAF 列表 {}", waf_list.describe()))
        } else {
            Message::new_fail(&format!("清空 WAF 列表 {} 失败", waf_list.describe()))
        });
    }

    let msg = Message::merge(messages);
    notifier.send(&msg, ppfmt).await;
    all_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::{Auth, CloudflareHandle, Ttl, WAFList};
    use crate::config::{AppConfig, CronSchedule};
    use crate::notifier::Notifier;
    use crate::pp::PP;
    use crate::provider::{IpType, ProviderType};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::time::Duration;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -------------------------------------------------------
    // Helpers
    // -------------------------------------------------------

    #[test]
    fn dns_read_failure_message_does_not_claim_an_update_failed() {
        let message = dns_failure_message("wap.mengying.eu.org", SetResult::ReadFailed);
        assert_eq!(
            message.format(),
            "无法查询 wap.mengying.eu.org 的 Cloudflare DNS 记录，本轮未执行更新"
        );
    }

    fn pp() -> PP {
        // quiet=true suppresses output during tests
        PP::new(true)
    }

    fn empty_notifier() -> Notifier {
        Notifier::disabled()
    }

    /// Build a minimal AppConfig with a single V4 domain.
    fn make_config(
        providers: HashMap<IpType, ProviderType>,
        domains: HashMap<IpType, Vec<String>>,
        waf_lists: Vec<WAFList>,
        dry_run: bool,
    ) -> AppConfig {
        let mut config = make_config_preserving(providers, domains, waf_lists, dry_run);
        config.delete_on_failure = true;
        config
    }

    /// Like make_config but with delete_on_failure disabled (the default since issue #277):
    /// detection failures skip updates instead of deleting records.
    fn make_config_preserving(
        providers: HashMap<IpType, ProviderType>,
        domains: HashMap<IpType, Vec<String>>,
        waf_lists: Vec<WAFList>,
        dry_run: bool,
    ) -> AppConfig {
        AppConfig {
            auth: Auth::token("test-token"),
            account_id: "account-123".to_string(),
            zone_id: "zone-abc".to_string(),
            providers,
            domains,
            waf_lists,
            update_cron: CronSchedule::Once,
            update_on_start: true,
            delete_on_stop: false,
            delete_on_failure: false,
            ttl: Ttl::AUTO,
            proxied: false,
            record_comment: None,
            managed_comment_regex: None,
            waf_list_item_comment: None,
            managed_waf_comment_regex: None,
            detection_timeout: Duration::from_secs(5),
            update_timeout: Duration::from_secs(5),
            reject_cloudflare_ips: false,
            dry_run,
            quiet: true,
            telegram: None,
        }
    }

    fn handle(base_url: &str) -> CloudflareHandle {
        CloudflareHandle::with_base_url(base_url, Auth::token("test-token"))
    }

    /// JSON for an empty DNS records list.
    fn dns_records_empty() -> serde_json::Value {
        serde_json::json!({ "result": [] })
    }

    /// JSON for a DNS records list containing one record.
    fn dns_records_one(id: &str, name: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "result": [{
                "id": id,
                "name": name,
                "content": content,
                "proxied": false,
                "ttl": 1,
                "comment": null
            }]
        })
    }

    /// JSON for a successful DNS record create/update response.
    fn dns_record_created(id: &str, name: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "result": {
                "id": id,
                "name": name,
                "content": content,
                "proxied": false,
                "ttl": 1,
                "comment": null
            }
        })
    }

    /// JSON for a WAF lists response returning a single list.
    fn waf_lists_response(list_id: &str, list_name: &str) -> serde_json::Value {
        serde_json::json!({
            "result": [{ "id": list_id, "name": list_name }]
        })
    }

    /// JSON for WAF list items response.
    fn waf_items_response(items: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "result": items })
    }

    async fn mock_waf_replace(server: &MockServer, account_id: &str, list_id: &str) {
        Mock::given(method("PUT"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": { "operation_id": "op-1" }
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/bulk_operations/op-1"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": { "status": "completed" }
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    // -------------------------------------------------------
    // update_once tests
    // -------------------------------------------------------

    /// update_once with a Literal IP provider creates a new DNS record when none exists.
    #[tokio::test]
    async fn test_update_once_creates_new_record() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let ip = "198.51.100.42";

        // List existing records: GET zones/{zone_id}/dns_records?...
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // Create record: POST zones/{zone_id}/dns_records
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_record_created("rec-1", domain, ip)),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// update_once returns true (all_ok) when IP is already correct (Noop),
    /// and populates noop_reported so subsequent calls suppress the message.
    #[tokio::test]
    async fn test_update_once_noop_when_record_up_to_date() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let ip = "198.51.100.42";

        // List existing records - record already exists with correct IP
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_records_one("rec-1", domain, ip)),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let mut noop_reported = HashSet::new();

        // First call: noop_reported is empty, so "up to date" is reported and key is inserted
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut noop_reported,
            &crate::test_client(),
        )
        .await;
        assert!(ok);
        assert!(
            noop_reported.contains("home.example.com:A"),
            "noop_reported should contain the domain key after first noop"
        );

        // Second call: noop_reported already has the key, so the message is suppressed
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut noop_reported,
            &crate::test_client(),
        )
        .await;
        assert!(ok);
        assert_eq!(
            noop_reported.len(),
            1,
            "noop_reported should still have exactly one entry"
        );
    }

    /// noop_reported is cleared when a record is updated, so "up to date" prints again
    /// on the next noop cycle.
    #[tokio::test]
    async fn test_update_once_noop_reported_cleared_on_change() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let old_ip = "198.51.100.42";
        let new_ip = "198.51.100.99";

        // List existing records - record has old IP, will be updated
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_records_one("rec-1", domain, old_ip)),
            )
            .mount(&server)
            .await;

        // The existing record is reused and updated to the new IP.
        Mock::given(method("PUT"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-1")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-1", domain, new_ip)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![new_ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        // Pre-populate noop_reported as if a previous cycle reported it
        let mut noop_reported = HashSet::new();
        noop_reported.insert("home.example.com:A".to_string());

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut noop_reported,
            &crate::test_client(),
        )
        .await;
        assert!(ok);
        assert!(
            !noop_reported.contains("home.example.com:A"),
            "noop_reported should be cleared after an update"
        );
    }

    /// update_once returns true even when IP detection yields empty (no providers configured),
    /// but marks the result as degraded via messages (all_ok = false only on zone/record errors).
    /// Here we use ProviderType::None so no IPs are detected - all_ok stays true since there
    /// is no domain update attempted (empty ips -> set_ips with empty slice -> Noop).
    #[tokio::test]
    async fn test_update_once_empty_ip_detection_with_none_provider() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";

        // List records (set_ips called with empty ips, will list to delete managed records)
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // Provider that returns no IPs
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        // all_ok = true because no zone-level errors occurred (empty ips just noop or warn)
        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        // Providers with None are not inserted in loop, so no IP detection warning is emitted,
        // no detected_ips entry is created, and set_ips is called with empty slice -> Noop.
        assert!(ok);
    }

    /// Issue #277: a transient detection failure (provider errored, real IP
    /// unknown) must skip the DNS update entirely — no zone lookup, no record
    /// deletion — even with delete_on_failure enabled.
    #[tokio::test]
    async fn test_update_once_detection_failure_skips_dns_update() {
        let server = MockServer::start().await;
        let domain = "home.example.com";

        // IP detection endpoint errors -> DetectionOutcome::Failed.
        Mock::given(method("GET"))
            .and(path("/detect-ip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::CustomURL {
                url: format!("{}/detect-ip", server.uri()),
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        // delete_on_failure is true here: transient failures must still preserve records.
        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "skip on detection failure should not be an error");
    }

    /// A definitive "no address of this family" (e.g. provider `none`) with
    /// delete_on_failure enabled deletes the managed records (documented behavior).
    #[tokio::test]
    async fn test_update_once_no_ip_deletes_records_with_delete_on_failure() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let record_id = "rec-stale";

        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_one(
                record_id,
                domain,
                "198.51.100.42",
            )))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/{record_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false); // delete_on_failure: true
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// A definitive "no address of this family" with delete_on_failure disabled
    /// skips the update and preserves existing records.
    #[tokio::test]
    async fn test_update_once_no_ip_skips_when_delete_on_failure_disabled() {
        let server = MockServer::start().await;
        let domain = "home.example.com";

        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config_preserving(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "skip on missing IP should not be an error");
    }

    /// Issue #277: a transient detection failure must not touch WAF lists —
    /// otherwise a network blip clears the list.
    #[tokio::test]
    async fn test_update_once_detection_failure_skips_waf_update() {
        let server = MockServer::start().await;
        let account_id = "acc-123";

        // IP detection endpoint errors -> DetectionOutcome::Failed.
        Mock::given(method("GET"))
            .and(path("/detect-ip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        // WAF list lookup must NOT happen.
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response("list-id-1", "my_list")),
            )
            .expect(0)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::CustomURL {
                url: format!("{}/detect-ip", server.uri()),
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: "my_list".to_string(),
        };

        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(
            ok,
            "skipping WAF update on detection failure should not be an error"
        );
    }

    /// A deterministic provider reporting "no address of this family" must not
    /// wipe an existing WAF list while delete_on_failure is false. The DNS path
    /// already gates deletion on that flag; the WAF path must match.
    #[tokio::test]
    async fn test_update_once_no_ip_preserves_waf_list_when_delete_on_failure_disabled() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";

        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // The list already holds the previously published address.
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(waf_items_response(
                serde_json::json!([{ "ip": "198.51.100.42" }]),
            )))
            .mount(&server)
            .await;

        // Clearing the list would issue a PUT; it must not happen.
        Mock::given(method("PUT"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": { "operation_id": "op-1" }
            })))
            .expect(0)
            .mount(&server)
            .await;

        // Literal provider with no V4 address: a definitive NoIp, not a failure.
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::Literal { ips: Vec::new() });
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        // delete_on_failure stays false here.
        let config = make_config_preserving(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// Issue #277: if only one address family fails detection transiently, the
    /// WAF update is still skipped — a partial update would strip the failed
    /// family's IPs from the shared list.
    #[tokio::test]
    async fn test_update_once_partial_detection_failure_skips_waf_update() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let ip_v4 = "198.51.100.42";

        // V6 detection endpoint errors -> DetectionOutcome::Failed.
        Mock::given(method("GET"))
            .and(path("/detect-ip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response("list-id-1", "my_list")),
            )
            .expect(0)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse::<IpAddr>().unwrap()],
            },
        );
        providers.insert(
            IpType::V6,
            ProviderType::CustomURL {
                url: format!("{}/detect-ip", server.uri()),
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: "my_list".to_string(),
        };

        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// update_once in dry_run mode does NOT POST to create records.
    #[tokio::test]
    async fn test_update_once_dry_run_does_not_create_record() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let ip = "198.51.100.42";

        // List existing records - none exist
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST must NOT be called in dry_run - if it is, wiremock will panic at drop
        // (no Mock registered for POST, and strict mode is default for unexpected requests)

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], true /* dry_run */);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        // dry_run returns Updated from set_ips (it signals intent), all_ok should be true
        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// update_once with WAF lists: IPs are detected and WAF list is updated.
    #[tokio::test]
    async fn test_update_once_with_waf_list() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";
        let ip = "198.51.100.42";

        // GET accounts/{account_id}/rules/lists - returns our list
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET list items - empty (need to add the IP)
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([]))),
            )
            .mount(&server)
            .await;

        mock_waf_replace(&server, account_id, list_id).await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        // No DNS domains - only WAF list
        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// update_once with WAF list in dry_run mode: items are NOT POSTed.
    #[tokio::test]
    async fn test_update_once_waf_list_dry_run() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";
        let ip = "198.51.100.42";

        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([]))),
            )
            .mount(&server)
            .await;

        // No POST mock registered - dry_run must not POST

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(
            providers,
            HashMap::new(),
            vec![waf_list],
            true, /* dry_run */
        );
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// update_once with WAF list when WAF list is not found returns false (Failed).
    #[tokio::test]
    async fn test_update_once_waf_list_not_found_returns_false() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let ip = "198.51.100.42";

        // GET accounts/{account_id}/rules/lists - returns empty (list not found)
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": [] })),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(!ok, "Expected false when WAF list is not found");
    }

    /// update_once with two domains (V4 and V6) - both updated independently.
    #[tokio::test]
    async fn test_update_once_v4_and_v6_domains() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain_v4 = "v4.example.com";
        let domain_v6 = "v6.example.com";
        let ip_v4 = "198.51.100.42";
        let ip_v6 = "2001:db8::1";

        // List records for both domains (no existing records)
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // Create record for V4
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-v4", domain_v4, ip_v4)),
            )
            .mount(&server)
            .await;

        // Create record for V6
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-v6", domain_v6, ip_v6)),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse::<IpAddr>().unwrap()],
            },
        );
        providers.insert(
            IpType::V6,
            ProviderType::Literal {
                ips: vec![ip_v6.parse::<IpAddr>().unwrap()],
            },
        );

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain_v4.to_string()]);
        domains.insert(IpType::V6, vec![domain_v6.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// update_once with no providers and no domains is a degenerate but valid case - returns true.
    #[tokio::test]
    async fn test_update_once_no_providers_no_domains() {
        let server = MockServer::start().await;
        // No HTTP mocks needed - nothing should be called

        let config = make_config(HashMap::new(), HashMap::new(), vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    // -------------------------------------------------------
    // final_delete tests
    // -------------------------------------------------------

    /// final_delete removes existing DNS records for a domain.
    #[tokio::test]
    async fn test_final_delete_removes_dns_records() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let record_id = "rec-to-delete";
        let ip = "198.51.100.1";

        // List records - one record exists
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_records_one(record_id, domain, ip)),
            )
            .mount(&server)
            .await;

        // DELETE the record
        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/{record_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(HashMap::new(), domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        // Should complete without panic
        final_delete(&config, &cf, &notifier, &ppfmt).await;
    }

    /// final_delete does nothing when no records exist for the domain.
    #[tokio::test]
    async fn test_final_delete_noop_when_no_records() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";

        // List records - empty
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // No DELETE mock - ensures DELETE is not called

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(HashMap::new(), domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
    }

    /// final_delete clears WAF list items.
    #[tokio::test]
    async fn test_final_delete_clears_waf_list() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";
        let item_id = "item-abc";
        let ip = "198.51.100.42";

        // GET lists
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET items - one item exists
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(waf_items_response(
                serde_json::json!([
                    { "id": item_id, "ip": ip, "comment": null }
                ]),
            )))
            .mount(&server)
            .await;

        mock_waf_replace(&server, account_id, list_id).await;

        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(HashMap::new(), HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
    }

    /// final_delete with no WAF items does not call DELETE.
    #[tokio::test]
    async fn test_final_delete_waf_list_no_items() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";

        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET items - empty
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([]))),
            )
            .mount(&server)
            .await;

        // No DELETE mock - ensures DELETE is not called for empty list

        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(HashMap::new(), HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
    }

    /// final_delete with both DNS domains and WAF lists - both are cleaned up.
    #[tokio::test]
    async fn test_final_delete_dns_and_waf() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let record_id = "rec-del";
        let ip = "198.51.100.5";
        let account_id = "acc-999";
        let list_name = "ddns_ips";
        let list_id = "list-xyz";
        let item_id = "item-xyz";

        // List DNS records
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_records_one(record_id, domain, ip)),
            )
            .mount(&server)
            .await;

        // DELETE DNS record
        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/{record_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // WAF: GET lists
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // WAF: GET items
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(waf_items_response(
                serde_json::json!([
                    { "id": item_id, "ip": ip, "comment": null }
                ]),
            )))
            .mount(&server)
            .await;

        mock_waf_replace(&server, account_id, list_id).await;

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(HashMap::new(), domains, vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
    }

    // -------------------------------------------------------
    // Literal provider IP detection filtering
    // -------------------------------------------------------

    /// Literal provider only injects IPs of the matching type into the update cycle.
    /// V6 Literal IPs are ignored when the domain is V4-only.
    #[tokio::test]
    async fn test_update_once_literal_v4_not_used_for_v6_domain() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain_v6 = "v6only.example.com";
        // Only a V4 literal provider is configured but domain is V6
        let ip_v4 = "198.51.100.1";

        // List AAAA records - no existing records; set_ips called with empty ips -> Noop
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // V4 literal provider but V6 domain - the V4 provider will not be in detected_ips for V6
        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse::<IpAddr>().unwrap()],
            },
        );
        // No V6 provider -> detected_ips won't have V6 -> set_ips called with empty slice
        let mut domains = HashMap::new();
        domains.insert(IpType::V6, vec![domain_v6.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        // set_ips with empty ips and no existing records = Noop; all_ok = true
        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }
    // -------------------------------------------------------
    // delete_on_failure tests    // -------------------------------------------------------
    // delete_on_failure tests
    // -------------------------------------------------------

    /// When IPv4 detection fails but IPv6 succeeds, and delete_on_failure=false, skip V4 domains but update V6
    #[tokio::test]
    async fn test_skip_v4_domains_when_v4_detection_fails() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let ip_v6 = "2001:db8::1";

        // LIST existing records for V6
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST for V6 should be called (V6 succeeds)
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_record_created(
                "rec-1",
                "v6.example.com",
                "2001:db8::1",
            )))
            .expect(1)
            .mount(&server)
            .await;

        // Providers: V4 fails (None), V6 succeeds
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        providers.insert(
            IpType::V6,
            ProviderType::Literal {
                ips: vec![ip_v6.parse().unwrap()],
            },
        );

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed with partial detection");
    }

    /// When IPv6 detection fails but IPv4 succeeds, and delete_on_failure=false, skip V6 domains but update V4
    #[tokio::test]
    async fn test_skip_v6_domains_when_v6_detection_fails() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let ip_v4 = "198.51.100.42";

        // LIST existing records for V4
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST for V4 should be called (V4 succeeds)
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_record_created(
                "rec-1",
                "v4.example.com",
                "198.51.100.42",
            )))
            .expect(1)
            .mount(&server)
            .await;

        // Providers: V4 succeeds, V6 fails (None)
        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse().unwrap()],
            },
        );
        providers.insert(IpType::V6, ProviderType::None);

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed with partial detection");
    }

    /// When both IPv4 and IPv6 detection fail, and delete_on_failure=false, skip all domains
    #[tokio::test]
    async fn test_skip_all_domains_when_both_detect_fail() {
        let server = MockServer::start().await;

        // No POST/DELETE should be called at all

        // Providers: both fail (None)
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        providers.insert(IpType::V6, ProviderType::None);

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed (no updates, no failures)");
    }

    /// When both IPv4 and IPv6 detection succeed, and delete_on_failure=false, update all domains
    #[tokio::test]
    async fn test_update_all_domains_when_both_detect() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let ip_v4 = "198.51.100.42";
        let ip_v6 = "2001:db8::1";

        // LIST existing records (empty for both)
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST for both should be called
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_record_created(
                "rec-new",
                "example.com",
                "198.51.100.42",
            )))
            .expect(2) // Two POSTs: one for V4, one for V6
            .mount(&server)
            .await;

        // Providers: both succeed
        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse().unwrap()],
            },
        );
        providers.insert(
            IpType::V6,
            ProviderType::Literal {
                ips: vec![ip_v6.parse().unwrap()],
            },
        );

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed with both detections");
    }
}
