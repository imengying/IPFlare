use crate::pp::PP;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::{Instant, sleep};

// --- Ttl ---

/// A record TTL. The field is private so every value goes through [`Ttl::new`]
/// and cannot bypass the below-30 clamp Cloudflare requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl(i64);

impl Ttl {
    pub const AUTO: Ttl = Ttl(1);

    pub fn new(value: i64) -> Self {
        if value < 30 { Ttl::AUTO } else { Ttl(value) }
    }

    pub fn seconds(&self) -> i64 {
        self.0
    }

    pub fn describe(&self) -> String {
        if self.0 == 1 {
            "auto".to_string()
        } else {
            format!("{}s", self.0)
        }
    }
}

// --- Auth ---

/// An API token. Cloudflare also accepts the legacy Global API Key, which this
/// project deliberately does not support. No invariant to guard, so the field
/// stays crate-visible for assertions.
#[derive(Debug, Clone)]
pub struct Auth(pub(crate) String);

impl Auth {
    pub fn token(token: &str) -> Self {
        Self(token.to_string())
    }

    pub fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("Authorization", format!("Bearer {}", self.0))
    }
}

// --- WAF List ---

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WAFList {
    pub account_id: String,
    pub list_name: String,
}

impl WAFList {
    pub fn new(account_id: &str, list_name: &str) -> Result<Self, String> {
        let account_id = account_id.trim().to_string();
        let list_name = list_name.trim().to_string();

        if list_name.is_empty()
            || !list_name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(format!("WAF list name must match [a-z0-9_]+: {list_name}"));
        }

        Ok(WAFList {
            account_id,
            list_name,
        })
    }

    pub fn describe(&self) -> String {
        format!("{}/{}", self.account_id, self.list_name)
    }
}

// --- API Response Types ---

/// A single entry of Cloudflare's `errors` array. The API returns HTTP 200 with
/// `success: false` for application-level failures, so this is the only place
/// the actual reason appears.
#[derive(Debug, Deserialize, Default)]
pub struct CfError {
    pub code: Option<i64>,
    pub message: Option<String>,
}

/// Render an `errors` array as a single human-readable line.
fn describe_errors(errors: &[CfError]) -> String {
    if errors.is_empty() {
        return "no error details returned".to_string();
    }
    errors
        .iter()
        .map(|error| {
            let message = error.message.as_deref().unwrap_or("unknown error");
            match error.code {
                Some(code) => format!("{message} (code {code})"),
                None => message.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Shared behaviour of Cloudflare's response envelopes, so a `success: false`
/// body is reported the same way regardless of which endpoint returned it.
pub trait CfEnvelope {
    fn is_failure(&self) -> bool;
    fn error_summary(&self) -> String;
}

#[derive(Debug, Deserialize)]
pub struct CfResponse<T> {
    pub result: Option<T>,
    pub success: Option<bool>,
    #[serde(default)]
    pub errors: Vec<CfError>,
}

impl<T> CfEnvelope for CfResponse<T> {
    fn is_failure(&self) -> bool {
        self.success == Some(false)
    }

    fn error_summary(&self) -> String {
        describe_errors(&self.errors)
    }
}

#[derive(Debug, Deserialize)]
pub struct CfListResponse<T> {
    pub result: Option<Vec<T>>,
    pub success: Option<bool>,
    pub result_info: Option<ResultInfo>,
    #[serde(default)]
    pub errors: Vec<CfError>,
}

impl<T> CfEnvelope for CfListResponse<T> {
    fn is_failure(&self) -> bool {
        self.success == Some(false)
    }

    fn error_summary(&self) -> String {
        describe_errors(&self.errors)
    }
}

#[derive(Debug, Deserialize)]
pub struct ResultInfo {
    pub total_pages: Option<u64>,
    pub cursors: Option<ListCursors>,
}

#[derive(Debug, Deserialize)]
pub struct ListCursors {
    pub after: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    pub content: String,
    pub proxied: Option<bool>,
    pub ttl: Option<i64>,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsRecordPayload {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub proxied: bool,
    pub ttl: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

// --- WAF API Types ---

#[derive(Debug, Deserialize)]
pub struct WAFListMeta {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct WAFListItem {
    pub ip: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WAFListCreateItem {
    pub ip: String,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WAFOperation {
    operation_id: String,
}

#[derive(Debug, Deserialize)]
struct WAFOperationStatus {
    status: String,
    error: Option<String>,
}

// --- Cloudflare API Handle ---

pub struct CloudflareHandle {
    client: Client,
    base_url: String,
    auth: Auth,
    operation_timeout: Duration,
    managed_comment_regex: Option<regex_lite::Regex>,
    managed_waf_comment_regex: Option<regex_lite::Regex>,
}

impl CloudflareHandle {
    pub fn new(
        auth: Auth,
        update_timeout: Duration,
        managed_comment_regex: Option<regex_lite::Regex>,
        managed_waf_comment_regex: Option<regex_lite::Regex>,
    ) -> Self {
        let client = Client::builder()
            .timeout(update_timeout)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
            auth,
            operation_timeout: update_timeout,
            managed_comment_regex,
            managed_waf_comment_regex,
        }
    }

    #[cfg(test)]
    pub fn with_base_url(base_url: &str, auth: Auth) -> Self {
        crate::init_crypto();
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: base_url.to_string(),
            auth,
            operation_timeout: Duration::from_secs(10),
            managed_comment_regex: None,
            managed_waf_comment_regex: None,
        }
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/{path}", self.base_url)
    }

    async fn api_request<T: serde::de::DeserializeOwned + CfEnvelope>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl Serialize>,
        ppfmt: &PP,
    ) -> Option<T> {
        let url = reqwest::Url::parse(&self.api_url(path)).ok()?;
        self.api_request_url(method, url, body, ppfmt).await
    }

    async fn api_request_url<T: serde::de::DeserializeOwned + CfEnvelope>(
        &self,
        method: reqwest::Method,
        url: reqwest::Url,
        body: Option<&impl Serialize>,
        ppfmt: &PP,
    ) -> Option<T> {
        let mut req = self
            .auth
            .apply(self.client.request(method.clone(), url.clone()));
        if let Some(b) = body {
            req = req.json(b);
        }
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<T>().await {
                        Ok(value) => {
                            // Cloudflare signals application-level failures with
                            // HTTP 200 and success: false; the reason is only in
                            // the errors array.
                            if value.is_failure() {
                                ppfmt.warningf(&format!(
                                    "API {method} '{url}' failed: {}",
                                    value.error_summary()
                                ));
                            }
                            Some(value)
                        }
                        Err(error) => {
                            ppfmt.warningf(&format!(
                                "API {method} '{url}' returned invalid JSON: {error}"
                            ));
                            None
                        }
                    }
                } else {
                    let url_str = resp.url().to_string();
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    // 4xx/5xx bodies carry the same errors array; prefer it over
                    // the raw JSON, which is unreadable in a log line.
                    let detail = serde_json::from_str::<CfResponse<serde_json::Value>>(&text)
                        .map(|response| describe_errors(&response.errors))
                        .unwrap_or_else(|_| {
                            let text = text.trim();
                            if text.is_empty() {
                                "empty response body".to_string()
                            } else {
                                text.to_string()
                            }
                        });
                    ppfmt.warningf(&format!(
                        "API {method} '{url_str}' failed: HTTP {status}: {detail}"
                    ));
                    None
                }
            }
            Err(e) => {
                ppfmt.warningf(&format!("API {method} '{url}' error: {e}"));
                None
            }
        }
    }

    // --- DNS Record Operations ---

    async fn list_records_filtered(
        &self,
        zone_id: &str,
        record_type: &str,
        name: Option<&str>,
        ppfmt: &PP,
    ) -> Option<Vec<DnsRecord>> {
        const PER_PAGE: u64 = 100;
        let base = self.api_url(&format!("zones/{zone_id}/dns_records"));
        let mut records = Vec::new();
        let mut page = 1_u64;

        loop {
            let mut url = reqwest::Url::parse(&base).ok()?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("per_page", &PER_PAGE.to_string())
                    .append_pair("page", &page.to_string())
                    .append_pair("type", record_type);
                if let Some(name) = name {
                    query.append_pair("name.exact", name);
                }
            }
            let response: CfListResponse<DnsRecord> = self
                .api_request_url(reqwest::Method::GET, url, None::<&()>, ppfmt)
                .await?;
            if response.success == Some(false) {
                return None;
            }
            let mut current = response.result?;
            let count = current.len();
            records.append(&mut current);
            let has_next = response
                .result_info
                .and_then(|info| info.total_pages.map(|total| page < total))
                .unwrap_or(count == PER_PAGE as usize);
            if !has_next {
                return Some(records);
            }
            page += 1;
        }
    }

    #[cfg(test)]
    pub async fn list_records(
        &self,
        zone_id: &str,
        record_type: &str,
        ppfmt: &PP,
    ) -> Option<Vec<DnsRecord>> {
        self.list_records_filtered(zone_id, record_type, None, ppfmt)
            .await
    }

    pub async fn list_records_by_name(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
        ppfmt: &PP,
    ) -> Option<Vec<DnsRecord>> {
        // Cloudflare normalizes DNS record names to lowercase server-side, so a
        // case-sensitive match against the user-supplied name (e.g. ExaMple.com)
        // would never find existing records and trigger 81058 duplicate-create
        // errors on every cycle. Match case-insensitively to mirror Cloudflare's
        // own comparison rules.
        let records = self
            .list_records_filtered(zone_id, record_type, Some(name), ppfmt)
            .await?;
        Some(
            records
                .into_iter()
                .filter(|r| r.name.eq_ignore_ascii_case(name))
                .collect(),
        )
    }

    fn is_managed_record(&self, record: &DnsRecord) -> bool {
        match &self.managed_comment_regex {
            Some(regex) => {
                let comment = record.comment.as_deref().unwrap_or("");
                regex.is_match(comment)
            }
            None => true, // No regex = manage all records
        }
    }

    pub async fn create_record(
        &self,
        zone_id: &str,
        payload: &DnsRecordPayload,
        ppfmt: &PP,
    ) -> Option<DnsRecord> {
        let path = format!("zones/{zone_id}/dns_records");
        let resp: Option<CfResponse<DnsRecord>> = self
            .api_request(reqwest::Method::POST, &path, Some(payload), ppfmt)
            .await;
        resp.filter(|r| r.success != Some(false))
            .and_then(|r| r.result)
    }

    pub async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        payload: &DnsRecordPayload,
        ppfmt: &PP,
    ) -> Option<DnsRecord> {
        let path = format!("zones/{zone_id}/dns_records/{record_id}");
        let resp: Option<CfResponse<DnsRecord>> = self
            .api_request(reqwest::Method::PUT, &path, Some(payload), ppfmt)
            .await;
        resp.filter(|r| r.success != Some(false))
            .and_then(|r| r.result)
    }

    pub async fn delete_record(&self, zone_id: &str, record_id: &str, ppfmt: &PP) -> bool {
        let path = format!("zones/{zone_id}/dns_records/{record_id}");
        let resp: Option<CfResponse<serde_json::Value>> = self
            .api_request(reqwest::Method::DELETE, &path, None::<&()>, ppfmt)
            .await;
        resp.is_some_and(|response| response.success != Some(false) && response.result.is_some())
    }

    /// Set IPs for a specific domain/record type. Handles create, update, delete, and dedup.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_ips(
        &self,
        zone_id: &str,
        fqdn: &str,
        record_type: &str,
        ips: &[IpAddr],
        proxied: bool,
        ttl: Ttl,
        comment: Option<&str>,
        dry_run: bool,
        ppfmt: &PP,
    ) -> SetResult {
        let Some(existing) = self
            .list_records_by_name(zone_id, record_type, fqdn, ppfmt)
            .await
        else {
            return SetResult::ReadFailed;
        };
        let managed: Vec<&DnsRecord> = existing
            .iter()
            .filter(|r| self.is_managed_record(r))
            .collect();

        if ips.is_empty() {
            // Delete all managed records
            if managed.is_empty() {
                return SetResult::Noop;
            }
            let mut success = true;
            for record in &managed {
                if dry_run {
                    ppfmt.infof(&format!(
                        "[DRY RUN] Would delete record {fqdn} ({})",
                        record.content
                    ));
                } else {
                    ppfmt.infof(&format!("Deleting record {fqdn} ({})", record.content));
                    success &= self.delete_record(zone_id, &record.id, ppfmt).await;
                }
            }
            return if success {
                SetResult::Updated
            } else {
                SetResult::Failed
            };
        }

        // For each IP, find or create a record
        let mut used_record_ids = Vec::new();
        let mut any_change = false;
        let mut success = true;

        for ip in ips {
            let ip_str = ip.to_string();

            // Find existing record with this IP
            let matching = managed
                .iter()
                .find(|r| r.content == ip_str && !used_record_ids.contains(&&r.id));

            if let Some(record) = matching {
                used_record_ids.push(&record.id);
                // Check if update needed (proxied or Ttl changed)
                let needs_update = record.proxied != Some(proxied)
                    || (ttl != Ttl::AUTO && record.ttl != Some(ttl.seconds()))
                    || (comment.is_some() && record.comment.as_deref() != comment);

                if needs_update {
                    any_change = true;
                    let payload = DnsRecordPayload {
                        record_type: record_type.to_string(),
                        name: fqdn.to_string(),
                        content: ip_str.clone(),
                        proxied,
                        ttl: ttl.seconds(),
                        comment: comment.map(|s| s.to_string()),
                    };
                    if dry_run {
                        ppfmt.infof(&format!("[DRY RUN] Would update record {fqdn} -> {ip_str}"));
                    } else {
                        ppfmt.infof(&format!("Updating record {fqdn} -> {ip_str}"));
                        success &= self
                            .update_record(zone_id, &record.id, &payload, ppfmt)
                            .await
                            .is_some();
                    }
                } else {
                    // Caller handles "up to date" logging based on SetResult::Noop
                }
            } else {
                // Find an existing managed record to update, or create new
                let reusable = managed.iter().find(|r| !used_record_ids.contains(&&r.id));

                let payload = DnsRecordPayload {
                    record_type: record_type.to_string(),
                    name: fqdn.to_string(),
                    content: ip_str.clone(),
                    proxied,
                    ttl: ttl.seconds(),
                    comment: comment.map(|s| s.to_string()),
                };

                if let Some(record) = reusable {
                    used_record_ids.push(&record.id);
                    any_change = true;
                    if dry_run {
                        ppfmt.infof(&format!("[DRY RUN] Would update record {fqdn} -> {ip_str}"));
                    } else {
                        ppfmt.infof(&format!("Updating record {fqdn} -> {ip_str}"));
                        success &= self
                            .update_record(zone_id, &record.id, &payload, ppfmt)
                            .await
                            .is_some();
                    }
                } else {
                    any_change = true;
                    if dry_run {
                        ppfmt.infof(&format!(
                            "[DRY RUN] Would add new record {fqdn} -> {ip_str}"
                        ));
                    } else {
                        ppfmt.infof(&format!("Adding new record {fqdn} -> {ip_str}"));
                        success &= self.create_record(zone_id, &payload, ppfmt).await.is_some();
                    }
                }
            }
        }

        // Delete extra managed records (duplicates)
        for record in &managed {
            if !used_record_ids.contains(&&record.id) {
                any_change = true;
                if dry_run {
                    ppfmt.infof(&format!(
                        "[DRY RUN] Would delete stale record {} ({})",
                        fqdn, record.content
                    ));
                } else if success {
                    ppfmt.infof(&format!(
                        "Deleting stale record {} ({})",
                        fqdn, record.content
                    ));
                    success &= self.delete_record(zone_id, &record.id, ppfmt).await;
                }
            }
        }

        if !success {
            SetResult::Failed
        } else if any_change {
            SetResult::Updated
        } else {
            SetResult::Noop
        }
    }

    /// Delete all managed records for a specific domain/record type.
    pub async fn final_delete(
        &self,
        zone_id: &str,
        fqdn: &str,
        record_type: &str,
        ppfmt: &PP,
    ) -> bool {
        let Some(existing) = self
            .list_records_by_name(zone_id, record_type, fqdn, ppfmt)
            .await
        else {
            return false;
        };
        let mut success = true;
        for record in &existing {
            if self.is_managed_record(record) {
                ppfmt.infof(&format!("Deleting record {fqdn} ({})", record.content));
                success &= self.delete_record(zone_id, &record.id, ppfmt).await;
            }
        }
        success
    }

    // --- WAF List Operations ---

    pub async fn find_waf_list(&self, waf_list: &WAFList, ppfmt: &PP) -> Option<WAFListMeta> {
        let path = format!("accounts/{}/rules/lists", waf_list.account_id);
        let resp: Option<CfListResponse<WAFListMeta>> = self
            .api_request(reqwest::Method::GET, &path, None::<&()>, ppfmt)
            .await;
        resp.filter(|r| r.success != Some(false))
            .and_then(|r| r.result)
            .and_then(|lists| lists.into_iter().find(|l| l.name == waf_list.list_name))
    }

    pub async fn list_waf_list_items(
        &self,
        account_id: &str,
        list_id: &str,
        ppfmt: &PP,
    ) -> Option<Vec<WAFListItem>> {
        const PER_PAGE: usize = 500;
        let base = self.api_url(&format!(
            "accounts/{account_id}/rules/lists/{list_id}/items"
        ));
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();

        loop {
            let mut url = reqwest::Url::parse(&base).ok()?;
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("per_page", &PER_PAGE.to_string());
                if let Some(cursor) = &cursor {
                    query.append_pair("cursor", cursor);
                }
            }
            let response: CfListResponse<WAFListItem> = self
                .api_request_url(reqwest::Method::GET, url, None::<&()>, ppfmt)
                .await?;
            if response.success == Some(false) {
                return None;
            }
            items.extend(response.result?);
            let next = response
                .result_info
                .and_then(|info| info.cursors)
                .and_then(|cursors| cursors.after)
                .filter(|value| !value.is_empty());
            let Some(next) = next else {
                return Some(items);
            };
            if !seen_cursors.insert(next.clone()) {
                ppfmt.warningf("WAF list pagination returned a repeated cursor");
                return None;
            }
            cursor = Some(next);
        }
    }

    async fn replace_waf_list_items(
        &self,
        account_id: &str,
        list_id: &str,
        items: &[WAFListCreateItem],
        ppfmt: &PP,
    ) -> bool {
        let path = format!("accounts/{account_id}/rules/lists/{list_id}/items");
        let response: Option<CfResponse<WAFOperation>> = self
            .api_request(reqwest::Method::PUT, &path, Some(&items), ppfmt)
            .await;
        let Some(operation) = response
            .filter(|response| response.success != Some(false))
            .and_then(|response| response.result)
        else {
            return false;
        };
        self.wait_for_waf_operation(account_id, &operation.operation_id, ppfmt)
            .await
    }

    async fn wait_for_waf_operation(
        &self,
        account_id: &str,
        operation_id: &str,
        ppfmt: &PP,
    ) -> bool {
        let path = format!("accounts/{account_id}/rules/lists/bulk_operations/{operation_id}");
        let deadline = Instant::now() + self.operation_timeout;
        loop {
            let response: Option<CfResponse<WAFOperationStatus>> = self
                .api_request(reqwest::Method::GET, &path, None::<&()>, ppfmt)
                .await;
            let Some(status) = response
                .filter(|response| response.success != Some(false))
                .and_then(|response| response.result)
            else {
                return false;
            };
            match status.status.as_str() {
                "completed" => return true,
                "failed" => {
                    ppfmt.warningf(&format!(
                        "WAF list operation {operation_id} failed: {}",
                        status.error.as_deref().unwrap_or("unknown error")
                    ));
                    return false;
                }
                "pending" | "running" if Instant::now() < deadline => {
                    sleep(Duration::from_millis(250)).await;
                }
                "pending" | "running" => {
                    ppfmt.warningf(&format!("WAF list operation {operation_id} timed out"));
                    return false;
                }
                other => {
                    ppfmt.warningf(&format!(
                        "WAF list operation {operation_id} returned status '{other}'"
                    ));
                    return false;
                }
            }
        }
    }

    /// Set WAF list to contain exactly the given IPs.
    pub async fn set_waf_list(
        &self,
        waf_list: &WAFList,
        ips: &[IpAddr],
        comment: Option<&str>,
        dry_run: bool,
        ppfmt: &PP,
    ) -> SetResult {
        let list_meta = match self.find_waf_list(waf_list, ppfmt).await {
            Some(meta) => meta,
            None => {
                ppfmt.warningf(&format!("WAF list {} not found", waf_list.describe()));
                return SetResult::Failed;
            }
        };

        let Some(existing_items) = self
            .list_waf_list_items(&waf_list.account_id, &list_meta.id, ppfmt)
            .await
        else {
            return SetResult::Failed;
        };

        // Filter to managed items
        let managed_items: Vec<&WAFListItem> = existing_items
            .iter()
            .filter(|item| match &self.managed_waf_comment_regex {
                Some(regex) => {
                    let c = item.comment.as_deref().unwrap_or("");
                    regex.is_match(c)
                }
                None => true,
            })
            .collect();

        let desired_ips: HashSet<String> = ips.iter().map(|ip| ip.to_string()).collect();
        let existing_ips: HashSet<String> = managed_items
            .iter()
            .filter_map(|item| item.ip.clone())
            .collect();

        let to_add: Vec<&String> = desired_ips.difference(&existing_ips).collect();
        let ips_to_remove: Vec<&String> = existing_ips.difference(&desired_ips).collect();
        let comments_match = managed_items.iter().all(|item| {
            item.ip
                .as_ref()
                .is_none_or(|ip| !desired_ips.contains(ip) || item.comment.as_deref() == comment)
        });

        if to_add.is_empty() && ips_to_remove.is_empty() && comments_match {
            // Caller handles "up to date" logging based on SetResult::Noop
            return SetResult::Noop;
        }

        if dry_run {
            for ip in &to_add {
                ppfmt.infof(&format!(
                    "[DRY RUN] Would add {} to WAF list {}",
                    ip,
                    waf_list.describe()
                ));
            }
            for ip in &ips_to_remove {
                ppfmt.infof(&format!(
                    "[DRY RUN] Would remove {} from WAF list {}",
                    ip,
                    waf_list.describe()
                ));
            }
            return SetResult::Updated;
        }

        for ip in &ips_to_remove {
            ppfmt.infof(&format!(
                "Removing {} from WAF list {}",
                ip,
                waf_list.describe()
            ));
        }
        for ip in &to_add {
            ppfmt.infof(&format!(
                "Adding {} to WAF list {}",
                ip,
                waf_list.describe()
            ));
        }

        let mut target = BTreeMap::new();
        for item in &existing_items {
            let managed = match &self.managed_waf_comment_regex {
                Some(regex) => regex.is_match(item.comment.as_deref().unwrap_or("")),
                None => true,
            };
            if !managed && let Some(ip) = &item.ip {
                target.insert(ip.clone(), item.comment.clone());
            }
        }
        for ip in &desired_ips {
            target.insert(ip.clone(), comment.map(str::to_string));
        }
        let target: Vec<WAFListCreateItem> = target
            .into_iter()
            .map(|(ip, comment)| WAFListCreateItem { ip, comment })
            .collect();

        if self
            .replace_waf_list_items(&waf_list.account_id, &list_meta.id, &target, ppfmt)
            .await
        {
            SetResult::Updated
        } else {
            SetResult::Failed
        }
    }

    /// Clear all managed items from a WAF list (for shutdown).
    pub async fn final_clear_waf_list(&self, waf_list: &WAFList, ppfmt: &PP) -> bool {
        !matches!(
            self.set_waf_list(waf_list, &[], None, false, ppfmt).await,
            SetResult::Failed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetResult {
    Noop,
    Updated,
    ReadFailed,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pp::PP;
    use std::net::IpAddr;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param, query_param_is_missing},
    };

    fn pp() -> PP {
        PP::new(false)
    }

    /// The managed-comment regex decides which existing records ipflare may
    /// touch. A missing comment must never count as managed, or an unrelated
    /// record would be overwritten.
    #[test]
    fn managed_record_regex_selects_by_comment() {
        fn record(comment: Option<&str>) -> DnsRecord {
            DnsRecord {
                id: "r1".to_string(),
                name: "test".to_string(),
                content: "1.2.3.4".to_string(),
                proxied: None,
                ttl: None,
                comment: comment.map(str::to_string),
            }
        }

        // No regex: every record is managed.
        let all = CloudflareHandle::with_base_url("http://unused", test_auth());
        assert!(all.is_managed_record(&record(None)));
        assert!(all.is_managed_record(&record(Some("anything"))));

        let filtered = handle_with_regex("http://unused", "^managed-by-ipflare$");
        assert!(filtered.is_managed_record(&record(Some("managed-by-ipflare"))));
        assert!(!filtered.is_managed_record(&record(Some("something-else"))));
        assert!(!filtered.is_managed_record(&record(None)));
    }

    /// A non-2xx response yields None for every verb, so a failed request is
    /// never mistaken for an empty result.
    #[tokio::test]
    async fn api_request_returns_none_on_http_error() {
        for (verb, status) in [
            (reqwest::Method::GET, 500),
            (reqwest::Method::POST, 403),
            (reqwest::Method::PUT, 400),
            (reqwest::Method::DELETE, 404),
        ] {
            let server = MockServer::start().await;
            Mock::given(method(verb.as_str()))
                .respond_with(ResponseTemplate::new(status).set_body_string("failure"))
                .mount(&server)
                .await;

            let cf = handle(&server.uri());
            let body = serde_json::json!({ "test": true });
            let result: Option<CfResponse<serde_json::Value>> = cf
                .api_request(verb.clone(), "endpoint", Some(&body), &PP::new(true))
                .await;
            assert!(result.is_none(), "{verb} {status} should yield None");
        }
    }

    /// Cloudflare rejects TTLs below 30 other than the magic value 1, so any
    /// configured value under 30 (including negatives) collapses to auto.
    #[test]
    fn ttl_below_30_becomes_auto() {
        for value in [-5, 0, 1, 29] {
            assert_eq!(Ttl::new(value), Ttl::AUTO, "ttl {value} should be auto");
        }
        for value in [30, 120, 86400] {
            assert_eq!(Ttl::new(value), Ttl(value), "ttl {value} should be kept");
        }
        assert_eq!(Ttl::AUTO.describe(), "auto");
        assert_eq!(Ttl(120).describe(), "120s");
    }

    fn test_auth() -> Auth {
        Auth::token("test-token")
    }

    /// Cloudflare's errors array is the only place the reason for a
    /// `success: false` response appears, so it must survive into the log line.
    #[test]
    fn describes_error_array() {
        let errors = vec![
            CfError {
                code: Some(81044),
                message: Some("Record does not exist".to_string()),
            },
            CfError {
                code: None,
                message: Some("Bad request".to_string()),
            },
        ];
        assert_eq!(
            describe_errors(&errors),
            "Record does not exist (code 81044); Bad request"
        );
    }

    #[test]
    fn describes_empty_error_array() {
        assert_eq!(describe_errors(&[]), "no error details returned");
        assert_eq!(
            describe_errors(&[CfError::default()]),
            "unknown error".to_string()
        );
    }

    /// A 200 response carrying `success: false` must be reported as a failure and
    /// must not be mistaken for a successful empty result.
    #[tokio::test]
    async fn reports_success_false_with_error_details() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/zone-1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "result": null,
                "errors": [{ "code": 9109, "message": "Invalid access token" }]
            })))
            .mount(&server)
            .await;

        let cf = handle(&server.uri());
        assert!(cf.list_records("zone-1", "A", &pp()).await.is_none());
    }

    fn handle(base_url: &str) -> CloudflareHandle {
        CloudflareHandle::with_base_url(base_url, test_auth())
    }

    fn handle_with_regex(base_url: &str, pattern: &str) -> CloudflareHandle {
        crate::init_crypto();
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .expect("Failed to build HTTP client");
        CloudflareHandle {
            client,
            base_url: base_url.to_string(),
            auth: test_auth(),
            operation_timeout: Duration::from_secs(10),
            managed_comment_regex: Some(regex_lite::Regex::new(pattern).unwrap()),
            managed_waf_comment_regex: None,
        }
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
    // Ttl tests
    // -------------------------------------------------------

    // -------------------------------------------------------
    // Auth tests
    // -------------------------------------------------------

    // -------------------------------------------------------
    // WAFList tests
    // -------------------------------------------------------

    #[test]
    fn waf_list_new_valid() {
        let wl = WAFList::new("abc123", "my_list").unwrap();
        assert_eq!(wl.account_id, "abc123");
        assert_eq!(wl.list_name, "my_list");
    }

    #[test]
    fn waf_list_new_rejects_invalid_names() {
        assert!(WAFList::new("acc", "").is_err());
        assert!(WAFList::new("acc", "My-List").is_err());
        assert!(WAFList::new("acc", "UPPER").is_err());
        assert!(WAFList::new("acc", "has space").is_err());
    }

    // -------------------------------------------------------
    // CloudflareHandle with wiremock
    // -------------------------------------------------------

    fn dns_record_json(
        id: &str,
        name: &str,
        content: &str,
        comment: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "content": content,
            "proxied": false,
            "ttl": 1,
            "comment": comment
        })
    }

    fn dns_list_response(records: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "result": records })
    }

    fn dns_single_response(record: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "result": record })
    }

    // --- list_records / list_records_by_name ---

    #[tokio::test]
    async fn list_records_returns_all() {
        let server = MockServer::start().await;
        let body = dns_list_response(vec![
            dns_record_json("r1", "a.example.com", "1.2.3.4", None),
            dns_record_json("r2", "b.example.com", "5.6.7.8", None),
        ]);
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let records = h.list_records("z1", "A", &pp()).await.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, "r1");
        assert_eq!(records[1].id, "r2");
    }

    #[tokio::test]
    async fn list_records_follows_all_pages() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": [dns_record_json("r1", "a.example.com", "1.2.3.4", None)],
                "result_info": {"page": 1, "total_pages": 2}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": [dns_record_json("r2", "b.example.com", "5.6.7.8", None)],
                "result_info": {"page": 2, "total_pages": 2}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let records = handle(&server.uri())
            .list_records("z1", "A", &pp())
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
    }

    // Issue #255: Cloudflare normalizes record names to lowercase, so a
    // case-sensitive match against the user-supplied name (e.g. ExaMple.com)
    // would loop forever creating duplicates. Verify match is case-insensitive.
    #[tokio::test]
    async fn list_records_by_name_case_insensitive() {
        let server = MockServer::start().await;
        let body = dns_list_response(vec![dns_record_json("r1", "example.com", "1.2.3.4", None)]);
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let records = h
            .list_records_by_name("z1", "A", "ExaMple.com", &pp())
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "r1");
    }

    #[tokio::test]
    async fn list_records_by_name_filters() {
        let server = MockServer::start().await;
        let body = dns_list_response(vec![
            dns_record_json("r1", "a.example.com", "1.2.3.4", None),
            dns_record_json("r2", "b.example.com", "5.6.7.8", None),
        ]);
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let records = h
            .list_records_by_name("z1", "A", "a.example.com", &pp())
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content, "1.2.3.4");
    }

    // --- create_record ---

    #[tokio::test]
    async fn create_record_success() {
        let server = MockServer::start().await;
        let resp = dns_single_response(dns_record_json("new-id", "x.example.com", "9.9.9.9", None));
        Mock::given(method("POST"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(resp))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let payload = DnsRecordPayload {
            record_type: "A".to_string(),
            name: "x.example.com".to_string(),
            content: "9.9.9.9".to_string(),
            proxied: false,
            ttl: 1,
            comment: None,
        };
        let result = h.create_record("z1", &payload, &pp()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "new-id");
    }

    // --- update_record ---

    #[tokio::test]
    async fn update_record_success() {
        let server = MockServer::start().await;
        let resp = dns_single_response(dns_record_json("r1", "x.example.com", "10.0.0.1", None));
        Mock::given(method("PUT"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(resp))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let payload = DnsRecordPayload {
            record_type: "A".to_string(),
            name: "x.example.com".to_string(),
            content: "10.0.0.1".to_string(),
            proxied: false,
            ttl: 1,
            comment: None,
        };
        let result = h.update_record("z1", "r1", &payload, &pp()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().content, "10.0.0.1");
    }

    // --- delete_record ---

    #[tokio::test]
    async fn delete_record_success() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "result": { "id": "r1" } })),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        assert!(h.delete_record("z1", "r1", &pp()).await);
    }

    // --- set_ips: no existing records -> creates ---

    #[tokio::test]
    async fn set_ips_creates_when_no_existing() {
        let server = MockServer::start().await;
        // list returns empty
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![])))
            .mount(&server)
            .await;
        // create
        Mock::given(method("POST"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_single_response(dns_record_json(
                    "new1",
                    "a.example.com",
                    "1.2.3.4",
                    None,
                ))),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: matching existing record -> noop ---

    #[tokio::test]
    async fn set_ips_noop_when_matching() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![dns_record_json(
                    "r1",
                    "a.example.com",
                    "1.2.3.4",
                    None,
                )])),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Noop);
    }

    // --- set_ips: stale record -> updates ---

    #[tokio::test]
    async fn set_ips_updates_stale_record() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![dns_record_json(
                    "r1",
                    "a.example.com",
                    "9.9.9.9",
                    None,
                )])),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_single_response(dns_record_json(
                    "r1",
                    "a.example.com",
                    "1.2.3.4",
                    None,
                ))),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: extra records -> deletes extras ---

    #[tokio::test]
    async fn set_ips_deletes_extra_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                    dns_record_json("r1", "a.example.com", "1.2.3.4", None),
                    dns_record_json("r2", "a.example.com", "5.5.5.5", None),
                ])),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "result": { "id": "r2" } })),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: empty ips -> deletes all managed ---

    #[tokio::test]
    async fn set_ips_empty_ips_deletes_all() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![dns_record_json(
                    "r1",
                    "a.example.com",
                    "1.2.3.4",
                    None,
                )])),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "result": { "id": "r1" } })),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec![];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: dry_run doesn't mutate ---

    #[tokio::test]
    async fn set_ips_dry_run_no_mutation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![])))
            .mount(&server)
            .await;
        // No POST mock -- if set_ips tries to POST, wiremock will return 404

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                true,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- is_managed_record ---

    // --- final_delete ---

    #[tokio::test]
    async fn final_delete_removes_managed_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                    dns_record_json("r1", "a.example.com", "1.2.3.4", None),
                    dns_record_json("r2", "a.example.com", "5.6.7.8", None),
                ])),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "result": { "id": "r1" } })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "result": { "id": "r2" } })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        h.final_delete("z1", "a.example.com", "A", &pp()).await;
        // Expectations on mocks validate the DELETE calls were made
    }

    // --- find_waf_list ---

    #[tokio::test]
    async fn find_waf_list_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "list-1", "name": "blocklist" },
                    { "id": "list-2", "name": "allowlist" }
                ]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "allowlist".to_string(),
        };
        let result = h.find_waf_list(&wl, &pp()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "list-2");
    }

    #[tokio::test]
    async fn find_waf_list_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "list-1", "name": "other" }]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "missing".to_string(),
        };
        let result = h.find_waf_list(&wl, &pp()).await;
        assert!(result.is_none());
    }

    // --- set_waf_list ---

    #[tokio::test]
    async fn set_waf_list_adds_new_items() {
        let server = MockServer::start().await;
        // find_waf_list
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        // list items - empty
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": [] })),
            )
            .mount(&server)
            .await;
        mock_waf_replace(&server, "acct1", "wl-1").await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let result = h
            .set_waf_list(&wl, &ips, Some("ipflare"), false, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- CloudflareHandle::new ---

    // --- API error paths ---

    // --- set_ips: update due to proxied change ---

    #[tokio::test]
    async fn set_ips_updates_when_proxied_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                    serde_json::json!({
                        "id": "r1",
                        "name": "a.example.com",
                        "content": "1.2.3.4",
                        "proxied": false,
                        "ttl": 1,
                        "comment": null
                    }),
                ])),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_single_response(dns_record_json(
                    "r1",
                    "a.example.com",
                    "1.2.3.4",
                    None,
                ))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        // proxied=true but record has proxied=false -> should update
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                true,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: dry_run with existing records ---

    #[tokio::test]
    async fn set_ips_dry_run_with_existing_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![dns_record_json(
                    "r1",
                    "a.example.com",
                    "9.9.9.9",
                    None,
                )])),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                true,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: empty ips, no managed records -> noop ---

    #[tokio::test]
    async fn set_ips_empty_ips_no_records_noop() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![])))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec![];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Noop);
    }

    #[tokio::test]
    async fn set_ips_returns_failed_when_delete_fails() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![dns_record_json(
                    "r1",
                    "a.example.com",
                    "1.2.3.4",
                    None,
                )])),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let result = handle(&server.uri())
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &[],
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Failed);
    }

    #[tokio::test]
    async fn set_ips_reports_read_failure_without_writing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let result = handle(&server.uri())
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &["1.2.3.4".parse().unwrap()],
                false,
                Ttl::AUTO,
                None,
                false,
                &pp(),
            )
            .await;

        assert_eq!(result, SetResult::ReadFailed);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, wiremock::http::Method::GET);
    }

    #[tokio::test]
    async fn list_waf_items_follows_after_cursor() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/a/rules/lists/l/items"))
            .and(query_param("per_page", "500"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": [{"ip": "1.2.3.4"}],
                "result_info": {"cursors": {"after": "next"}}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/a/rules/lists/l/items"))
            .and(query_param("cursor", "next"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": [{"ip": "5.6.7.8"}],
                "result_info": {"cursors": {}}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let items = handle(&server.uri())
            .list_waf_list_items("a", "l", &pp())
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
    }

    // --- set_ips: empty ips, managed records -> deletes in dry_run ---

    #[tokio::test]
    async fn set_ips_empty_ips_dry_run_deletes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_list_response(vec![dns_record_json(
                    "r1",
                    "a.example.com",
                    "1.2.3.4",
                    None,
                )])),
            )
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec![];
        let result = h
            .set_ips(
                "z1",
                "a.example.com",
                "A",
                &ips,
                false,
                Ttl::AUTO,
                None,
                true,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_waf_list: not found -> Failed ---

    #[tokio::test]
    async fn set_waf_list_not_found_returns_failed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "missing".to_string(),
        };
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let result = h.set_waf_list(&wl, &ips, None, false, &pp()).await;
        assert_eq!(result, SetResult::Failed);
    }

    // --- set_waf_list: noop when already up to date ---

    #[tokio::test]
    async fn set_waf_list_noop_when_up_to_date() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "item-1", "ip": "10.0.0.1", "comment": null }
                ]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let result = h.set_waf_list(&wl, &ips, None, false, &pp()).await;
        assert_eq!(result, SetResult::Noop);
    }

    // --- set_waf_list: dry_run ---

    #[tokio::test]
    async fn set_waf_list_dry_run() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "item-1", "ip": "10.0.0.1", "comment": null }]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        // New IP to add + existing to remove
        let ips: Vec<IpAddr> = vec!["10.0.0.2".parse().unwrap()];
        let result = h.set_waf_list(&wl, &ips, None, true, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- final_clear_waf_list ---

    #[tokio::test]
    async fn final_clear_waf_list_deletes_all() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "item-1", "ip": "10.0.0.1", "comment": null },
                    { "id": "item-2", "ip": "10.0.0.2", "comment": null }
                ]
            })))
            .mount(&server)
            .await;
        mock_waf_replace(&server, "acct1", "wl-1").await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        h.final_clear_waf_list(&wl, &pp()).await;
    }

    #[tokio::test]
    async fn final_clear_waf_list_not_found_noop() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "missing".to_string(),
        };
        // Should not panic
        h.final_clear_waf_list(&wl, &pp()).await;
    }

    #[tokio::test]
    async fn set_waf_list_removes_stale_items() {
        let server = MockServer::start().await;
        // find_waf_list
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        // list items - has one stale item
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "item-1", "ip": "10.0.0.1", "comment": null }
                ]
            })))
            .mount(&server)
            .await;
        mock_waf_replace(&server, "acct1", "wl-1").await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        let ips: Vec<IpAddr> = vec![]; // no desired IPs -> should delete the existing one
        let result = h.set_waf_list(&wl, &ips, None, false, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    #[tokio::test]
    async fn set_waf_list_updates_changed_comment() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{"ip": "10.0.0.1", "comment": "old"}]
            })))
            .mount(&server)
            .await;
        mock_waf_replace(&server, "acct1", "wl-1").await;

        let result = handle(&server.uri())
            .set_waf_list(
                &WAFList {
                    account_id: "acct1".to_string(),
                    list_name: "mylist".to_string(),
                },
                &["10.0.0.1".parse().unwrap()],
                Some("new"),
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    #[tokio::test]
    async fn set_waf_list_reports_failed_bulk_operation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": {"operation_id": "failed-op"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/accounts/acct1/rules/lists/bulk_operations/failed-op",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "result": {"status": "failed", "error": "rejected"}
            })))
            .mount(&server)
            .await;

        let result = handle(&server.uri())
            .set_waf_list(
                &WAFList {
                    account_id: "acct1".to_string(),
                    list_name: "mylist".to_string(),
                },
                &["10.0.0.1".parse().unwrap()],
                None,
                false,
                &pp(),
            )
            .await;
        assert_eq!(result, SetResult::Failed);
    }
}
