mod cf_ip_filter;
mod cloudflare;
mod config;
mod domain;
mod notifier;
mod pp;
mod provider;
mod updater;

use crate::cloudflare::CloudflareHandle;
use crate::config::{AppConfig, CronSchedule};
use crate::notifier::Notifier;
use crate::pp::PP;
use rand::RngExt;
use reqwest::Client;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal;
use tokio::time::{Duration, sleep};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let unknown: Vec<&str> = args
        .iter()
        .filter(|argument| argument.as_str() != "--dry-run")
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        eprintln!("Unrecognized argument(s): {}", unknown.join(", "));
        std::process::exit(2);
    }
    let dry_run = args.iter().any(|argument| argument == "--dry-run");

    println!("ipflare v{VERSION}");
    let app_config = match config::load_config(dry_run) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };

    let ppfmt = PP::new(app_config.quiet);
    if dry_run {
        ppfmt.noticef("[DRY RUN] No records will be created, updated, or deleted.");
    }
    config::print_config_summary(&app_config, &ppfmt);

    let notifier = config::setup_notifier(&app_config, &ppfmt);
    let handle = CloudflareHandle::new(
        app_config.auth.clone(),
        app_config.update_timeout,
        app_config.managed_comment_regex.clone(),
        app_config.managed_waf_comment_regex.clone(),
    );

    let running = Arc::new(AtomicBool::new(true));
    let signal_running = Arc::clone(&running);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        println!("Stopping...");
        signal_running.store(false, Ordering::SeqCst);
    });

    let mut cf_cache = cf_ip_filter::CachedCloudflareFilter::new();
    let detection_client = Client::builder()
        .timeout(app_config.detection_timeout)
        .build()
        .expect("Failed to build detection HTTP client");

    let mut success = run_schedule(
        &app_config,
        &handle,
        &notifier,
        &ppfmt,
        running,
        &mut cf_cache,
        &detection_client,
    )
    .await;

    if app_config.delete_on_stop {
        ppfmt.noticef("Deleting records on stop...");
        success &= updater::final_delete(&app_config, &handle, &notifier, &ppfmt).await;
    }
    if !success {
        std::process::exit(1);
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal as unix_signal};

        match unix_signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(_) => {
                let _ = signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_schedule(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &Notifier,
    ppfmt: &PP,
    running: Arc<AtomicBool>,
    cf_cache: &mut cf_ip_filter::CachedCloudflareFilter,
    detection_client: &Client,
) -> bool {
    let mut noop_reported = HashSet::new();

    if matches!(config.update_cron, CronSchedule::Once) {
        return updater::update_once(
            config,
            handle,
            notifier,
            cf_cache,
            ppfmt,
            &mut noop_reported,
            detection_client,
        )
        .await;
    }

    let interval = config
        .update_cron
        .next_duration()
        .unwrap_or(Duration::from_secs(300));
    ppfmt.noticef(&format!(
        "Started ipflare, updating every {}",
        describe_duration(interval)
    ));

    if config.update_on_start {
        updater::update_once(
            config,
            handle,
            notifier,
            cf_cache,
            ppfmt,
            &mut noop_reported,
            detection_client,
        )
        .await;
    }

    while running.load(Ordering::SeqCst) {
        // Spread the wait around the configured interval rather than always
        // after it, so the average cycle matches what the user configured.
        let max_jitter = jitter_bound(interval.as_secs());
        let random_value = if max_jitter > 0 {
            rand::rng().random_range(0..=(max_jitter * 2))
        } else {
            0
        };
        let wait = jitter_duration(interval.as_secs(), random_value);

        ppfmt.infof(&format!("Next update in {}", describe_duration(wait)));
        if !sleep_until_shutdown(wait, &running).await {
            return true;
        }

        updater::update_once(
            config,
            handle,
            notifier,
            cf_cache,
            ppfmt,
            &mut noop_reported,
            detection_client,
        )
        .await;
    }

    true
}

/// Sleep in one-second steps so a shutdown signal is noticed promptly.
/// Returns false if shutdown was requested before the wait elapsed.
async fn sleep_until_shutdown(wait: Duration, running: &AtomicBool) -> bool {
    let mut remaining = wait;
    while !remaining.is_zero() {
        if !running.load(Ordering::SeqCst) {
            return false;
        }
        let step = remaining.min(Duration::from_secs(1));
        sleep(step).await;
        remaining -= step;
    }
    running.load(Ordering::SeqCst)
}

/// Half-width of the jitter window: 10% of the interval, so the wait lands
/// within ±10% of the configured value.
fn jitter_bound(interval_secs: u64) -> u64 {
    interval_secs / 10
}

/// Apply `random_value` (expected in `0..=jitter_bound*2`) as an offset centred
/// on the interval, keeping the average cycle equal to the configured interval.
fn jitter_duration(interval_secs: u64, random_value: u64) -> Duration {
    let max_jitter = jitter_bound(interval_secs);
    if max_jitter == 0 {
        return Duration::from_secs(interval_secs);
    }
    let offset = random_value.min(max_jitter * 2);
    Duration::from_secs(interval_secs + offset - max_jitter)
}

fn describe_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 3600 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        if minutes > 0 {
            format!("{hours}h{minutes}m")
        } else {
            format!("{hours}h")
        }
    } else if seconds >= 60 {
        let minutes = seconds / 60;
        let remainder = seconds % 60;
        if remainder > 0 {
            format!("{minutes}m{remainder}s")
        } else {
            format!("{minutes}m")
        }
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
pub(crate) fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
pub(crate) fn test_client() -> reqwest::Client {
    init_crypto();
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("Failed to build test HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wait is centred on the interval: ±10%, never a one-sided addition.
    #[test]
    fn jitter_is_centred_on_the_interval() {
        // 300s interval => bound 30s => window 270..=330s.
        assert_eq!(jitter_duration(300, 0), Duration::from_secs(270));
        assert_eq!(jitter_duration(300, 30), Duration::from_secs(300));
        assert_eq!(jitter_duration(300, 60), Duration::from_secs(330));
        // Out-of-range input is clamped, not wrapped, so it can never
        // collapse the wait to zero.
        assert_eq!(jitter_duration(300, 999), Duration::from_secs(330));
    }

    /// Short intervals have no room for jitter and must wait the full interval.
    #[test]
    fn jitter_preserves_short_intervals() {
        assert_eq!(jitter_bound(9), 0);
        assert_eq!(jitter_duration(9, 99), Duration::from_secs(9));
        assert_eq!(jitter_duration(1, 0), Duration::from_secs(1));
    }

    /// The mean of the jitter window equals the configured interval.
    #[test]
    fn jitter_window_averages_to_the_interval() {
        let bound = jitter_bound(600);
        let total: u64 = (0..=(bound * 2))
            .map(|value| jitter_duration(600, value).as_secs())
            .sum();
        let samples = bound * 2 + 1;
        assert_eq!(total / samples, 600);
    }

    #[test]
    fn formats_durations() {
        assert_eq!(describe_duration(Duration::from_secs(45)), "45s");
        assert_eq!(describe_duration(Duration::from_secs(330)), "5m30s");
        assert_eq!(describe_duration(Duration::from_secs(5400)), "1h30m");
    }
}
