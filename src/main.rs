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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;
use tokio::time::{sleep, Duration};

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

    let ppfmt = PP::new(app_config.emoji, app_config.quiet);
    if dry_run {
        ppfmt.noticef(
            pp::EMOJI_WARNING,
            "[DRY RUN] No records will be created, updated, or deleted.",
        );
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
        ppfmt.noticef(pp::EMOJI_STOP, "Deleting records on stop...");
        success &= updater::final_delete(&app_config, &handle, &notifier, &ppfmt).await;
    }
    if !success {
        std::process::exit(1);
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal as unix_signal, SignalKind};

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
    ppfmt.noticef(
        pp::EMOJI_LAUNCH,
        &format!(
            "Started ipflare, updating every {}",
            describe_duration(interval)
        ),
    );

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
        ppfmt.infof(
            pp::EMOJI_SLEEP,
            &format!("Next update in {}", describe_duration(interval)),
        );
        for _ in 0..interval.as_secs() {
            if !running.load(Ordering::SeqCst) {
                return true;
            }
            sleep(Duration::from_secs(1)).await;
        }

        let max_jitter = interval.as_secs() / 5;
        if max_jitter > 0 {
            let random_value = rand::rng().random_range(0..=max_jitter);
            sleep(jitter_duration(interval.as_secs(), random_value)).await;
        }
        if !running.load(Ordering::SeqCst) {
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

fn jitter_duration(interval_secs: u64, random_value: u64) -> Duration {
    let max_jitter = interval_secs / 5;
    if max_jitter == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs(random_value % (max_jitter + 1))
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

    #[test]
    fn jitter_stays_within_limit() {
        assert_eq!(jitter_duration(300, 30), Duration::from_secs(30));
        assert_eq!(jitter_duration(300, 61), Duration::ZERO);
        assert_eq!(jitter_duration(4, 99), Duration::ZERO);
    }

    #[test]
    fn formats_durations() {
        assert_eq!(describe_duration(Duration::from_secs(45)), "45s");
        assert_eq!(describe_duration(Duration::from_secs(330)), "5m30s");
        assert_eq!(describe_duration(Duration::from_secs(5400)), "1h30m");
    }
}
