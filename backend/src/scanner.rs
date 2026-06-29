//! ZapScanner — Async wrapper around the OWASP ZAP REST API.
//!
//! Connects to a ZAP daemon and orchestrates:
//!   open_url → configure_spider → spider → configure_active_scan → active_scan → get_alerts
//!
//! Uses `reqwest` for truly async HTTP calls — no thread-pool overhead like the Python version.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::models::{AlertData, ScanModeConfig, ScanPhase, ScanStatus, ScannerConfig};
use crate::owasp;

/// Auto-stop if no progress for this many seconds.
const STALL_TIMEOUT_SECS: u64 = 300;

/// Exponential backoff: start at 500ms, cap at 5s.
fn poll_interval(attempt: u32) -> Duration {
    let ms = 500u64 * (1u64 << attempt.min(5));
    Duration::from_millis(ms.min(5000))
}

/// Drives ZAP spider + active scan and collects alerts.
#[derive(Clone)]
pub struct ZapScanner {
    client: Client,
    base_url: String,
}

impl ZapScanner {
    pub fn new(zap_base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
            base_url: zap_base_url.trim_end_matches('/').to_string(),
        }
    }

    // ------------------------------------------------------------------
    // Public entry-point
    // ------------------------------------------------------------------

    /// Execute the complete scan pipeline, updating `status` in-place.
    pub async fn run_full_scan(&self, status: Arc<ScanStatus>, mode_cfg: ScanModeConfig, scanner_cfg: &ScannerConfig) {
        let scan_id = status.scan_id.clone();
        let target = status.target_url.clone();

        info!(
            scan_id = %scan_id,
            target = %target,
            mode = %status.scan_mode,
            "Starting scan"
        );

        if let Err(e) = self.run_pipeline(&status, &mode_cfg, scanner_cfg).await {
            tracing::error!(scan_id = %scan_id, error = %e, "Scan failed");
            status.set_phase(ScanPhase::Error);
            status.set_error(e.to_string());
            status.finish();
        }
    }

    async fn run_pipeline(
        &self,
        status: &Arc<ScanStatus>,
        mode_cfg: &ScanModeConfig,
        scanner_cfg: &ScannerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Single deadline for the entire scan — shared across all phases so the
        // documented time cap (e.g. 15 min for Deep) is the *total* wall time.
        let deadline = Instant::now() + Duration::from_secs(mode_cfg.max_scan_secs);

        // Clear stale alerts from previous ZAP scans so they don't leak
        // into this scan's results (ZAP accumulates alerts across its session).
        if let Err(e) = self.zap_get("/JSON/core/action/deleteAllAlerts/").await {
            warn!(error = %e, "Failed to clear previous alerts — duplicates may appear");
        }

        // Open the target URL in ZAP
        self.open_url(&status.target_url).await?;
        self.wait_for_passive_scan(status, mode_cfg).await;

        if mode_cfg.run_spider {
            self.configure_spider(mode_cfg).await;
            self.run_spider(status, mode_cfg, deadline).await?;
            self.wait_for_passive_scan(status, mode_cfg).await;
        } else {
            status.set_spider_progress(100);
            info!(
                scan_id = %status.scan_id,
                mode = %status.scan_mode,
                "Skipping spider for passive stealth mode"
            );
        }
        if status.is_stop_requested() {
            let alerts = self.get_alerts(&status.target_url, mode_cfg, scanner_cfg).await;
            status.set_alerts(alerts);
            status.set_phase(ScanPhase::Stopped);
            status.finish();
            info!(
                scan_id = %status.scan_id,
                alerts = status.get_alerts().len(),
                "Scan stopped by user — collected partial alerts"
            );
            return Ok(());
        }

        // Phase 2 — Active Scan (skip for quick/stealth)
        if mode_cfg.run_active_scan {
            self.configure_active_scan(mode_cfg).await;
            self.run_active_scan(status, mode_cfg, deadline).await?;
            if status.is_stop_requested() {
                let alerts = self.get_alerts(&status.target_url, mode_cfg, scanner_cfg).await;
                status.set_alerts(alerts);
                status.set_phase(ScanPhase::Stopped);
                status.finish();
                info!(
                    scan_id = %status.scan_id,
                    alerts = status.get_alerts().len(),
                    "Scan stopped by user — collected partial alerts"
                );
                return Ok(());
            }
        } else {
            status.set_active_scan_progress(100);
            info!(
                scan_id = %status.scan_id,
                mode = %status.scan_mode,
                "Skipping active scan for this mode"
            );
        }

        // Phase 3 — Collect results
        let alerts = self.get_alerts(&status.target_url, mode_cfg, scanner_cfg).await;
        let count = alerts.len();
        status.set_alerts(alerts);
        status.set_phase(ScanPhase::Complete);
        status.finish();
        info!(
            scan_id = %status.scan_id,
            alerts = count,
            mode = %status.scan_mode,
            "Scan complete"
        );

        Ok(())
    }

    // ------------------------------------------------------------------
    // Force stop
    // ------------------------------------------------------------------

    pub async fn force_stop(&self, status: &ScanStatus) {
        status.request_stop();

        if let Some(ref sid) = status.get_spider_id() {
            if let Err(e) = self
                .zap_get(&format!("/JSON/spider/action/stop/?scanId={}", sid))
                .await
            {
                warn!(error = %e, "Error stopping spider");
            } else {
                info!(scan_id = %status.scan_id, "Spider force-stopped");
            }
        }

        if let Some(ref aid) = status.get_ascan_id() {
            if let Err(e) = self
                .zap_get(&format!("/JSON/ascan/action/stop/?scanId={}", aid))
                .await
            {
                warn!(error = %e, "Error stopping active scan");
            } else {
                info!(scan_id = %status.scan_id, "Active scan force-stopped");
            }
        }

        info!(scan_id = %status.scan_id, "Stop requested");
    }

    // ------------------------------------------------------------------
    // Configuration helpers
    // ------------------------------------------------------------------

    async fn configure_spider(&self, cfg: &ScanModeConfig) {
        let tc = self
            .zap_get(&format!(
                "/JSON/spider/action/setOptionThreadCount/?Integer={}",
                cfg.spider_thread_count
            ))
            .await;
        let mc = self
            .zap_get(&format!(
                "/JSON/spider/action/setOptionMaxChildren/?Integer={}",
                cfg.spider_max_children
            ))
            .await;
        let delay = self
            .zap_get(&format!(
                "/JSON/spider/action/setOptionDelayInMs/?Integer={}",
                cfg.request_delay_ms
            ))
            .await;

        match (tc, mc, delay) {
            (Ok(_), Ok(_), Ok(_)) => {
                info!(
                    threads = cfg.spider_thread_count,
                    max_children = cfg.spider_max_children,
                    delay_ms = cfg.request_delay_ms,
                    "Spider configured"
                );
            }
            (tc_res, mc_res, delay_res) => {
                if let Err(e) = tc_res {
                    warn!(error = %e, "Failed to configure spider threads");
                }
                if let Err(e) = mc_res {
                    warn!(error = %e, "Failed to configure spider max children");
                }
                if let Err(e) = delay_res {
                    warn!(error = %e, "Failed to configure spider delay");
                }
            }
        }
    }

    async fn configure_active_scan(&self, cfg: &ScanModeConfig) {
        // Set default policy
        let _ = self
            .zap_get("/JSON/ascan/action/setOptionDefaultPolicy/?id=0")
            .await;

        // Get scanners for "Default Policy"
        let scanners = match self.zap_get("/JSON/ascan/view/scanners/?policyId=0").await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Failed to get active scan scanners");
                return;
            }
        };

        if let Some(arr) = scanners.get("scanners").and_then(|v| v.as_array()) {
            for scanner in arr {
                if let Some(id) = scanner.get("id").and_then(|v| v.as_str()) {
                    if let Some(ref strength) = cfg.attack_strength {
                        let _ = self
                            .zap_get(&format!(
                            "/JSON/ascan/action/setScannerAttackStrength/?id={}&attackStrength={}",
                            id, strength
                        ))
                            .await;
                    }
                    if let Some(ref threshold) = cfg.alert_threshold {
                        let _ = self
                            .zap_get(&format!(
                            "/JSON/ascan/action/setScannerAlertThreshold/?id={}&alertThreshold={}",
                            id, threshold
                        ))
                            .await;
                    }
                }
            }
        }

        let _ = self
            .zap_get(&format!(
                "/JSON/ascan/action/setOptionDelayInMs/?Integer={}",
                cfg.request_delay_ms
            ))
            .await;

        info!(
            strength = ?cfg.attack_strength,
            threshold = ?cfg.alert_threshold,
            delay_ms = cfg.request_delay_ms,
            "Active scan configured"
        );
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    async fn open_url(&self, target: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.zap_get(&format!(
            "/JSON/core/action/accessUrl/?url={}&followRedirects=true",
            urlencoding_encode(target)
        ))
        .await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }

    async fn run_spider(
        &self,
        status: &Arc<ScanStatus>,
        cfg: &ScanModeConfig,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        status.set_phase(ScanPhase::Spider);
        status.set_spider_progress(0);

        let resp = self
            .zap_get(&format!(
                "/JSON/spider/action/scan/?url={}&maxChildren={}&recurse=true&subtreeOnly=",
                urlencoding_encode(&status.target_url),
                cfg.spider_max_children
            ))
            .await?;

        let zap_id = extract_scan_id(&resp, "scan")
            .ok_or_else(|| format!("ZAP spider failed to start — response: {:?}", resp))?;

        status.set_spider_id(zap_id.clone());
        info!(zap_scan_id = %zap_id, "Spider started");

        let mut last_progress_time = Instant::now();
        let mut last_progress_value: i32 = 0;
        let mut poll_attempt: u32 = 0;

        loop {
            if status.is_stop_requested() {
                info!(scan_id = %status.scan_id, "Stop requested — aborting spider");
                let _ = self
                    .zap_get(&format!("/JSON/spider/action/stop/?scanId={}", zap_id))
                    .await;
                return Ok(());
            }

            let progress = self.get_spider_status(&zap_id).await;
            status.set_spider_progress(progress);
            debug!(progress = progress, "Spider progress");

            if progress != last_progress_value {
                last_progress_value = progress;
                last_progress_time = Instant::now();
                poll_attempt = 0;
            } else {
                poll_attempt += 1;
                if last_progress_time.elapsed().as_secs() > STALL_TIMEOUT_SECS {
                    warn!(
                        scan_id = %status.scan_id,
                        stall_secs = STALL_TIMEOUT_SECS,
                        "Spider stalled — auto-stopping"
                    );
                    let _ = self
                        .zap_get(&format!("/JSON/spider/action/stop/?scanId={}", zap_id))
                        .await;
                    break;
                }
            }
            if Instant::now() >= deadline {
                warn!(
                    scan_id = %status.scan_id,
                    max_secs = cfg.max_scan_secs,
                    "Spider exceeded total scan time limit — auto-stopping"
                );
                let _ = self
                    .zap_get(&format!("/JSON/spider/action/stop/?scanId={}", zap_id))
                    .await;
                break;
            }

            if progress >= 100 {
                break;
            }
            tokio::time::sleep(poll_interval(poll_attempt)).await;
        }

        status.set_spider_progress(100);
        info!(target = %status.target_url, "Spider completed");
        Ok(())
    }

    async fn wait_for_passive_scan(&self, status: &Arc<ScanStatus>, cfg: &ScanModeConfig) {
        let started_at = Instant::now();
        let mut poll_attempt: u32 = 0;
        loop {
            if status.is_stop_requested() {
                return;
            }

            tokio::time::sleep(poll_interval(poll_attempt)).await;
            poll_attempt += 1;

            match self.zap_get("/JSON/pscan/view/recordsToScan/").await {
                Ok(v) => {
                    let remaining = v
                        .get("recordsToScan")
                        .and_then(|s| {
                            s.as_str()
                                .and_then(|s| s.parse::<i32>().ok())
                                .or_else(|| s.as_i64().map(|n| n as i32))
                        })
                        .unwrap_or(0);
                    if remaining <= 0 {
                        return;
                    }
                    debug!(remaining = remaining, "Waiting for passive scan queue");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to read passive scan queue");
                    return;
                }
            }

            if started_at.elapsed().as_secs() >= cfg.max_scan_secs.min(30) {
                warn!(
                    scan_id = %status.scan_id,
                    "Passive scan queue wait timed out"
                );
                return;
            }
        }
    }

    async fn run_active_scan(
        &self,
        status: &Arc<ScanStatus>,
        cfg: &ScanModeConfig,
        deadline: Instant,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        status.set_phase(ScanPhase::ActiveScan);
        status.set_active_scan_progress(0);

        let resp = self.zap_get(&format!(
            "/JSON/ascan/action/scan/?url={}&recurse=true&inScopeOnly=false&scanPolicyName=&method=&postData=",
            urlencoding_encode(&status.target_url)
        )).await?;

        let zap_id = extract_scan_id(&resp, "scan")
            .ok_or_else(|| format!("ZAP active scan failed to start — response: {:?}", resp))?;

        status.set_ascan_id(zap_id.clone());
        info!(zap_scan_id = %zap_id, "Active scan started");

        let mut last_progress_time = Instant::now();
        let mut last_progress_value: i32 = 0;
        let mut poll_attempt: u32 = 0;

        loop {
            if status.is_stop_requested() {
                info!(scan_id = %status.scan_id, "Stop requested — aborting active scan");
                let _ = self
                    .zap_get(&format!("/JSON/ascan/action/stop/?scanId={}", zap_id))
                    .await;
                return Ok(());
            }

            let progress = self.get_ascan_status(&zap_id).await;
            status.set_active_scan_progress(progress);
            debug!(progress = progress, "Active scan progress");

            if progress != last_progress_value {
                last_progress_value = progress;
                last_progress_time = Instant::now();
                poll_attempt = 0;
            } else {
                poll_attempt += 1;
                if last_progress_time.elapsed().as_secs() > STALL_TIMEOUT_SECS {
                    warn!(
                        scan_id = %status.scan_id,
                        stall_secs = STALL_TIMEOUT_SECS,
                        "Active scan stalled — auto-stopping"
                    );
                    let _ = self
                        .zap_get(&format!("/JSON/ascan/action/stop/?scanId={}", zap_id))
                        .await;
                    break;
                }
            }
            if Instant::now() >= deadline {
                warn!(
                    scan_id = %status.scan_id,
                    max_secs = cfg.max_scan_secs,
                    "Active scan exceeded total scan time limit — auto-stopping"
                );
                let _ = self
                    .zap_get(&format!("/JSON/ascan/action/stop/?scanId={}", zap_id))
                    .await;
                break;
            }

            if progress >= 100 {
                break;
            }
            tokio::time::sleep(poll_interval(poll_attempt)).await;
        }

        status.set_active_scan_progress(100);
        info!(target = %status.target_url, "Active scan completed");
        Ok(())
    }

    async fn get_alerts(&self, target_url: &str, cfg: &ScanModeConfig, scanner_cfg: &ScannerConfig) -> Vec<AlertData> {
        let resp = self
            .zap_get(&format!(
                "/JSON/core/view/alerts/?baseurl={}&start=0&count={}",
                urlencoding_encode(target_url),
                scanner_cfg.alert_fetch_count,
            ))
            .await;

        let raw_alerts = match resp {
            Ok(v) => v.get("alerts").cloned().unwrap_or(Value::Array(vec![])),
            Err(e) => {
                warn!(error = %e, "Failed to get alerts");
                return Vec::new();
            }
        };

        let arr = match raw_alerts.as_array() {
            Some(a) => a,
            None => return Vec::new(),
        };

        let keep_risks = ["High", "Medium", "Low"];
        let mut filtered: Vec<AlertData> = Vec::new();
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut seen_urls: Vec<std::collections::HashSet<String>> = Vec::new();

        for alert in arr {
            let risk = alert.get("risk").and_then(|v| v.as_str()).unwrap_or("");
            if !keep_risks.contains(&risk) {
                continue;
            }

            let name = str_field_or(alert, "name", "Unknown");

            // Check exclusion list
            if scanner_cfg.excluded_alerts.iter().any(|excluded| {
                name.to_ascii_lowercase().contains(&excluded.to_ascii_lowercase())
            }) {
                debug!(alert = %name, "Skipping excluded alert");
                continue;
            }

            let url = str_field(alert, "url");
            let param = str_field(alert, "param");
            let confidence = str_field(alert, "confidence");
            if confidence_rank(&confidence) < cfg.min_confidence_rank {
                debug!(
                    alert = %name,
                    confidence = %confidence,
                    "Dropping low-confidence alert"
                );
                continue;
            }

            let cweid = alert
                .get("cweid")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    alert
                        .get("cweid")
                        .and_then(|v| v.as_i64())
                        .map(|_| "") // handled below
                        .unwrap_or("-1")
                });

            // Handle numeric cweid
            let cweid_str = if cweid.is_empty() {
                alert
                    .get("cweid")
                    .and_then(|v| v.as_i64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-1".to_string())
            } else {
                cweid.to_string()
            };

            let owasp_code = owasp::cwe_to_owasp(&cweid_str);
            let owasp_category = if owasp_code.is_empty() {
                ""
            } else {
                owasp::owasp_name(owasp_code)
            };

            let cwe_link = if !cweid_str.is_empty() && cweid_str != "-1" {
                format!("https://cwe.mitre.org/data/definitions/{}.html", cweid_str)
            } else {
                String::new()
            };

            let evidence = str_field(alert, "evidence");
            let alert_key = stable_alert_key(alert, &name);
            let fingerprint = alert_fingerprint(&alert_key, risk, &cweid_str, &param);

            if let Some(&idx) = seen.get(&fingerprint) {
                add_affected_url(&mut filtered[idx], &mut seen_urls[idx], &url);
                merge_alert_details(&mut filtered[idx], &confidence, &evidence);
                continue;
            }

            let idx = filtered.len();
            seen.insert(fingerprint, idx);
            let mut url_set = std::collections::HashSet::new();
            let mut affected_urls = Vec::new();
            if let Some(canonical_url) = canonicalize_alert_url(&url) {
                url_set.insert(canonical_url.clone());
                affected_urls.push(canonical_url);
            }
            seen_urls.push(url_set);

            filtered.push(AlertData {
                id: alert_key,
                name,
                risk: risk.to_string(),
                confidence,
                description: str_field(alert, "description"),
                url,
                affected_urls,
                solution: str_field(alert, "solution"),
                reference: str_field(alert, "reference"),
                cweid: cweid_str,
                cwe_link,
                wascid: str_field(alert, "wascid"),
                param,
                evidence,
                owasp_code: owasp_code.to_string(),
                owasp_category: owasp_category.to_string(),
            });

            if filtered.len() >= cfg.max_alerts {
                warn!(
                    max_alerts = cfg.max_alerts,
                    "Alert collection reached mode cap"
                );
                break;
            }
        }

        // Sort by severity: High → Medium → Low
        filtered.sort_by_key(|a| match a.risk.as_str() {
            "High" => 0,
            "Medium" => 1,
            "Low" => 2,
            _ => 99,
        });

        filtered
    }

    // ------------------------------------------------------------------
    // ZAP HTTP helpers
    // ------------------------------------------------------------------

    async fn zap_get(&self, path: &str) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.client.get(&url).send().await?;
        let body = resp.json::<Value>().await?;
        Ok(body)
    }

    async fn get_spider_status(&self, scan_id: &str) -> i32 {
        match self
            .zap_get(&format!("/JSON/spider/view/status/?scanId={}", scan_id))
            .await
        {
            Ok(v) => v
                .get("status")
                .and_then(|s| s.as_str().and_then(|s| s.parse::<i32>().ok()))
                .unwrap_or(0),
            Err(_) => 0,
        }
    }

    async fn get_ascan_status(&self, scan_id: &str) -> i32 {
        match self
            .zap_get(&format!("/JSON/ascan/view/status/?scanId={}", scan_id))
            .await
        {
            Ok(v) => v
                .get("status")
                .and_then(|s| s.as_str().and_then(|s| s.parse::<i32>().ok()))
                .unwrap_or(0),
            Err(_) => 0,
        }
    }
}

fn stable_alert_key(alert: &Value, name: &str) -> String {
    ["pluginId", "alertRef", "id"]
        .iter()
        .map(|key| str_field(alert, key))
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| normalize_text(name))
}

fn alert_fingerprint(alert_key: &str, risk: &str, cweid: &str, param: &str) -> String {
    format!(
        "{}|{}|{}|{}",
        normalize_text(alert_key),
        normalize_text(risk),
        normalize_text(cweid),
        normalize_text(param)
    )
}

fn add_affected_url(
    alert: &mut AlertData,
    seen_urls: &mut std::collections::HashSet<String>,
    raw_url: &str,
) {
    if let Some(canonical_url) = canonicalize_alert_url(raw_url) {
        if seen_urls.insert(canonical_url.clone()) {
            alert.affected_urls.push(canonical_url);
        }
    }
}

fn merge_alert_details(alert: &mut AlertData, confidence: &str, evidence: &str) {
    if confidence_rank(confidence) > confidence_rank(&alert.confidence) {
        alert.confidence = confidence.to_string();
    }

    if alert.evidence.is_empty() && !evidence.is_empty() {
        alert.evidence = evidence.to_string();
    }
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "High" | "Confirmed" | "User Confirmed" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

fn canonicalize_alert_url(raw_url: &str) -> Option<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut url = reqwest::Url::parse(trimmed).ok()?;
    url.set_fragment(None);
    if let Some(host) = url.host_str().map(|host| host.to_ascii_lowercase()) {
        let _ = url.set_host(Some(&host));
    }

    let path = url.path().trim_end_matches('/');
    let normalized_path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    url.set_path(&normalized_path);

    Some(url.to_string())
}

fn normalize_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Simple percent-encoding for URL parameters.
fn urlencoding_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", b));
            }
        }
    }
    result
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|val| {
            val.as_str()
                .map(|s| s.to_string())
                .or_else(|| val.as_i64().map(|n| n.to_string()))
        })
        .unwrap_or_default()
}

fn str_field_or(v: &Value, key: &str, default: &str) -> String {
    let s = str_field(v, key);
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

/// Extract a scan ID from a ZAP JSON response, handling both string and
/// numeric representations. Returns `None` if the key is missing or the
/// value is not a valid numeric ID.
fn extract_scan_id(resp: &Value, key: &str) -> Option<String> {
    resp.get(key).and_then(|v| match v {
        Value::String(s) if !s.is_empty() && s.parse::<i64>().is_ok() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_alert_url_removes_fragments_and_trailing_slashes() {
        assert_eq!(
            canonicalize_alert_url("https://Example.com/admin/#section").as_deref(),
            Some("https://example.com/admin")
        );
        assert_eq!(
            canonicalize_alert_url("https://Example.com/").as_deref(),
            Some("https://example.com/")
        );
    }

    #[test]
    fn canonicalize_alert_url_empty_and_whitespace() {
        assert_eq!(canonicalize_alert_url(""), None);
        assert_eq!(canonicalize_alert_url("   "), None);
    }

    #[test]
    fn canonicalize_alert_url_preserves_query_params() {
        assert_eq!(
            canonicalize_alert_url("https://example.com/search?q=test&page=1").as_deref(),
            Some("https://example.com/search?q=test&page=1")
        );
    }

    #[test]
    fn alert_fingerprint_ignores_evidence_and_confidence_noise() {
        let first = alert_fingerprint("10020", "Low", "693", "X-Frame-Options");
        let second = alert_fingerprint("10020", " low ", "693", "  X-Frame-Options ");

        assert_eq!(first, second);
    }

    #[test]
    fn alert_fingerprint_different_risks_differ() {
        let high = alert_fingerprint("10020", "High", "693", "X-Frame-Options");
        let low = alert_fingerprint("10020", "Low", "693", "X-Frame-Options");
        assert_ne!(high, low);
    }

    #[test]
    fn normalize_text_collapses_whitespace() {
        assert_eq!(normalize_text("  hello   world  "), "hello world");
    }

    #[test]
    fn normalize_text_lowercases() {
        assert_eq!(normalize_text("Hello World"), "hello world");
    }

    #[test]
    fn normalize_text_empty() {
        assert_eq!(normalize_text(""), "");
        assert_eq!(normalize_text("   "), "");
    }

    #[test]
    fn confidence_rank_values() {
        assert_eq!(confidence_rank("High"), 3);
        assert_eq!(confidence_rank("Confirmed"), 3);
        assert_eq!(confidence_rank("User Confirmed"), 3);
        assert_eq!(confidence_rank("Medium"), 2);
        assert_eq!(confidence_rank("Low"), 1);
        assert_eq!(confidence_rank("Informational"), 0);
        assert_eq!(confidence_rank(""), 0);
    }

    #[test]
    fn urlencoding_encode_preserves_safe_chars() {
        assert_eq!(urlencoding_encode("hello-world_v1.0~test"), "hello-world_v1.0~test");
    }

    #[test]
    fn urlencoding_encode_encodes_special_chars() {
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
        assert_eq!(urlencoding_encode("http://example.com"), "http%3A%2F%2Fexample.com");
    }

    #[test]
    fn urlencoding_encode_empty_string() {
        assert_eq!(urlencoding_encode(""), "");
    }

    #[test]
    fn str_field_extracts_string() {
        let v = serde_json::json!({"name": "test-alert"});
        assert_eq!(str_field(&v, "name"), "test-alert");
    }

    #[test]
    fn str_field_extracts_number_as_string() {
        let v = serde_json::json!({"cweid": 79});
        assert_eq!(str_field(&v, "cweid"), "79");
    }

    #[test]
    fn str_field_missing_key_returns_empty() {
        let v = serde_json::json!({"name": "test"});
        assert_eq!(str_field(&v, "missing"), "");
    }

    #[test]
    fn str_field_or_uses_default() {
        let v = serde_json::json!({});
        assert_eq!(str_field_or(&v, "name", "Unknown"), "Unknown");
    }

    #[test]
    fn str_field_or_uses_value_when_present() {
        let v = serde_json::json!({"name": "test"});
        assert_eq!(str_field_or(&v, "name", "Unknown"), "test");
    }

    #[test]
    fn extract_scan_id_string() {
        let v = serde_json::json!({"scan": "42"});
        assert_eq!(extract_scan_id(&v, "scan"), Some("42".to_string()));
    }

    #[test]
    fn extract_scan_id_number() {
        let v = serde_json::json!({"scan": 42});
        assert_eq!(extract_scan_id(&v, "scan"), Some("42".to_string()));
    }

    #[test]
    fn extract_scan_id_non_numeric_string_returns_none() {
        let v = serde_json::json!({"scan": "not-a-number"});
        assert_eq!(extract_scan_id(&v, "scan"), None);
    }

    #[test]
    fn extract_scan_id_missing_key_returns_none() {
        let v = serde_json::json!({});
        assert_eq!(extract_scan_id(&v, "scan"), None);
    }

    #[test]
    fn stable_alert_key_prefers_plugin_id() {
        let v = serde_json::json!({"pluginId": "10020", "alertRef": "10020", "id": "5"});
        assert_eq!(stable_alert_key(&v, "Fallback Name"), "10020");
    }

    #[test]
    fn stable_alert_key_falls_back_to_name() {
        let v = serde_json::json!({});
        assert_eq!(stable_alert_key(&v, "Some Alert"), "some alert");
    }

    #[test]
    fn stable_alert_key_prefers_alert_ref() {
        let v = serde_json::json!({"alertRef": "10020", "id": "5"});
        assert_eq!(stable_alert_key(&v, "Fallback"), "10020");
    }

    #[test]
    fn str_field_null_returns_empty() {
        let v = serde_json::json!({"key": null});
        assert_eq!(str_field(&v, "key"), "");
    }

    #[test]
    fn str_field_boolean_returns_empty() {
        let v = serde_json::json!({"flag": true});
        assert_eq!(str_field(&v, "flag"), "");
    }

    #[test]
    fn str_field_or_empty_value_uses_default() {
        let v = serde_json::json!({"name": ""});
        assert_eq!(str_field_or(&v, "name", "Default"), "Default");
    }

    #[test]
    fn extract_scan_id_empty_string_returns_none() {
        let v = serde_json::json!({"scan": ""});
        assert_eq!(extract_scan_id(&v, "scan"), None);
    }

    #[test]
    fn extract_scan_id_boolean_returns_none() {
        let v = serde_json::json!({"scan": true});
        assert_eq!(extract_scan_id(&v, "scan"), None);
    }

    #[test]
    fn alert_fingerprint_different_cwe_differ() {
        let a = alert_fingerprint("10020", "High", "79", "id");
        let b = alert_fingerprint("10020", "High", "89", "id");
        assert_ne!(a, b);
    }

    #[test]
    fn alert_fingerprint_different_param_differ() {
        let a = alert_fingerprint("10020", "Medium", "79", "username");
        let b = alert_fingerprint("10020", "Medium", "79", "password");
        assert_ne!(a, b);
    }

    #[test]
    fn confidence_rank_known_aliases() {
        assert_eq!(confidence_rank("High"), 3);
        assert_eq!(confidence_rank("Confirmed"), 3);
        assert_eq!(confidence_rank("User Confirmed"), 3);
        assert_eq!(confidence_rank("Medium"), 2);
        assert_eq!(confidence_rank("Low"), 1);
    }

    #[test]
    fn urlencoding_encode_unicode() {
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
    }

    #[test]
    fn urlencoding_encode_null_byte() {
        assert_eq!(urlencoding_encode("hello\0world"), "hello%00world");
    }

    #[test]
    fn canonicalize_alert_url_removes_auth_but_keeps_query() {
        let raw = "https://user:pass@Example.com:8080/path?q=1&r=2#frag";
        let result = canonicalize_alert_url(raw);
        assert!(result.is_some());
        let u = result.unwrap();
        assert!(u.contains("example.com"));
        assert!(u.contains("8080"));
        assert!(u.contains("q=1"));
        assert!(!u.contains("frag"));
    }

    #[test]
    fn normalize_text_special_chars() {
        assert_eq!(normalize_text("hello\t\nworld"), "hello world");
        assert_eq!(normalize_text("  multiple   spaces  "), "multiple spaces");
    }
}
