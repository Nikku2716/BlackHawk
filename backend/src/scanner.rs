//! ZapScanner — Async wrapper around the OWASP ZAP REST API.
//!
//! Connects to a ZAP daemon and orchestrates:
//!   open_url → configure_spider → spider → configure_active_scan → active_scan → get_alerts
//!
//! Uses `reqwest` for truly async HTTP calls — no thread-pool overhead like the Python version.

use std::sync::Arc;
use std::time::Instant;

use reqwest::Client;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::models::{AlertData, ScanModeConfig, ScanPhase, ScanStatus};
use crate::owasp;

/// Seconds between polling ZAP for progress.
const POLL_INTERVAL_MS: u64 = 1000;

/// Auto-stop if no progress for this many seconds.
const STALL_TIMEOUT_SECS: u64 = 300;

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
    pub async fn run_full_scan(
        &self,
        status: Arc<ScanStatus>,
        mode_cfg: ScanModeConfig,
    ) {
        let scan_id = status.scan_id.clone();
        let target = status.target_url.clone();

        info!(
            scan_id = %scan_id,
            target = %target,
            mode = %status.scan_mode,
            "Starting scan"
        );

        if let Err(e) = self.run_pipeline(&status, &mode_cfg).await {
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
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Clear stale alerts from previous ZAP scans so they don't leak
        // into this scan's results (ZAP accumulates alerts across its session).
        if let Err(e) = self.zap_get("/JSON/core/action/deleteAllAlerts/").await {
            warn!(error = %e, "Failed to clear previous alerts — duplicates may appear");
        }

        // Open the target URL in ZAP
        self.open_url(&status.target_url).await?;

        // Configure spider
        self.configure_spider(mode_cfg).await;

        // Phase 1 — Spider
        self.run_spider(status).await?;
        if status.is_stop_requested() {
            let alerts = self.get_alerts(&status.target_url).await;
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
            self.run_active_scan(status).await?;
            if status.is_stop_requested() {
                let alerts = self.get_alerts(&status.target_url).await;
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
        let alerts = self.get_alerts(&status.target_url).await;
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
            if let Err(e) = self.zap_get(&format!(
                "/JSON/spider/action/stop/?scanId={}", sid
            )).await {
                warn!(error = %e, "Error stopping spider");
            } else {
                info!(scan_id = %status.scan_id, "Spider force-stopped");
            }
        }

        if let Some(ref aid) = status.get_ascan_id() {
            if let Err(e) = self.zap_get(&format!(
                "/JSON/ascan/action/stop/?scanId={}", aid
            )).await {
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

        match (tc, mc) {
            (Ok(_), Ok(_)) => {
                info!(
                    threads = cfg.spider_thread_count,
                    max_children = cfg.spider_max_children,
                    "Spider configured"
                );
            }
            (Err(e1), _) => warn!(error = %e1, "Failed to configure spider threads"),
            (_, Err(e2)) => warn!(error = %e2, "Failed to configure spider max children"),
        }
    }

    async fn configure_active_scan(&self, cfg: &ScanModeConfig) {
        // Set default policy
        let _ = self.zap_get("/JSON/ascan/action/setOptionDefaultPolicy/?id=0").await;

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
                    if let Some(strength) = cfg.attack_strength {
                        let _ = self.zap_get(&format!(
                            "/JSON/ascan/action/setScannerAttackStrength/?id={}&attackStrength={}",
                            id, strength
                        )).await;
                    }
                    if let Some(threshold) = cfg.alert_threshold {
                        let _ = self.zap_get(&format!(
                            "/JSON/ascan/action/setScannerAlertThreshold/?id={}&alertThreshold={}",
                            id, threshold
                        )).await;
                    }
                }
            }
        }

        info!(
            strength = ?cfg.attack_strength,
            threshold = ?cfg.alert_threshold,
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
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(())
    }

    async fn run_spider(
        &self,
        status: &Arc<ScanStatus>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        status.set_phase(ScanPhase::Spider);
        status.set_spider_progress(0);

        let resp = self.zap_get(&format!(
            "/JSON/spider/action/scan/?url={}&maxChildren=&recurse=true&subtreeOnly=",
            urlencoding_encode(&status.target_url)
        )).await?;

        let zap_id = resp
            .get("scan")
            .and_then(|v| v.as_str().or_else(|| v.as_i64().map(|_| "")))
            .map(|s| s.to_string())
            .or_else(|| resp.get("scan").and_then(|v| v.as_i64()).map(|n| n.to_string()))
            .unwrap_or_default();

        if zap_id.is_empty() || zap_id.parse::<i64>().is_err() {
            return Err(format!("ZAP spider failed to start — response: {:?}", resp).into());
        }

        status.set_spider_id(zap_id.clone());
        info!(zap_scan_id = %zap_id, "Spider started");

        let mut last_progress_time = Instant::now();
        let mut last_progress_value: i32 = 0;

        loop {
            if status.is_stop_requested() {
                info!(scan_id = %status.scan_id, "Stop requested — aborting spider");
                let _ = self.zap_get(&format!(
                    "/JSON/spider/action/stop/?scanId={}", zap_id
                )).await;
                return Ok(());
            }

            let progress = self.get_spider_status(&zap_id).await;
            status.set_spider_progress(progress);
            debug!(progress = progress, "Spider progress");

            // Stall detection
            if progress != last_progress_value {
                last_progress_value = progress;
                last_progress_time = Instant::now();
            } else if last_progress_time.elapsed().as_secs() > STALL_TIMEOUT_SECS {
                warn!(
                    scan_id = %status.scan_id,
                    stall_secs = STALL_TIMEOUT_SECS,
                    "Spider stalled — auto-stopping"
                );
                let _ = self.zap_get(&format!(
                    "/JSON/spider/action/stop/?scanId={}", zap_id
                )).await;
                break;
            }

            if progress >= 100 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
        }

        status.set_spider_progress(100);
        info!(target = %status.target_url, "Spider completed");
        Ok(())
    }

    async fn run_active_scan(
        &self,
        status: &Arc<ScanStatus>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        status.set_phase(ScanPhase::ActiveScan);
        status.set_active_scan_progress(0);

        let resp = self.zap_get(&format!(
            "/JSON/ascan/action/scan/?url={}&recurse=true&inScopeOnly=false&scanPolicyName=&method=&postData=",
            urlencoding_encode(&status.target_url)
        )).await?;

        let zap_id = resp
            .get("scan")
            .and_then(|v| v.as_str().or_else(|| v.as_i64().map(|_| "")))
            .map(|s| s.to_string())
            .or_else(|| resp.get("scan").and_then(|v| v.as_i64()).map(|n| n.to_string()))
            .unwrap_or_default();

        if zap_id.is_empty() || zap_id.parse::<i64>().is_err() {
            return Err(format!("ZAP active scan failed to start — response: {:?}", resp).into());
        }

        status.set_ascan_id(zap_id.clone());
        info!(zap_scan_id = %zap_id, "Active scan started");

        let mut last_progress_time = Instant::now();
        let mut last_progress_value: i32 = 0;

        loop {
            if status.is_stop_requested() {
                info!(scan_id = %status.scan_id, "Stop requested — aborting active scan");
                let _ = self.zap_get(&format!(
                    "/JSON/ascan/action/stop/?scanId={}", zap_id
                )).await;
                return Ok(());
            }

            let progress = self.get_ascan_status(&zap_id).await;
            status.set_active_scan_progress(progress);
            debug!(progress = progress, "Active scan progress");

            // Stall detection
            if progress != last_progress_value {
                last_progress_value = progress;
                last_progress_time = Instant::now();
            } else if last_progress_time.elapsed().as_secs() > STALL_TIMEOUT_SECS {
                warn!(
                    scan_id = %status.scan_id,
                    stall_secs = STALL_TIMEOUT_SECS,
                    "Active scan stalled — auto-stopping"
                );
                let _ = self.zap_get(&format!(
                    "/JSON/ascan/action/stop/?scanId={}", zap_id
                )).await;
                break;
            }

            if progress >= 100 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
        }

        status.set_active_scan_progress(100);
        info!(target = %status.target_url, "Active scan completed");
        Ok(())
    }

    async fn get_alerts(&self, target_url: &str) -> Vec<AlertData> {
        let resp = self.zap_get(&format!(
            "/JSON/core/view/alerts/?baseurl={}&start=0&count=500",
            urlencoding_encode(target_url)
        )).await;

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
        // Maps fingerprint → index in `filtered` so we can merge URLs
        // into an existing entry instead of creating duplicates.
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for alert in arr {
            let risk = alert.get("risk").and_then(|v| v.as_str()).unwrap_or("");
            if !keep_risks.contains(&risk) {
                continue;
            }

            let name = str_field_or(alert, "name", "Unknown");
            let url = str_field(alert, "url");
            let param = str_field(alert, "param");

            // Deduplicate by vulnerability type + parameter only.
            // Different URLs with the same vulnerability are merged
            // into a single entry with an `affected_urls` list.
            let fingerprint = format!("{}|{}", name, param);

            if let Some(&idx) = seen.get(&fingerprint) {
                // Merge: add this URL to the existing entry if not already present
                if !url.is_empty() && !filtered[idx].affected_urls.contains(&url) {
                    filtered[idx].affected_urls.push(url);
                }
                continue;
            }

            let cweid = alert.get("cweid").and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    alert.get("cweid").and_then(|v| v.as_i64())
                        .map(|_| "") // handled below
                        .unwrap_or("-1")
                });

            // Handle numeric cweid
            let cweid_str = if cweid.is_empty() {
                alert.get("cweid")
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

            let affected_urls = if url.is_empty() {
                vec![]
            } else {
                vec![url.clone()]
            };

            let idx = filtered.len();
            seen.insert(fingerprint, idx);

            filtered.push(AlertData {
                id: str_field(alert, "id"),
                name,
                risk: risk.to_string(),
                confidence: str_field(alert, "confidence"),
                description: str_field(alert, "description"),
                url,
                affected_urls,
                solution: str_field(alert, "solution"),
                reference: str_field(alert, "reference"),
                cweid: cweid_str,
                cwe_link,
                wascid: str_field(alert, "wascid"),
                param,
                evidence: str_field(alert, "evidence"),
                owasp_code: owasp_code.to_string(),
                owasp_category: owasp_category.to_string(),
            });
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
    if s.is_empty() { default.to_string() } else { s }
}
