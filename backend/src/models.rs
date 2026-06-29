//! Request/response models and internal scan state.
//!
//! Mirrors the Pydantic models from the Python backend with identical JSON shapes
//! so the frontend requires zero changes.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Global scanner configuration (parsed from env vars)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub alert_threshold: String,
    pub min_confidence_rank: u8,
    pub excluded_alerts: Vec<String>,
    pub alert_fetch_count: u32,
    pub api_key: Option<String>,
    pub webhook_url: Option<String>,
    pub db_path: String,
    pub spider_threads_quick: u32,
    pub spider_threads_fast: u32,
    pub spider_threads_deep: u32,
    pub spider_delay_quick: u32,
    pub spider_delay_fast: u32,
    pub spider_delay_deep: u32,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            alert_threshold: "MEDIUM".to_string(),
            min_confidence_rank: 2,
            excluded_alerts: Vec::new(),
            alert_fetch_count: 5000,
            api_key: None,
            webhook_url: None,
            db_path: "data/scans.db".to_string(),
            spider_threads_quick: 2,
            spider_threads_fast: 4,
            spider_threads_deep: 6,
            spider_delay_quick: 300,
            spider_delay_fast: 200,
            spider_delay_deep: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Scan phase enum
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Idle,
    Spider,
    ActiveScan,
    Complete,
    Stopped,
    Error,
}

impl ScanPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanPhase::Idle => "idle",
            ScanPhase::Spider => "spider",
            ScanPhase::ActiveScan => "active_scan",
            ScanPhase::Complete => "complete",
            ScanPhase::Stopped => "stopped",
            ScanPhase::Error => "error",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ScanPhase::Complete | ScanPhase::Stopped | ScanPhase::Error
        )
    }
}

// ---------------------------------------------------------------------------
// Scan mode configuration
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ScanModeConfig {
    pub run_spider: bool,
    pub spider_thread_count: u32,
    pub spider_max_children: u32,
    pub request_delay_ms: u32,
    pub max_scan_secs: u64,
    pub run_active_scan: bool,
    pub attack_strength: Option<String>,
    pub alert_threshold: Option<String>,
    pub min_confidence_rank: u8,
    pub max_alerts: usize,
}

pub fn get_scan_mode_config(mode: &str, cfg: &ScannerConfig) -> ScanModeConfig {
    match mode {
        "quick" => ScanModeConfig {
            run_spider: true,
            spider_thread_count: cfg.spider_threads_quick,
            spider_max_children: 5,
            request_delay_ms: cfg.spider_delay_quick,
            max_scan_secs: 180,
            run_active_scan: false,
            attack_strength: None,
            alert_threshold: None,
            min_confidence_rank: cfg.min_confidence_rank,
            max_alerts: 100,
        },
        "deep" => ScanModeConfig {
            run_spider: true,
            spider_thread_count: cfg.spider_threads_deep,
            spider_max_children: 50,
            request_delay_ms: cfg.spider_delay_deep,
            max_scan_secs: 900,
            run_active_scan: true,
            attack_strength: Some("MEDIUM".to_string()),
            alert_threshold: Some(cfg.alert_threshold.clone()),
            min_confidence_rank: cfg.min_confidence_rank,
            max_alerts: 300,
        },
        "stealth" => ScanModeConfig {
            run_spider: false,
            spider_thread_count: 1,
            spider_max_children: 0,
            request_delay_ms: 1500,
            max_scan_secs: 120,
            run_active_scan: false,
            attack_strength: None,
            alert_threshold: None,
            min_confidence_rank: cfg.min_confidence_rank,
            max_alerts: 50,
        },
        // "fast" and anything else
        _ => ScanModeConfig {
            run_spider: true,
            spider_thread_count: cfg.spider_threads_fast,
            spider_max_children: 10,
            request_delay_ms: cfg.spider_delay_fast,
            max_scan_secs: 420,
            run_active_scan: true,
            attack_strength: Some("LOW".to_string()),
            alert_threshold: Some(cfg.alert_threshold.clone()),
            min_confidence_rank: cfg.min_confidence_rank,
            max_alerts: 150,
        },
    }
}

// ---------------------------------------------------------------------------
// Internal scan state (shared across tasks via Arc)
// ---------------------------------------------------------------------------

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Mutable scan state shared between the API handlers and the background scan task.
///
/// Uses `AtomicBool` for the stop flag (lock-free) and `Mutex` for fields that
/// are only written by the background task and read by API handlers.
pub struct ScanStatus {
    pub scan_id: String,
    pub target_url: String,
    pub scan_mode: String,
    pub phase: Mutex<ScanPhase>,
    pub spider_progress: Mutex<i32>,
    pub active_scan_progress: Mutex<i32>,
    pub alerts: Mutex<Vec<AlertData>>,
    pub error: Mutex<Option<String>>,
    pub started_at: f64,
    pub finished_at: Mutex<Option<f64>>,
    pub stop_requested: AtomicBool,
    pub zap_spider_id: Mutex<Option<String>>,
    pub zap_ascan_id: Mutex<Option<String>>,
}

impl ScanStatus {
    pub fn new(scan_id: String, target_url: String, scan_mode: String) -> Self {
        Self {
            scan_id,
            target_url,
            scan_mode,
            phase: Mutex::new(ScanPhase::Idle),
            spider_progress: Mutex::new(0),
            active_scan_progress: Mutex::new(0),
            alerts: Mutex::new(Vec::new()),
            error: Mutex::new(None),
            started_at: now_epoch(),
            finished_at: Mutex::new(None),
            stop_requested: AtomicBool::new(false),
            zap_spider_id: Mutex::new(None),
            zap_ascan_id: Mutex::new(None),
        }
    }

    pub fn is_stop_requested(&self) -> bool {
        self.stop_requested.load(Ordering::Relaxed)
    }

    pub fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::Relaxed);
    }

    pub fn set_phase(&self, phase: ScanPhase) {
        *self.phase.lock().unwrap() = phase;
    }

    pub fn get_phase(&self) -> ScanPhase {
        *self.phase.lock().unwrap()
    }

    pub fn set_spider_progress(&self, p: i32) {
        *self.spider_progress.lock().unwrap() = p;
    }

    pub fn get_spider_progress(&self) -> i32 {
        *self.spider_progress.lock().unwrap()
    }

    pub fn set_active_scan_progress(&self, p: i32) {
        *self.active_scan_progress.lock().unwrap() = p;
    }

    pub fn get_active_scan_progress(&self) -> i32 {
        *self.active_scan_progress.lock().unwrap()
    }

    pub fn set_alerts(&self, a: Vec<AlertData>) {
        *self.alerts.lock().unwrap() = a;
    }

    pub fn get_alerts(&self) -> Vec<AlertData> {
        self.alerts.lock().unwrap().clone()
    }

    pub fn set_error(&self, e: String) {
        *self.error.lock().unwrap() = Some(e);
    }

    pub fn get_error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    pub fn finish(&self) {
        *self.finished_at.lock().unwrap() = Some(now_epoch());
    }

    pub fn get_finished_at(&self) -> Option<f64> {
        *self.finished_at.lock().unwrap()
    }

    pub fn set_spider_id(&self, id: String) {
        *self.zap_spider_id.lock().unwrap() = Some(id);
    }

    pub fn get_spider_id(&self) -> Option<String> {
        self.zap_spider_id.lock().unwrap().clone()
    }

    pub fn set_ascan_id(&self, id: String) {
        *self.zap_ascan_id.lock().unwrap() = Some(id);
    }

    pub fn get_ascan_id(&self) -> Option<String> {
        self.zap_ascan_id.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Alert data (internal + serializable)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertData {
    pub id: String,
    pub name: String,
    pub risk: String,
    pub confidence: String,
    pub description: String,
    pub url: String,
    /// All unique URLs where this vulnerability was detected.
    pub affected_urls: Vec<String>,
    pub solution: String,
    pub reference: String,
    pub cweid: String,
    pub cwe_link: String,
    pub wascid: String,
    pub param: String,
    pub evidence: String,
    pub owasp_code: String,
    pub owasp_category: String,
}

// ---------------------------------------------------------------------------
// API request / response models (JSON shapes match Python backend exactly)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target_url: String,
    #[serde(default = "default_scan_mode")]
    pub scan_mode: String,
}

fn default_scan_mode() -> String {
    "stealth".to_string()
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub scan_id: String,
    pub target_url: String,
    pub phase: String,
    pub spider_progress: i32,
    pub active_scan_progress: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResultsResponse {
    pub scan_id: String,
    pub target_url: String,
    pub phase: String,
    pub total_alerts: usize,
    pub summary: AlertSummary,
    pub alerts: Vec<AlertData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertSummary {
    #[serde(rename = "High")]
    pub high: usize,
    #[serde(rename = "Medium")]
    pub medium: usize,
    #[serde(rename = "Low")]
    pub low: usize,
}

impl AlertSummary {
    pub fn from_alerts(alerts: &[AlertData]) -> Self {
        let mut s = AlertSummary::default();
        for a in alerts {
            match a.risk.as_str() {
                "High" => s.high += 1,
                "Medium" => s.medium += 1,
                "Low" => s.low += 1,
                _ => {}
            }
        }
        s
    }
}

#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    pub scan_id: String,
    pub target_url: String,
    pub scan_mode: String,
    pub phase: String,
    pub started_at: f64,
    pub finished_at: Option<f64>,
    pub alert_summary: AlertSummary,
    pub total_alerts: usize,
}

#[derive(Debug, Serialize)]
pub struct ExportJson {
    pub scan_id: String,
    pub target_url: String,
    pub scan_mode: String,
    pub phase: String,
    pub started_at: f64,
    pub finished_at: Option<f64>,
    pub summary: AlertSummary,
    pub total_alerts: usize,
    pub alerts: Vec<AlertData>,
}

/// Query param for the export endpoint.
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "json".to_string()
}
